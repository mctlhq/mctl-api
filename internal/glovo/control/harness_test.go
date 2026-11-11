// Copyright 2026 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package control

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/basket"
	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
	"github.com/mctlhq/mctl-api/internal/glovo/orders"
	"github.com/mctlhq/mctl-api/internal/glovojoin"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

const (
	pw       = "pw-control-test" //nolint:gosec // throwaway password of roles in a per-test scratch database
	tenant   = "acme"
	ownerPrn = "prn_OWNER00000000000000000001"
	provider = "fake"
	install  = "install-1"
	revision = "3"
)

const basePayload = `{"v":"mctl-approval-basket/v1","store_ref":"pst_0123456789abcdef0123","currency":"EUR",
"lines":[{"item_code":"FAKE-1","quantity":1,"unit_price_minor":500}],
"subtotal_minor":500,"delivery_fee_minor":199,"service_fee_minor":50,"discount_minor":0,"total_minor":749}`

func rnd(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func tok(prefix string, n int) string { return prefix + strings.ToUpper(rnd(n))[:n] }

// fakeIndex is the #988 order store, reduced to what the control worker
// reads and writes: immutable fields live in memory, the mutable state and
// command id in a real table so that FOR UPDATE, rollback and commit are the
// database's own.
type fakeIndex struct {
	mu        sync.Mutex
	tmpl      map[string]orders.Order
	snaps     map[string]orders.Snapshot
	marks     []string
	markErr   error
	lockCalls int
	peekOwner string // when set, PeekOrderScope reports this owner
}

// BindApproval is the #988 call CreateGlovoApprovalTx makes; the fixture binds
// the order itself.
func (f *fakeIndex) BindApproval(context.Context, pgx.Tx, orders.Scope, orders.Actor, string, string) error {
	return nil
}

func (f *fakeIndex) PeekOrderScope(_ context.Context, _ dbq.Querier, ref string, tenants []string) (orders.Scope, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.tmpl[ref]
	if !ok || !in(tenants, o.Tenant) {
		return orders.Scope{}, glovo.ErrNotFound
	}
	if f.peekOwner != "" {
		return orders.Scope{Tenant: o.Tenant, PrincipalID: f.peekOwner}, nil
	}
	return orders.Scope{Tenant: o.Tenant, PrincipalID: o.OwnerPrincipalID}, nil
}

func in(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func (f *fakeIndex) LockOrderForControl(ctx context.Context, tx pgx.Tx, ref string, tenants []string) (*orders.Order, error) {
	f.mu.Lock()
	o, ok := f.tmpl[ref]
	f.lockCalls++
	f.mu.Unlock()
	if !ok || !in(tenants, o.Tenant) {
		return nil, glovo.ErrNotFound
	}
	var state, cmd string
	if err := tx.QueryRow(ctx, `SELECT state, command_id FROM ctl_fake_orders WHERE order_ref = $1 FOR UPDATE`, ref).Scan(&state, &cmd); err != nil {
		return nil, err
	}
	o.State, o.CommandID = state, cmd
	return &o, nil
}

func (f *fakeIndex) Snapshot(_ context.Context, _ dbq.Querier, _ orders.Scope, ref string, _ int) (*orders.Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.snaps[ref]
	if !ok {
		return nil, glovo.ErrNotFound
	}
	return &s, nil
}

func (f *fakeIndex) move(ctx context.Context, tx pgx.Tx, o *orders.Order, from []string, to, cmd string, a orders.Actor) error {
	if !in(from, o.State) {
		return glovo.Refuse(glovo.CodeInvalidTransition)
	}
	if a.Kind != orders.ActorControlWorker || a.ID != ActorID {
		return glovo.Refuse(glovo.CodeInvalidRequest)
	}
	if _, err := tx.Exec(ctx, `UPDATE ctl_fake_orders SET state = $2, command_id = CASE WHEN $3 = '' THEN command_id ELSE $3 END WHERE order_ref = $1`, o.OrderRef, to, cmd); err != nil {
		return err
	}
	f.mu.Lock()
	f.marks = append(f.marks, to)
	f.mu.Unlock()
	o.State = to
	if cmd != "" {
		o.CommandID = cmd
	}
	return nil
}

func (f *fakeIndex) MarkDispatched(ctx context.Context, tx pgx.Tx, o *orders.Order, cmd string, a orders.Actor) error {
	if f.markErr != nil {
		return f.markErr
	}
	if o.ApprovalRef == "" {
		return glovo.Refuse(glovo.CodeInvalidTransition)
	}
	return f.move(ctx, tx, o, []string{orders.StateFinalized}, orders.StateDispatched, cmd, a)
}

func (f *fakeIndex) MarkCancelled(ctx context.Context, tx pgx.Tx, o *orders.Order, a orders.Actor) error {
	return f.move(ctx, tx, o, []string{orders.StateOpen, orders.StateFinalized, orders.StateDispatched}, orders.StateCancelled, "", a)
}

func (f *fakeIndex) MarkUnknown(ctx context.Context, tx pgx.Tx, o *orders.Order, a orders.Actor) error {
	return f.move(ctx, tx, o, []string{orders.StateDispatched}, orders.StateUnknown, "", a)
}

func (f *fakeIndex) MarkClosed(ctx context.Context, tx pgx.Tx, o *orders.Order, a orders.Actor) error {
	return f.move(ctx, tx, o, []string{orders.StateDispatched}, orders.StateClosed, "", a)
}

type fakeConns struct {
	mu   sync.Mutex
	conn glovo.Connection
	err  error
}

func (f *fakeConns) LockOwnerShared(context.Context, pgx.Tx, string, string) error { return nil }

func (f *fakeConns) LiveConnectionTx(context.Context, pgx.Tx, glovo.Owner) (*glovo.Connection, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	c := f.conn
	return &c, nil
}

type fakeMembers struct {
	member bool
	err    error
	hang   chan struct{} // a non-nil channel blocks the read until it is closed
}

func (f *fakeMembers) IsMember(_ context.Context, _, _ string) (bool, error) {
	if f.hang != nil {
		<-f.hang // deliberately ignores ctx: the bound must not rely on the provider
	}
	return f.member, f.err
}

type fakeJoins struct{ err error }

func (f *fakeJoins) LookupJoinRefTx(_ context.Context, _ dbq.Querier, kind orders.JoinKind, _, _, _ string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	if kind == orders.JoinTenant {
		return "tnr_TENANT000000000000000001", nil
	}
	return "prr_PRINCIPAL00000000000000001", nil
}

type fakeExecs struct {
	tenant, owner, wi, wf string
	err                   error
}

func (f *fakeExecs) ExecutionBindingTx(context.Context, dbq.Querier, string) (string, string, string, string, error) {
	return f.tenant, f.owner, f.wi, f.wf, f.err
}

// env is a scratch database with the three roles of the owner-confirmed model:
// a migration role that owns the schema, a work-items role and the shared
// runtime role the control worker runs on.
type env struct {
	t           *testing.T
	base, db    string
	mig, wi, rt string
	migURL      string
	rtURL       string
	mp, rtp     *pgxpool.Pool
	st          *workitems.Store
	gs          *glovo.Store // set by newRealEnv only
	connTTL     time.Duration
	bs          *bridge.Store
	idx         *fakeIndex
	conns       *fakeConns
	members     *fakeMembers
	joins       *fakeJoins
	execs       *fakeExecs
	d           *Dispatcher
	canon       []byte
	fingerprint string
	tenants     []string

	startHook func(ctx context.Context, q dbq.Querier) error
	startErr  error
	startWF   string
	ready     error
}

// newBase is the scratch database and its three roles, with no schema.
func newBase(t *testing.T) *env {
	t.Helper()
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL is unset in CI: the control database tests must run, not skip")
		}
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	sfx := rnd(6)
	e := &env{t: t, base: base, db: "c985db_" + sfx, mig: "c985mig_" + sfx, wi: "c985wi_" + sfx, rt: "c985rt_" + sfx, tenants: []string{tenant}}
	root, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer func() { _ = root.Close(ctx) }()
	var stmts []string
	for _, r := range []string{e.mig, e.wi, e.rt} {
		stmts = append(stmts, fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`, r, pw))
	}
	stmts = append(stmts, fmt.Sprintf(`CREATE DATABASE %s OWNER %s`, e.db, e.mig),
		fmt.Sprintf(`REVOKE ALL ON DATABASE %s FROM PUBLIC`, e.db),
		fmt.Sprintf(`GRANT CONNECT ON DATABASE %s TO %s, %s`, e.db, e.wi, e.rt))
	for _, s := range stmts {
		if _, err := root.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s, err)
		}
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), base)
		if err != nil {
			return
		}
		defer func() { _ = c.Close(context.Background()) }()
		_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, e.db))
		for _, r := range []string{e.rt, e.wi, e.mig} {
			_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP ROLE IF EXISTS %s`, r))
		}
	})
	e.migURL = e.url(e.mig)
	e.rtURL = e.url(e.rt)
	return e
}

func newEnv(t *testing.T) *env { return newEnvWith(t, false) }

// newRealEnv is newEnv with the real Glovo connection store (its schema, the
// L1 and L2 advisory locks, the live-connection read and the revocation hook
// bridge.CancelOpenForConnections) in place of fakeConns. Only the orders index
// stays a fake.
func newRealEnv(t *testing.T) *env { return newEnvWith(t, true) }

func newEnvWith(t *testing.T, real bool) *env {
	t.Helper()
	e := newBase(t)
	ctx := context.Background()
	var err error
	if real {
		if err := glovo.ApplySchema(ctx, e.migURL, e.rt); err != nil {
			t.Fatalf("glovo.ApplySchema: %v", err)
		}
		if err := glovojoin.ApplySchema(ctx, e.migURL, e.rt); err != nil {
			t.Fatalf("glovojoin.ApplySchema: %v", err)
		}
		if err := orders.ApplySchema(ctx, e.migURL, e.rt); err != nil {
			t.Fatalf("orders.ApplySchema: %v", err)
		}
	}
	if err := workitems.ApplyGlovoApprovalSchema(ctx, e.migURL, e.rt, workitems.WithWorkItemsRole(e.wi)); err != nil {
		t.Fatalf("ApplyGlovoApprovalSchema: %v", err)
	}
	if err := bridge.ApplySchema(ctx, e.migURL, e.rt, bridge.WithWorkItemsRole(e.wi)); err != nil {
		t.Fatalf("bridge.ApplySchema: %v", err)
	}
	e.mp = e.pool(e.migURL)
	e.rtp = e.pool(e.rtURL)
	for _, s := range []string{
		`CREATE TABLE ctl_fake_orders (order_ref text PRIMARY KEY, state text NOT NULL, command_id text NOT NULL DEFAULT '')`,
		fmt.Sprintf(`GRANT SELECT, INSERT, UPDATE ON ctl_fake_orders TO %s`, e.rt),
	} {
		if _, err := e.mp.Exec(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	e.bs, err = bridge.NewRuntimeStore(ctx, e.rtp)
	if err != nil {
		t.Fatalf("NewRuntimeStore: %v", err)
	}
	e.idx = &fakeIndex{tmpl: map[string]orders.Order{}, snaps: map[string]orders.Snapshot{}}
	st, err := workitems.NewStore(ctx, e.url(e.wi), workitems.WithGlovoOrders(e.idx))
	if err != nil {
		t.Fatalf("workitems.NewStore: %v", err)
	}
	t.Cleanup(st.Close)
	e.st = st
	e.conns = &fakeConns{}
	var conns Connections = e.conns
	if real {
		e.gs, err = glovo.NewStore(ctx, e.rtp, e.rt, e.mig, glovo.WithExplicitURL(true),
			glovo.WithRevocationHook(bridge.CancelOpenForConnections), glovo.WithLockTimeout(5*time.Second))
		if err != nil {
			t.Fatalf("glovo.NewStore: %v", err)
		}
		conns = e.gs
	}
	e.members = &fakeMembers{member: true}
	e.joins = &fakeJoins{}
	e.execs = &fakeExecs{tenant: tenant, owner: ownerPrn}
	_, e.canon, err = basket.Parse([]byte(basePayload))
	if err != nil {
		t.Fatal(err)
	}
	e.fingerprint = basket.Fingerprint(e.canon)
	e.d = &Dispatcher{
		DB: e.rtp, Bridge: e.bs, Orders: e.idx, Receipts: e.st, Conns: conns, Members: e.members, Joins: e.joins, Execs: e.execs,
		ControlStart: func(ctx context.Context, q dbq.Querier, _ string) (string, string, error) {
			if e.startHook != nil {
				if err := e.startHook(ctx, q); err != nil {
					return "", "", err
				}
			}
			if e.startErr != nil {
				return "", "", e.startErr
			}
			return e.startWF, "run-1", nil
		},
		ReadyCheck: func(context.Context) error { return e.ready },
	}
	return e
}

func (e *env) url(user string) string {
	u, err := url.Parse(e.base)
	if err != nil {
		e.t.Fatal(err)
	}
	u.User = url.UserPassword(user, pw)
	u.Path = "/" + e.db
	return u.String()
}

func (e *env) pool(u string) *pgxpool.Pool {
	e.t.Helper()
	p, err := pgxpool.New(context.Background(), u)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(p.Close)
	return p
}

func (e *env) tx(fn func(tx pgx.Tx)) {
	e.t.Helper()
	tx, err := e.rtp.Begin(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	fn(tx)
	if err := tx.Commit(context.Background()); err != nil {
		e.t.Fatalf("commit: %v", err)
	}
}

func (e *env) mustMig(sql string, args ...any) {
	e.t.Helper()
	if _, err := e.mp.Exec(context.Background(), sql, args...); err != nil {
		e.t.Fatalf("%s: %v", sql, err)
	}
}

func (e *env) count(sql string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.mp.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		e.t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func (e *env) str(sql string, args ...any) string {
	e.t.Helper()
	var s string
	if err := e.mp.QueryRow(context.Background(), sql, args...).Scan(&s); err != nil {
		e.t.Fatalf("%s: %v", sql, err)
	}
	return s
}

// fixture is one finalized order with an approved receipt and a live
// connection, the state the dispatch route starts from.
type fixture struct {
	aar, orderRef, connRef, exec, wi, wf string
}

// realConn is a connection made through the real store: its id, the install
// id and the install revision the order and the receipt must carry.
type realConn struct {
	ref, installID string
	rev            int64
}

type fixOpt struct {
	real *realConn // nil: the constants and fakeConns

	freshFor time.Duration // 0 means 15 minutes
	noDecide bool          // leave the receipt pending
}

func (e *env) finalized(o fixOpt) fixture {
	e.t.Helper()
	ctx := context.Background()
	var f fixture
	f.wf = "wf-" + rnd(4)
	f.orderRef, f.connRef = tok("ordr_", 26), tok("gcn_", 26)
	instID, instRev := install, int64(3)
	if o.real != nil {
		f.connRef, instID, instRev = o.real.ref, o.real.installID, o.real.rev
	}
	revStr := strconv.FormatInt(instRev, 10)
	e.tx(func(tx pgx.Tx) {
		wi, we, err := e.st.CreateGlovoExecutionTx(ctx, tx, workitems.GlovoExecutionInput{
			Tenant: tenant, OwnerPrincipalID: ownerPrn, WorkflowID: f.wf, Actor: "service:glovo-prepare"})
		if err != nil {
			e.t.Fatalf("CreateGlovoExecutionTx: %v", err)
		}
		f.wi, f.exec = wi, we
		a, created, err := e.st.CreateGlovoApprovalTx(ctx, tx, workitems.GlovoApprovalInput{Tenant: tenant, OwnerPrincipalID: ownerPrn,
			WorkItemID: wi, ExecutionID: we, OrderRef: f.orderRef, ConnectionRef: f.connRef, InstallID: instID, InstallRevision: revStr,
			BasketFingerprint: e.fingerprint, Provider: provider, ExpiresIn: time.Hour})
		if err != nil || !created {
			e.t.Fatalf("CreateGlovoApprovalTx: %v %v", err, created)
		}
		f.aar = a.ID
	})
	if !o.noDecide {
		fresh := o.freshFor
		if fresh == 0 {
			fresh = 15 * time.Minute
		}
		e.tx(func(tx pgx.Tx) {
			if _, err := e.st.DecideGlovoApprovalTx(ctx, tx, workitems.ActionDecisionInput{ID: f.aar, DecidedBy: "oidc:owner",
				DecidedByPrincipalID: ownerPrn, Decision: "approve", AuthorityBasis: workitems.GlovoAuthorityBasis,
				AuthzMode: "enforce", ContextDigest: e.fingerprint, FreshFor: fresh}); err != nil {
				e.t.Fatalf("decide: %v", err)
			}
		})
	}
	e.idx.mu.Lock()
	e.idx.tmpl[f.orderRef] = orders.Order{OrderRef: f.orderRef, Tenant: tenant, OwnerPrincipalID: ownerPrn, ConnectionID: f.connRef,
		InstallID: instID, InstallRevision: instRev, FinalBasketFingerprint: e.fingerprint, FinalSnapshotSeq: 1, ApprovalRef: f.aar, ExecutionID: f.exec}
	e.idx.snaps[f.orderRef] = orders.Snapshot{OrderRef: f.orderRef, Seq: 1, Fingerprint: e.fingerprint, Canonical: e.canon}
	e.idx.mu.Unlock()
	e.mustMig(`INSERT INTO ctl_fake_orders (order_ref, state) VALUES ($1, 'finalized')`, f.orderRef)
	e.conns.conn = glovo.Connection{ConnectionID: f.connRef, Owner: glovo.Owner{TenantID: tenant, PrincipalID: ownerPrn},
		InstallID: instID, InstallRevision: instRev, State: glovo.Active}
	e.execs.wi, e.execs.wf = f.wi, f.wf
	e.startWF = f.wf
	return f
}

func (e *env) setOrder(f fixture, fn func(*orders.Order)) {
	e.idx.mu.Lock()
	defer e.idx.mu.Unlock()
	o := e.idx.tmpl[f.orderRef]
	fn(&o)
	e.idx.tmpl[f.orderRef] = o
}

func (e *env) dispatch(f fixture) (*Result, error) {
	return e.d.Dispatch(context.Background(), e.tenants, f.orderRef, f.aar, e.fingerprint)
}

func (e *env) orderState(f fixture) string {
	return e.str(`SELECT state FROM ctl_fake_orders WHERE order_ref = $1`, f.orderRef)
}

func (e *env) aarState(f fixture) string {
	return e.str(`SELECT state FROM public.action_approval_requests WHERE id = $1`, f.aar)
}

// untouched asserts that a refused call left no trace: no command, the order
// still finalized and the receipt still approved.
func (e *env) untouched(f fixture, wantAAR string) {
	e.t.Helper()
	if n := e.count(`SELECT count(*) FROM bridge_commands`); n != 0 {
		e.t.Errorf("bridge_commands has %d rows after a refusal", n)
	}
	if got := e.orderState(f); got != orders.StateFinalized {
		e.t.Errorf("order is %s after a refusal", got)
	}
	if got := e.aarState(f); got != wantAAR {
		e.t.Errorf("receipt is %s after a refusal, want %s", got, wantAAR)
	}
}

func wantCode(t *testing.T, err error, want glovo.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("want %s, got success", want)
	}
	if got := Refusal(err).Code; got != want {
		t.Fatalf("want %s, got %s (%v)", want, got, err)
	}
}

var errBoom = errors.New("boom")

// rawCommand writes a place_order_fake command of f's execution straight into
// the outbox as the owner, at the given sequence, under an approval of its own
// (one mutating command per approval is a unique index).
func (e *env) rawCommand(f fixture, seq int, opKey string) {
	e.t.Helper()
	e.mustMig(`INSERT INTO bridge_commands (command_id, execution_id, work_item_id, workflow_id, tenant,
		owner_principal_id, tenant_ref, principal_ref, order_ref, connection_ref, install_revision, provider_ref, operation_kind,
		attempt, intent_hash, approval_ref, operation_key, sequence, payload, payload_digest, command_nonce, ttl_seconds, expires_at)
		VALUES ($1,$2,$3,'wf',$4,$5,'tnr_x','prr_x',$6,$7,$8,$9,'place_order_fake',1,$10,$11,$12,$13,$14::jsonb,'d','n',600,now()+interval '10 minutes')`,
		tok("cmd_", 26), f.exec, f.wi, tenant, ownerPrn, tok("ordr_", 26), f.connRef, revision, provider,
		"sha256:"+rnd(32), tok("aar_", 26), opKey, seq, string(e.canon))
}

// untouchedExceptCommands is untouched with the command count left to the caller.
func (e *env) untouchedExceptCommands(f fixture) {
	e.t.Helper()
	if got := e.orderState(f); got != orders.StateFinalized {
		e.t.Errorf("order is %s after a refusal", got)
	}
	if got := e.aarState(f); got != "approved" {
		e.t.Errorf("receipt is %s after a refusal", got)
	}
}

// forceApproval rewrites a receipt column as the database superuser with the
// guard trigger off for the statement, to build a row the guard makes
// unreachable through the API (an approved receipt with no freshness bound).
// The test fails if the superuser connection is not available.
func (e *env) forceApproval(f fixture, set string) {
	e.t.Helper()
	u, err := url.Parse(e.base)
	if err != nil {
		e.t.Fatal(err)
	}
	u.Path = "/" + e.db
	ctx := context.Background()
	c, err := pgx.Connect(ctx, u.String())
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = c.Close(ctx) }()
	for _, q := range []string{
		`ALTER TABLE public.action_approval_requests DISABLE TRIGGER aar_guard`,
		`UPDATE public.action_approval_requests SET ` + set + ` WHERE id = '` + f.aar + `'`,
		`ALTER TABLE public.action_approval_requests ENABLE TRIGGER aar_guard`,
	} {
		if _, err := c.Exec(ctx, q); err != nil {
			e.t.Fatalf("%s: %v", q, err)
		}
	}
}

// fresh is a new Dispatcher over the same collaborators as e.d.
func (e *env) fresh() *Dispatcher {
	return &Dispatcher{DB: e.d.DB, Bridge: e.d.Bridge, Orders: e.d.Orders, Receipts: e.d.Receipts, Conns: e.d.Conns, Members: e.d.Members,
		Joins: e.d.Joins, Execs: e.d.Execs, ControlStart: e.d.ControlStart, ReadyCheck: e.d.ReadyCheck}
}

// rowLocked reports whether the NOWAIT row lock query fails with lock_not_available
// from another session, using the runtime role in its own short transaction.
func (e *env) rowLocked(q string, args ...any) bool {
	e.t.Helper()
	ctx := context.Background()
	tx, err := e.mp.Begin(ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var one int
	err = tx.QueryRow(ctx, q, args...).Scan(&one)
	if err == nil {
		return false
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "55P03" {
		return true
	}
	e.t.Fatalf("rowLocked: %v", err)
	return false
}

var (
	adminActor  = glovo.Actor{PrincipalID: "prn_ADMIN00000000000000000001", Kind: glovo.ActorAdmin}
	ownerActor  = glovo.Actor{PrincipalID: ownerPrn, Kind: glovo.ActorUser}
	workerActor = glovo.Actor{PrincipalID: "worker", Kind: glovo.ActorWorker}
	ownerOf     = glovo.Owner{TenantID: tenant, PrincipalID: ownerPrn}
)

// installTenant installs the tenant in the real store and returns its revision
// and install id. It is idempotent for the one tenant of the test.
func (e *env) installTenant() (string, int64) {
	e.t.Helper()
	i, err := e.gs.Install(context.Background(), tenant, adminActor)
	if err != nil {
		e.t.Fatalf("Install: %v", err)
	}
	return i.InstallID, i.InstallRevision
}

// activateNew makes the owner a connection through the real store, Connect
// then ActivateTx, the way the #961 worker does.
func (e *env) activateNew(key string) *realConn {
	e.t.Helper()
	ctx := context.Background()
	instID, rev := e.installTenant()
	r, err := e.gs.Connect(ctx, glovo.ConnectInput{Owner: ownerOf, ExpectedInstallRevision: rev, IdempotencyKey: key, Actor: ownerActor})
	if err != nil {
		e.t.Fatalf("Connect: %v", err)
	}
	return e.activate(r.Connection, instID, rev)
}

func (e *env) activate(c *glovo.Connection, instID string, rev int64) *realConn {
	e.t.Helper()
	ctx := context.Background()
	ttl := time.Hour
	if e.connTTL > 0 {
		ttl = e.connTTL
	}
	tx, err := e.rtp.Begin(ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	a, err := e.gs.ActivateTx(ctx, tx, glovo.ActivateInput{Owner: ownerOf, ConnectionID: c.ConnectionID, ExpectedVersion: c.Version,
		ExpectedInstallRevision: rev, ExpiresIn: ttl, Actor: workerActor})
	if err != nil {
		e.t.Fatalf("ActivateTx: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		e.t.Fatal(err)
	}
	return &realConn{ref: a.ConnectionID, installID: instID, rev: rev}
}
