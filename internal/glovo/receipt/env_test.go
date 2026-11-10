package receipt

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/basket"
	"github.com/mctlhq/mctl-api/internal/glovo/orders"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

const (
	pw        = "pw-receipt-test" //nolint:gosec // throwaway password of roles in a per-test scratch database
	tenant    = "acme"
	ownerPrn  = "prn_OWNER00000000000000000001"
	provider  = "fake"
	installID = "install-1"
	revision  = "3"
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

// fakeOrders is the #988 collaborator: it records the lock order and serves
// the order the test configured.
type fakeOrders struct {
	mu    sync.Mutex
	log   *[]string
	order orders.Order
	err   error
}

func (f *fakeOrders) BindApproval(context.Context, pgx.Tx, orders.Scope, orders.Actor, string, string) error {
	return nil
}

func (f *fakeOrders) LockOrderForControl(_ context.Context, _ pgx.Tx, _ string, _ []string) (*orders.Order, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	*f.log = append(*f.log, "L3")
	if f.err != nil {
		return nil, f.err
	}
	o := f.order
	return &o, nil
}

type fakeConns struct {
	log  *[]string
	conn glovo.Connection
	err  error
}

func (f *fakeConns) LockOwnerShared(context.Context, pgx.Tx, string, string) error {
	*f.log = append(*f.log, "L1L2")
	return nil
}

func (f *fakeConns) LiveConnectionTx(context.Context, pgx.Tx, glovo.Owner) (*glovo.Connection, error) {
	if f.err != nil {
		return nil, f.err
	}
	c := f.conn
	return &c, nil
}

type fakeMembers struct {
	member bool
	err    error
}

func (f *fakeMembers) IsMember(string, string) (bool, error) { return f.member, f.err }

// env is a scratch database with the three roles of the owner-confirmed model,
// the generic and Glovo schemas, and the bridge schema.
type env struct {
	t             *testing.T
	base, db      string
	mig, wi, rt   string
	migURL, rtURL string
	mp, rtp       *pgxpool.Pool
	store         *workitems.Store
	log           []string
	ord           *fakeOrders
	conns         *fakeConns
	members       *fakeMembers
	fence         *Fence
	caller        bridge.Caller
	fingerprint   string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL is unset in CI: the receipt database tests must run, not skip")
		}
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	sfx := rnd(6)
	e := &env{t: t, base: base, db: "r989db_" + sfx, mig: "r989mig_" + sfx, wi: "r989wi_" + sfx, rt: "r989rt_" + sfx}
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
	wiURL := e.url(e.wi)
	e.rtURL = e.url(e.rt)
	if err := workitems.ApplyGlovoApprovalSchema(ctx, e.migURL, e.rt, workitems.WithWorkItemsRole(e.wi)); err != nil {
		t.Fatalf("ApplyGlovoApprovalSchema: %v", err)
	}
	bs, err := bridge.NewStore(ctx, e.migURL)
	if err != nil {
		t.Fatalf("bridge.NewStore: %v", err)
	}
	t.Cleanup(bs.Close)
	e.mp = e.pool(e.migURL)
	e.rtp = e.pool(e.rtURL)
	// Test-only: the runtime role reads the bridge tables (production gives the
	// receipt a role that does; see the package comment).
	for _, s := range []string{
		fmt.Sprintf(`GRANT SELECT ON bridge_commands, bridge_write_permits TO %s`, e.rt),
	} {
		if _, err := e.mp.Exec(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	e.ord = &fakeOrders{log: &e.log}
	st, err := workitems.NewStore(ctx, wiURL, workitems.WithGlovoOrders(e.ord))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(st.Close)
	e.store = st
	e.conns = &fakeConns{log: &e.log}
	e.members = &fakeMembers{member: true}
	e.fence = NewFence(st, e.ord, e.conns, e.members)
	e.caller = bridge.Caller{ProviderRef: provider, Actor: "test", Tenants: []string{tenant}}
	_, canon, err := basket.Parse([]byte(basePayload))
	if err != nil {
		t.Fatal(err)
	}
	e.fingerprint = basket.Fingerprint(canon)
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

// fixture is one order with a reserved approval and a command bound to it.
type fixture struct {
	aar, cmd, orderRef, connRef, exec, wi string
	in                                    workitems.GlovoApprovalInput
}

// reserved builds a decided, reserved approval and the bridge command written
// with payload (basePayload when empty). The order fake serves a dispatched
// order of that command.
func (e *env) reserved(payload string) fixture {
	e.t.Helper()
	if payload == "" {
		payload = basePayload
	}
	ctx := context.Background()
	var f fixture
	f.cmd = tok("cmd_", 26)
	e.tx(func(tx pgx.Tx) {
		wi, we, err := e.store.CreateGlovoExecutionTx(ctx, tx, workitems.GlovoExecutionInput{
			Tenant: tenant, OwnerPrincipalID: ownerPrn, WorkflowID: "wf-" + rnd(4), Actor: "service:glovo-prepare"})
		if err != nil {
			e.t.Fatalf("CreateGlovoExecutionTx: %v", err)
		}
		f.wi, f.exec = wi, we
		f.orderRef, f.connRef = tok("ordr_", 26), tok("gcn_", 26)
		f.in = workitems.GlovoApprovalInput{Tenant: tenant, OwnerPrincipalID: ownerPrn, WorkItemID: wi, ExecutionID: we,
			OrderRef: f.orderRef, ConnectionRef: f.connRef, InstallID: installID, InstallRevision: revision,
			BasketFingerprint: e.fingerprint, Provider: provider, ExpiresIn: time.Hour}
		a, created, err := e.store.CreateGlovoApprovalTx(ctx, tx, f.in)
		if err != nil || !created {
			e.t.Fatalf("CreateGlovoApprovalTx: %v %v", err, created)
		}
		f.aar = a.ID
	})
	e.tx(func(tx pgx.Tx) {
		if _, err := e.store.DecideGlovoApprovalTx(ctx, tx, workitems.ActionDecisionInput{ID: f.aar, DecidedBy: "oidc:owner",
			DecidedByPrincipalID: ownerPrn, Decision: "approve", AuthorityBasis: workitems.GlovoAuthorityBasis,
			AuthzMode: "enforce", ContextDigest: e.fingerprint, FreshFor: 15 * time.Minute}); err != nil {
			e.t.Fatalf("decide: %v", err)
		}
	})
	ih := workitems.IntentHash(workitems.GlovoIntent(workitems.GlovoBinding{Tenant: tenant, OwnerPrincipalID: ownerPrn,
		ExecutionID: f.exec, WorkItemID: f.wi, OrderRef: f.orderRef, ConnectionRef: f.connRef, InstallID: installID,
		InstallRevision: revision, BasketFingerprint: e.fingerprint, Provider: provider}))
	if _, err := e.mp.Exec(ctx, `INSERT INTO bridge_commands (command_id, execution_id, work_item_id, workflow_id, tenant,
		owner_principal_id, tenant_ref, principal_ref, order_ref, connection_ref, install_revision, provider_ref, operation_kind,
		attempt, intent_hash, approval_ref, operation_key, sequence, payload, payload_digest, command_nonce, ttl_seconds, expires_at)
		VALUES ($1,$2,$3,'wf',$4,$5,'tnr_x','prr_x',$6,$7,$8,$9,'place_order_fake',1,$10,$11,'op-'||$1,1,$12::jsonb,'d','n',600,now()+interval '10 minutes')`,
		f.cmd, f.exec, f.wi, tenant, ownerPrn, f.orderRef, f.connRef, revision, provider, ih, f.aar, payload); err != nil {
		e.t.Fatalf("insert command: %v", err)
	}
	e.tx(func(tx pgx.Tx) {
		ok, err := e.store.ReserveGlovoApprovalTx(ctx, tx, f.aar, workitems.ReserveCommand{CommandID: f.cmd, Tenant: tenant,
			OwnerPrincipalID: ownerPrn, ExecutionID: f.exec, OrderRef: f.orderRef, ConnectionRef: f.connRef,
			InstallRevision: revision, IntentHash: ih, BasketFingerprint: e.fingerprint})
		if err != nil || ok { // true means replayed
			e.t.Fatalf("reserve: %v replayed=%v", err, ok)
		}
	})
	e.ord.order = orders.Order{OrderRef: f.orderRef, Tenant: tenant, OwnerPrincipalID: ownerPrn, ConnectionID: f.connRef,
		InstallID: installID, InstallRevision: 3, State: orders.StateDispatched, FinalBasketFingerprint: e.fingerprint,
		ApprovalRef: f.aar, CommandID: f.cmd, ExecutionID: f.exec}
	e.conns.conn = glovo.Connection{ConnectionID: f.connRef, Owner: glovo.Owner{TenantID: tenant, PrincipalID: ownerPrn},
		InstallID: installID, InstallRevision: 3, State: glovo.Active}
	e.log = nil
	return f
}

func (f fixture) binding(e *env) bridge.FenceBinding {
	ih := workitems.IntentHash(workitems.GlovoIntent(workitems.GlovoBinding{Tenant: tenant, OwnerPrincipalID: ownerPrn,
		ExecutionID: f.exec, WorkItemID: f.wi, OrderRef: f.orderRef, ConnectionRef: f.connRef, InstallID: installID,
		InstallRevision: revision, BasketFingerprint: e.fingerprint, Provider: provider}))
	return bridge.FenceBinding{CommandID: f.cmd, ExecutionID: f.exec, WorkItemID: f.wi, Tenant: tenant, OwnerPrincipalID: ownerPrn,
		ConnectionRef: f.connRef, InstallRevision: revision, IntentHash: ih, ApprovalRef: f.aar, OperationKey: "op-" + f.cmd, LeaseEpoch: 1}
}

// run is PreLock then Check in one transaction, as permitTx does. commit says
// whether the transaction is committed on success.
func (e *env) run(f fixture, b bridge.FenceBinding) (string, error) {
	e.t.Helper()
	ctx := context.Background()
	tx, err := e.rtp.Begin(ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := e.fence.PreLock(ctx, tx, e.caller, f.cmd); err != nil {
		return "", err
	}
	ref, err := e.fence.Check(ctx, tx, b)
	if err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		e.t.Fatalf("commit: %v", err)
	}
	return ref, nil
}

func (e *env) state(aar string) string {
	e.t.Helper()
	var s string
	if err := e.mp.QueryRow(context.Background(), `SELECT state FROM public.action_approval_requests WHERE id=$1`, aar).Scan(&s); err != nil {
		e.t.Fatal(err)
	}
	return s
}

// siblingCommand writes a second bridge command that names f's approval, and
// points the order fake at it as the dispatched command.
func (e *env) siblingCommand(f fixture) fixture {
	e.t.Helper()
	g := f
	g.cmd = tok("cmd_", 26)
	if _, err := e.mp.Exec(context.Background(), `INSERT INTO bridge_commands (command_id, execution_id, work_item_id, workflow_id, tenant,
		owner_principal_id, tenant_ref, principal_ref, order_ref, connection_ref, install_revision, provider_ref, operation_kind,
		attempt, intent_hash, approval_ref, operation_key, sequence, payload, payload_digest, command_nonce, ttl_seconds, expires_at)
		SELECT $1, execution_id, work_item_id, workflow_id, tenant, owner_principal_id, tenant_ref, principal_ref, order_ref,
		connection_ref, install_revision, provider_ref, operation_kind, attempt, intent_hash, approval_ref, 'op-'||$1, 2, payload,
		payload_digest, command_nonce, ttl_seconds, expires_at FROM bridge_commands WHERE command_id=$2`, g.cmd, f.cmd); err != nil {
		e.t.Fatalf("insert sibling: %v", err)
	}
	e.ord.order.CommandID = g.cmd
	return g
}
