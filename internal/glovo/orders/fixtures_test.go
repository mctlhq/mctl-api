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

package orders

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/basket"
	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
)

const testPassword = "pw-orders-test" //nolint:gosec // throwaway password of roles in a per-test scratch database

const (
	tenantA = "team-a"
	tenantB = "team-b"
	ownerA  = "prn_ownerA0000000000000000001"
	ownerA2 = "prn_ownerA0000000000000000002"
	ownerB  = "prn_ownerB0000000000000000001"
)

type env struct {
	t       *testing.T
	mig, rt string
	migURL  string
	rtURL   string
	admin   *pgx.Conn
	pool    *pgxpool.Pool
	conns   *fakeConns
	store   *Store
	// extraRoles are cluster roles a test created; they are dropped after the
	// database that they own objects in.
	extraRoles []string
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func adminURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv("TEST_DATABASE_URL")
	if u == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL is unset in CI: the glovo order database tests must run, not skip")
		}
		t.Skip("TEST_DATABASE_URL not set")
	}
	return u
}

func urlFor(t *testing.T, base, user, pass, db string) string {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(user, pass)
	u.Path = "/" + db
	return u.String()
}

// fakeConns is the #959 double: it counts LiveConnectionTx calls.
type fakeConns struct {
	mu    sync.Mutex
	conn  *glovo.Connection
	err   error
	calls int
}

func (f *fakeConns) LiveConnectionTx(_ context.Context, _ pgx.Tx, owner glovo.Owner) (*glovo.Connection, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	c := *f.conn
	c.Owner = owner
	return &c, nil
}

func (f *fakeConns) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeConns) set(c *glovo.Connection, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.conn, f.err = c, err
}

// fakeExecs is the #989 double: the same join as ExecutionBindingTx.
type fakeExecs struct{}

func (fakeExecs) ExecutionBindingTx(ctx context.Context, q dbq.Querier, id string) (string, string, string, string, error) {
	var tenant, owner, wi string
	err := q.QueryRow(ctx, `SELECT w.tenant, w.owner_principal_id, w.id FROM public.work_item_executions e
 JOIN public.work_items w ON w.id = e.work_item_id WHERE e.id = $1`, id).Scan(&tenant, &owner, &wi)
	return tenant, owner, wi, "", err
}

var liveConn = &glovo.Connection{ConnectionID: "gcn_0123456789abcdef0123", InstallID: "gin_install", InstallRevision: 3}

// newEnvNoSchema creates a scratch database and the two roles, the work-item
// tables of the guard and nothing else.
func newEnvNoSchema(t *testing.T) *env {
	t.Helper()
	base := adminURL(t)
	ctx := context.Background()
	sfx := randHex(6)
	db, mig, rt := "o988db_"+sfx, "o988mig_"+sfx, "o988rt_"+sfx
	root, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	for _, stmt := range []string{
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`, mig, testPassword),
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`, rt, testPassword),
		fmt.Sprintf(`CREATE DATABASE %s OWNER %s`, db, mig),
		fmt.Sprintf(`REVOKE ALL ON DATABASE %s FROM PUBLIC`, db),
		fmt.Sprintf(`GRANT CONNECT ON DATABASE %s TO %s`, db, rt),
	} {
		if _, err := root.Exec(ctx, stmt); err != nil {
			t.Fatalf("setup %q: %v", stmt, err)
		}
	}
	_ = root.Close(ctx)
	e := &env{t: t, mig: mig, rt: rt, conns: &fakeConns{conn: liveConn}}
	e.migURL = urlFor(t, base, mig, testPassword, db)
	e.rtURL = urlFor(t, base, rt, testPassword, db)
	t.Cleanup(func() {
		if e.pool != nil {
			e.pool.Close()
		}
		if e.admin != nil {
			_ = e.admin.Close(context.Background())
		}
		c, err := pgx.Connect(context.Background(), base)
		if err != nil {
			return
		}
		defer func() { _ = c.Close(context.Background()) }()
		_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, db))
		for _, r := range e.extraRoles {
			_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP ROLE IF EXISTS %s`, r))
		}
		_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP ROLE IF EXISTS %s`, rt))
		_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP ROLE IF EXISTS %s`, mig))
	})
	// The migration role is a connection that owns everything of the slice;
	// it also stands in for the #989 owner of the work-item tables.
	e.admin, err = pgx.Connect(ctx, e.migURL)
	if err != nil {
		t.Fatalf("migration connect: %v", err)
	}
	for _, stmt := range []string{
		`CREATE TABLE public.work_items (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, owner_principal_id TEXT NOT NULL)`,
		`CREATE TABLE public.work_item_executions (id TEXT PRIMARY KEY, work_item_id TEXT NOT NULL REFERENCES public.work_items (id))`,
		fmt.Sprintf(`GRANT SELECT ON public.work_items, public.work_item_executions TO %s`, rt),
	} {
		if _, err := e.admin.Exec(ctx, stmt); err != nil {
			t.Fatalf("fixture %q: %v", stmt, err)
		}
	}
	return e
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := newEnvNoSchema(t)
	if err := ApplySchema(context.Background(), e.migURL, e.rt); err != nil {
		t.Fatalf("ApplySchema: %v", err)
	}
	var err error
	e.pool, err = pgxpool.New(context.Background(), e.rtURL)
	if err != nil {
		t.Fatal(err)
	}
	e.store, err = NewStore(context.Background(), e.pool, e.rt, e.mig, e.conns, fakeExecs{})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return e
}

// execution inserts a work item and an execution for (tenant, owner) and
// returns the we_ id.
func (e *env) execution(tenant, owner string) string {
	e.t.Helper()
	wi, we := "wi_"+randHex(10), "we_"+randHex(10)
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO public.work_items (id, tenant, owner_principal_id) VALUES ($1, $2, $3)`, []any{wi, tenant, owner}},
		{`INSERT INTO public.work_item_executions (id, work_item_id) VALUES ($1, $2)`, []any{we, wi}},
	} {
		if _, err := e.admin.Exec(context.Background(), q.sql, q.args...); err != nil {
			e.t.Fatal(err)
		}
	}
	return we
}

func basketJSON(price int) []byte {
	sub := price
	return []byte(fmt.Sprintf(`{"v":"mctl-approval-basket/v1","store_ref":"pst_0123456789abcdef0123","currency":"EUR","lines":[{"item_code":"FAKE-1","quantity":1,"unit_price_minor":%d}],"subtotal_minor":%d,"delivery_fee_minor":199,"service_fee_minor":50,"discount_minor":0,"total_minor":%d}`, price, sub, sub+249))
}

func fingerprintOf(t *testing.T, raw []byte) string {
	t.Helper()
	_, canonical, err := basket.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return basket.Fingerprint(canonical)
}

func (e *env) input(sc Scope, key string, price int) CreateInput {
	return CreateInput{
		Scope: sc, Actor: Actor{Kind: ActorOwner, ID: sc.PrincipalID},
		IdempotencyKey: key, RequestHash: "h-" + key,
		ConnectionID: liveConn.ConnectionID, InstallID: liveConn.InstallID, ExpectedInstallRevision: liveConn.InstallRevision,
		ApprovalBasket: basketJSON(price), ExpectedFingerprint: fingerprintOf(e.t, basketJSON(price)),
		ExecutionID: e.execution(sc.Tenant, sc.PrincipalID), OrderRef: NewOrderRef(),
	}
}

// inTx runs fn on one READ COMMITTED transaction of the runtime pool and
// commits when fn returns nil.
func (e *env) inTx(fn func(tx pgx.Tx) error) error {
	e.t.Helper()
	ctx := context.Background()
	tx, err := e.pool.Begin(ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (e *env) create(in CreateInput) (*Order, bool, error) {
	e.t.Helper()
	var o *Order
	var replayed bool
	err := e.inTx(func(tx pgx.Tx) error {
		var err error
		o, replayed, err = e.store.Create(context.Background(), tx, in)
		return err
	})
	return o, replayed, err
}

func (e *env) mustCreate(sc Scope, key string, price int) *Order {
	e.t.Helper()
	o, _, err := e.create(e.input(sc, key, price))
	if err != nil {
		e.t.Fatalf("Create: %v", err)
	}
	return o
}

func (e *env) finalize(sc Scope, o *Order) *Order {
	e.t.Helper()
	var out *Order
	snap, err := e.store.Snapshot(context.Background(), e.pool, sc, o.OrderRef, 1)
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.inTx(func(tx pgx.Tx) error {
		var err error
		out, err = e.store.Finalize(context.Background(), tx, sc, Actor{Kind: ActorOwner, ID: sc.PrincipalID}, o.OrderRef, o.Version, snap.Fingerprint)
		return err
	}); err != nil {
		e.t.Fatalf("Finalize: %v", err)
	}
	return out
}

func newAAR() string { return "aar_" + randHex(10) }

func newCMD() string {
	s, _ := randAlnum(26)
	return "cmd_" + s
}

func wantCode(t *testing.T, err error, code glovo.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("want %s, got nil", code)
	}
	if !glovoIs(err, code) {
		t.Fatalf("want %s, got %v", code, err)
	}
}

func glovoIs(err error, code glovo.Code) bool {
	var ge *glovo.Error
	if ok := asGlovo(err, &ge); ok {
		return ge.Code == code
	}
	return false
}

func asGlovo(err error, target **glovo.Error) bool { return errors.As(err, target) }
