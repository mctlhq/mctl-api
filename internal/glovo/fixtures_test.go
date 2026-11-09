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

package glovo

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/secretscan"
)

// env is one disposable database with its own migration and runtime roles.
// Roles and schema glovo are created per test, so tests are independent and
// parallel-safe, run the real triggers, and never touch another database. The
// admin connection (TEST_DATABASE_URL) is used only to create and drop the
// database and the two roles.
type env struct {
	t        *testing.T
	dbName   string
	mig, rt  string
	migURL   string
	rtURL    string
	pool     *pgxpool.Pool
	store    *Store
	hookSeen *hookRecorder
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
			t.Fatal("TEST_DATABASE_URL is unset in CI: the glovo database tests must run, not skip")
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

const testPassword = "pw-glovo-test"

// newEnvNoSchema creates the database and roles but applies nothing.
func newEnvNoSchema(t *testing.T) *env {
	t.Helper()
	base := adminURL(t)
	ctx := context.Background()
	sfx := randHex(6)
	e := &env{t: t, dbName: "g959db_" + sfx, mig: "g959mig_" + sfx, rt: "g959rt_" + sfx}
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer admin.Close(ctx)
	for _, stmt := range []string{
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`, e.mig, testPassword),
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`, e.rt, testPassword),
		fmt.Sprintf(`CREATE DATABASE %s OWNER %s`, e.dbName, e.mig),
		fmt.Sprintf(`REVOKE ALL ON DATABASE %s FROM PUBLIC`, e.dbName),
		fmt.Sprintf(`GRANT CONNECT ON DATABASE %s TO %s`, e.dbName, e.rt),
	} {
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Fatalf("setup %q: %v", stmt, err)
		}
	}
	e.migURL = urlFor(t, base, e.mig, testPassword, e.dbName)
	e.rtURL = urlFor(t, base, e.rt, testPassword, e.dbName)
	t.Cleanup(func() {
		if e.pool != nil {
			e.pool.Close()
		}
		c, err := pgx.Connect(context.Background(), base)
		if err != nil {
			return
		}
		defer c.Close(context.Background())
		_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, e.dbName))
		_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP ROLE IF EXISTS %s`, e.rt))
		_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP ROLE IF EXISTS %s`, e.mig))
	})
	return e
}

type hookRecorder struct {
	mu    sync.Mutex
	calls [][]string
	actor []string
	err   error
}

func (h *hookRecorder) hook(_ context.Context, _ pgx.Tx, ended []string, actor string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.err != nil {
		return h.err
	}
	h.calls = append(h.calls, append([]string(nil), ended...))
	h.actor = append(h.actor, actor)
	return nil
}

func (h *hookRecorder) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.calls)
}

func (h *hookRecorder) reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls, h.actor = nil, nil
}

// newEnv applies the schema as the migration role and builds a Store over a
// pool connected as the runtime role, with a recording RevocationHook.
func newEnv(t *testing.T, opts ...Option) *env {
	t.Helper()
	e := newEnvNoSchema(t)
	ctx := context.Background()
	if err := ApplySchema(ctx, e.migURL, e.rt); err != nil {
		t.Fatalf("ApplySchema: %v", err)
	}
	pool, err := pgxpool.New(ctx, e.rtURL)
	if err != nil {
		t.Fatal(err)
	}
	e.pool = pool
	e.hookSeen = &hookRecorder{}
	all := append([]Option{WithExplicitURL(true), WithRevocationHook(e.hookSeen.hook)}, opts...)
	st, err := NewStore(ctx, pool, e.rt, e.mig, all...)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	e.store = st
	return e
}

// migPool opens a pool as the migration role (the owner), for tests that
// check what the owner can do.
func (e *env) migPool() *pgxpool.Pool {
	e.t.Helper()
	p, err := pgxpool.New(context.Background(), e.migURL)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(p.Close)
	return p
}

// fixture is the synthetic population: tenants alpha and beta, principals A1
// and A2 in alpha and B1 in beta. No emails, names, tokens or cookies.
type fixture struct {
	Alpha, Beta string
	A1, A2, B1  Owner
	actorA1     Actor
	actorAdmin  Actor
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	mint := func() string {
		id, err := newPrefixedID(PrincipalPrefix, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	f := fixture{Alpha: "tg959-alpha-" + randHex(4), Beta: "tg959-beta-" + randHex(4)}
	f.A1 = Owner{f.Alpha, mint()}
	f.A2 = Owner{f.Alpha, mint()}
	f.B1 = Owner{f.Beta, mint()}
	f.actorA1 = Actor{PrincipalID: f.A1.PrincipalID, Kind: ActorUser}
	f.actorAdmin = Actor{PrincipalID: mint(), Kind: ActorAdmin}
	return f
}

var workerActor = Actor{PrincipalID: "worker", Kind: ActorWorker}

func workerCtx() context.Context { return WithActor(context.Background(), workerActor) }

// install installs the tenant and returns its revision.
func (e *env) install(f fixture, tenant string) *Install {
	e.t.Helper()
	i, err := e.store.Install(context.Background(), tenant, f.actorAdmin)
	if err != nil {
		e.t.Fatalf("Install: %v", err)
	}
	return i
}

func (e *env) connect(o Owner, rev int64, key string) *Connection {
	e.t.Helper()
	r, err := e.store.Connect(context.Background(), ConnectInput{
		Owner: o, ExpectedInstallRevision: rev, IdempotencyKey: key,
		Actor: Actor{PrincipalID: o.PrincipalID, Kind: ActorUser}})
	if err != nil {
		e.t.Fatalf("Connect: %v", err)
	}
	return r.Connection
}

func userActor(o Owner) Actor { return Actor{PrincipalID: o.PrincipalID, Kind: ActorUser} }

// activate takes a pending_handoff connection to active on its own tx.
func (e *env) activate(o Owner, c *Connection, rev int64, ttl time.Duration) *Connection {
	e.t.Helper()
	ctx := context.Background()
	tx, err := e.pool.Begin(ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	a, err := e.store.ActivateTx(ctx, tx, ActivateInput{Owner: o, ConnectionID: c.ConnectionID,
		ExpectedVersion: c.Version, ExpectedInstallRevision: rev, ExpiresIn: ttl, Actor: workerActor})
	if err != nil {
		e.t.Fatalf("ActivateTx: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		e.t.Fatal(err)
	}
	return a
}

func isCode(err error, c Code) bool {
	e, ok := err.(*Error)
	return ok && e.Code == c
}

func mustCode(t *testing.T, err error, c Code) {
	t.Helper()
	if !isCode(err, c) {
		t.Fatalf("want %s, got %v", c, err)
	}
}

func (e *env) count(q string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		e.t.Fatalf("%s: %v", q, err)
	}
	return n
}

func (e *env) auditCount(entity string) int {
	return e.count(`SELECT count(*) FROM glovo.glovo_audit_events WHERE entity_id = $1`, entity)
}

func scanSecret(b []byte) (string, bool) { return secretscan.Scan(b) }

// stmtTracer records every statement a pool sends.
type stmtTracer struct {
	mu   sync.Mutex
	sqls []string
}

func (s *stmtTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	s.mu.Lock()
	s.sqls = append(s.sqls, d.SQL)
	s.mu.Unlock()
	return ctx
}
func (s *stmtTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
func (s *stmtTracer) reset() {
	s.mu.Lock()
	s.sqls = nil
	s.mu.Unlock()
}
func (s *stmtTracer) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.sqls...)
}

// tracedPool opens a runtime-role pool that records every statement.
func tracedPool(t *testing.T, e *env, tr *stmtTracer) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(e.rtURL)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Tracer = tr
	p, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}
