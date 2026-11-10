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

package bridge

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/glovo"
)

const rtPassword = "pw-bridge-runtime-test" //nolint:gosec // throwaway password of roles in a per-test scratch database

// rtEnv is a scratch database with a migration role, a runtime role and a
// work-items role, and no bridge table yet.
type rtEnv struct {
	t                *testing.T
	base, db         string
	mig, rt, wi, mnt string
	migURL, rtURL    string
	migPool, rtPool  *pgxpool.Pool
}

func rtRnd() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (e *rtEnv) url(user string) string {
	u, err := url.Parse(e.base)
	if err != nil {
		e.t.Fatal(err)
	}
	u.User = url.UserPassword(user, rtPassword)
	u.Path = "/" + e.db
	return u.String()
}

func newRTEnv(t *testing.T) *rtEnv {
	t.Helper()
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL is unset in CI: the bridge runtime database tests must run, not skip")
		}
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	sfx := rtRnd()
	e := &rtEnv{t: t, base: base, db: "b985db_" + sfx, mig: "b985mig_" + sfx, rt: "b985rt_" + sfx, wi: "b985wi_" + sfx, mnt: "b985mn_" + sfx}
	root, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer func() { _ = root.Close(ctx) }()
	var stmts []string
	for _, r := range []string{e.mig, e.rt, e.wi, e.mnt} {
		stmts = append(stmts, fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`, r, rtPassword))
	}
	// A non-C collation, where the database default would hide a lock order that
	// follows the collation instead of the bytes; a server without the locale
	// falls back to its default (the collation pin test then fails loudly).
	const collation = ` TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'en_US.UTF-8' LC_CTYPE 'en_US.UTF-8'`
	createDB := fmt.Sprintf(`CREATE DATABASE %s OWNER %s`, e.db, e.mig)
	if _, err := root.Exec(ctx, `CREATE DATABASE `+e.db+`_probe`+collation); err == nil {
		_, _ = root.Exec(ctx, `DROP DATABASE `+e.db+`_probe`)
		createDB += collation
	}
	stmts = append(stmts, createDB,
		fmt.Sprintf(`REVOKE ALL ON DATABASE %s FROM PUBLIC`, e.db),
		fmt.Sprintf(`GRANT CONNECT ON DATABASE %s TO %s, %s, %s`, e.db, e.rt, e.wi, e.mnt))
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
		for _, r := range []string{e.mnt, e.wi, e.rt, e.mig} {
			_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP ROLE IF EXISTS %s`, r))
		}
	})
	e.migURL, e.rtURL = e.url(e.mig), e.url(e.rt)
	e.migPool = e.pool(e.migURL)
	e.rtPool = e.pool(e.rtURL)
	return e
}

func (e *rtEnv) pool(u string) *pgxpool.Pool {
	e.t.Helper()
	p, err := pgxpool.New(context.Background(), u)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(p.Close)
	return p
}

func (e *rtEnv) apply() {
	e.t.Helper()
	if err := ApplySchema(context.Background(), e.migURL, e.rt, WithWorkItemsRole(e.wi), WithMaintenanceRole(e.mnt)); err != nil {
		e.t.Fatalf("ApplySchema: %v", err)
	}
}

func (e *rtEnv) mustMig(sql string, args ...any) {
	e.t.Helper()
	if _, err := e.migPool.Exec(context.Background(), sql, args...); err != nil {
		e.t.Fatalf("%s: %v", sql, err)
	}
}

func notReadyReason(err error) string {
	var nr *glovo.NotReadyError
	if errors.As(err, &nr) {
		return nr.Reason
	}
	return ""
}

func (e *rtEnv) runtimeStore() *Store {
	e.t.Helper()
	s, err := NewRuntimeStore(context.Background(), e.rtPool)
	if err != nil {
		e.t.Fatalf("NewRuntimeStore: %v", err)
	}
	return s
}

// enqueueRT enqueues one command through s, optionally of kind place_order_fake
// with the given approval ref.
func enqueueRT(t *testing.T, s *Store, tenant, kind, approval, conn string) string {
	t.Helper()
	pgSeq++
	suffix := fmt.Sprintf("%016d", time.Now().UnixNano()%1e15+int64(pgSeq))
	in := EnqueueInput{
		ExecutionID: "we_" + suffix, WorkItemID: "wi_" + suffix, WorkflowID: "wf-" + suffix, Tenant: tenant,
		OwnerPrincipalID: "owner", TenantRef: "tnr_" + suffix, PrincipalRef: "prr_" + suffix, OrderRef: "ordr_" + suffix,
		ConnectionRef: conn, InstallRevision: "r1", ProviderRef: "glovo", Kind: kind, Attempt: 1,
		OperationKey: "op-" + suffix, IntentHash: "sha256:" + strings.Repeat("0", 64), Payload: json.RawMessage(`{"quantity_total":1}`),
	}
	if kind == KindPlaceOrderFake {
		in.ApprovalRef = approval
	}
	tx, err := s.Pool().Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	id, created, err := s.Enqueue(context.Background(), tx, in)
	if err != nil || !created {
		t.Fatalf("enqueue: %v created=%v", err, created)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestApplySchemaTwiceAndRuntimeStore(t *testing.T) {
	e := newRTEnv(t)
	e.apply()
	e.apply() // a second run changes nothing and does not fail

	s := e.runtimeStore()
	if !s.WireVersionsEnabled() {
		t.Fatal("NewRuntimeStore must call EnableWireVersions")
	}
	if err := VerifyRuntimeGrants(context.Background(), e.rtPool); err != nil {
		t.Fatalf("grants: %v", err)
	}
	// The store borrows the shared pool: Close must leave it usable.
	s.Close()
	if err := e.rtPool.Ping(context.Background()); err != nil {
		t.Fatalf("Close released a borrowed pool: %v", err)
	}
	if v := ownerOf(t, e, "bridge_commands"); v != e.mig {
		t.Fatalf("bridge_commands owner = %s, want the migration role", v)
	}
}

func ownerOf(t *testing.T, e *rtEnv, rel string) string {
	t.Helper()
	var o string
	if err := e.migPool.QueryRow(context.Background(), `SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = to_regclass($1)`, rel).Scan(&o); err != nil {
		t.Fatal(err)
	}
	return o
}

func TestApplySchemaFailsUnderRuntimeRoleAndRefusesBadInput(t *testing.T) {
	e := newRTEnv(t)
	ctx := context.Background()
	if err := ApplySchema(ctx, e.rtURL, e.rt); err == nil {
		t.Fatal("ApplySchema must fail under the runtime role (no CREATE, no ownership)")
	}
	if err := ApplySchema(ctx, e.migURL, "Bad Role;"); err == nil {
		t.Fatal("an invalid role name must be refused")
	}
	if err := ApplySchema(ctx, e.migURL, "no_such_role_"+rtRnd()); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("a missing runtime role must be refused, got %v", err)
	}
	var present bool
	if err := e.migPool.QueryRow(ctx, `SELECT to_regclass('bridge_schema_version') IS NOT NULL`).Scan(&present); err != nil || present {
		t.Fatalf("a refused ApplySchema must leave no version row table (present=%v err=%v)", present, err)
	}
	// A recorded version above the compiled one is refused.
	e.apply()
	e.mustMig(`UPDATE bridge_schema_version SET version = $1`, RuntimeSchemaVersion+1)
	if err := ApplySchema(ctx, e.migURL, e.rt); err == nil || !strings.Contains(err.Error(), "above the compiled version") {
		t.Fatalf("a newer recorded version must be refused, got %v", err)
	}
}

func TestApplySchemaRefusesForeignOwnerNamingTables(t *testing.T) {
	e := newRTEnv(t)
	ctx := context.Background()
	// The legacy path: NewStore under the work-items style role creates and owns
	// the tables. Here the runtime role plays "another owner".
	e.mustMig(`GRANT CREATE ON SCHEMA public TO ` + e.rt)
	legacy, err := NewStore(ctx, e.rtURL)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	legacy.Close()
	err = ApplySchema(ctx, e.migURL, e.rt)
	if err == nil || !strings.Contains(err.Error(), "bridge_commands") || !strings.Contains(err.Error(), "not owned by the migration role") {
		t.Fatalf("ApplySchema must name the foreign-owned tables, got %v", err)
	}
	var present bool
	if err := e.migPool.QueryRow(ctx, `SELECT to_regclass('bridge_schema_version') IS NOT NULL`).Scan(&present); err != nil || present {
		t.Fatalf("a refused ApplySchema must not select the runtime mode (present=%v err=%v)", present, err)
	}
}

func TestNewRuntimeStoreNotReady(t *testing.T) {
	ctx := context.Background()
	t.Run("schema missing", func(t *testing.T) {
		e := newRTEnv(t)
		if _, err := NewRuntimeStore(ctx, e.rtPool); notReadyReason(err) != NotReadySchemaMissing {
			t.Fatalf("got %v, want %s", err, NotReadySchemaMissing)
		}
	})
	t.Run("version mismatch", func(t *testing.T) {
		e := newRTEnv(t)
		e.apply()
		e.mustMig(`UPDATE bridge_schema_version SET version = version + 1`)
		if _, err := NewRuntimeStore(ctx, e.rtPool); notReadyReason(err) != NotReadySchemaVersion {
			t.Fatalf("got %v, want %s", err, NotReadySchemaVersion)
		}
	})
	t.Run("no version row is not a pass", func(t *testing.T) {
		e := newRTEnv(t)
		e.apply()
		e.mustMig(`DELETE FROM bridge_schema_version`)
		if _, err := NewRuntimeStore(ctx, e.rtPool); notReadyReason(err) != NotReadySchemaVersion {
			t.Fatalf("got %v, want %s", err, NotReadySchemaVersion)
		}
	})
	t.Run("read level below compiled", func(t *testing.T) {
		e := newRTEnv(t)
		e.apply()
		e.mustMig(`UPDATE bridge_read_schema_version SET level = 0`)
		if _, err := NewRuntimeStore(ctx, e.rtPool); notReadyReason(err) != NotReadyReadLevel {
			t.Fatalf("got %v, want %s", err, NotReadyReadLevel)
		}
	})
	t.Run("an extra grant", func(t *testing.T) {
		e := newRTEnv(t)
		e.apply()
		e.mustMig(`GRANT DELETE ON bridge_commands TO ` + e.rt)
		if _, err := NewRuntimeStore(ctx, e.rtPool); notReadyReason(err) != NotReadyBridgeGrants {
			t.Fatalf("got %v, want %s", err, NotReadyBridgeGrants)
		}
	})
	t.Run("a missing grant", func(t *testing.T) {
		e := newRTEnv(t)
		e.apply()
		e.mustMig(`REVOKE INSERT ON bridge_write_permits FROM ` + e.rt)
		if _, err := NewRuntimeStore(ctx, e.rtPool); notReadyReason(err) != NotReadyBridgeGrants {
			t.Fatalf("got %v, want %s", err, NotReadyBridgeGrants)
		}
	})
	t.Run("a column-level extra grant", func(t *testing.T) {
		e := newRTEnv(t)
		e.apply()
		e.mustMig(`GRANT UPDATE (data_digest) ON bridge_read_results TO ` + e.rt)
		if _, err := NewRuntimeStore(ctx, e.rtPool); notReadyReason(err) != NotReadyBridgeGrants {
			t.Fatalf("got %v, want %s", err, NotReadyBridgeGrants)
		}
	})
	t.Run("the sequence right", func(t *testing.T) {
		e := newRTEnv(t)
		e.apply()
		e.mustMig(`REVOKE ALL ON SEQUENCE ` + bridgeSequence + ` FROM ` + e.rt)
		if _, err := NewRuntimeStore(ctx, e.rtPool); notReadyReason(err) != NotReadyBridgeGrants {
			t.Fatalf("got %v, want %s", err, NotReadyBridgeGrants)
		}
	})
}

// ddlTracer counts the statements that look like DDL.
type ddlTracer struct{ n atomic.Int64 }

func (d *ddlTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	s := strings.ToUpper(strings.TrimSpace(data.SQL))
	for _, p := range []string{"CREATE", "ALTER", "DROP", "GRANT", "REVOKE"} {
		if strings.HasPrefix(s, p) {
			d.n.Add(1)
		}
	}
	return ctx
}
func (*ddlTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestNewRuntimeStoreSendsNoDDL(t *testing.T) {
	e := newRTEnv(t)
	e.apply()
	cfg, err := pgxpool.ParseConfig(e.rtURL)
	if err != nil {
		t.Fatal(err)
	}
	tr := &ddlTracer{}
	cfg.ConnConfig.Tracer = tr
	p, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := NewRuntimeStore(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if n := tr.n.Load(); n != 0 {
		t.Fatalf("NewRuntimeStore sent %d DDL statements", n)
	}
}

func TestSchemaMigratedProbe(t *testing.T) {
	e := newRTEnv(t)
	ctx := context.Background()
	if ok, err := SchemaMigrated(ctx, e.rtPool); err != nil || ok {
		t.Fatalf("before ApplySchema: ok=%v err=%v", ok, err)
	}
	e.apply()
	// The probe needs no table privilege: the work-items role holds none on it.
	wiPool := e.pool(e.url(e.wi))
	if ok, err := SchemaMigrated(ctx, wiPool); err != nil || !ok {
		t.Fatalf("after ApplySchema: ok=%v err=%v", ok, err)
	}
	// A probe that cannot run is an error, never "not migrated".
	closed := e.pool(e.rtURL)
	closed.Close()
	if ok, err := SchemaMigrated(ctx, closed); err == nil || ok {
		t.Fatalf("a failed probe must be an error: ok=%v err=%v", ok, err)
	}
}

func TestOneMutatingCommandPerApproval(t *testing.T) {
	e := newRTEnv(t)
	e.apply()
	s := e.runtimeStore()
	enqueueRT(t, s, "acme", KindPlaceOrderFake, "aar_UNIQUE0000000000000001", "gcn_AAAAAAAAAAAAAAAAAAAA01")
	pgSeq++
	suffix := fmt.Sprintf("%016d", time.Now().UnixNano()%1e15+int64(pgSeq))
	in := EnqueueInput{
		ExecutionID: "we_" + suffix, WorkItemID: "wi_" + suffix, WorkflowID: "wf-" + suffix, Tenant: "acme", OwnerPrincipalID: "owner",
		TenantRef: "tnr_" + suffix, PrincipalRef: "prr_" + suffix, OrderRef: "ordr_" + suffix, ConnectionRef: "gcn_AAAAAAAAAAAAAAAAAAAA01",
		InstallRevision: "r1", ProviderRef: "glovo", Kind: KindPlaceOrderFake, Attempt: 1, OperationKey: "op-" + suffix,
		IntentHash: "sha256:" + strings.Repeat("0", 64), Payload: json.RawMessage(`{"quantity_total":1}`),
		ApprovalRef: "aar_UNIQUE0000000000000001",
	}
	tx, err := s.Pool().Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, _, err := s.Enqueue(context.Background(), tx, in); err == nil {
		t.Fatal("a second place_order_fake row with the same aar_ must fail at insert")
	}
}

func TestCommandEffect(t *testing.T) {
	e := newRTEnv(t)
	e.apply()
	s := e.runtimeStore()
	ctx := context.Background()
	id := enqueueRT(t, s, "acme", KindPlaceOrderFake, "aar_EFFECT0000000000000001", "gcn_AAAAAAAAAAAAAAAAAAAA02")
	st, eff, err := s.CommandEffect(ctx, e.rtPool, []string{"acme"}, id)
	if err != nil || st != StatusPending || eff != "none" {
		t.Fatalf("got (%q,%q,%v)", st, eff, err)
	}
	if _, _, err := s.CommandEffect(ctx, e.rtPool, []string{"other"}, id); !errors.Is(err, ErrCommandNotFound) {
		t.Fatalf("a foreign tenant must be not found, got %v", err)
	}
	if _, _, err := s.CommandEffect(ctx, e.rtPool, nil, id); !errors.Is(err, ErrCommandNotFound) {
		t.Fatalf("an empty tenant bound must be not found, got %v", err)
	}
	if _, _, err := s.CommandEffect(ctx, e.rtPool, []string{"acme"}, "cmd_ABSENT00000000000000000A"); !errors.Is(err, ErrCommandNotFound) {
		t.Fatalf("an absent id must be not found, got %v", err)
	}
	other := enqueueRT(t, s, "acme", KindQuote, "", "gcn_AAAAAAAAAAAAAAAAAAAA03")
	if _, _, err := s.CommandEffect(ctx, e.rtPool, []string{"acme"}, other); !errors.Is(err, ErrCommandNotFound) {
		t.Fatalf("a non-place_order_fake kind must be not found, got %v", err)
	}
	// A failed read is an error, never a pair.
	closed := e.pool(e.rtURL)
	closed.Close()
	if _, _, err := s.CommandEffect(ctx, closed, []string{"acme"}, id); err == nil || errors.Is(err, ErrCommandNotFound) {
		t.Fatalf("a failed read must be an error that is not not_found, got %v", err)
	}
}

func TestCancelOpenForConnections(t *testing.T) {
	e := newRTEnv(t)
	e.apply()
	s := e.runtimeStore()
	ctx := context.Background()
	const conn = "gcn_CANCEL000000000000000A"
	pending := enqueueRT(t, s, "acme", KindPlaceOrderFake, "aar_CANCEL0000000000000001", conn)
	permitted := enqueueRT(t, s, "acme", KindPlaceOrderFake, "aar_CANCEL0000000000000002", conn)
	otherConn := enqueueRT(t, s, "acme", KindPlaceOrderFake, "aar_CANCEL0000000000000003", "gcn_CANCEL000000000000000B")
	e.mustMig(`UPDATE bridge_commands SET status='leased', effect_state='permitted', lease_epoch=1 WHERE command_id=$1`, permitted)

	run := func(ids []string) {
		tx, err := e.rtPool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := CancelOpenForConnections(ctx, tx, ids, "svc:revoker"); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	run(nil) // nothing to do is not an error
	run([]string{conn})
	got := func(id string) (string, string, bool) {
		var st, eff string
		var cr bool
		if err := e.migPool.QueryRow(ctx, `SELECT status, effect_state, cancel_requested FROM bridge_commands WHERE command_id=$1`, id).Scan(&st, &eff, &cr); err != nil {
			t.Fatal(err)
		}
		return st, eff, cr
	}
	if st, eff, cr := got(pending); st != StatusCancelled || eff != "none" || !cr {
		t.Fatalf("pending: (%s,%s,%v)", st, eff, cr)
	}
	if st, eff, cr := got(permitted); st != StatusCancelled || eff != "unknown" || !cr {
		t.Fatalf("a permitted effect must become unknown: (%s,%s,%v)", st, eff, cr)
	}
	if st, _, _ := got(otherConn); st != StatusPending {
		t.Fatalf("another connection's command must not change: %s", st)
	}
	var transitions int
	if err := e.migPool.QueryRow(ctx, `SELECT count(*) FROM bridge_command_transitions WHERE actor='svc:revoker' AND to_status='cancelled'`).Scan(&transitions); err != nil {
		t.Fatal(err)
	}
	if transitions != 2 {
		t.Fatalf("want 2 cancel transitions, got %d", transitions)
	}
	run([]string{conn}) // a second run finds nothing open
}

// TestCancelOpenForConnectionsLocksInCommandOrder proves L5: the commands are
// locked, and so cancelled, in command_id order whatever order they were
// created in. The transition ids record the order the rows were handled in.
// The lock order is the byte order of command_id, whatever the database
// collation says. Ids that differ only by case sort one way in en_US and the
// other in bytes; with ORDER BY command_id alone the locks (and so the cancel
// transitions) follow the collation and this fails.
func TestCancelOpenForConnectionsOrdersBytewise(t *testing.T) {
	e := newRTEnv(t)
	e.apply()
	s := e.runtimeStore()
	ctx := context.Background()
	var coll string
	if err := e.migPool.QueryRow(ctx, `SELECT datcollate FROM pg_database WHERE datname = current_database()`).Scan(&coll); err != nil {
		t.Fatal(err)
	}
	if coll == "C" || coll == "POSIX" {
		t.Fatalf("this test needs a database with a non-C collation, got %q (the server lacks en_US.UTF-8)", coll)
	}
	const conn = "gcn_COLLATE00000000000000"
	ids := []string{"cmd_aaaaaaaaaaaaaaaaaaaaaaaaaa", "cmd_Aaaaaaaaaaaaaaaaaaaaaaaaaa", "cmd_bbbbbbbbbbbbbbbbbbbbbbbbbb", "cmd_Bbbbbbbbbbbbbbbbbbbbbbbbbb"}
	for i, id := range ids {
		cmd := enqueueRT(t, s, "acme", KindPlaceOrderFake, fmt.Sprintf("aar_COLLATE%014d", i), conn)
		e.mustMig(`UPDATE bridge_commands SET command_id = $2 WHERE command_id = $1`, cmd, id)
	}
	tx, err := e.rtPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := CancelOpenForConnections(ctx, tx, []string{conn}, "svc:revoker"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := e.migPool.Query(ctx, `SELECT command_id FROM bridge_command_transitions WHERE to_status='cancelled' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		got = append(got, id)
	}
	want := []string{ids[1], ids[3], ids[0], ids[2]} // bytes: A..., B..., a..., b...
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("cancel order %v, want the byte order %v (collation %s)", got, want, coll)
	}
}

func TestCancelOpenForConnectionsLocksInCommandOrder(t *testing.T) {
	e := newRTEnv(t)
	e.apply()
	s := e.runtimeStore()
	ctx := context.Background()
	var conns []string
	for i := 0; i < 8; i++ {
		c := fmt.Sprintf("gcn_ORDER%019d", i)
		conns = append(conns, c)
		enqueueRT(t, s, "acme", KindPlaceOrderFake, fmt.Sprintf("aar_ORDER%016d", i), c)
	}
	tx, err := e.rtPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := CancelOpenForConnections(ctx, tx, conns, "svc:revoker"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := e.migPool.Query(ctx, `SELECT command_id FROM bridge_command_transitions WHERE to_status='cancelled' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		got = append(got, id)
	}
	if len(got) != len(conns) {
		t.Fatalf("want %d cancelled commands, got %d", len(conns), len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Fatalf("commands were not handled in command_id order: %v", got)
		}
	}
}

func TestCommandResultForTriples(t *testing.T) {
	e := newRTEnv(t)
	e.apply()
	s := e.runtimeStore()
	ctx := context.Background()
	mk := func(n int) string {
		return enqueueRT(t, s, "acme", KindPlaceOrderFake, fmt.Sprintf("aar_TRIPLE%017d", n), fmt.Sprintf("gcn_TRIPLE%017d", n))
	}
	read := func(id string) *CommandResult {
		t.Helper()
		r, err := s.CommandResultFor(ctx, e.rtPool, []string{"acme"}, id)
		if err != nil {
			t.Fatalf("CommandResultFor: %v", err)
		}
		return r
	}
	// Pending and leased have no triple.
	p := mk(1)
	if r := read(p); r.Status != StatusPending || r.Outcome != "" || r.ProviderEffect != "" || r.ErrorCode != "" || r.OrderRef == "" || r.Tenant != "acme" {
		t.Fatalf("pending: %+v", r)
	}
	// Cancelled and expired, per effect state.
	cases := []struct {
		status, effect, outcome, pe, code string
	}{
		{StatusCancelled, "none", "cancelled", "none", "none"},
		{StatusCancelled, "not_performed", "cancelled", "none", "none"},
		{StatusCancelled, "unknown", "cancelled", "unknown", "none"},
		{StatusCancelled, "permitted", "cancelled", "unknown", "none"},
		{StatusCancelled, "succeeded", "cancelled", "unknown", "none"},
		{StatusExpired, "none", "failed_terminal", "none", "expired"},
		{StatusExpired, "not_performed", "failed_terminal", "none", "expired"},
		{StatusExpired, "failed", "failed_terminal", "unknown", "expired"},
		{StatusExpired, "unknown", "failed_terminal", "unknown", "expired"},
	}
	for i, c := range cases {
		id := mk(10 + i)
		e.mustMig(`UPDATE bridge_commands SET status=$2, effect_state=$3 WHERE command_id=$1`, id, c.status, c.effect)
		r := read(id)
		if r.Outcome != c.outcome || r.ProviderEffect != c.pe || r.ErrorCode != c.code {
			t.Errorf("%s/%s: got (%s,%s,%s) want (%s,%s,%s)", c.status, c.effect, r.Outcome, r.ProviderEffect, r.ErrorCode, c.outcome, c.pe, c.code)
		}
	}
	// Completed returns the stored triple and digest.
	done := mk(30)
	e.mustMig(`UPDATE bridge_commands SET status='completed', effect_state='succeeded', result_digest='sha256:aa',
		result='{"outcome":"succeeded","provider_effect":"applied","error_code":"none"}'::jsonb WHERE command_id=$1`, done)
	if r := read(done); r.Outcome != "succeeded" || r.ProviderEffect != "applied" || r.ErrorCode != "none" || r.ResultDigest != "sha256:aa" {
		t.Fatalf("completed: %+v", r)
	}
	// A completed command without a readable result is an error, not a triple.
	for i, res := range []string{"NULL", `'{}'::jsonb`, `'{"outcome":"succeeded"}'::jsonb`, `'{"outcome":"succeeded","provider_effect":"applied"}'::jsonb`} {
		id := mk(40 + i)
		e.mustMig(`UPDATE bridge_commands SET status='completed', effect_state='succeeded', result=`+res+` WHERE command_id=$1`, id)
		if _, err := s.CommandResultFor(ctx, e.rtPool, []string{"acme"}, id); !errors.Is(err, ErrResultInconsistent) {
			t.Errorf("completed with result %s: want ErrResultInconsistent, got %v", res, err)
		}
	}
	// Absent, foreign tenant, empty bound and another kind are one answer.
	for name, f := range map[string]func() error{
		"absent": func() error {
			_, err := s.CommandResultFor(ctx, e.rtPool, []string{"acme"}, "cmd_ABSENT00000000000000000A")
			return err
		},
		"foreign": func() error { _, err := s.CommandResultFor(ctx, e.rtPool, []string{"other"}, p); return err },
		"empty":   func() error { _, err := s.CommandResultFor(ctx, e.rtPool, nil, p); return err },
		"kind": func() error {
			q := enqueueRT(t, s, "acme", KindQuote, "", "gcn_TRIPLE00000000000000099")
			_, err := s.CommandResultFor(ctx, e.rtPool, []string{"acme"}, q)
			return err
		},
	} {
		if err := f(); !errors.Is(err, ErrCommandNotFound) {
			t.Errorf("%s: want ErrCommandNotFound, got %v", name, err)
		}
	}
	// A failed read is an error that is not not_found.
	closed := e.pool(e.rtURL)
	closed.Close()
	if _, err := s.CommandResultFor(ctx, closed, []string{"acme"}, p); err == nil || errors.Is(err, ErrCommandNotFound) {
		t.Fatalf("a failed read must be an error that is not not_found, got %v", err)
	}
}

// A store built with NewStore never accepts v1alpha2 commands: wire versions
// are enabled only by NewRuntimeStore.
func TestNewStoreLeavesWireVersionsDisabled(t *testing.T) {
	e := newRTEnv(t)
	ctx := context.Background()
	e.mustMig(`GRANT CREATE ON SCHEMA public TO ` + e.rt)
	legacy, err := NewStore(ctx, e.rtURL)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer legacy.Close()
	if legacy.WireVersionsEnabled() {
		t.Fatal("a store built with NewStore has wire versions enabled")
	}
	var nilStore *Store
	if nilStore.WireVersionsEnabled() {
		t.Fatal("a nil store has wire versions enabled")
	}
}

// NewRuntimeStore is the only caller of EnableWireVersions in shipped code.
func TestEnableWireVersionsHasOneCaller(t *testing.T) {
	var callers []string
	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(path) //nolint:gosec // walks the repository's own sources
		if rerr != nil {
			return rerr
		}
		if strings.Contains(string(b), ".EnableWireVersions(") {
			callers = append(callers, filepath.ToSlash(path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(callers) != 1 || !strings.HasSuffix(callers[0], "internal/bridge/runtime.go") {
		t.Fatalf("EnableWireVersions callers in shipped code: %v, want only internal/bridge/runtime.go", callers)
	}
}
