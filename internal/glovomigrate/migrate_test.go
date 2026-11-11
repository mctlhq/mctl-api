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

package glovomigrate

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovobasket"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

const testPassword = "pw-migrate-test-7f3a" //nolint:gosec // throwaway password of roles in a per-test scratch database

// env is one disposable database with its own roles. The admin connection
// (TEST_DATABASE_URL, a superuser) creates and drops the database and roles.
type env struct {
	t                          *testing.T
	base, db                   string
	mig, rt, wi, legacy, blind string
	buf                        bytes.Buffer
}

func adminURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv("TEST_DATABASE_URL")
	if u == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL is unset in CI: the migrator database tests must run, not skip")
		}
		t.Skip("TEST_DATABASE_URL not set")
	}
	return u
}

func rnd() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func urlFor(t *testing.T, base, user, pass, db string) string {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	if user != "" {
		u.User = url.UserPassword(user, pass)
	}
	u.Path = "/" + db
	q := u.Query()
	q.Set("sslmode", "disable")
	u.RawQuery = q.Encode()
	return u.String()
}

func newEnv(t *testing.T) *env {
	t.Helper()
	base := adminURL(t)
	ctx := context.Background()
	s := rnd()
	e := &env{t: t, base: base, db: "gm_db_" + s, mig: "gm_mig_" + s, rt: "gm_rt_" + s, wi: "gm_wi_" + s, legacy: "gm_legacy_" + s, blind: "gm_blind_" + s}
	root, err := pgx.Connect(ctx, urlFor(t, base, "", "", "postgres"))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer func() { _ = root.Close(ctx) }()
	for _, r := range []string{e.mig, e.rt, e.wi, e.legacy, e.blind} {
		e.exec(root, fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`, r, testPassword))
	}
	e.exec(root, fmt.Sprintf(`CREATE DATABASE %s OWNER %s`, e.db, e.mig))
	e.exec(root, fmt.Sprintf(`REVOKE ALL ON DATABASE %s FROM PUBLIC`, e.db))
	e.exec(root, fmt.Sprintf(`GRANT CONNECT ON DATABASE %s TO %s, %s, %s, %s`, e.db, e.rt, e.wi, e.legacy, e.blind))
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), urlFor(t, base, "", "", "postgres"))
		if err != nil {
			return
		}
		defer func() { _ = c.Close(context.Background()) }()
		_, _ = c.Exec(ctx, fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, e.db))
		for _, r := range []string{e.blind, e.legacy, e.wi, e.rt, e.mig} {
			_, _ = c.Exec(ctx, fmt.Sprintf(`DROP ROLE IF EXISTS %s`, r))
		}
	})
	return e
}

// root is a superuser connection to the scratch database.
func (e *env) root() *pgx.Conn {
	e.t.Helper()
	db := "postgres"
	if e.db != "" {
		db = e.db
	}
	c, err := pgx.Connect(context.Background(), urlFor(e.t, e.base, "", "", db))
	if err != nil {
		e.t.Fatalf("admin connect: %v", err)
	}
	e.t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

func (e *env) exec(c *pgx.Conn, sql string, args ...any) {
	e.t.Helper()
	if _, err := c.Exec(context.Background(), sql, args...); err != nil {
		e.t.Fatalf("exec %q: %v", sql, err)
	}
}

func (e *env) dsn(role string) string { return urlFor(e.t, e.base, role, testPassword, e.db) }

func (e *env) cfg(mode Mode) Config {
	e.buf.Reset()
	return Config{
		DSN: e.dsn(e.mig), ExpectRole: e.mig, RuntimeRole: e.rt, WorkItemsRole: e.wi,
		LockTimeout: 2 * time.Second, StatementTimeout: 30 * time.Second, Mode: mode, Out: &e.buf,
		allowInsecureTLS: true,
	}
}

func (e *env) run(c Config) error {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return Run(ctx, c)
}

// noSecrets fails if text carries the DSN password or a connection string.
func (e *env) noSecrets(text string) {
	e.t.Helper()
	if strings.Contains(text, testPassword) || strings.Contains(text, "postgres://") || strings.Contains(text, "postgresql://") {
		e.t.Fatalf("secret or connection string in output: %q", text)
	}
}

// legacyEra builds a 4.154-era database: the work-items tables created and
// owned by the legacy role (no Glovo objects), a few approval rows, then the
// operator's D1 ownership transfer to the migration role plus the transitional
// grants that keep the legacy role working.
func (e *env) legacyEra() {
	e.t.Helper()
	ctx := context.Background()
	root := e.root()
	e.exec(root, fmt.Sprintf(`GRANT CREATE ON SCHEMA public TO %s`, e.legacy))
	if err := workitems.ApplySchema(ctx, e.dsn(e.legacy), ""); err != nil {
		e.t.Fatalf("legacy-era generic schema: %v", err)
	}
	leg, err := pgx.Connect(ctx, e.dsn(e.legacy))
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = leg.Close(ctx) }()
	for i, st := range []string{"pending", "approved", "consumed", "executed"} {
		e.insertApproval(leg, fmt.Sprintf("old-%d", i), "devloop.deploy", st)
	}
	// D1: ownership transfer in one place, then transitional grants.
	rows, err := root.Query(ctx, `SELECT c.relname, c.relkind::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
	  WHERE n.nspname = 'public' AND c.relkind IN ('r','p') AND pg_get_userbyid(c.relowner) = $1`, e.legacy)
	if err != nil {
		e.t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var n, k string
		if err := rows.Scan(&n, &k); err != nil {
			e.t.Fatal(err)
		}
		tables = append(tables, n)
	}
	rows.Close()
	for _, n := range tables {
		e.exec(root, fmt.Sprintf(`ALTER TABLE public.%s OWNER TO %s`, pgx.Identifier{n}.Sanitize(), e.mig))
		e.exec(root, fmt.Sprintf(`GRANT ALL ON TABLE public.%s TO %s`, pgx.Identifier{n}.Sanitize(), e.legacy))
	}
	fr, err := root.Query(ctx, `SELECT p.oid::regprocedure::text FROM pg_proc p WHERE p.pronamespace = to_regnamespace('public') AND pg_get_userbyid(p.proowner) = $1`, e.legacy)
	if err != nil {
		e.t.Fatal(err)
	}
	var funcs []string
	for fr.Next() {
		var f string
		if err := fr.Scan(&f); err != nil {
			e.t.Fatal(err)
		}
		funcs = append(funcs, f)
	}
	fr.Close()
	for _, f := range funcs {
		e.exec(root, fmt.Sprintf(`ALTER FUNCTION %s OWNER TO %s`, f, e.mig))
	}
	e.exec(root, fmt.Sprintf(`GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO %s`, e.legacy))
}

// insertApproval writes one old-shape row: only the columns the 4.154 code
// wrote, with the generic state machine's states.
func (e *env) insertApproval(c *pgx.Conn, id, kind, state string) {
	e.t.Helper()
	_, err := c.Exec(context.Background(), `INSERT INTO action_approval_requests
	  (id, execution_id, action_kind, target, args_digest, policy_rule_id, policy_version, idempotency_key,
	   requested_by, intent_hash, state, expires_at, created_at, schema_version)
	  VALUES ($1,'exec-1',$2,'svc','dig','rule','v1',$1,'user','ih',$3, now() + interval '1 day', now(), '1')`, id, kind, state)
	if err != nil {
		e.t.Fatalf("insert approval %s (%s): %v", id, state, err)
	}
}

// dump is a deterministic picture of everything the migrator may touch.
func (e *env) dump() string {
	e.t.Helper()
	ctx := context.Background()
	c := e.root()
	var b strings.Builder
	for _, q := range []string{
		`SELECT n.nspname || '.' || c.relname || ':' || c.relkind::text || ':' || pg_get_userbyid(c.relowner) || ':' || coalesce(c.relacl::text,'')
		   FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname IN ('glovo','public') AND c.relkind IN ('r','S','i') ORDER BY 1`,
		`SELECT p.oid::regprocedure::text || ':' || pg_get_userbyid(p.proowner) || ':' || md5(p.prosrc) FROM pg_proc p
		   WHERE p.pronamespace IN (to_regnamespace('glovo'), to_regnamespace('public')) ORDER BY 1`,
		`SELECT tgrelid::regclass::text || ':' || tgname || ':' || tgenabled::text FROM pg_trigger WHERE NOT tgisinternal ORDER BY 1`,
		`SELECT conrelid::regclass::text || ':' || conname || ':' || convalidated::text || ':' || pg_get_constraintdef(oid) FROM pg_constraint
		   WHERE connamespace IN (to_regnamespace('glovo'), to_regnamespace('public')) ORDER BY 1`,
		`SELECT attrelid::regclass::text || '.' || attname || ':' || attacl::text FROM pg_attribute WHERE attacl IS NOT NULL
		   AND attrelid IN (SELECT oid FROM pg_class WHERE relnamespace IN (to_regnamespace('glovo'), to_regnamespace('public'))) ORDER BY 1`,
	} {
		rows, err := c.Query(ctx, q)
		if err != nil {
			e.t.Fatal(err)
		}
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				e.t.Fatal(err)
			}
			b.WriteString(s + "\n")
		}
		rows.Close()
	}
	for _, t := range []string{"glovo.glovo_schema_version", "glovo.approval_schema_version", "glovo.basket_schema_version", "public.work_items_schema_version"} {
		var ok bool
		if err := c.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, t).Scan(&ok); err != nil {
			e.t.Fatal(err)
		}
		if ok {
			var v string
			if err := c.QueryRow(ctx, `SELECT coalesce(string_agg(version::text, ','), '') FROM `+t).Scan(&v); err != nil {
				e.t.Fatal(err)
			}
			b.WriteString(t + "=" + v + "\n")
		}
	}
	return b.String()
}

func (e *env) schemaExists() bool {
	var ok bool
	if err := e.root().QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'glovo')`).Scan(&ok); err != nil {
		e.t.Fatal(err)
	}
	return ok
}

// assertBootChecks runs the runtime role's own boot verification of the two
// schemas the 4.156.0 boot checks, proving the migrator's result is what boot
// accepts.
func (e *env) assertBootChecks() {
	e.t.Helper()
	ctx := context.Background()
	c, err := pgx.Connect(ctx, e.dsn(e.rt))
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = c.Close(ctx) }()
	if err := workitems.VerifyGlovoApprovalSchema(ctx, c); err != nil {
		e.t.Fatalf("boot check VerifyGlovoApprovalSchema as the runtime role: %v", err)
	}
	if err := glovobasket.VerifySchema(ctx, c); err != nil {
		e.t.Fatalf("boot check glovobasket.VerifySchema as the runtime role: %v", err)
	}
}

func TestEmptyDatabaseAppliesAllThreeInOrderAndBootAccepts(t *testing.T) {
	e := newEnv(t)
	var order []string
	c := e.cfg(ModeApply)
	c.onStep = func(n string) { order = append(order, n) }
	if err := e.run(c); err != nil {
		t.Fatalf("apply on an empty database: %v\n%s", err, e.buf.String())
	}
	if !slices.Equal(order, []string{StepBase, StepApproval, StepBasket}) {
		t.Fatalf("steps ran in order %v", order)
	}
	if !slices.Equal(StepNames(), order) {
		t.Fatalf("StepNames %v is not the enforced order %v", StepNames(), order)
	}
	e.assertBootChecks()
	e.noSecrets(e.buf.String())
	// verify agrees.
	if err := e.run(e.cfg(ModeVerify)); err != nil {
		t.Fatalf("verify after apply: %v\n%s", err, e.buf.String())
	}
}

func TestRerunIsStateIdentical(t *testing.T) {
	e := newEnv(t)
	if err := e.run(e.cfg(ModeApply)); err != nil {
		t.Fatal(err)
	}
	first := e.dump()
	if err := e.run(e.cfg(ModeApply)); err != nil {
		t.Fatalf("second run: %v\n%s", err, e.buf.String())
	}
	if second := e.dump(); second != first {
		t.Fatalf("a re-run changed the catalog:\n--- first\n%s\n--- second\n%s", first, second)
	}
	// A disabled guard is re-enabled by the next run (convergence).
	e.exec(e.root(), `ALTER TABLE public.action_approval_requests DISABLE TRIGGER aar_guard`)
	if err := e.run(e.cfg(ModeVerify)); !errors.Is(err, ErrNotReady) {
		t.Fatalf("verify with a disabled guard: %v", err)
	}
	if err := e.run(e.cfg(ModeApply)); err != nil {
		t.Fatal(err)
	}
	if got := e.dump(); got != first {
		t.Fatalf("the re-run did not restore the guard:\n%s", got)
	}
}

func TestLegacyEraDatabaseKeepsApprovalsWorking(t *testing.T) {
	e := newEnv(t)
	e.legacyEra()
	ctx := context.Background()
	if err := e.run(e.cfg(ModeApply)); err != nil {
		t.Fatalf("apply on a 4.154-era database: %v\n%s", err, e.buf.String())
	}
	e.assertBootChecks()
	root := e.root()
	// Existing rows survive, byte for byte in the columns that matter.
	var n int
	if err := root.QueryRow(ctx, `SELECT count(*) FROM public.action_approval_requests WHERE id LIKE 'old-%' AND action_kind = 'devloop.deploy'`).Scan(&n); err != nil || n != 4 {
		t.Fatalf("existing approval rows: %d, %v", n, err)
	}
	var states string
	if err := root.QueryRow(ctx, `SELECT string_agg(state, ',' ORDER BY id) FROM public.action_approval_requests WHERE id LIKE 'old-%'`).Scan(&states); err != nil || states != "pending,approved,consumed,executed" {
		t.Fatalf("existing approval states: %q, %v", states, err)
	}
	// Old-shape inserts and the generic state machine still work as the legacy
	// owner-side role and as the work-items role, which has no access to schema glovo.
	for _, who := range []string{e.legacy, e.wi} {
		c, err := pgx.Connect(ctx, e.dsn(who))
		if err != nil {
			t.Fatal(err)
		}
		id := "new-" + who
		e.insertApproval(c, id, "devloop.deploy", "pending")
		for _, st := range []string{"approved", "consumed", "executed"} {
			if _, err := c.Exec(ctx, `UPDATE action_approval_requests SET state = $2 WHERE id = $1`, id, st); err != nil {
				t.Fatalf("%s: old-shape transition to %s: %v", who, st, err)
			}
		}
		_ = c.Close(ctx)
	}
	// What changes, exactly: the new states are Glovo-only and the glovo kinds
	// are guarded.
	for _, bad := range []struct{ kind, state string }{{"devloop.deploy", "reserved"}, {"devloop.deploy", "unknown"}, {"glovo.other", "pending"}} {
		if _, err := root.Exec(ctx, `INSERT INTO public.action_approval_requests
		  (id, execution_id, action_kind, target, args_digest, policy_rule_id, policy_version, idempotency_key,
		   requested_by, intent_hash, state, expires_at, created_at, schema_version)
		  VALUES ('x-'||$2||$1,'e',$1,'t','d','r','v','k-'||$2||$1,'u','i',$2, now(), now(), '1')`, bad.kind, bad.state); err == nil {
			t.Fatalf("(%s, %s) is accepted: the new CHECKs are not in force", bad.kind, bad.state)
		}
	}
	e.noSecrets(e.buf.String())
}

func TestRefusesIfOwnershipNotTransferredBeforeAnythingIsApplied(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := e.root()
	e.exec(root, fmt.Sprintf(`GRANT CREATE ON SCHEMA public TO %s`, e.legacy))
	if err := workitems.ApplySchema(ctx, e.dsn(e.legacy), ""); err != nil {
		t.Fatal(err)
	}
	before := e.dump()
	err := e.run(e.cfg(ModeApply))
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "ownership transfer") {
		t.Fatalf("legacy-owned tables: %v", err)
	}
	if got := e.dump(); got != before || e.schemaExists() {
		t.Fatalf("a refused run changed the database:\n%s", got)
	}
	// Dry-run reports the same refusal and still changes nothing.
	if err := e.run(e.cfg(ModeDryRun)); err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if !strings.Contains(e.buf.String(), "would REFUSE") {
		t.Fatalf("dry-run did not warn about the refusal:\n%s", e.buf.String())
	}
}

func TestWrongRoleIsRefusedBeforeAnyChange(t *testing.T) {
	e := newEnv(t)
	before := e.dump()
	// The DSN user is the runtime role.
	c := e.cfg(ModeApply)
	c.DSN = e.dsn(e.rt)
	if err := e.run(c); !errors.Is(err, ErrRefused) {
		t.Fatalf("runtime-role DSN: %v", err)
	}
	// The DSN user is right but the session role is not (SET ROLE through the
	// connection options): the in-transaction check must catch it too.
	e.exec(e.root(), fmt.Sprintf(`GRANT %s TO %s`, e.rt, e.mig))
	c = e.cfg(ModeApply)
	c.DSN = e.dsn(e.mig) + "&options=" + url.QueryEscape("-c role="+e.rt)
	err := e.run(c)
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("session role differs from the DSN user: %v", err)
	}
	// A superuser is refused even when named as the expected role.
	c = e.cfg(ModeApply)
	su, perr := pgconn.ParseConfig(urlFor(t, e.base, "", "", e.db))
	if perr != nil {
		t.Fatal(perr)
	}
	c.ExpectRole, c.DSN = su.User, urlFor(t, e.base, "", "", e.db)
	if su.User != "" && roleNameRE.MatchString(su.User) {
		if err := e.run(c); !errors.Is(err, ErrRefused) {
			t.Fatalf("superuser: %v", err)
		}
	}
	if e.dump() != before || e.schemaExists() {
		t.Fatal("a refused run changed the database")
	}
}

func TestLockTimeoutRollsBackAndIsRetryable(t *testing.T) {
	e := newEnv(t)
	e.legacyEra()
	ctx := context.Background()
	holder, err := pgx.Connect(ctx, e.dsn(e.mig))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Close(ctx) }()
	tx, err := holder.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `LOCK TABLE public.action_approval_requests IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	c := e.cfg(ModeApply)
	c.LockTimeout = 400 * time.Millisecond
	var order []string
	c.onStep = func(n string) { order = append(order, n) }
	start := time.Now()
	err = e.run(c)
	took := time.Since(start)
	if !errors.Is(err, ErrLockTimeout) {
		t.Fatalf("blocked run: %v\n%s", err, e.buf.String())
	}
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "55P03" {
		t.Fatalf("the cause is not SQLSTATE 55P03: %v", err)
	}
	if took > 10*time.Second {
		t.Fatalf("the blocked step waited %s, lock_timeout is not applied", took)
	}
	if !slices.Equal(order, []string{StepBase, StepApproval}) {
		t.Fatalf("steps attempted: %v (basket must not run after approval failed)", order)
	}
	// Step 1 committed; the failed step left nothing behind.
	var base, approval bool
	if err := e.root().QueryRow(ctx, `SELECT to_regclass('glovo.glovo_schema_version') IS NOT NULL, to_regclass('glovo.approval_schema_version') IS NOT NULL`).Scan(&base, &approval); err != nil {
		t.Fatal(err)
	}
	if !base || approval {
		t.Fatalf("after the lock timeout: base=%v approval=%v", base, approval)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	// The retry completes.
	if err := e.run(e.cfg(ModeApply)); err != nil {
		t.Fatalf("retry: %v\n%s", err, e.buf.String())
	}
	e.assertBootChecks()
}

func TestStatementTimeoutAppliesInEveryTransaction(t *testing.T) {
	e := newEnv(t)
	e.legacyEra()
	ctx := context.Background()
	holder, err := pgx.Connect(ctx, e.dsn(e.mig))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Close(ctx) }()
	tx, err := holder.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `LOCK TABLE public.action_approval_requests IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	// A long lock_timeout, a short statement_timeout: the statement is
	// cancelled (57014) by the second, which proves it is set.
	c := e.cfg(ModeApply)
	c.LockTimeout, c.StatementTimeout = 30*time.Second, 400*time.Millisecond
	start := time.Now()
	err = e.run(c)
	var pe *pgconn.PgError
	if !errors.Is(err, ErrStepFailed) || !errors.As(err, &pe) || pe.Code != "57014" {
		t.Fatalf("expected a statement_timeout cancel (57014), got %v", err)
	}
	if time.Since(start) > 15*time.Second {
		t.Fatal("statement_timeout did not bound the step")
	}
}

func TestTimeoutsAreLocalToTheTransaction(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, e.dsn(e.mig))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	cfg := e.cfg(ModeApply)
	cfg.withDefaults()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.setup(ctx, tx); err != nil {
		t.Fatal(err)
	}
	var lt, st string
	if err := tx.QueryRow(ctx, `SELECT current_setting('lock_timeout'), current_setting('statement_timeout')`).Scan(&lt, &st); err != nil {
		t.Fatal(err)
	}
	if lt != "2s" || st != "30s" {
		t.Fatalf("in the transaction lock_timeout=%s statement_timeout=%s", lt, st)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `SELECT current_setting('lock_timeout'), current_setting('statement_timeout')`).Scan(&lt, &st); err != nil {
		t.Fatal(err)
	}
	if lt != "0" || st != "0" {
		t.Fatalf("after the commit lock_timeout=%s statement_timeout=%s: SET LOCAL leaked", lt, st)
	}
}

func TestPartialFailureRollsBackTheFailedStepOnly(t *testing.T) {
	// Step 1 fails at its last statements (the runtime role does not exist):
	// every DDL it ran is rolled back and no later step runs.
	e := newEnv(t)
	before := e.dump()
	c := e.cfg(ModeApply)
	c.RuntimeRole = "gm_no_such_role_" + rnd()
	var order []string
	c.onStep = func(n string) { order = append(order, n) }
	err := e.run(c)
	if !errors.Is(err, ErrStepFailed) {
		t.Fatalf("missing runtime role: %v", err)
	}
	if !slices.Equal(order, []string{StepBase}) {
		t.Fatalf("steps attempted: %v", order)
	}
	if e.schemaExists() || e.dump() != before {
		t.Fatalf("a failed step left objects behind:\n%s", e.dump())
	}

	// Step 2 fails (the work-items role does not exist): step 1 is committed,
	// step 2's tables are not there, step 3 never ran.
	e2 := newEnv(t)
	c = e2.cfg(ModeApply)
	c.WorkItemsRole = "gm_no_such_wi_" + rnd()
	order = nil
	c.onStep = func(n string) { order = append(order, n) }
	if err := e2.run(c); !errors.Is(err, ErrStepFailed) {
		t.Fatalf("missing work-items role: %v", err)
	}
	if !slices.Equal(order, []string{StepBase, StepApproval}) {
		t.Fatalf("steps attempted: %v", order)
	}
	var baseOK bool
	var wi, appr, basket *string
	if err := e2.root().QueryRow(context.Background(), `SELECT to_regclass('glovo.glovo_schema_version') IS NOT NULL,
	  to_regclass('public.work_items')::text, to_regclass('glovo.approval_schema_version')::text, to_regclass('glovo.baskets')::text`).Scan(&baseOK, &wi, &appr, &basket); err != nil {
		t.Fatal(err)
	}
	if !baseOK || wi != nil || appr != nil || basket != nil {
		t.Fatalf("after step 2 failed: base=%v work_items=%v approval=%v basket=%v", baseOK, wi, appr, basket)
	}
	// Fixing the cause and re-running completes from where it stopped.
	if err := e2.run(e2.cfg(ModeApply)); err != nil {
		t.Fatalf("resume: %v", err)
	}
	e2.assertBootChecks()
}

func TestDryRunChangesNothingAndPrintsThePlan(t *testing.T) {
	e := newEnv(t)
	before := e.dump()
	if err := e.run(e.cfg(ModeDryRun)); err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if e.schemaExists() || e.dump() != before {
		t.Fatal("dry-run changed the database")
	}
	out := e.buf.String()
	for _, want := range []string{"step glovo-base", "step approval-v2", "step basket-v1", "would create", "dry-run: nothing was applied"} {
		if !strings.Contains(out, want) {
			t.Fatalf("dry-run output lacks %q:\n%s", want, out)
		}
	}
	e.noSecrets(out)
	// After a real run, dry-run reports a re-apply and still changes nothing.
	if err := e.run(e.cfg(ModeApply)); err != nil {
		t.Fatal(err)
	}
	after := e.dump()
	if err := e.run(e.cfg(ModeDryRun)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.buf.String(), "would re-apply") || e.dump() != after {
		t.Fatalf("dry-run after apply:\n%s", e.buf.String())
	}
}

func TestVerifyEmptyIsNotReadyAndBlindRoleCouldNotObserve(t *testing.T) {
	e := newEnv(t)
	if err := e.run(e.cfg(ModeVerify)); !errors.Is(err, ErrNotReady) {
		t.Fatalf("verify on an empty database: %v", err)
	}
	if ExitCode(ErrNotReady) != ExitNotReady {
		t.Fatal("exit code")
	}
	if err := e.run(e.cfg(ModeApply)); err != nil {
		t.Fatal(err)
	}
	// A role that can connect but cannot read the catalog objects: the read
	// fails, and that must be "could not observe", never "clean" or "absent".
	c := e.cfg(ModeVerify)
	c.ExpectRole, c.DSN = e.blind, e.dsn(e.blind)
	err := e.run(c)
	if !errors.Is(err, ErrCouldNotObserve) {
		t.Fatalf("verify as a role without access: %v\n%s", err, e.buf.String())
	}
	if errors.Is(err, ErrNotReady) || ExitCode(err) == ExitOK {
		t.Fatalf("an unreadable catalog must not be reported as not-ready or ok: %v", err)
	}
	if strings.Contains(e.buf.String(), "READY: all three") {
		t.Fatalf("an unreadable catalog was reported ready:\n%s", e.buf.String())
	}
}

func TestSchemaNewerIsRefusedBeforeAnyChange(t *testing.T) {
	for _, tc := range []struct{ table, name string }{
		{"glovo.basket_schema_version", StepBasket},
		{"glovo.approval_schema_version", StepApproval},
		{"glovo.glovo_schema_version", StepBase},
		{"public.work_items_schema_version", StepApproval},
	} {
		t.Run(tc.table, func(t *testing.T) {
			e := newEnv(t)
			if err := e.run(e.cfg(ModeApply)); err != nil {
				t.Fatal(err)
			}
			e.exec(e.root(), fmt.Sprintf(`UPDATE %s SET version = version + 1`, tc.table))
			before := e.dump()
			var order []string
			c := e.cfg(ModeApply)
			c.onStep = func(n string) { order = append(order, n) }
			err := e.run(c)
			if !errors.Is(err, ErrSchemaNewer) || ExitCode(err) != ExitRefused {
				t.Fatalf("newer %s: %v", tc.table, err)
			}
			if !strings.Contains(err.Error(), tc.name) || !strings.Contains(err.Error(), "nothing was changed") {
				t.Fatalf("the error does not name the step and the no-change guarantee: %v", err)
			}
			if len(order) != 0 || e.dump() != before {
				t.Fatalf("steps ran (%v) or the database changed before the refusal", order)
			}
			if err := e.run(e.cfg(ModeDryRun)); !errors.Is(err, ErrSchemaNewer) {
				t.Fatalf("dry-run on a newer schema: %v", err)
			}
		})
	}
}

func TestNoSecretInAnyFailurePath(t *testing.T) {
	e := newEnv(t)
	// A connection failure (the role does not exist; a throwaway cluster may
	// trust every password): the text carries neither secret.
	c := e.cfg(ModeApply)
	ghost := "gm_ghost_" + rnd()
	u, _ := url.Parse(c.DSN)
	u.User = url.UserPassword(ghost, "wrong-"+testPassword)
	c.DSN, c.ExpectRole = u.String(), ghost
	err := e.run(c)
	if err == nil {
		t.Fatal("a nonexistent role connected")
	}
	e.noSecrets(err.Error() + e.buf.String())
	if strings.Contains(err.Error()+e.buf.String(), "wrong-"+testPassword) {
		t.Fatal("the password leaked")
	}
	// An error that embeds the DSN is redacted on the way out of Run.
	dsn := e.dsn(e.mig)
	got := redact(fmt.Errorf("boom %s and %s", dsn, testPassword), dsn)
	if strings.Contains(got.Error(), testPassword) || strings.Contains(got.Error(), dsn) {
		t.Fatalf("redact left a secret: %v", got)
	}
	// The sentinel survives redaction.
	if !errors.Is(redact(fmt.Errorf("%w: %s", ErrStepFailed, dsn), dsn), ErrStepFailed) {
		t.Fatal("redact broke errors.Is")
	}
}

func TestCheckDSN(t *testing.T) {
	const role = "glovo_migrator"
	for _, tc := range []struct {
		name, dsn string
		env       string
		ok        bool
	}{
		{"disable", "postgres://glovo_migrator:p@db.example:5432/x?sslmode=disable", "", false},
		{"allow", "postgres://glovo_migrator:p@db.example/x?sslmode=allow", "", false},
		{"prefer", "postgres://glovo_migrator:p@db.example/x?sslmode=prefer", "", false},
		{"unset defaults to prefer", "postgres://glovo_migrator:p@db.example/x", "", false},
		{"require", "postgres://glovo_migrator:p@db.example/x?sslmode=require", "", true},
		{"verify-ca", "postgres://glovo_migrator:p@db.example/x?sslmode=verify-ca", "", true},
		{"verify-full", "postgres://glovo_migrator:p@db.example/x?sslmode=verify-full", "", true},
		{"keyword form", "host=db.example user=glovo_migrator password=p dbname=x sslmode=require", "", true},
		{"env cannot weaken an explicit require", "postgres://glovo_migrator:p@db.example/x?sslmode=require", "disable", true},
		{"env disable with no sslmode", "postgres://glovo_migrator:p@db.example/x", "disable", false},
		{"unix socket has no TLS", "host=/var/run/postgresql user=glovo_migrator dbname=x sslmode=require", "", false},
		{"wrong user", "postgres://someone_else:p@db.example/x?sslmode=require", "", false},
		{"unparseable", "postgres://glovo_migrator:p@db.example:notaport/x?sslmode=require", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.env != "" {
				t.Setenv("PGSSLMODE", tc.env)
			} else {
				t.Setenv("PGSSLMODE", "")
			}
			err := CheckDSN(tc.dsn, role)
			if tc.ok && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !tc.ok {
				if err == nil || !errors.Is(err, ErrRefused) {
					t.Fatalf("accepted or wrong error: %v", err)
				}
				if strings.Contains(err.Error(), "p@") || strings.Contains(err.Error(), "db.example") {
					t.Fatalf("the refusal echoes the DSN: %v", err)
				}
			}
		})
	}
}

func TestRunWithoutAllowInsecureRefusesPlaintextDSN(t *testing.T) {
	e := newEnv(t)
	c := e.cfg(ModeApply)
	c.allowInsecureTLS = false // what the command line always has
	if err := e.run(c); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "sslmode") {
		t.Fatalf("plaintext DSN: %v", err)
	}
	if e.schemaExists() {
		t.Fatal("a refused run changed the database")
	}
}

func TestConfigValidation(t *testing.T) {
	e := newEnv(t)
	for name, mut := range map[string]func(*Config){
		"bad runtime role":       func(c *Config) { c.RuntimeRole = "Bad-Role" },
		"no work-items role":     func(c *Config) { c.WorkItemsRole = "" },
		"same runtime and wi":    func(c *Config) { c.WorkItemsRole = c.RuntimeRole },
		"migrator is runtime":    func(c *Config) { c.RuntimeRole = c.ExpectRole },
		"empty dsn":              func(c *Config) { c.DSN = "" },
		"negative lock timeout":  func(c *Config) { c.LockTimeout = -time.Second },
		"sub-ms statement bound": func(c *Config) { c.StatementTimeout = time.Microsecond },
	} {
		c := e.cfg(ModeApply)
		mut(&c)
		if err := e.run(c); !errors.Is(err, ErrRefused) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// The apply functions are the code boot's counterparts verify: the compiled
// versions the migrator reports are the ones the packages record.
func TestCompiledVersionsMatchThePackages(t *testing.T) {
	if glovo.CompiledSchemaVersion() < 1 || workitems.CompiledGlovoApprovalSchemaVersion() != 2 || glovobasket.SchemaVersion != 1 {
		t.Fatalf("versions: glovo=%d approval=%d basket=%d", glovo.CompiledSchemaVersion(), workitems.CompiledGlovoApprovalSchemaVersion(), glovobasket.SchemaVersion)
	}
}
