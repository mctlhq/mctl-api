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
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// adminConn connects as the TEST_DATABASE_URL (admin) role to the test
// database, to make the deliberate mutations of the negative matrix. The
// runtime role cannot make them.
func (e *env) adminConn() *pgx.Conn {
	e.t.Helper()
	u, err := url.Parse(adminURL(e.t))
	if err != nil {
		e.t.Fatal(err)
	}
	u.Path = "/" + e.dbName
	c, err := pgx.Connect(context.Background(), u.String())
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

func (e *env) adminExec(stmt string) {
	e.t.Helper()
	if _, err := e.adminConn().Exec(context.Background(), stmt); err != nil {
		e.t.Fatalf("admin %q: %v", stmt, err)
	}
}

func sqlState(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code
	}
	return ""
}

func TestApplySchemaConcurrentAndIdempotent(t *testing.T) {
	e := newEnvNoSchema(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func(i int) { defer wg.Done(); errs[i] = ApplySchema(ctx, e.migURL, e.rt) }(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("apply %d: %v", i, err)
		}
	}
	// again with every CHECK in place: a no-op
	if err := ApplySchema(ctx, e.migURL, e.rt); err != nil {
		t.Fatal(err)
	}
	c := e.adminConn()
	var n int
	// only schema glovo holds objects of this slice
	if err := c.QueryRow(ctx, `SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname NOT IN ('glovo', 'pg_catalog', 'information_schema', 'pg_toast') AND c.relkind IN ('r','i','S','v','m')`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d relations outside schema glovo: %v", n, err)
	}
	if err := c.QueryRow(ctx, `SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
 WHERE n.nspname NOT IN ('glovo', 'pg_catalog', 'information_schema')`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d functions outside schema glovo: %v", n, err)
	}
	if err := c.QueryRow(ctx, `SELECT count(*) FROM glovo.glovo_schema_version WHERE version = $1`, schemaVersion).Scan(&n); err != nil || n != 1 {
		t.Fatalf("schema version rows %d: %v", n, err)
	}
}

func TestNewStoreFailsClosedWithoutDDL(t *testing.T) {
	ctx := context.Background()
	// no schema at all
	e := newEnvNoSchema(t)
	tr := &stmtTracer{}
	pool := tracedPool(t, e, tr)
	if _, err := NewStore(ctx, pool, e.rt, e.mig); err == nil {
		t.Fatal("NewStore started without a schema")
	}
	// schema applied: NewStore issues no DDL
	if err := ApplySchema(ctx, e.migURL, e.rt); err != nil {
		t.Fatal(err)
	}
	tr.reset()
	if _, err := NewStore(ctx, pool, e.rt, e.mig); err != nil {
		t.Fatal(err)
	}
	for _, s := range tr.snapshot() {
		l := strings.ToUpper(strings.TrimSpace(s))
		for _, kw := range []string{"CREATE", "ALTER", "DROP", "GRANT", "REVOKE", "TRUNCATE"} {
			if strings.HasPrefix(l, kw) {
				t.Fatalf("NewStore ran DDL: %s", s)
			}
		}
	}
	// a different recorded version fails closed, both above and below
	for _, v := range []int{schemaVersion + 1, schemaVersion - 1} {
		e.adminExec(fmt.Sprintf(`UPDATE glovo.glovo_schema_version SET version = %d`, v))
		if _, err := NewStore(ctx, pool, e.rt, e.mig); err == nil {
			t.Fatalf("NewStore accepted version %d", v)
		}
	}
	// a recorded version above the compiled one is a downgrade ApplySchema refuses
	e.adminExec(fmt.Sprintf(`UPDATE glovo.glovo_schema_version SET version = %d`, schemaVersion+1))
	if err := ApplySchema(ctx, e.migURL, e.rt); err == nil {
		t.Fatal("ApplySchema downgraded the schema")
	}
	// the shared pool is not closed by a failed NewStore
	if err := pool.Ping(ctx); err != nil {
		t.Fatal("pool closed:", err)
	}
	// invalid role names for NewStore
	if _, err := NewStore(ctx, pool, `x"; DROP ROLE y; --`, e.mig); err == nil {
		t.Fatal("hostile role accepted")
	}
	if _, err := NewStore(ctx, nil, e.rt, e.mig); err == nil {
		t.Fatal("nil pool accepted")
	}
}

func TestApplySchemaRefusesForeignOwners(t *testing.T) {
	ctx := context.Background()
	t.Run("schema owned by another role", func(t *testing.T) {
		e := newEnvNoSchema(t)
		e.adminExec(fmt.Sprintf(`CREATE SCHEMA glovo AUTHORIZATION %s`, e.rt))
		if err := ApplySchema(ctx, e.migURL, e.rt); err == nil {
			t.Fatal("adopted a foreign schema")
		}
	})
	t.Run("table owned by another role", func(t *testing.T) {
		e := newEnv(t)
		e.adminExec(fmt.Sprintf(`ALTER TABLE glovo.glovo_pilot_allowlist OWNER TO %s`, e.rt))
		if err := ApplySchema(ctx, e.migURL, e.rt); err == nil {
			t.Fatal("adopted a foreign table")
		}
	})
	t.Run("function owned by another role", func(t *testing.T) {
		e := newEnv(t)
		e.adminExec(fmt.Sprintf(`ALTER FUNCTION glovo.glovo_audit_immutable() OWNER TO %s`, e.rt))
		if err := ApplySchema(ctx, e.migURL, e.rt); err == nil {
			t.Fatal("adopted a foreign function")
		}
	})
}

func TestRuntimeRolePrivileges(t *testing.T) {
	e := newEnv(t)
	f := newFixture(t)
	ctx := context.Background()
	ia := e.install(f, f.Alpha)
	e.connect(f.A1, ia.InstallRevision, "k")

	// DML the runtime role needs
	if _, err := e.pool.Exec(ctx, `INSERT INTO glovo.glovo_pilot_allowlist (tenant_id, principal_id, added_by, added_at)
 VALUES ($1, $2, $3, now())`, f.Alpha, f.A1.PrincipalID, f.actorAdmin.PrincipalID); err != nil {
		t.Fatal(err)
	}
	ok, err := e.store.IsAllowlisted(ctx, f.Alpha, f.A1.PrincipalID)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	if ok, _ := e.store.IsAllowlisted(ctx, f.Alpha, f.A2.PrincipalID); ok {
		t.Fatal("A2 allowlisted")
	}
	if _, err := e.pool.Exec(ctx, `DELETE FROM glovo.glovo_pilot_allowlist WHERE tenant_id = $1`, f.Alpha); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(ctx, `DELETE FROM glovo.glovo_connect_requests WHERE tenant_id = $1`, f.Alpha); err != nil {
		t.Fatalf("connect_requests DELETE (the 24 h cleanup) is granted: %v", err)
	}
	// the allowlist CHECK
	if _, err := e.pool.Exec(ctx, `INSERT INTO glovo.glovo_pilot_allowlist VALUES ('t', 'usr_1', 'prn_x', now())`); err == nil {
		t.Fatal("allowlist accepted a non-prn_ principal")
	}

	// rights it must not have
	denied := []string{
		`UPDATE glovo.glovo_audit_events SET reason_code = 'x'`,
		`DELETE FROM glovo.glovo_audit_events`,
		`DELETE FROM glovo.glovo_connections`,
		`DELETE FROM glovo.glovo_installs`,
		`UPDATE glovo.glovo_pilot_allowlist SET added_by = 'x'`,
		`INSERT INTO glovo.glovo_schema_version VALUES (9)`,
		`UPDATE glovo.glovo_schema_version SET version = 9`,
		`CREATE TABLE glovo.glovo_rogue (a int)`,
		`CREATE TABLE public.glovo_rogue (a int)`,
	}
	tables := []string{"glovo_installs", "glovo_connections", "glovo_connect_requests", "glovo_audit_events", "glovo_pilot_allowlist", "glovo_schema_version"}
	for _, tb := range tables {
		denied = append(denied,
			fmt.Sprintf(`ALTER TABLE glovo.%s DISABLE TRIGGER ALL`, tb),
			fmt.Sprintf(`ALTER TABLE glovo.%s ADD COLUMN x int`, tb),
			fmt.Sprintf(`ALTER TABLE glovo.%s DISABLE TRIGGER USER`, tb),
			fmt.Sprintf(`DROP TABLE glovo.%s`, tb),
			fmt.Sprintf(`TRUNCATE glovo.%s`, tb),
			fmt.Sprintf(`CREATE TRIGGER x BEFORE INSERT ON glovo.%s FOR EACH ROW EXECUTE FUNCTION glovo.glovo_audit_immutable()`, tb),
		)
	}
	denied = append(denied,
		`DROP TRIGGER glovo_audit_events_immutable ON glovo.glovo_audit_events`,
		`DROP TRIGGER glovo_connections_no_delete ON glovo.glovo_connections`,
		`DROP FUNCTION glovo.glovo_audit_immutable() CASCADE`,
		`DROP SCHEMA glovo CASCADE`,
	)
	for _, stmt := range denied {
		_, err := e.pool.Exec(ctx, stmt)
		if err == nil {
			t.Errorf("runtime role could run %q", stmt)
			continue
		}
		if st := sqlState(err); st != "42501" && st != "23001" && st != "55000" {
			// DELETE/UPDATE with a trigger can also raise first on some paths; the
			// statement must still have failed, which it did
			t.Logf("%q: SQLSTATE %s: %v", stmt, st, err)
		}
	}
	// the hostile-GUC attempt on the connection and audit tables as the runtime role
	if _, err := e.pool.Exec(ctx, `DELETE FROM glovo.glovo_connections`); err == nil {
		t.Fatal("DELETE on glovo_connections succeeded")
	}
}

// TestOtherRolesHaveNoGlovoAccess: the work-items and commerce roles (any role
// that is not the runtime role) get permission denied on schema glovo.
func TestOtherRolesHaveNoGlovoAccess(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	other := "g959other_" + randHex(4)
	e.adminExec(fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s'`, other, testPassword))
	e.adminExec(fmt.Sprintf(`GRANT CONNECT ON DATABASE %s TO %s`, e.dbName, other))
	t.Cleanup(func() {
		c := e.adminConn()
		_, _ = c.Exec(ctx, fmt.Sprintf(`DROP OWNED BY %s`, other))
		_, _ = c.Exec(ctx, fmt.Sprintf(`DROP ROLE IF EXISTS %s`, other))
	})
	p, err := pgxpool.New(ctx, urlFor(t, adminURL(t), other, testPassword, e.dbName))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for _, tb := range []string{"glovo_installs", "glovo_connections", "glovo_connect_requests", "glovo_audit_events", "glovo_pilot_allowlist", "glovo_schema_version"} {
		_, err := p.Exec(ctx, fmt.Sprintf(`SELECT 1 FROM glovo.%s`, tb))
		if sqlState(err) != "42501" {
			t.Errorf("%s: want permission denied, got %v", tb, err)
		}
	}
}

type readyCase struct {
	name   string
	mutate string
	revert string
	reason string
}

// TestReadyNegativeMatrix: each mutation turns Ready red with its reason, and
// reverting it turns Ready green again.
func TestReadyNegativeMatrix(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	rt, mig := e.rt, e.mig
	if err := e.store.Ready(ctx); err != nil {
		t.Fatalf("green setup is not green: %v", err)
	}
	cases := []readyCase{
		{"extra TRIGGER", fmt.Sprintf(`GRANT TRIGGER ON glovo.glovo_connections TO %s`, rt), fmt.Sprintf(`REVOKE TRIGGER ON glovo.glovo_connections FROM %s`, rt), NotReadyGrants},
		{"extra TRUNCATE", fmt.Sprintf(`GRANT TRUNCATE ON glovo.glovo_audit_events TO %s`, rt), fmt.Sprintf(`REVOKE TRUNCATE ON glovo.glovo_audit_events FROM %s`, rt), NotReadyGrants},
		{"extra REFERENCES", fmt.Sprintf(`GRANT REFERENCES ON glovo.glovo_installs TO %s`, rt), fmt.Sprintf(`REVOKE REFERENCES ON glovo.glovo_installs FROM %s`, rt), NotReadyGrants},
		{"extra DELETE on connections", fmt.Sprintf(`GRANT DELETE ON glovo.glovo_connections TO %s`, rt), fmt.Sprintf(`REVOKE DELETE ON glovo.glovo_connections FROM %s`, rt), NotReadyGrants},
		{"extra UPDATE on audit", fmt.Sprintf(`GRANT UPDATE ON glovo.glovo_audit_events TO %s`, rt), fmt.Sprintf(`REVOKE UPDATE ON glovo.glovo_audit_events FROM %s`, rt), NotReadyGrants},
		{"column-level UPDATE on audit", fmt.Sprintf(`GRANT UPDATE (reason_code) ON glovo.glovo_audit_events TO %s`, rt), fmt.Sprintf(`REVOKE UPDATE (reason_code) ON glovo.glovo_audit_events FROM %s`, rt), NotReadyGrants},
		{"missing DELETE", fmt.Sprintf(`REVOKE DELETE ON glovo.glovo_pilot_allowlist FROM %s`, rt), fmt.Sprintf(`GRANT DELETE ON glovo.glovo_pilot_allowlist TO %s`, rt), NotReadyGrants},
		{"missing SELECT", fmt.Sprintf(`REVOKE SELECT ON glovo.glovo_schema_version FROM %s`, rt), fmt.Sprintf(`GRANT SELECT ON glovo.glovo_schema_version TO %s`, rt), NotReadyVersion},
		{"CREATE on schema", fmt.Sprintf(`GRANT CREATE ON SCHEMA glovo TO %s`, rt), fmt.Sprintf(`REVOKE CREATE ON SCHEMA glovo FROM %s`, rt), NotReadySchemaPrivileges},
		{"no USAGE on schema", fmt.Sprintf(`REVOKE USAGE ON SCHEMA glovo FROM %s`, rt), fmt.Sprintf(`GRANT USAGE ON SCHEMA glovo TO %s`, rt), NotReadyVersion},
		{"runtime owns a table", fmt.Sprintf(`ALTER TABLE glovo.glovo_pilot_allowlist OWNER TO %s`, rt),
			// an owner holds every right, so the revert also restores the registered grants
			fmt.Sprintf(`ALTER TABLE glovo.glovo_pilot_allowlist OWNER TO %s; REVOKE ALL ON TABLE glovo.glovo_pilot_allowlist FROM %s; GRANT SELECT, INSERT, DELETE ON TABLE glovo.glovo_pilot_allowlist TO %s`, mig, rt, rt), NotReadyOwner},
		{"runtime owns a function", fmt.Sprintf(`ALTER FUNCTION glovo.glovo_audit_immutable() OWNER TO %s`, rt), fmt.Sprintf(`ALTER FUNCTION glovo.glovo_audit_immutable() OWNER TO %s`, mig), NotReadyOwner},
		{"an object owned by a third role", "placeholder", fmt.Sprintf(`ALTER TABLE glovo.glovo_pilot_allowlist OWNER TO %s`, mig), NotReadyOwner},
		{"member of the owner role", fmt.Sprintf(`GRANT %s TO %s`, mig, rt), fmt.Sprintf(`REVOKE %s FROM %s`, mig, rt), NotReadyRoleOwner},
		{"rolsuper", fmt.Sprintf(`ALTER ROLE %s SUPERUSER`, rt), fmt.Sprintf(`ALTER ROLE %s NOSUPERUSER`, rt), NotReadyRolePrivileged},
		{"rolcreaterole", fmt.Sprintf(`ALTER ROLE %s CREATEROLE`, rt), fmt.Sprintf(`ALTER ROLE %s NOCREATEROLE`, rt), NotReadyRolePrivileged},
		{"rolcreatedb", fmt.Sprintf(`ALTER ROLE %s CREATEDB`, rt), fmt.Sprintf(`ALTER ROLE %s NOCREATEDB`, rt), NotReadyRolePrivileged},
		{"rolbypassrls", fmt.Sprintf(`ALTER ROLE %s BYPASSRLS`, rt), fmt.Sprintf(`ALTER ROLE %s NOBYPASSRLS`, rt), NotReadyRolePrivileged},
		{"audit trigger disabled", `ALTER TABLE glovo.glovo_audit_events DISABLE TRIGGER glovo_audit_events_immutable`, `ALTER TABLE glovo.glovo_audit_events ENABLE TRIGGER glovo_audit_events_immutable`, NotReadyTrigger},
		{"no-delete trigger disabled", `ALTER TABLE glovo.glovo_connections DISABLE TRIGGER glovo_connections_no_delete`, `ALTER TABLE glovo.glovo_connections ENABLE TRIGGER glovo_connections_no_delete`, NotReadyTrigger},
		{"audit trigger dropped", `DROP TRIGGER glovo_audit_events_no_truncate ON glovo.glovo_audit_events`, `CREATE TRIGGER glovo_audit_events_no_truncate BEFORE TRUNCATE ON glovo.glovo_audit_events FOR EACH STATEMENT EXECUTE FUNCTION glovo.glovo_audit_immutable()`, NotReadyTrigger},
		{"schema version mismatch", `UPDATE glovo.glovo_schema_version SET version = 99`, fmt.Sprintf(`UPDATE glovo.glovo_schema_version SET version = %d`, schemaVersion), NotReadyVersion},
		{"a glovo table with no registry row", fmt.Sprintf(`SET ROLE %s; CREATE TABLE glovo.glovo_rogue (a int); RESET ROLE`, mig), `DROP TABLE glovo.glovo_rogue`, NotReadyUnregistered},
	}
	// the third-role case needs a role that owns the object
	third := "g959third_" + randHex(4)
	e.adminExec(fmt.Sprintf(`CREATE ROLE %s`, third))
	t.Cleanup(func() {
		c := e.adminConn()
		_, _ = c.Exec(ctx, fmt.Sprintf(`DROP ROLE IF EXISTS %s`, third))
	})
	for i := range cases {
		if cases[i].name == "an object owned by a third role" {
			cases[i].mutate = fmt.Sprintf(`ALTER TABLE glovo.glovo_pilot_allowlist OWNER TO %s`, third)
		}
	}
	for _, c := range cases {
		e.adminExec(c.mutate)
		err := e.store.Ready(ctx)
		var nr *NotReadyError
		if !errors.As(err, &nr) || nr.Reason != c.reason || !errors.Is(err, &Error{Code: CodeNotReady}) {
			t.Errorf("%s: want not_ready/%s, got %v", c.name, c.reason, err)
		}
		e.adminExec(c.revert)
		if err := e.store.Ready(ctx); err != nil {
			t.Errorf("%s: after revert: %v", c.name, err)
		}
	}
}

func TestReadyOtherInputs(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	reason := func(err error) string {
		var nr *NotReadyError
		if errors.As(err, &nr) {
			return nr.Reason
		}
		return fmt.Sprint(err)
	}
	// no RevocationHook
	noHook, err := NewStore(ctx, e.pool, e.rt, e.mig, WithExplicitURL(true))
	if err != nil {
		t.Fatal(err)
	}
	if r := reason(noHook.Ready(ctx)); r != NotReadyHook {
		t.Fatal(r)
	}
	// the URL was not explicit (GLOVO_DB_URL unset, AUDIT_DB_URL set)
	noURL, err := NewStore(ctx, e.pool, e.rt, e.mig, WithExplicitURL(false), WithRevocationHook(e.hookSeen.hook))
	if err != nil {
		t.Fatal(err)
	}
	if r := reason(noURL.Ready(ctx)); r != NotReadyExplicitURL {
		t.Fatal(r)
	}
	// the default is not explicit either
	dflt, _ := NewStore(ctx, e.pool, e.rt, e.mig, WithRevocationHook(e.hookSeen.hook))
	if r := reason(dflt.Ready(ctx)); r != NotReadyExplicitURL {
		t.Fatal(r)
	}
	// current_user differs from the configured runtime role
	other, err := NewStore(ctx, e.pool, "someone_else", e.mig, WithExplicitURL(true), WithRevocationHook(e.hookSeen.hook))
	if err != nil {
		t.Fatal(err)
	}
	if r := reason(other.Ready(ctx)); r != NotReadyRoleMismatch {
		t.Fatal(r)
	}
	// the migration role named as the runtime role
	same, _ := NewStore(ctx, e.pool, e.rt, e.rt, WithExplicitURL(true), WithRevocationHook(e.hookSeen.hook))
	if r := reason(same.Ready(ctx)); r != NotReadyRoleOwner {
		t.Fatal(r)
	}
	// a pool connected as the migration role is refused as the runtime role
	mp := e.migPool()
	asOwner, err := NewStore(ctx, mp, e.mig, e.mig, WithExplicitURL(true), WithRevocationHook(e.hookSeen.hook))
	if err == nil && reason(asOwner.Ready(ctx)) == "<nil>" {
		t.Fatal("the owner passed as the runtime role")
	}
}

// TestReadyWithAnotherSlicesTable: a table of another slice that is present
// with its registered row leaves Ready green; without its row, or with an
// extra or missing right, it is not_ready.
func TestReadyWithAnotherSlicesTable(t *testing.T) {
	e := newEnv(t, WithEndPurgerRequired(true), WithEndPurger(func(context.Context, pgx.Tx, []string) error { return nil }))
	ctx := context.Background()
	// required table absent
	if r := e.store.Ready(ctx); r == nil || !strings.Contains(r.Error(), NotReadyTableMissing) {
		t.Fatalf("want table_missing, got %v", r)
	}
	mp := e.migPool()
	if _, err := mp.Exec(ctx, `CREATE TABLE glovo.glovo_handoff_refs (ref text PRIMARY KEY, consumed_at timestamptz)`); err != nil {
		t.Fatal(err)
	}
	if r := e.store.Ready(ctx); r == nil || !strings.Contains(r.Error(), NotReadyUnregistered) {
		t.Fatalf("no registry row: %v", r)
	}
	RegisterGrants(GrantRow{Table: "glovo_handoff_refs", Privileges: []string{"SELECT", "INSERT", "DELETE"}, UpdateColumns: nil, Description: "test row"})
	t.Cleanup(func() { unregisterGrant("glovo_handoff_refs") })
	// registered but not granted: missing rights
	if r := e.store.Ready(ctx); r == nil || !strings.Contains(r.Error(), NotReadyGrants) {
		t.Fatalf("missing rights: %v", r)
	}
	if _, err := mp.Exec(ctx, fmt.Sprintf(`GRANT SELECT, INSERT, DELETE ON glovo.glovo_handoff_refs TO %s`, e.rt)); err != nil {
		t.Fatal(err)
	}
	if r := e.store.Ready(ctx); r != nil {
		t.Fatalf("granted as registered: %v", r)
	}
	if _, err := mp.Exec(ctx, fmt.Sprintf(`GRANT UPDATE ON glovo.glovo_handoff_refs TO %s`, e.rt)); err != nil {
		t.Fatal(err)
	}
	if r := e.store.Ready(ctx); r == nil || !strings.Contains(r.Error(), NotReadyGrants) {
		t.Fatalf("extra right: %v", r)
	}
}

func unregisterGrant(table string) {
	grantsMu.Lock()
	defer grantsMu.Unlock()
	delete(expectedGrants, table)
}

func TestApplySchemaGrantsMatchRegistry(t *testing.T) {
	e := newEnv(t)
	c := e.adminConn()
	for _, tb := range slice959Tables {
		row, _ := grantFor(tb)
		for _, p := range knownPrivilegeList() {
			var has bool
			if err := c.QueryRow(context.Background(), fmt.Sprintf(`SELECT has_table_privilege($1, 'glovo.%s', $2)`, tb), e.rt, p).Scan(&has); err != nil {
				t.Fatal(err)
			}
			want := false
			for _, rp := range row.Privileges {
				want = want || rp == p
			}
			if has != want {
				t.Errorf("%s %s: has %v want %v", tb, p, has, want)
			}
		}
	}
}

func knownPrivilegeList() []string {
	return []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"}
}

func TestRawSQLChecks(t *testing.T) {
	e := newEnv(t)
	f := newFixture(t)
	ctx := context.Background()
	ia := e.install(f, f.Alpha)
	c := e.connect(f.A1, ia.InstallRevision, "k")
	for _, stmt := range []string{
		fmt.Sprintf(`UPDATE glovo.glovo_connections SET state = 'active', expires_at = NULL WHERE connection_id = '%s'`, c.ConnectionID),
		fmt.Sprintf(`UPDATE glovo.glovo_connections SET state = 'bogus' WHERE connection_id = '%s'`, c.ConnectionID),
		fmt.Sprintf(`UPDATE glovo.glovo_connections SET state = 'revoked', ended_at = NULL WHERE connection_id = '%s'`, c.ConnectionID),
		fmt.Sprintf(`UPDATE glovo.glovo_connections SET secret_ref = 'bad' WHERE connection_id = '%s'`, c.ConnectionID),
		fmt.Sprintf(`UPDATE glovo.glovo_installs SET state = 'bogus' WHERE install_id = '%s'`, ia.InstallID),
		`INSERT INTO glovo.glovo_installs (install_id, tenant_id, install_revision, state, installed_by, created_at, updated_at) VALUES ('gin_z', 't', 0, 'installed', 'prn_x', now(), now())`,
	} {
		if _, err := e.pool.Exec(ctx, stmt); err == nil {
			t.Errorf("accepted: %s", stmt)
		} else if sqlState(err) != "23514" {
			t.Errorf("%s: SQLSTATE %s, want a CHECK violation: %v", stmt, sqlState(err), err)
		}
	}
	// a second live connection for the owner is stopped by the partial unique index
	_, err := e.pool.Exec(ctx, `INSERT INTO glovo.glovo_connections (connection_id, tenant_id, principal_id, install_id, install_revision, state, created_at, updated_at)
 VALUES ('gcn_dup', $1, $2, $3, 1, 'pending_handoff', now(), now())`, f.Alpha, f.A1.PrincipalID, ia.InstallID)
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.ConstraintName != "glovo_connections_one_live" {
		t.Fatalf("%v", err)
	}
	// one install row per tenant
	if _, err := e.pool.Exec(ctx, `INSERT INTO glovo.glovo_installs (install_id, tenant_id, install_revision, state, installed_by, created_at, updated_at)
 VALUES ('gin_dup', $1, 1, 'installed', 'prn_x', now(), now())`, f.Alpha); err == nil {
		t.Fatal("two installs for one tenant")
	}
}
