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

package glovojoin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/glovo"
)

const testPassword = "pw-join-test" //nolint:gosec // throwaway password of roles in a per-test scratch database

type env struct {
	t       *testing.T
	mig, rt string
	migURL  string
	rtURL   string
	mp, rp  *pgxpool.Pool
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
			t.Fatal("TEST_DATABASE_URL is unset in CI: the glovo join database tests must run, not skip")
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

// newEnvNoSchema creates a scratch database and the migration and runtime
// roles, and applies nothing.
func newEnvNoSchema(t *testing.T) *env {
	t.Helper()
	base := adminURL(t)
	ctx := context.Background()
	sfx := randHex(6)
	db, mig, rt := "j957db_"+sfx, "j957mig_"+sfx, "j957rt_"+sfx
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
	e := &env{t: t, mig: mig, rt: rt}
	e.migURL = urlFor(t, base, mig, testPassword, db)
	e.rtURL = urlFor(t, base, rt, testPassword, db)
	t.Cleanup(func() {
		if e.mp != nil {
			e.mp.Close()
		}
		if e.rp != nil {
			e.rp.Close()
		}
		c, err := pgx.Connect(context.Background(), base)
		if err != nil {
			return
		}
		defer func() { _ = c.Close(context.Background()) }()
		_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, db))
		_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP ROLE IF EXISTS %s`, rt))
		_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP ROLE IF EXISTS %s`, mig))
	})
	var err2 error
	if e.mp, err2 = smallPool(ctx, e.migURL); err2 != nil {
		t.Fatal(err2)
	}
	if e.rp, err2 = smallPool(ctx, e.rtURL); err2 != nil {
		t.Fatal(err2)
	}
	return e
}

// smallPool opens a pool of at most two connections: the CI Postgres has a low
// max_connections and these tests build many databases.
func smallPool(ctx context.Context, u string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(u)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = 2
	return pgxpool.NewWithConfig(ctx, cfg)
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := newEnvNoSchema(t)
	if err := ApplySchema(context.Background(), e.migURL, e.rt); err != nil {
		t.Fatalf("ApplySchema: %v", err)
	}
	return e
}

func digestOf(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

func mustExec(t *testing.T, p *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := p.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

const (
	orderRefA = "ordr_0123456789abcdef0123456789"
	orderRefB = "ordr_abcdef0123456789abcdef0123"
)

func workflowID(orderRef string) string { return "asst-glovo-tnr_x-prr_x-gin_x-" + orderRef }

// insertStart inserts a pending control_starts row as the runtime role.
func (e *env) insertStart(orderRef string) {
	e.t.Helper()
	input := []byte(`{"schema_version":"v1alpha1"}`)
	mustExec(e.t, e.rp, `INSERT INTO glovo.control_starts (order_ref, workflow_id, input, input_digest, next_attempt_at, created_at, updated_at)
 VALUES ($1, $2, $3, $4, now(), now(), now())`, orderRef, workflowID(orderRef), input, digestOf(input))
}

func TestApplySchemaTwice(t *testing.T) {
	e := newEnv(t)
	if err := ApplySchema(context.Background(), e.migURL, e.rt); err != nil {
		t.Fatalf("second ApplySchema: %v", err)
	}
	var n int
	if err := e.rp.QueryRow(context.Background(), `SELECT count(*) FROM glovo.join_schema_version`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("version rows = %d, %v", n, err)
	}
}

func TestApplySchemaFailsAsRuntimeRole(t *testing.T) {
	e := newEnvNoSchema(t)
	if err := ApplySchema(context.Background(), e.rtURL, e.rt); err == nil {
		t.Fatal("ApplySchema succeeded under the runtime role")
	}
	var have bool
	if err := e.mp.QueryRow(context.Background(), `SELECT to_regclass('glovo.control_starts') IS NOT NULL`).Scan(&have); err != nil || have {
		t.Fatalf("a table exists after a refused ApplySchema: %v %v", have, err)
	}
}

func TestApplySchemaRejectsBadRoleName(t *testing.T) {
	e := newEnvNoSchema(t)
	for _, r := range []string{"", "Glovo", "glovo runtime", "x;drop", strings.Repeat("a", 64)} {
		if err := ApplySchema(context.Background(), e.migURL, r); err == nil {
			t.Errorf("role %q accepted", r)
		}
	}
}

func TestApplySchemaRefusesForeignOwner(t *testing.T) {
	e := newEnvNoSchema(t)
	ctx := context.Background()
	mustExec(t, e.mp, `CREATE SCHEMA glovo`)
	su, err := url.Parse(adminURL(t))
	if err != nil {
		t.Fatal(err)
	}
	mu, _ := url.Parse(e.migURL)
	su.Path = mu.Path
	root, err := pgx.Connect(ctx, su.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close(ctx) }()
	for _, s := range []string{`CREATE TABLE glovo.control_starts (x int)`, `ALTER TABLE glovo.control_starts OWNER TO ` + e.rt} {
		if _, err := root.Exec(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	if err := ApplySchema(ctx, e.migURL, e.rt); err == nil || !strings.Contains(err.Error(), "not owned by the migration role") {
		t.Fatalf("ApplySchema with a foreign-owned table = %v", err)
	}
}

func TestApplySchemaRefusesDowngrade(t *testing.T) {
	e := newEnv(t)
	mustExec(t, e.mp, `UPDATE glovo.join_schema_version SET version = 99`)
	if err := ApplySchema(context.Background(), e.migURL, e.rt); err == nil {
		t.Fatal("ApplySchema accepted a newer recorded version")
	}
}

// TestGrantsAreExactlyTheRegisteredRows reads the effective privileges of the
// runtime role from the catalog and compares them with the registry, which is
// the Go copy of the design 6d.1 rows. Nothing beyond a registered right may
// exist, at table or column level, and the role cannot create in the schema.
func TestGrantsAreExactlyTheRegisteredRows(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	privs := []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"}
	for _, table := range joinTables {
		row, ok := glovo.GrantFor(table)
		if !ok {
			t.Fatalf("%s has no registered grant row", table)
		}
		want := map[string]bool{}
		for _, p := range row.Privileges {
			want[p] = true
		}
		for _, p := range privs {
			var got bool
			if err := e.rp.QueryRow(ctx, `SELECT has_table_privilege(current_user, $1, $2)`, "glovo."+table, p).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != want[p] {
				t.Errorf("%s %s: granted=%v, registered=%v", table, p, got, want[p])
			}
		}
		cols, err := e.rp.Query(ctx, `SELECT attname FROM pg_attribute WHERE attrelid = $1::regclass AND attnum > 0 AND NOT attisdropped ORDER BY attnum`, "glovo."+table)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for cols.Next() {
			var n string
			if err := cols.Scan(&n); err != nil {
				t.Fatal(err)
			}
			names = append(names, n)
		}
		cols.Close()
		wantCols := map[string]bool{}
		for _, c := range row.UpdateColumns {
			wantCols[c] = true
		}
		var granted []string
		for _, c := range names {
			var got bool
			// has_column_privilege is true for a table-level UPDATE too, so a
			// registered table-level UPDATE is excluded above by want["UPDATE"].
			if err := e.rp.QueryRow(ctx, `SELECT has_column_privilege(current_user, $1, $2, 'UPDATE')`, "glovo."+table, c).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got {
				granted = append(granted, c)
			}
		}
		if want["UPDATE"] {
			continue
		}
		sort.Strings(granted)
		if strings.Join(granted, ",") != strings.Join(row.UpdateColumns, ",") {
			t.Errorf("%s UPDATE columns = %v, registered %v", table, granted, row.UpdateColumns)
		}
	}
	var create, usage bool
	if err := e.rp.QueryRow(ctx, `SELECT has_schema_privilege(current_user, 'glovo', 'CREATE'), has_schema_privilege(current_user, 'glovo', 'USAGE')`).Scan(&create, &usage); err != nil {
		t.Fatal(err)
	}
	if create || !usage {
		t.Errorf("schema glovo: CREATE=%v USAGE=%v, want false and true", create, usage)
	}
	var owned int
	if err := e.rp.QueryRow(ctx, `SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'glovo' AND pg_get_userbyid(c.relowner) = current_user`).Scan(&owned); err != nil || owned != 0 {
		t.Errorf("the runtime role owns %d relations: %v", owned, err)
	}
}

// TestRegisteredGrantRows pins the registry to the design 6d.1 table.
func TestRegisteredGrantRows(t *testing.T) {
	want := map[string]string{
		"join_previews":       "DELETE,INSERT,SELECT UPDATE(consumed_order_ref)",
		"join_scope_refs":     "DELETE,INSERT,SELECT",
		"join_read_refs":      "DELETE,INSERT,SELECT",
		"control_starts":      "INSERT,SELECT UPDATE(attempts,next_attempt_at,started_run_id,state,updated_at)",
		"join_schema_version": "SELECT",
	}
	if len(joinTables) != len(want) {
		t.Fatalf("%d tables, want %d", len(joinTables), len(want))
	}
	for _, table := range joinTables {
		row, ok := glovo.GrantFor(table)
		if !ok {
			t.Fatalf("%s has no grant row", table)
		}
		got := strings.Join(row.Privileges, ",")
		if len(row.UpdateColumns) > 0 {
			got += " UPDATE(" + strings.Join(row.UpdateColumns, ",") + ")"
		}
		if got != want[table] {
			t.Errorf("%s: %s, want %s", table, got, want[table])
		}
	}
}

// TestControlStartInputIsInsertOnly proves the runtime role cannot rewrite the
// stored workflow input or its digest, while the dispatcher columns update.
func TestControlStartInputIsInsertOnly(t *testing.T) {
	e := newEnv(t)
	e.insertStart(orderRefA)
	for _, col := range []string{"input", "input_digest", "workflow_id", "order_ref"} {
		_, err := e.rp.Exec(context.Background(), fmt.Sprintf(`UPDATE glovo.control_starts SET %s = %s WHERE order_ref = $1`, col, col), orderRefA)
		if err == nil {
			t.Errorf("the runtime role updated %s", col)
		}
	}
	mustExec(t, e.rp, `UPDATE glovo.control_starts SET state = 'started', started_run_id = 'run-1', attempts = 1, updated_at = now() WHERE order_ref = $1`, orderRefA)
	if _, err := e.rp.Exec(context.Background(), `DELETE FROM glovo.control_starts`); err == nil {
		t.Error("the runtime role deleted a control start")
	}
}

func TestControlStartConstraints(t *testing.T) {
	e := newEnv(t)
	good := []byte(`{"a":1}`)
	cases := []struct{ name, sql string }{
		{"digest mismatch", `INSERT INTO glovo.control_starts (order_ref, workflow_id, input, input_digest, next_attempt_at, created_at, updated_at) VALUES ('` + orderRefA + `', '` + workflowID(orderRefA) + `', '\x7b7d', 'sha256:` + strings.Repeat("0", 64) + `', now(), now(), now())`},
		{"workflow id of another order", `INSERT INTO glovo.control_starts (order_ref, workflow_id, input, input_digest, next_attempt_at, created_at, updated_at) VALUES ('` + orderRefA + `', '` + workflowID(orderRefB) + `', '\x7b7d', '` + digestOf([]byte("{}")) + `', now(), now(), now())`},
		{"started without a run id", `INSERT INTO glovo.control_starts (order_ref, workflow_id, input, input_digest, state, next_attempt_at, created_at, updated_at) VALUES ('` + orderRefA + `', '` + workflowID(orderRefA) + `', '\x7b7d', '` + digestOf([]byte("{}")) + `', 'started', now(), now(), now())`},
		{"pending with a run id", `INSERT INTO glovo.control_starts (order_ref, workflow_id, input, input_digest, started_run_id, next_attempt_at, created_at, updated_at) VALUES ('` + orderRefA + `', '` + workflowID(orderRefA) + `', '\x7b7d', '` + digestOf([]byte("{}")) + `', 'run-1', now(), now(), now())`},
		{"bad state", `INSERT INTO glovo.control_starts (order_ref, workflow_id, input, input_digest, state, next_attempt_at, created_at, updated_at) VALUES ('` + orderRefA + `', '` + workflowID(orderRefA) + `', '\x7b7d', '` + digestOf([]byte("{}")) + `', 'done', now(), now(), now())`},
		{"bad order ref", `INSERT INTO glovo.control_starts (order_ref, workflow_id, input, input_digest, next_attempt_at, created_at, updated_at) VALUES ('pord_x', 'asst-glovo-pord_x', '\x7b7d', '` + digestOf([]byte("{}")) + `', now(), now(), now())`},
	}
	for _, c := range cases {
		if _, err := e.rp.Exec(context.Background(), c.sql); err == nil {
			t.Errorf("%s: the insert was accepted", c.name)
		}
	}
	mustExec(t, e.rp, `INSERT INTO glovo.control_starts (order_ref, workflow_id, input, input_digest, next_attempt_at, created_at, updated_at) VALUES ($1, $2, $3, $4, now(), now(), now())`, orderRefA, workflowID(orderRefA), good, digestOf(good))
	// a second row for the same order, and a second order with the same workflow id
	if _, err := e.rp.Exec(context.Background(), `INSERT INTO glovo.control_starts (order_ref, workflow_id, input, input_digest, next_attempt_at, created_at, updated_at) VALUES ($1, $2, $3, $4, now(), now(), now())`, orderRefA, workflowID(orderRefA)+"x", good, digestOf(good)); err == nil {
		t.Error("two control starts for one order")
	}
}

// TestPreviewSingleUseClaim pins the single-use claim of design 5 / 6 step 4b:
// the partial unique index and the WHERE consumed_order_ref IS NULL claim.
func TestPreviewSingleUseClaim(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	basket := []byte(`{"v":"x"}`)
	for _, id := range []string{"gpv_" + randHex(11), "gpv_" + randHex(11)} {
		mustExec(t, e.rp, `INSERT INTO glovo.join_previews (id, tenant, principal_id, connection_id, install_id, install_revision, approval_basket, fingerprint, payload_hash, created_at, expires_at)
 VALUES ($1, 't', 'prn_a', 'gcn_a', 'gin_a', 1, $2, $3, 'h', now(), now() + interval '10 minutes')`, id, basket, digestOf(basket))
	}
	var ids []string
	rows, err := e.rp.Query(ctx, `SELECT id FROM glovo.join_previews ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	claim := func(id, ordr string) (int64, error) {
		tag, err := e.rp.Exec(ctx, `UPDATE glovo.join_previews SET consumed_order_ref = $2 WHERE id = $1 AND consumed_order_ref IS NULL`, id, ordr)
		return tag.RowsAffected(), err
	}
	if n, err := claim(ids[0], orderRefA); n != 1 || err != nil {
		t.Fatalf("first claim = %d, %v", n, err)
	}
	if n, err := claim(ids[0], orderRefB); n != 0 || err != nil {
		t.Fatalf("second claim on one preview = %d, %v", n, err)
	}
	if _, err := claim(ids[1], orderRefA); err == nil {
		t.Fatal("one order consumed two previews")
	}
	// the runtime role may update only the claim column
	if _, err := e.rp.Exec(ctx, `UPDATE glovo.join_previews SET approval_basket = '\x00' WHERE id = $1`, ids[1]); err == nil {
		t.Error("the runtime role updated approval_basket")
	}
	// the fingerprint must match the stored bytes, and an empty preview has none
	if _, err := e.rp.Exec(ctx, `INSERT INTO glovo.join_previews (id, tenant, principal_id, connection_id, install_id, install_revision, approval_basket, fingerprint, payload_hash, created_at, expires_at)
 VALUES ($1, 't', 'p', 'c', 'i', 1, $2, 'sha256:`+strings.Repeat("1", 64)+`', 'h', now(), now() + interval '1 minute')`, "gpv_"+randHex(11), basket); err == nil {
		t.Error("a preview with a wrong fingerprint was accepted")
	}
	mustExec(t, e.rp, `INSERT INTO glovo.join_previews (id, tenant, principal_id, connection_id, install_id, install_revision, payload_hash, created_at, expires_at)
 VALUES ($1, 't', 'p', 'c', 'i', 1, 'h', now(), now() + interval '1 minute')`, "gpv_"+randHex(11))
	// the 15 minute bound
	if _, err := e.rp.Exec(ctx, `INSERT INTO glovo.join_previews (id, tenant, principal_id, connection_id, install_id, install_revision, payload_hash, created_at, expires_at)
 VALUES ($1, 't', 'p', 'c', 'i', 1, 'h', now(), now() + interval '16 minutes')`, "gpv_"+randHex(11)); err == nil {
		t.Error("a preview that lives longer than 15 minutes was accepted")
	}
}

func TestScopeAndReadRefTables(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	h := digestOf([]byte("ref"))[len("sha256:"):]
	mustExec(t, e.rp, `INSERT INTO glovo.join_scope_refs (ref_hash, principal_id, tenant, install_id, install_revision, grant_family_id, created_at, expires_at) VALUES ($1, 'prn_a', 't', 'gin_a', 1, 'fam', now(), now() + interval '5 minutes')`, h)
	if _, err := e.rp.Exec(ctx, `INSERT INTO glovo.join_scope_refs (ref_hash, principal_id, tenant, install_id, install_revision, grant_family_id, created_at, expires_at) VALUES ('gsc_plaintext', 'prn_a', 't', 'gin_a', 1, 'fam', now(), now() + interval '1 minute')`); err == nil {
		t.Error("a non-hash value was accepted as a ref hash")
	}
	if _, err := e.rp.Exec(ctx, `INSERT INTO glovo.join_scope_refs (ref_hash, principal_id, tenant, install_id, install_revision, grant_family_id, created_at, expires_at) VALUES ($1, 'prn_a', 't', 'gin_a', 1, 'fam', now(), now() + interval '6 minutes')`, digestOf([]byte("other"))[7:]); err == nil {
		t.Error("a scope ref that lives longer than 5 minutes was accepted")
	}
	ins := `INSERT INTO glovo.join_read_refs (tenant, principal_id, connection_id, kind, ref, created_at, expires_at) VALUES ('t', 'p', 'c', $1, $2, now(), now() + interval '1 hour') ON CONFLICT DO NOTHING`
	mustExec(t, e.rp, ins, "pho", "pho_1")
	mustExec(t, e.rp, ins, "pho", "pho_1")
	if _, err := e.rp.Exec(ctx, ins, "token", "x"); err == nil {
		t.Error("an unknown read ref kind was accepted")
	}
	var n int
	if err := e.rp.QueryRow(ctx, `SELECT count(*) FROM glovo.join_read_refs`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("read refs = %d, %v", n, err)
	}
	// bounded expiry sweeps are DELETE rights; refs of the table never carry a payload column
	mustExec(t, e.rp, `DELETE FROM glovo.join_read_refs WHERE expires_at < now()`)
}

// TestPreviewNullBasketHasNoFingerprint: sha256(NULL) is NULL, so a CHECK
// that only compares the fingerprint accepts a NULL basket with any
// fingerprint (a CHECK that evaluates to NULL passes). An empty preview has
// no basket and no fingerprint, and nothing else.
func TestPreviewNullBasketHasNoFingerprint(t *testing.T) {
	e := newEnv(t)
	ins := `INSERT INTO glovo.join_previews (id, tenant, principal_id, connection_id, install_id, install_revision, approval_basket, fingerprint, payload_hash, created_at, expires_at)
 VALUES ($1, 't', 'p', 'c', 'i', 1, $2, $3, 'h', now(), now() + interval '1 minute')`
	if _, err := e.rp.Exec(context.Background(), ins, "gpv_"+randHex(11), nil, "sha256:"+strings.Repeat("1", 64)); err == nil {
		t.Fatal("a NULL basket with a fingerprint was accepted")
	}
	if _, err := e.rp.Exec(context.Background(), ins, "gpv_"+randHex(11), nil, "x"); err == nil {
		t.Fatal("a NULL basket with a non-hash fingerprint was accepted")
	}
	mustExec(t, e.rp, ins, "gpv_"+randHex(11), nil, "")
}

// TestCheckColumnsAreNotNull sweeps the NULL class: a CHECK over a nullable
// column evaluates to NULL for a NULL operand and the row is accepted. Every
// column a CHECK of these tables reads is NOT NULL, except the two that are
// nullable by design and whose checks are written for NULL on purpose.
func TestCheckColumnsAreNotNull(t *testing.T) {
	e := newEnv(t)
	rows, err := e.rp.Query(context.Background(), `
SELECT DISTINCT c.relname || '.' || a.attname
  FROM pg_constraint k
  JOIN pg_class c ON c.oid = k.conrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'glovo'
  JOIN LATERAL unnest(k.conkey) AS col(attnum) ON true
  JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = col.attnum
 WHERE k.contype = 'c' AND c.relname = ANY($1) AND NOT a.attnotnull
 ORDER BY 1`, joinTables)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	deliberate := map[string]bool{
		"join_previews.approval_basket":    true, // NULL is the empty preview; paired with fingerprint = ''
		"join_previews.consumed_order_ref": true, // NULL is the unclaimed preview
	}
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			t.Fatal(err)
		}
		if !deliberate[col] {
			t.Errorf("a CHECK reads the nullable column %s: a NULL operand makes it pass", col)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

// TestPreviewClaimIsWriteOnce: the runtime role holds UPDATE on
// consumed_order_ref, so the database itself must refuse to clear or rewrite
// a set claim; otherwise a consumed preview could be claimed again.
func TestPreviewClaimIsWriteOnce(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	id := "gpv_" + randHex(11)
	mustExec(t, e.rp, `INSERT INTO glovo.join_previews (id, tenant, principal_id, connection_id, install_id, install_revision, payload_hash, created_at, expires_at)
 VALUES ($1, 't', 'p', 'c', 'i', 1, 'h', now(), now() + interval '1 minute')`, id)
	mustExec(t, e.rp, `UPDATE glovo.join_previews SET consumed_order_ref = $2 WHERE id = $1`, id, orderRefA)
	for name, sql := range map[string]string{
		"cleared":   `UPDATE glovo.join_previews SET consumed_order_ref = NULL WHERE id = $1`,
		"rewritten": `UPDATE glovo.join_previews SET consumed_order_ref = '` + orderRefB + `' WHERE id = $1`,
	} {
		if _, err := e.rp.Exec(ctx, sql, id); err == nil {
			t.Errorf("the claim was %s", name)
		}
	}
	// writing the same value again is a no-op, not a change
	mustExec(t, e.rp, `UPDATE glovo.join_previews SET consumed_order_ref = $2 WHERE id = $1`, id, orderRefA)
	var got string
	if err := e.rp.QueryRow(ctx, `SELECT consumed_order_ref FROM glovo.join_previews WHERE id = $1`, id).Scan(&got); err != nil || got != orderRefA {
		t.Fatalf("claim = %q, %v", got, err)
	}
}

// TestApplySchemaRevokesDriftedGrants: a re-run converges the grants back to
// the registered rows. An extra table-level right and an extra column right
// that someone granted by hand are removed.
func TestApplySchemaRevokesDriftedGrants(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	mustExec(t, e.mp, `GRANT DELETE ON glovo.control_starts TO `+e.rt)
	mustExec(t, e.mp, `GRANT UPDATE (input) ON glovo.control_starts TO `+e.rt)
	mustExec(t, e.mp, `GRANT TRUNCATE ON glovo.join_previews TO `+e.rt)
	var drifted bool
	if err := e.rp.QueryRow(ctx, `SELECT has_table_privilege(current_user, 'glovo.control_starts', 'DELETE') AND has_column_privilege(current_user, 'glovo.control_starts', 'input', 'UPDATE')`).Scan(&drifted); err != nil || !drifted {
		t.Fatalf("the drift was not set up: %v %v", drifted, err)
	}
	if err := ApplySchema(ctx, e.migURL, e.rt); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`SELECT has_table_privilege(current_user, 'glovo.control_starts', 'DELETE')`,
		`SELECT has_column_privilege(current_user, 'glovo.control_starts', 'input', 'UPDATE')`,
		`SELECT has_table_privilege(current_user, 'glovo.join_previews', 'TRUNCATE')`,
	} {
		var still bool
		if err := e.rp.QueryRow(ctx, q).Scan(&still); err != nil || still {
			t.Errorf("%s = %v, %v after a re-run", q, still, err)
		}
	}
}

// TestNoControlImport: go list -deps of this package lists no
// internal/glovo/control (the control package imports this one, never the
// reverse; #957 task A14, round 6 G3).
func TestNoControlImport(t *testing.T) {
	forbidden := "github.com/mctlhq/mctl-api/internal/glovo/control"
	out, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	deps := strings.Fields(string(out))
	if len(deps) < 10 {
		t.Fatalf("go list returned %d deps: the check would pass on nothing", len(deps))
	}
	for _, d := range deps {
		if d == forbidden || strings.HasPrefix(d, forbidden+"/") {
			t.Fatalf("internal/glovojoin depends on %s", d)
		}
	}
}

// TestApplySchemaWaitsForTheSchemaLocks: every slice writes schema glovo, so
// ApplySchema serializes against the #959 migrator (glovo-schema) and against
// itself (glovo-join-schema). It blocks while either lock is held elsewhere.
func TestApplySchemaWaitsForTheSchemaLocks(t *testing.T) {
	for _, key := range []string{"glovo-schema", "glovo-join-schema"} {
		t.Run(key, func(t *testing.T) {
			e := newEnvNoSchema(t)
			ctx := context.Background()
			holder, err := e.mp.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := holder.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, key); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- ApplySchema(ctx, e.migURL, e.rt) }()
			select {
			case err := <-done:
				_ = holder.Rollback(ctx)
				t.Fatalf("ApplySchema did not wait for %s: %v", key, err)
			case <-time.After(400 * time.Millisecond):
			}
			if err := holder.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("ApplySchema after the lock was released: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("ApplySchema did not finish after the lock was released")
			}
		})
	}
}
