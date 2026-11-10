package workitems

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const splitPassword = "pw-workitems-split-test" //nolint:gosec // throwaway password of roles in a per-test scratch database

// splitEnv is a scratch database with the three roles of the owner-confirmed
// model: a migration role that owns every object, the work-items role and the
// Glovo runtime role. Nothing is applied yet.
type splitEnv struct {
	t           *testing.T
	base, db    string
	mig, wi, rt string
	migURL      string
	wiURL       string
	rtURL       string
	extraRoles  []string
}

func splitAdminURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv("TEST_DATABASE_URL")
	if u == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL is unset in CI: the work-items split-role database tests must run, not skip")
		}
		t.Skip("TEST_DATABASE_URL not set")
	}
	return u
}

func splitHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func splitURL(t *testing.T, base, user, pass, db string) string {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(user, pass)
	u.Path = "/" + db
	return u.String()
}

func newSplitEnv(t *testing.T) *splitEnv {
	t.Helper()
	base := splitAdminURL(t)
	ctx := context.Background()
	sfx := splitHex(6)
	e := &splitEnv{t: t, base: base, db: "w989db_" + sfx, mig: "w989mig_" + sfx, wi: "w989wi_" + sfx, rt: "w989rt_" + sfx}
	root, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer func() { _ = root.Close(ctx) }()
	stmts := []string{}
	for _, r := range []string{e.mig, e.wi, e.rt} {
		stmts = append(stmts, fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`, r, splitPassword))
	}
	stmts = append(stmts,
		fmt.Sprintf(`CREATE DATABASE %s OWNER %s`, e.db, e.mig),
		fmt.Sprintf(`REVOKE ALL ON DATABASE %s FROM PUBLIC`, e.db),
		fmt.Sprintf(`GRANT CONNECT ON DATABASE %s TO %s, %s`, e.db, e.wi, e.rt))
	for _, s := range stmts {
		if _, err := root.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s, err)
		}
	}
	e.migURL = splitURL(t, base, e.mig, splitPassword, e.db)
	e.wiURL = splitURL(t, base, e.wi, splitPassword, e.db)
	e.rtURL = splitURL(t, base, e.rt, splitPassword, e.db)
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), base)
		if err != nil {
			return
		}
		defer func() { _ = c.Close(context.Background()) }()
		_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, e.db))
		for _, r := range append(e.extraRoles, e.rt, e.wi, e.mig) {
			_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP ROLE IF EXISTS %s`, r))
		}
	})
	return e
}

// applyGeneric runs the generic ApplySchema under the migration role.
func (e *splitEnv) applyGeneric() {
	e.t.Helper()
	if err := ApplySchema(context.Background(), e.migURL, e.wi); err != nil {
		e.t.Fatalf("ApplySchema: %v", err)
	}
}

func (e *splitEnv) conn(url string) *pgx.Conn {
	e.t.Helper()
	c, err := pgx.Connect(context.Background(), url)
	if err != nil {
		e.t.Fatalf("connect: %v", err)
	}
	e.t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

func (e *splitEnv) pool(url string) *pgxpool.Pool {
	e.t.Helper()
	p, err := pgxpool.New(context.Background(), url)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(p.Close)
	return p
}

// catalogDump renders owners, columns, constraints, indexes, triggers and
// table privileges of the generic relations, so two applies can be compared.
func (e *splitEnv) catalogDump(c *pgx.Conn) string {
	e.t.Helper()
	var out string
	for _, q := range []string{
		`SELECT c.relname || ':' || pg_get_userbyid(c.relowner) || ':' || coalesce(c.relacl::text,'') FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY 1`,
		`SELECT c.relname || '.' || a.attname || ' ' || format_type(a.atttypid,a.atttypmod) || ' ' || a.attnotnull::text || ' ' || coalesce(pg_get_expr(d.adbin,d.adrelid),'') FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE n.nspname='public' AND a.attnum>0 AND NOT a.attisdropped AND c.relkind='r' ORDER BY 1`,
		`SELECT conrelid::regclass::text || ':' || conname || ':' || pg_get_constraintdef(oid) || ':' || convalidated::text FROM pg_constraint WHERE connamespace='public'::regnamespace ORDER BY 1`,
		`SELECT indexdef FROM pg_indexes WHERE schemaname='public' ORDER BY 1`,
		`SELECT tgrelid::regclass::text || ':' || tgname || ':' || tgenabled::text FROM pg_trigger WHERE NOT tgisinternal ORDER BY 1`,
		`SELECT p.proname || ':' || pg_get_userbyid(p.proowner) || ':' || md5(p.prosrc) FROM pg_proc p WHERE pronamespace='public'::regnamespace ORDER BY 1`,
		`SELECT table_name || ':' || privilege_type || ':' || grantee FROM information_schema.role_table_grants WHERE table_schema='public' ORDER BY 1`,
	} {
		rows, err := c.Query(context.Background(), q)
		if err != nil {
			e.t.Fatalf("dump %q: %v", q, err)
		}
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				e.t.Fatal(err)
			}
			out += s + "\n"
		}
		rows.Close()
		out += "--\n"
	}
	return out
}
