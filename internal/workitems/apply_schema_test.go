package workitems

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestGenericRelationsCoverTheDDL holds the ownership list and the grant list
// to the DDL text of the block, so a new table cannot be left unowned or
// ungranted.
func TestGenericRelationsCoverTheDDL(t *testing.T) {
	tableRE := regexp.MustCompile(`(?m)^CREATE TABLE IF NOT EXISTS (\w+)`)
	funcRE := regexp.MustCompile(`(?m)^CREATE OR REPLACE FUNCTION (\w+)\(`)
	var tables, funcs []string
	for _, b := range genericSchemaBlocks {
		for _, m := range tableRE.FindAllStringSubmatch(b.sql, -1) {
			tables = append(tables, m[1])
		}
		for _, m := range funcRE.FindAllStringSubmatch(b.sql, -1) {
			funcs = append(funcs, m[1])
		}
	}
	tables = append(tables, "work_items_schema_version")
	slices.Sort(tables)
	want := slices.Clone(genericRelations)
	slices.Sort(want)
	if !slices.Equal(tables, want) {
		t.Fatalf("genericRelations drifted from the DDL:\n ddl  %v\n list %v", tables, want)
	}
	slices.Sort(funcs)
	wf := slices.Clone(genericFunctions)
	slices.Sort(wf)
	if !slices.Equal(funcs, wf) {
		t.Fatalf("genericFunctions drifted from the DDL:\n ddl  %v\n list %v", funcs, wf)
	}
	var granted []string
	for _, g := range genericGrants {
		granted = append(granted, g.Table)
	}
	slices.Sort(granted)
	if !slices.Equal(granted, want) {
		t.Fatalf("genericGrants must cover exactly the generic relations:\n grants %v\n list   %v", granted, want)
	}
}

// TestApplySchemaOnEmptyDatabaseAndTwice: the first apply creates everything
// under the migration role, the second changes nothing.
func TestApplySchemaOnEmptyDatabaseAndTwice(t *testing.T) {
	e := newSplitEnv(t)
	e.applyGeneric()
	c := e.conn(e.migURL)
	first := e.catalogDump(c)
	for _, rel := range genericRelations {
		if !strings.Contains(first, rel+":"+e.mig+":") {
			t.Fatalf("%s is not owned by the migration role:\n%s", rel, first)
		}
	}
	e.applyGeneric()
	if second := e.catalogDump(c); second != first {
		t.Fatalf("the second ApplySchema changed the catalog:\n--- first\n%s\n--- second\n%s", first, second)
	}
	var n int
	if err := c.QueryRow(context.Background(), `SELECT count(*) FROM public.work_items_schema_version`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("schema version rows = %d, %v", n, err)
	}
}

// TestApplySchemaRefusesAForeignOwner: a table that another role owns is
// refused, and left untouched.
func TestApplySchemaRefusesAForeignOwner(t *testing.T) {
	e := newSplitEnv(t)
	other := "w989other_" + splitHex(4)
	e.extraRoles = append(e.extraRoles, other)
	root := e.conn(e.base)
	for _, s := range []string{
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s'`, other, splitPassword),
		fmt.Sprintf(`GRANT CONNECT ON DATABASE %s TO %s`, e.db, other),
	} {
		if _, err := root.Exec(context.Background(), s); err != nil {
			t.Fatal(err)
		}
	}
	mig := e.conn(e.migURL)
	if _, err := mig.Exec(context.Background(), fmt.Sprintf(`GRANT CREATE ON SCHEMA public TO %s`, other)); err != nil {
		t.Fatal(err)
	}
	oc := e.conn(splitURL(t, e.base, other, splitPassword, e.db))
	if _, err := oc.Exec(context.Background(), `CREATE TABLE public.work_items (id TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	err := ApplySchema(context.Background(), e.migURL, e.wi, WithWorkItemsRole(e.wi))
	if err == nil || !strings.Contains(err.Error(), "not owned by the migration role") {
		t.Fatalf("ApplySchema over a foreign-owned table: %v", err)
	}
	var cols int
	if err := mig.QueryRow(context.Background(), `SELECT count(*) FROM pg_attribute WHERE attrelid='public.work_items'::regclass AND attnum>0 AND NOT attisdropped`).Scan(&cols); err != nil || cols != 1 {
		t.Fatalf("the foreign table was modified: %d columns, %v", cols, err)
	}
	var events bool
	if err := mig.QueryRow(context.Background(), `SELECT to_regclass('public.work_item_events') IS NOT NULL`).Scan(&events); err != nil || events {
		t.Fatalf("ApplySchema created a table before it refused: %v %v", events, err)
	}
}

// TestApplySchemaRefusesAHigherVersion: a downgrade is refused.
func TestApplySchemaRefusesAHigherVersion(t *testing.T) {
	e := newSplitEnv(t)
	e.applyGeneric()
	mig := e.conn(e.migURL)
	if _, err := mig.Exec(context.Background(), `UPDATE public.work_items_schema_version SET version = version + 1`); err != nil {
		t.Fatal(err)
	}
	if err := ApplySchema(context.Background(), e.migURL, e.wi, WithWorkItemsRole(e.wi)); err == nil || !strings.Contains(err.Error(), "above the compiled version") {
		t.Fatalf("ApplySchema with a newer recorded version: %v", err)
	}
}

// TestNewStoreSendsNoDDLWhenItDoesNotOwnTheTables: as the work-items role the
// store only verifies the version. With the old behaviour the first ALTER
// TABLE fails ("must be owner of table").
func TestNewStoreSendsNoDDLWhenItDoesNotOwnTheTables(t *testing.T) {
	e := newSplitEnv(t)
	e.applyGeneric()
	s, err := NewStore(context.Background(), e.wiURL)
	if err != nil {
		t.Fatalf("NewStore as the work-items role: %v", err)
	}
	s.Close()

	mig := e.conn(e.migURL)
	if _, err := mig.Exec(context.Background(), `UPDATE public.work_items_schema_version SET version = version + 1`); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(context.Background(), e.wiURL); err == nil || !strings.Contains(err.Error(), "schema version") {
		t.Fatalf("NewStore with a wrong recorded version must fail closed: %v", err)
	}
	if _, err := mig.Exec(context.Background(), `DROP TABLE public.work_items_schema_version`); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(context.Background(), e.wiURL); err == nil {
		t.Fatal("NewStore with no recorded version must fail closed")
	}
}

// TestGenericGrantsAreExact: the work-items role holds exactly genericGrants.
func TestGenericGrantsAreExact(t *testing.T) {
	e := newSplitEnv(t)
	e.applyGeneric()
	c := e.conn(e.migURL)
	want := map[string]map[string]bool{}
	for _, g := range genericGrants {
		want[g.Table] = map[string]bool{}
		for _, p := range g.Privileges {
			want[g.Table][p] = true
		}
	}
	for _, rel := range genericRelations {
		for _, p := range []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"} {
			var has bool
			if err := c.QueryRow(context.Background(), `SELECT has_table_privilege($1, $2, $3)`, e.wi, "public."+rel, p).Scan(&has); err != nil {
				t.Fatal(err)
			}
			if has != want[rel][p] {
				t.Errorf("work-items role %s on %s: have %v, want %v", p, rel, has, want[rel][p])
			}
		}
	}
}

// TestApplySchemaGrantsNothingWithoutAWorkItemsRole: as WithWorkItemsRole
// documents, without it ApplySchema issues no generic grants. runtimeRole used
// to stand in for the work-items role, so the runtime role received the full
// generic DML set it was never named for.
func TestApplySchemaGrantsNothingWithoutAWorkItemsRole(t *testing.T) {
	e := newSplitEnv(t)
	if err := ApplySchema(context.Background(), e.migURL, e.rt); err != nil {
		t.Fatalf("ApplySchema: %v", err)
	}
	mig := e.conn(e.migURL)
	for _, g := range genericGrants {
		for _, priv := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
			var has bool
			if err := mig.QueryRow(context.Background(), `SELECT has_table_privilege($1, $2, $3)`,
				e.rt, "public."+g.Table, priv).Scan(&has); err != nil {
				t.Fatal(err)
			}
			if has {
				t.Errorf("runtime role %s holds %s on %s without WithWorkItemsRole", e.rt, priv, g.Table)
			}
		}
	}
	var seq bool
	if err := mig.QueryRow(context.Background(), `SELECT has_sequence_privilege($1, 'public.work_item_intents_id_seq', 'USAGE')`, e.rt).Scan(&seq); err != nil {
		t.Fatal(err)
	}
	if seq {
		t.Errorf("runtime role %s holds USAGE on work_item_intents_id_seq without WithWorkItemsRole", e.rt)
	}
}
