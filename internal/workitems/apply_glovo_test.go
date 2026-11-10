package workitems

import (
	"context"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The object lists of the slice are held to the DDL text.
func TestGlovoApprovalObjectListsCoverTheDDL(t *testing.T) {
	tableRE := regexp.MustCompile(`(?m)^CREATE TABLE IF NOT EXISTS glovo\.(\w+)`)
	funcRE := regexp.MustCompile(`(?m)^CREATE OR REPLACE FUNCTION glovo\.(\w+)\(`)
	var tables, funcs []string
	for _, m := range tableRE.FindAllStringSubmatch(glovoApprovalTables, -1) {
		tables = append(tables, m[1])
	}
	for _, m := range funcRE.FindAllStringSubmatch(glovoApprovalFunctionsSQL, -1) {
		funcs = append(funcs, m[1])
	}
	slices.Sort(tables)
	slices.Sort(funcs)
	wt, wf := slices.Clone(glovoApprovalRelations), slices.Clone(glovoApprovalFunctions)
	slices.Sort(wt)
	slices.Sort(wf)
	if !slices.Equal(tables, wt) || !slices.Equal(funcs, wf) {
		t.Fatalf("object lists drifted: tables %v vs %v, functions %v vs %v", tables, wt, funcs, wf)
	}
}

func TestApplyGlovoApprovalSchemaTwiceAndForeignOwner(t *testing.T) {
	e := newSplitEnv(t)
	ctx := context.Background()
	apply := func() error { return ApplyGlovoApprovalSchema(ctx, e.migURL, e.rt, WithWorkItemsRole(e.wi)) }
	if err := apply(); err != nil {
		t.Fatal(err)
	}
	c := e.conn(e.migURL)
	dump := func() string {
		out := e.catalogDump(c)
		for _, q := range []string{
			`SELECT c.relname || ':' || pg_get_userbyid(c.relowner) || ':' || coalesce(c.relacl::text,'') FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='glovo' ORDER BY 1`,
			`SELECT p.proname || ':' || pg_get_userbyid(p.proowner) || ':' || md5(p.prosrc) FROM pg_proc p WHERE pronamespace='glovo'::regnamespace ORDER BY 1`,
			`SELECT tgrelid::regclass::text || ':' || tgname || ':' || tgenabled::text || ':' || tgtype::text FROM pg_trigger WHERE NOT tgisinternal AND tgname IN ('aar_guard','aar_binding_required','approval_bindings_guard') ORDER BY 1`,
			`SELECT attrelid::regclass::text || '.' || attname || ':' || coalesce(attacl::text,'') FROM pg_attribute WHERE attacl IS NOT NULL AND attrelid IN ('public.action_approval_requests'::regclass, 'glovo.approval_bindings'::regclass) ORDER BY 1`,
			`SELECT version::text FROM glovo.approval_schema_version`,
		} {
			rows, err := c.Query(ctx, q)
			if err != nil {
				t.Fatal(err)
			}
			for rows.Next() {
				var s string
				if err := rows.Scan(&s); err != nil {
					t.Fatal(err)
				}
				out += s + "\n"
			}
			rows.Close()
		}
		return out
	}
	first := dump()
	for _, rel := range glovoApprovalRelations {
		if !strings.Contains(first, rel+":"+e.mig+":") {
			t.Fatalf("glovo.%s is not owned by the migration role", rel)
		}
	}
	for _, fn := range glovoApprovalFunctions {
		if !strings.Contains(first, fn+":"+e.mig+":") {
			t.Fatalf("glovo.%s is not owned by the migration role", fn)
		}
	}
	for _, trg := range []string{"aar_guard", "aar_binding_required", "approval_bindings_guard"} {
		if !strings.Contains(first, ":"+trg+":O:") {
			t.Fatalf("trigger %s missing or not enabled", trg)
		}
	}
	if err := apply(); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if second := dump(); second != first {
		t.Fatalf("the second apply changed the catalog:\n--- first\n%s\n--- second\n%s", first, second)
	}
	// A trigger disabled by hand is re-enabled by the next apply.
	if _, err := c.Exec(ctx, `ALTER TABLE public.action_approval_requests DISABLE TRIGGER aar_guard`); err != nil {
		t.Fatal(err)
	}
	if err := apply(); err != nil {
		t.Fatal(err)
	}
	if got := dump(); got != first {
		t.Fatalf("apply did not restore the disabled trigger:\n%s", got)
	}

	// A different runtime role is written into the guard and the grants.
	if err := ApplyGlovoApprovalSchema(ctx, e.migURL, e.wi, WithWorkItemsRole(e.wi)); err == nil {
		t.Fatal("the runtime role may not be the work-items role")
	}
	if err := ApplyGlovoApprovalSchema(ctx, e.migURL, "Bad-Role"); err == nil {
		t.Fatal("an invalid role name was accepted")
	}

	// An object owned by another role is refused: a foreign owner of the bindings table.
	root := e.conn(strings.Replace(e.base, "/postgres?", "/"+e.db+"?", 1))
	if _, err := root.Exec(ctx, `ALTER TABLE glovo.approval_bindings OWNER TO `+e.rt); err != nil {
		t.Fatal(err)
	}
	if err := apply(); err == nil || !strings.Contains(err.Error(), "not owned by the migration role") {
		t.Fatalf("foreign-owned binding table: %v", err)
	}
	if _, err := root.Exec(ctx, `ALTER TABLE glovo.approval_bindings OWNER TO `+e.mig); err != nil {
		t.Fatal(err)
	}
	if _, err := root.Exec(ctx, `ALTER FUNCTION glovo.aar_guard() OWNER TO `+e.rt); err != nil {
		t.Fatal(err)
	}
	if err := apply(); err == nil || !strings.Contains(err.Error(), "not owned by the migration role") {
		t.Fatalf("foreign-owned guard function: %v", err)
	}
	if _, err := root.Exec(ctx, `ALTER FUNCTION glovo.aar_guard() OWNER TO `+e.mig); err != nil {
		t.Fatal(err)
	}
	// The generic action approval table owned by the runtime role (the state before the ownership move) is refused.
	if _, err := root.Exec(ctx, `ALTER TABLE public.action_approval_requests OWNER TO `+e.rt); err != nil {
		t.Fatal(err)
	}
	if err := apply(); err == nil {
		t.Fatal("a runtime-owned action_approval_requests was accepted")
	}
	if _, err := root.Exec(ctx, `ALTER TABLE public.action_approval_requests OWNER TO `+e.mig); err != nil {
		t.Fatal(err)
	}
	// A recorded version above the compiled one is refused.
	if _, err := c.Exec(ctx, `UPDATE glovo.approval_schema_version SET version = 99`); err != nil {
		t.Fatal(err)
	}
	if err := apply(); err == nil || !strings.Contains(err.Error(), "above the compiled version") {
		t.Fatalf("higher version: %v", err)
	}
	if _, err := c.Exec(ctx, `UPDATE glovo.approval_schema_version SET version = 1`); err != nil {
		t.Fatal(err)
	}
	if err := apply(); err != nil {
		t.Fatalf("apply after repairs: %v", err)
	}
}

// The widened state CHECK is replaced once and the new CHECKs are validated.
func TestGlovoApprovalChecksAreValidated(t *testing.T) {
	e := newSplitEnv(t)
	if err := ApplyGlovoApprovalSchema(context.Background(), e.migURL, e.rt, WithWorkItemsRole(e.wi)); err != nil {
		t.Fatal(err)
	}
	c := e.conn(e.migURL)
	rows, err := c.Query(context.Background(), `SELECT conname, convalidated, pg_get_constraintdef(oid) FROM pg_constraint
		WHERE conrelid='public.action_approval_requests'::regclass AND contype='c' ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	found := map[string]string{}
	for rows.Next() {
		var n, def string
		var valid bool
		if err := rows.Scan(&n, &valid, &def); err != nil {
			t.Fatal(err)
		}
		if !valid {
			t.Errorf("constraint %s is not validated", n)
		}
		found[n] = def
	}
	for _, n := range []string{"action_approval_requests_state_check", "action_approval_requests_glovo_kind_chk", "action_approval_requests_glovo_states_chk"} {
		if _, ok := found[n]; !ok {
			t.Errorf("missing constraint %s", n)
		}
	}
	if d := found["action_approval_requests_state_check"]; !strings.Contains(d, "'reserved'") || !strings.Contains(d, "'unknown'") || !strings.Contains(d, "'in_flight'") {
		t.Errorf("state check not widened: %s", d)
	}
	// Generic rows cannot use the Glovo-only states, and Glovo rows cannot use the generic-only ones.
	for _, bad := range []string{
		`INSERT INTO public.action_approval_requests (id, execution_id, action_kind, target, args_digest, policy_rule_id, policy_version, idempotency_key, requested_by, intent_hash, state, expires_at, created_at, schema_version)
		 VALUES ('aar_g1','we_1','deploy.apply','t','d','r','1','k1','x','h','reserved',now(),now(),'v')`,
		`INSERT INTO public.action_approval_requests (id, execution_id, action_kind, target, args_digest, policy_rule_id, policy_version, idempotency_key, requested_by, intent_hash, state, expires_at, created_at, schema_version)
		 VALUES ('aar_g2','we_1','deploy.apply','t','d','r','1','k2','x','h','unknown',now(),now(),'v')`,
		`INSERT INTO public.action_approval_requests (id, execution_id, action_kind, target, args_digest, policy_rule_id, policy_version, idempotency_key, requested_by, intent_hash, state, expires_at, created_at, schema_version)
		 VALUES ('aar_g3','we_1','glovo.other','t','d','r','1','k3','x','h','pending',now(),now(),'v')`,
	} {
		if _, err := c.Exec(context.Background(), bad); err == nil {
			t.Errorf("accepted: %s", bad)
		}
	}
}
