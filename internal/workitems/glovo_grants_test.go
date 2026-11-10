package workitems

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// T15e: the grants are pinned by literals in the test, not by the constants
// the DDL is generated from, so widening either side turns this red.
func TestAppliedGrantsAreExactlyTheDocumentedOnes(t *testing.T) {
	g := newGlovoEnv(t)
	ctx := context.Background()
	privs := func(role, table string) []string {
		var out []string
		for _, p := range []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"} {
			var has bool
			if err := g.rtp.QueryRow(ctx, `SELECT has_table_privilege($1, $2::regclass, $3)`, role, table, p).Scan(&has); err != nil {
				t.Fatal(err)
			}
			if has {
				out = append(out, p)
			}
		}
		return out
	}
	updCols := func(role, table string) string {
		rows, err := g.rtp.Query(ctx, `SELECT a.attname FROM pg_attribute a WHERE a.attrelid=$2::regclass AND a.attnum>0
			AND NOT a.attisdropped AND has_column_privilege($1, $2::regclass, a.attnum, 'UPDATE') ORDER BY 1`, role, table)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var cols []string
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				t.Fatal(err)
			}
			cols = append(cols, c)
		}
		return strings.Join(cols, ",")
	}

	t.Run("work-items role", func(t *testing.T) {
		want := map[string]string{
			"work_items": "SELECT,INSERT,UPDATE", "work_item_events": "SELECT,INSERT", "work_item_intents": "SELECT,INSERT",
			"work_item_executions": "SELECT,INSERT,UPDATE", "work_item_surface_refs": "SELECT,INSERT,UPDATE",
			"work_item_create_requests": "SELECT,INSERT", "work_item_requests": "SELECT,INSERT", "execution_provenance": "SELECT,INSERT",
			"work_item_context_snapshots": "SELECT,INSERT", "action_approval_requests": "SELECT,INSERT,UPDATE",
			"work_item_execution_requests": "SELECT,INSERT,UPDATE", "agent_run_tokens": "SELECT,INSERT,UPDATE,DELETE",
			"work_items_schema_version": "SELECT",
		}
		for table, w := range want {
			if got := strings.Join(privs(g.wi, "public."+table), ","); got != w {
				t.Errorf("%s: work-items role holds %q, want %q", table, got, w)
			}
		}
	})
	t.Run("glovo runtime role", func(t *testing.T) {
		wantTables := map[string]string{
			"public.action_approval_requests": "SELECT,INSERT", "glovo.approval_bindings": "SELECT,INSERT",
			"public.work_items": "SELECT,INSERT", "public.work_item_executions": "SELECT,INSERT", "public.work_item_events": "SELECT,INSERT",
		}
		for table, w := range wantTables {
			if got := strings.Join(privs(g.rt, table), ","); got != w {
				t.Errorf("%s: runtime role holds %q, want %q", table, got, w)
			}
		}
		wantCols := []string{"authority_basis", "authz_mode", "consumed_at", "decided_at", "decided_by", "decided_by_principal_id",
			"decided_context_digest", "decided_via_principal_id", "fresh_until", "reason", "reserved_at", "state"}
		sort.Strings(wantCols)
		if got := updCols(g.rt, "public.action_approval_requests"); !reflect.DeepEqual(strings.Split(got, ","), wantCols) {
			t.Errorf("runtime UPDATE columns on aar = %s, want %v", got, wantCols)
		}
		if got := updCols(g.rt, "glovo.approval_bindings"); got != "command_id" {
			t.Errorf("runtime UPDATE columns on bindings = %q, want command_id", got)
		}
	})
}

// The database, not only the store, refuses to spend an expired reservation.
func TestGuardRefusesConsumeAfterExpiry(t *testing.T) {
	g := newGlovoEnv(t)
	ctx := context.Background()
	f := g.prepare(t)
	g.decide(t, f, DecisionApprove)
	cmd := newCmdID(t)
	g.tx(t, func(tx pgx.Tx) {
		if _, err := g.store.ReserveGlovoApprovalTx(ctx, tx, f.aar, f.reserveCmd(cmd)); err != nil {
			t.Fatal(err)
		}
	})
	mp := g.pool(g.migURL)
	for _, q := range []string{`ALTER TABLE public.action_approval_requests DISABLE TRIGGER USER`,
		`UPDATE public.action_approval_requests SET fresh_until=clock_timestamp()+interval '1 second' WHERE id='` + f.aar + `'`,
		`ALTER TABLE public.action_approval_requests ENABLE TRIGGER USER`} {
		if _, err := mp.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := g.rtp.Exec(ctx, `SELECT pg_sleep(1.5)`); err != nil {
		t.Fatal(err)
	}
	_, err := g.rtp.Exec(ctx, `UPDATE public.action_approval_requests SET state='consumed', consumed_at=clock_timestamp() WHERE id=$1`, f.aar)
	if err == nil {
		t.Fatal("the guard let an expired reservation be consumed")
	}
	if st, _ := g.stored(t, f.aar); st != ApprovalReserved {
		t.Fatalf("state = %s, want reserved", st)
	}
}
