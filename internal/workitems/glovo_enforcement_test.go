package workitems

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type rawStmt struct {
	sql  string
	args []any
}

// rawGlovoRow is a valid Glovo-kind INSERT; overrides replace single columns.
func rawGlovoRow(over map[string]any) rawStmt {
	m := map[string]any{
		"id": "aar_" + splitHex(16), "execution_id": "we_" + strings.Repeat("A", 26), "action_kind": "glovo.place_order_fake",
		"target": "glovo:v1:t", "args_digest": "sha256:" + strings.Repeat("ab", 32),
		"policy_rule_id": "glovo.order.owner-approval", "policy_version": "1",
		"artifact_hash": "sha256:" + strings.Repeat("ab", 32), "work_item_id": "wi_" + strings.Repeat("A", 26),
		"idempotency_key": "k-" + splitHex(8), "requested_by": "service:glovo-prepare", "intent_hash": "sha256:" + strings.Repeat("00", 32),
		"state": "pending", "expires_at": time.Now().Add(time.Hour), "created_at": time.Now(), "schema_version": ActionApprovalSchemaVersion,
		"subject_principal_id": testOwner, "intent_source": "execution:we_x", "policy_decision": "require_approval",
		"policy_reasons": []string{"glovo.order.owner-approval"},
	}
	for k, v := range over {
		m[k] = v
	}
	cols := make([]string, 0, len(m))
	for k := range m {
		cols = append(cols, k)
	}
	sort.Strings(cols)
	args := make([]any, len(cols))
	ph := make([]string, len(cols))
	for i, c := range cols {
		args[i] = m[c]
		ph[i] = fmt.Sprintf("$%d", i+1)
	}
	return rawStmt{`INSERT INTO public.action_approval_requests (` + strings.Join(cols, ",") + `) VALUES (` + strings.Join(ph, ",") + `)`, args}
}

// insertRawWithBinding inserts a raw row and a matching binding in one tx.
func (g *glovoEnv) insertRawWithBinding(ctx context.Context, tx pgx.Tx, over map[string]any) (string, error) {
	row := rawGlovoRow(over)
	id := row.args[indexOfCol(row.sql, "id")].(string)
	if _, err := tx.Exec(ctx, row.sql, row.args...); err != nil {
		return id, err
	}
	_, err := tx.Exec(ctx, `INSERT INTO glovo.approval_bindings (`+glovoBindingColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'',now())`,
		id, "acme", testOwner, rawVal(row, "execution_id"), rawVal(row, "work_item_id"), "ordr_"+splitHex(14), "gcn_"+strings.Repeat("B", 26),
		"install-1", "3", rawVal(row, "artifact_hash"), "fake")
	return id, err
}

func indexOfCol(sql, col string) int {
	start := strings.Index(sql, "(") + 1
	end := strings.Index(sql, ")")
	for i, c := range strings.Split(sql[start:end], ",") {
		if c == col {
			return i
		}
	}
	return -1
}

func rawVal(r rawStmt, col string) any { return r.args[indexOfCol(r.sql, col)] }

// T15: the database refuses, as the runtime role, every forbidden write.
func TestGlovoDatabaseEnforcement(t *testing.T) {
	g := newGlovoEnv(t)
	ctx := context.Background()

	refuse := func(name string, over map[string]any) {
		t.Run("insert/"+name, func(t *testing.T) {
			tx, err := g.rtp.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if _, err := g.insertRawWithBinding(ctx, tx, over); err == nil {
				// the deferred binding check can still refuse at commit
				if err := tx.Commit(ctx); err == nil {
					t.Fatal("the insert was accepted")
				}
			}
		})
	}
	// Control: a valid row with a binding commits.
	g.tx(t, func(tx pgx.Tx) {
		if _, err := g.insertRawWithBinding(ctx, tx, nil); err != nil {
			t.Fatalf("control insert: %v", err)
		}
	})
	for _, st := range []string{"approved", "reserved", "consumed", "unknown", "denied"} {
		refuse("state="+st, map[string]any{"state": st})
	}
	refuse("decided_by", map[string]any{"decided_by": "someone"})
	refuse("decided_by_principal_id", map[string]any{"decided_by_principal_id": testOwner})
	refuse("decided_via_principal_id", map[string]any{"decided_via_principal_id": testOwner})
	refuse("decided_context_digest", map[string]any{"decided_context_digest": "x"})
	refuse("authority_basis", map[string]any{"authority_basis": "resource_owner"})
	refuse("consumed_at", map[string]any{"consumed_at": time.Now()})
	refuse("reserved_at", map[string]any{"reserved_at": time.Now()})
	refuse("executed_at", map[string]any{"executed_at": time.Now()})
	refuse("requested_by", map[string]any{"requested_by": "service:other"})
	refuse("empty intent_source", map[string]any{"intent_source": ""})
	refuse("wrong policy_rule_id", map[string]any{"policy_rule_id": "other.rule"})
	refuse("wrong policy_version", map[string]any{"policy_version": "2"})
	refuse("empty policy_decision", map[string]any{"policy_decision": ""})
	refuse("empty policy_reasons", map[string]any{"policy_reasons": []string{}})
	refuse("empty artifact_hash", map[string]any{"artifact_hash": ""})
	refuse("malformed artifact_hash", map[string]any{"artifact_hash": "sha256:zz"})
	refuse("glovo.other", map[string]any{"action_kind": "glovo.other"})
	refuse("glovo.cancel_order_fake", map[string]any{"action_kind": "glovo.cancel_order_fake"})
	// A Glovo row committed without its binding.
	t.Run("insert/no binding", func(t *testing.T) {
		tx, err := g.rtp.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		row := rawGlovoRow(nil)
		if _, err := tx.Exec(ctx, row.sql, row.args...); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err == nil {
			t.Fatal("a Glovo approval committed without its binding")
		}
	})
	t.Run("insert/binding disagrees", func(t *testing.T) {
		tx, err := g.rtp.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		row := rawGlovoRow(nil)
		if _, err := tx.Exec(ctx, row.sql, row.args...); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO glovo.approval_bindings (`+glovoBindingColumns+`) VALUES ($1,'acme',$2,$3,$4,$5,$6,'i','3',$7,'fake','',now())`,
			rawVal(row, "id"), testOwner, rawVal(row, "execution_id"), rawVal(row, "work_item_id"), "ordr_"+splitHex(14),
			"gcn_"+strings.Repeat("B", 26), "sha256:"+strings.Repeat("cd", 32)); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err == nil {
			t.Fatal("a binding with another fingerprint committed")
		}
	})

	// Updates and deletes on a real, approved row.
	f := g.prepare(t)
	upd := func(name, set string, args ...any) {
		t.Run("update/"+name, func(t *testing.T) {
			tx, err := g.rtp.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			_, err = tx.Exec(ctx, `UPDATE public.action_approval_requests SET `+set+` WHERE id='`+f.aar+`'`, args...)
			if err == nil {
				t.Fatalf("`%s` was accepted", set)
			}
		})
	}
	// Immutable columns are outside the runtime role's column grant, so the
	// database refuses them as permission denied; the trigger refuses them for
	// any role that holds the column (the owner path is covered by the next test).
	for _, c := range []string{"action_kind='deploy.apply'", "intent_hash='sha256:x'", "expires_at=now()", "artifact_hash='x'",
		"execution_id='we_x'", "work_item_id='wi_x'", "subject_principal_id='prn_x'", "requested_by='x'",
		"policy_rule_id='x'", "policy_version='9'", "target='x'", "args_digest='x'"} {
		upd("immutable/"+c, c)
	}
	// pending -> approved by anyone but the owner, or under another basis.
	upd("approve/no owner", "state='approved', decided_by_principal_id='prn_OTHER', authority_basis='resource_owner', fresh_until=now()+interval '1 hour'")
	upd("approve/wrong basis", "state='approved', decided_by_principal_id='"+testOwner+"', authority_basis='platform_admin', fresh_until=now()+interval '1 hour'")
	upd("approve/no fresh", "state='approved', decided_by_principal_id='"+testOwner+"', authority_basis='resource_owner'")
	// skipping the machine
	upd("pending->reserved", "state='reserved', reserved_at=now()")
	upd("pending->consumed", "state='consumed', consumed_at=now()")
	upd("pending->unknown", "state='unknown'")
	upd("pending->in_flight", "state='in_flight'")
	upd("pending->executed", "state='executed'")
	t.Run("delete", func(t *testing.T) {
		if _, err := g.rtp.Exec(ctx, `DELETE FROM public.action_approval_requests WHERE id=$1`, f.aar); err == nil {
			t.Fatal("DELETE accepted")
		}
	})
	t.Run("alter table disable trigger", func(t *testing.T) {
		for _, s := range []string{
			`ALTER TABLE public.action_approval_requests DISABLE TRIGGER aar_guard`,
			`ALTER TABLE public.action_approval_requests DISABLE TRIGGER USER`,
			`ALTER TABLE glovo.approval_bindings DISABLE TRIGGER approval_bindings_guard`,
			`DROP TRIGGER aar_guard ON public.action_approval_requests`,
			`ALTER TABLE public.action_approval_requests DISABLE TRIGGER aar_binding_required`,
		} {
			if _, err := g.rtp.Exec(ctx, s); err == nil {
				t.Errorf("%s was accepted", s)
			}
		}
	})
	t.Run("binding updates", func(t *testing.T) {
		for _, s := range []string{
			`UPDATE glovo.approval_bindings SET tenant='x' WHERE approval_id='` + f.aar + `'`,
			`UPDATE glovo.approval_bindings SET order_ref='ordr_` + strings.Repeat("Z", 20) + `' WHERE approval_id='` + f.aar + `'`,
			`UPDATE glovo.approval_bindings SET basket_fingerprint='sha256:` + strings.Repeat("00", 32) + `' WHERE approval_id='` + f.aar + `'`,
			`UPDATE glovo.approval_bindings SET command_id='not-a-command' WHERE approval_id='` + f.aar + `'`,
			`DELETE FROM glovo.approval_bindings WHERE approval_id='` + f.aar + `'`,
		} {
			if _, err := g.rtp.Exec(ctx, s); err == nil {
				t.Errorf("%s was accepted", s)
			}
		}
		// The first command_id write is the only one allowed.
		cmd := newCmdID(t)
		if _, err := g.rtp.Exec(ctx, `UPDATE glovo.approval_bindings SET command_id=$2 WHERE approval_id=$1`, f.aar, cmd); err != nil {
			t.Fatalf("first command_id write: %v", err)
		}
		if _, err := g.rtp.Exec(ctx, `UPDATE glovo.approval_bindings SET command_id=$2 WHERE approval_id=$1`, f.aar, newCmdID(t)); err == nil {
			t.Error("a second command_id write was accepted")
		}
		if _, err := g.rtp.Exec(ctx, `UPDATE glovo.approval_bindings SET command_id='' WHERE approval_id=$1`, f.aar); err == nil {
			t.Error("clearing command_id was accepted")
		}
	})
}

// The trigger is the second wall: the table owner holds every column, so the
// trigger alone must refuse what the column grant refuses the runtime role.
func TestGlovoGuardRefusesTheOwnerRoleToo(t *testing.T) {
	g := newGlovoEnv(t)
	ctx := context.Background()
	f := g.prepare(t)
	c := g.conn(g.migURL)
	for _, set := range []string{
		"action_kind='deploy.apply'", "intent_hash='sha256:x'", "expires_at=now()", "artifact_hash='x'", "execution_id='we_x'",
		"work_item_id='wi_x'", "subject_principal_id='prn_x'", "requested_by='x'", "policy_rule_id='x'", "policy_version='9'",
		"state='approved'", "state='reserved'", "state='consumed'",
	} {
		if _, err := c.Exec(ctx, `UPDATE public.action_approval_requests SET `+set+` WHERE id=$1`, f.aar); err == nil {
			t.Errorf("owner role: `%s` was accepted", set)
		}
	}
	if _, err := c.Exec(ctx, `DELETE FROM public.action_approval_requests WHERE id=$1`, f.aar); err == nil {
		t.Error("owner role: DELETE accepted")
	}
	// Final-state transitions, with the owner's full column rights.
	g.decide(t, f, DecisionApprove)
	cmd := newCmdID(t)
	g.tx(t, func(tx pgx.Tx) {
		if _, err := g.store.ReserveGlovoApprovalTx(ctx, tx, f.aar, f.reserveCmd(cmd)); err != nil {
			t.Fatal(err)
		}
		if err := g.store.ConsumeGlovoApprovalTx(ctx, tx, f.aar, cmd); err != nil {
			t.Fatal(err)
		}
	})
	for _, to := range []string{"approved", "pending", "reserved", "denied", "unknown"} {
		if _, err := c.Exec(ctx, `UPDATE public.action_approval_requests SET state=$2 WHERE id=$1`, f.aar, to); err == nil {
			t.Errorf("consumed -> %s was accepted for the owner role", to)
		}
	}
	// Decision columns of a decided row do not change.
	for _, set := range []string{"decided_by='x'", "authority_basis='platform_admin'", "fresh_until=now()", "consumed_at=now()"} {
		if _, err := c.Exec(ctx, `UPDATE public.action_approval_requests SET `+set+` WHERE id=$1`, f.aar); err == nil {
			t.Errorf("a recorded decision column changed: %s", set)
		}
	}
}

// T15b: foreign roles and grants.
func TestGlovoForeignRolesAndExactGrants(t *testing.T) {
	g := newGlovoEnv(t)
	ctx := context.Background()
	wi := g.wiPool()
	// The work-items role is refused a Glovo-kind insert by the guard, and any update of a Glovo row.
	row := rawGlovoRow(nil)
	if _, err := wi.Exec(ctx, row.sql, row.args...); err == nil || !strings.Contains(err.Error(), "only the glovo runtime role") {
		t.Fatalf("work-items role inserted a Glovo approval: %v", err)
	}
	f := g.prepare(t)
	if _, err := wi.Exec(ctx, `UPDATE public.action_approval_requests SET state='denied' WHERE id=$1`, f.aar); err == nil || !strings.Contains(err.Error(), "only the glovo runtime role") {
		t.Fatalf("work-items role updated a Glovo approval: %v", err)
	}
	if _, err := wi.Exec(ctx, `DELETE FROM public.action_approval_requests WHERE id=$1`, f.aar); err == nil {
		t.Fatal("work-items role deleted a Glovo approval")
	}
	for _, q := range []string{`SELECT 1 FROM glovo.approval_bindings`, `INSERT INTO glovo.approval_bindings (approval_id) VALUES ('x')`} {
		if _, err := wi.Exec(ctx, q); err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("work-items role on glovo.approval_bindings (%s): %v", q, err)
		}
	}
	// The generic path of the work-items role is unchanged: a generic approval is created and decided.
	a, created, err := g.store.CreateActionApproval(ctx, ActionApprovalInput{
		ActionIntent: ActionIntent{ExecutionID: "we_" + splitHex(8), ActionKind: "deploy.apply", Target: "t", ArgsDigest: "d", PolicyRuleID: "r", PolicyVersion: "1"},
		RequestedBy:  "agent:x", IdempotencyKey: "k1", ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil || !created {
		t.Fatalf("generic create: %v", err)
	}
	if _, err := g.store.DecideActionApproval(ctx, ActionDecisionInput{ID: a.ID, DecidedBy: "oidc:admin", Decision: DecisionApprove}); err != nil {
		t.Fatalf("generic decide: %v", err)
	}

	// The runtime role's column-level UPDATE equals the registered list, per column.
	rows, err := g.rtp.Query(ctx, `SELECT a.attname,
		has_column_privilege(current_user, 'public.action_approval_requests', a.attname, 'UPDATE'),
		has_column_privilege(current_user, 'public.action_approval_requests', a.attname, 'INSERT'),
		has_column_privilege(current_user, 'public.action_approval_requests', a.attname, 'SELECT')
		FROM pg_attribute a WHERE a.attrelid='public.action_approval_requests'::regclass AND a.attnum>0 AND NOT a.attisdropped ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	want := map[string]bool{}
	for _, c := range glovoRuntimeUpdateColumns {
		want[c] = true
	}
	seen := 0
	for rows.Next() {
		var name string
		var u, i, s bool
		if err := rows.Scan(&name, &u, &i, &s); err != nil {
			t.Fatal(err)
		}
		seen++
		if u != want[name] || !i || !s {
			t.Errorf("column %s: update=%v (want %v) insert=%v select=%v", name, u, want[name], i, s)
		}
	}
	if seen == 0 {
		t.Fatal("no columns read")
	}
	// Table-level rights: no DELETE, TRUNCATE, TRIGGER or REFERENCES; table UPDATE is column-only.
	var del, trunc, trg, ref, tblUpd bool
	if err := g.rtp.QueryRow(ctx, `SELECT has_table_privilege('public.action_approval_requests','DELETE'),
		has_table_privilege('public.action_approval_requests','TRUNCATE'), has_table_privilege('public.action_approval_requests','TRIGGER'),
		has_table_privilege('public.action_approval_requests','REFERENCES'), has_table_privilege('public.action_approval_requests','UPDATE')`).Scan(&del, &trunc, &trg, &ref, &tblUpd); err != nil {
		t.Fatal(err)
	}
	if del || trunc || trg || ref || tblUpd {
		t.Fatalf("table-level rights: delete=%v truncate=%v trigger=%v references=%v update=%v", del, trunc, trg, ref, tblUpd)
	}
	// work-items tables: SELECT and INSERT only; bindings: SELECT, INSERT, UPDATE(command_id).
	for _, tbl := range []string{"public.work_items", "public.work_item_executions", "public.work_item_events", "glovo.approval_bindings"} {
		var s, i, u, d bool
		if err := g.rtp.QueryRow(ctx, `SELECT has_table_privilege($1,'SELECT'), has_table_privilege($1,'INSERT'), has_table_privilege($1,'UPDATE'), has_table_privilege($1,'DELETE')`, tbl).Scan(&s, &i, &u, &d); err != nil {
			t.Fatal(err)
		}
		if !s || !i || u || d {
			t.Errorf("%s: select=%v insert=%v update=%v delete=%v", tbl, s, i, u, d)
		}
	}
	var cu bool
	if err := g.rtp.QueryRow(ctx, `SELECT has_column_privilege('glovo.approval_bindings','command_id','UPDATE') AND NOT has_column_privilege('glovo.approval_bindings','tenant','UPDATE')`).Scan(&cu); err != nil || !cu {
		t.Fatalf("binding column grant: %v %v", cu, err)
	}
	// No other public table is reachable: the runtime role holds nothing on the other generic tables.
	for _, tbl := range []string{"work_item_intents", "execution_provenance", "agent_run_tokens", "work_item_surface_refs", "work_items_schema_version"} {
		var s bool
		if err := g.rtp.QueryRow(ctx, `SELECT has_table_privilege('public.`+tbl+`','SELECT')`).Scan(&s); err != nil || s {
			t.Errorf("runtime role can read public.%s (%v)", tbl, err)
		}
	}
	// The work-items role holds no privilege in schema glovo.
	var usage bool
	if err := wi.QueryRow(ctx, `SELECT has_schema_privilege('glovo','USAGE')`).Scan(&usage); err != nil || usage {
		t.Fatalf("work-items role has USAGE on schema glovo: %v %v", usage, err)
	}
}
