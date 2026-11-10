package workitems

import (
	"context"
	"sort"
	"strings"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
)

// Reasons VerifyGlovoApprovalSchema reports; every one is a not_ready.
const (
	NotReadyApprovalVersion  = "approval_schema_version_mismatch"
	NotReadyApprovalTrigger  = "approval_trigger_disabled_or_missing"
	NotReadyApprovalOwner    = "approval_table_owner_mismatch"
	NotReadyApprovalGrants   = "approval_grants_mismatch"
	NotReadyApprovalCheckSQL = "approval_check_failed"
)

func approvalNotReady(reason string) error { return &glovo.NotReadyError{Reason: reason} }

// VerifyGlovoApprovalSchema is the start-up proof of the approval schema, run
// as the runtime role on the Glovo pool (mctl-api#989 design section 8): the
// recorded version matches, the four guards are enabled, the tables are owned
// by a role the runtime role is not a member of, and the runtime role's
// grants on them are exactly those of ApplyGlovoApprovalSchema (the UPDATE
// column list per column, and no table-wide UPDATE, DELETE or TRUNCATE). A
// check that could not run is not_ready, never a pass.
func VerifyGlovoApprovalSchema(ctx context.Context, q dbq.Querier) error {
	var versions []int
	rows, err := q.Query(ctx, `SELECT version FROM glovo.approval_schema_version`)
	if err != nil {
		return &glovo.NotReadyError{Reason: NotReadyApprovalCheckSQL, Cause: err}
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return &glovo.NotReadyError{Reason: NotReadyApprovalCheckSQL, Cause: err}
		}
		versions = append(versions, v)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return &glovo.NotReadyError{Reason: NotReadyApprovalCheckSQL, Cause: err}
	}
	if len(versions) != 1 || versions[0] != glovoApprovalSchemaVersion {
		return approvalNotReady(NotReadyApprovalVersion)
	}

	var enabled int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM pg_trigger t
		WHERE NOT t.tgisinternal AND t.tgenabled = 'O' AND (
		   (t.tgrelid = 'public.action_approval_requests'::regclass AND t.tgname IN ('aar_guard','aar_binding_required'))
		OR (t.tgrelid = 'glovo.approval_bindings'::regclass AND t.tgname = 'approval_bindings_guard')
		OR (t.tgrelid = 'glovo.basket_approval_bindings'::regclass AND t.tgname = 'basket_approval_bindings_guard'))`).Scan(&enabled); err != nil {
		return &glovo.NotReadyError{Reason: NotReadyApprovalCheckSQL, Cause: err}
	}
	if enabled != 4 {
		return approvalNotReady(NotReadyApprovalTrigger)
	}

	var owners, member int
	if err := q.QueryRow(ctx, `SELECT count(DISTINCT c.relowner),
		count(*) FILTER (WHERE pg_has_role(current_user, c.relowner, 'MEMBER'))
		FROM pg_class c WHERE c.oid IN ('public.action_approval_requests'::regclass, 'glovo.approval_bindings'::regclass,
		                                'glovo.basket_approval_bindings'::regclass)`).Scan(&owners, &member); err != nil {
		return &glovo.NotReadyError{Reason: NotReadyApprovalCheckSQL, Cause: err}
	}
	if owners != 1 || member != 0 {
		return approvalNotReady(NotReadyApprovalOwner)
	}

	type want struct {
		table      string
		table_priv map[string]bool
		updateCols []string
	}
	wants := []want{
		{"public.action_approval_requests", map[string]bool{"SELECT": true, "INSERT": true, "UPDATE": false, "DELETE": false, "TRUNCATE": false}, glovoRuntimeUpdateColumns},
		{"glovo.approval_bindings", map[string]bool{"SELECT": true, "INSERT": true, "UPDATE": false, "DELETE": false, "TRUNCATE": false}, []string{"command_id"}},
		{"glovo.basket_approval_bindings", map[string]bool{"SELECT": true, "INSERT": true, "UPDATE": false, "DELETE": false, "TRUNCATE": false}, nil},
	}
	for _, g := range glovoPublicGrants {
		wants = append(wants, want{"public." + g.Table, map[string]bool{"SELECT": true, "INSERT": true, "UPDATE": false, "DELETE": false, "TRUNCATE": false}, nil})
	}
	for _, w := range wants {
		for priv, expect := range w.table_priv {
			var has bool
			if err := q.QueryRow(ctx, `SELECT has_table_privilege(current_user, $1::regclass, $2)`, w.table, priv).Scan(&has); err != nil {
				return &glovo.NotReadyError{Reason: NotReadyApprovalCheckSQL, Cause: err}
			}
			if has != expect {
				return approvalNotReady(NotReadyApprovalGrants)
			}
		}
		colRows, err := q.Query(ctx, `SELECT a.attname FROM pg_attribute a
			WHERE a.attrelid = $1::regclass AND a.attnum > 0 AND NOT a.attisdropped
			  AND has_column_privilege(current_user, $1::regclass, a.attnum, 'UPDATE')`, w.table)
		if err != nil {
			return &glovo.NotReadyError{Reason: NotReadyApprovalCheckSQL, Cause: err}
		}
		var got []string
		for colRows.Next() {
			var c string
			if err := colRows.Scan(&c); err != nil {
				colRows.Close()
				return &glovo.NotReadyError{Reason: NotReadyApprovalCheckSQL, Cause: err}
			}
			got = append(got, c)
		}
		colRows.Close()
		if err := colRows.Err(); err != nil {
			return &glovo.NotReadyError{Reason: NotReadyApprovalCheckSQL, Cause: err}
		}
		exp := append([]string(nil), w.updateCols...)
		sort.Strings(got)
		sort.Strings(exp)
		if strings.Join(got, ",") != strings.Join(exp, ",") {
			return approvalNotReady(NotReadyApprovalGrants)
		}
	}
	return nil
}
