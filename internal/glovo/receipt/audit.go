package receipt

import (
	"context"
	"fmt"

	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Joint is one Glovo approval read together with the bridge command it is
// bound to (design section 7).
type Joint struct {
	ApprovalID    string
	State         string // stored aar_ state
	CommandID     string // binding command_id, "" when unbound
	HaveCommand   bool   // the bridge command row exists
	CommandStatus string // bridge_commands.status
	EffectState   string // bridge_commands.effect_state
	HavePermit    bool   // a bridge_write_permits row exists
}

// Verdicts of Classify.
const (
	VerdictOK        = "ok"
	VerdictSweepDue  = "sweep_due" // a reserved row whose command ended without a permit: the sweeper's job
	VerdictViolation = "violation"
)

func terminalStatus(s string) bool { return s == "completed" || s == "expired" || s == "cancelled" }

// Classify holds one joint to the invariant table of design section 7. Any
// pair the table does not name is a violation, with the reason.
func Classify(j Joint) (verdict, reason string) {
	bad := func(r string) (string, string) { return VerdictViolation, r }
	switch j.State {
	case workitems.ApprovalReserved:
		switch {
		case !j.HaveCommand:
			return bad("reserved_command_missing")
		case j.HavePermit:
			return bad("reserved_with_permit")
		case j.EffectState != "none":
			return bad("reserved_effect_not_none")
		case terminalStatus(j.CommandStatus):
			return VerdictSweepDue, ""
		}
		return VerdictOK, ""
	case workitems.ApprovalConsumed:
		switch {
		case !j.HaveCommand:
			return bad("consumed_command_missing")
		case !j.HavePermit:
			return bad("consumed_without_permit")
		case j.EffectState == "none":
			return bad("consumed_effect_none")
		}
		return VerdictOK, ""
	case workitems.ApprovalUnknown:
		switch {
		case !j.HaveCommand:
			return bad("unknown_command_missing")
		case j.HavePermit:
			return bad("unknown_with_permit")
		}
		switch j.EffectState {
		case "none", "not_performed", "unknown":
			if !terminalStatus(j.CommandStatus) {
				return bad("unknown_command_not_ended")
			}
			return VerdictOK, ""
		}
		return bad("unknown_effect_" + j.EffectState)
	default:
		// pending, approved, refused: no command is bound.
		if j.CommandID != "" {
			return bad("command_bound_in_" + j.State)
		}
		return VerdictOK, ""
	}
}

// Violation is one joint that breaks the table.
type Violation struct{ ApprovalID, CommandID, Reason string }

// AuditResult is the outcome of Audit.
type AuditResult struct {
	Checked    int
	SweepDue   int
	Violations []Violation
}

// Audit reads every Glovo approval that has, or should have, a command and
// classifies it. q is a pool that can read the approval tables, schema glovo
// and the bridge tables (one database). A failed read is an error, never an
// empty result.
func Audit(ctx context.Context, q dbq.Querier) (*AuditResult, error) {
	rows, err := q.Query(ctx, `SELECT a.id, a.state, b.command_id,
		c.command_id IS NOT NULL, COALESCE(c.status, ''), COALESCE(c.effect_state, ''),
		EXISTS (SELECT 1 FROM bridge_write_permits p WHERE p.command_id = b.command_id)
		FROM public.action_approval_requests a
		JOIN glovo.approval_bindings b ON b.approval_id = a.id
		LEFT JOIN bridge_commands c ON c.command_id = b.command_id
		WHERE `+workitems.GlovoKindPredicate+` AND (a.state IN ('reserved','consumed','unknown') OR b.command_id <> '')`)
	if err != nil {
		return nil, fmt.Errorf("receipt: audit read: %w", err)
	}
	defer rows.Close()
	res := &AuditResult{}
	for rows.Next() {
		var j Joint
		if err := rows.Scan(&j.ApprovalID, &j.State, &j.CommandID, &j.HaveCommand, &j.CommandStatus, &j.EffectState, &j.HavePermit); err != nil {
			return nil, fmt.Errorf("receipt: audit scan: %w", err)
		}
		res.Checked++
		switch v, reason := Classify(j); v {
		case VerdictSweepDue:
			res.SweepDue++
		case VerdictViolation:
			res.Violations = append(res.Violations, Violation{ApprovalID: j.ApprovalID, CommandID: j.CommandID, Reason: reason})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("receipt: audit read: %w", err)
	}
	return res, nil
}
