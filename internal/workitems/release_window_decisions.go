package workitems

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Release window decisions (sync-window write path, S2).
//
// A release.window request is decided only on the release window approval
// page, by the owner, after a fresh sign-in whose ID token reports a second
// factor. As for a release grant, what that sign-in proved is the decision's
// evidence and is stored in the row itself (reason, decided_context_digest,
// authority_basis), with no schema change. The authority basis differs from a
// grant's, so a reader can tell the two decisions apart, and neither decide
// path accepts the other's rows: DecideReleaseApproval refuses release.window
// (it checks the kind) and DecideReleaseWindowApproval refuses release.grant.

// ReleaseWindowAuthorityBasis is the authority a release window is approved
// under: the owner principal list, a fresh sign-in, a second factor.
const ReleaseWindowAuthorityBasis = "release.window.owner.fresh_mfa"

// ReleaseWindowDecisionInput decides one release.window request. Evidence is
// the same record a release grant keeps: it names the args digest the decider
// was shown, which DecideReleaseWindowApproval checks against the row.
type ReleaseWindowDecisionInput struct {
	ID                   string
	DecidedBy            string
	DecidedByPrincipalID string
	Approve              bool
	Evidence             ReleaseEvidence
}

// DecideReleaseWindowApproval decides a pending release.window request. The
// row is locked, must be a self-consistent release window (ReleaseWindowOf),
// and must still carry the args digest the decider was shown; both an approval
// and a rejection record the evidence of the sign-in that made them.
func (s *Store) DecideReleaseWindowApproval(ctx context.Context, in ReleaseWindowDecisionInput) (*ActionApprovalRequest, error) {
	if in.DecidedByPrincipalID == "" {
		return nil, fmt.Errorf("%w: %s", ErrApprovalDeciderUnresolved, in.ID)
	}
	if err := checkText("decided_by", in.DecidedBy, MaxExternalIDBytes, true); err != nil {
		return nil, err
	}
	reason, digest, err := in.Evidence.Encode()
	if err != nil {
		return nil, err
	}
	if len(reason) > MaxApprovalReasonBytes {
		return nil, invalid("release window evidence is longer than %d bytes", MaxApprovalReasonBytes)
	}
	to := ApprovalDenied
	if in.Approve {
		to = ApprovalApproved
	}
	var out *ActionApprovalRequest
	err = s.withTx(ctx, "action-approval:"+in.ID, func(tx pgx.Tx) error {
		cur, err := s.getActionApproval(ctx, tx, in.ID, " FOR UPDATE")
		if err != nil {
			return err
		}
		if cur.ActionKind != ActionKindReleaseWindow {
			return fmt.Errorf("%w: %s", ErrApprovalKindNotSpendable, cur.ID)
		}
		if _, err := ReleaseWindowOf(cur); err != nil {
			return err
		}
		if cur.ArgsDigest != in.Evidence.ArgsDigest {
			return fmt.Errorf("%w: %s no longer binds what was shown", ErrApprovalTargetMismatch, cur.ID)
		}
		switch cur.State {
		case ApprovalPending:
		case ApprovalExpired:
			return fmt.Errorf("%w: %s expired at %s", ErrApprovalExpired, cur.ID, cur.ExpiresAt.Format(time.RFC3339))
		default:
			return fmt.Errorf("%w: %s is %s", ErrApprovalAlreadyDecided, cur.ID, cur.State)
		}
		now := s.now()
		out, err = scanActionApproval(tx.QueryRow(ctx, `UPDATE action_approval_requests
			SET state=$2, decided_by=$3, decided_at=$4, reason=$5, decided_by_principal_id=$6,
			    decided_context_digest=$7, authority_basis=$8
			WHERE id=$1 AND state='pending' AND action_kind=$9 RETURNING `+actionApprovalColumns,
			cur.ID, to, in.DecidedBy, now, reason, in.DecidedByPrincipalID, digest, ReleaseWindowAuthorityBasis,
			ActionKindReleaseWindow), now)
		if err != nil {
			return fmt.Errorf("workitems: decide release window approval: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ReleaseWindowDecisionOf reads the evidence of a decided release window and
// checks it against the row: the stored digest must be the digest of the
// stored evidence, the evidence must be canonical and must name the args
// digest of this row, and the authority basis must be the window one. A
// pending row has no decision (nil, nil).
func ReleaseWindowDecisionOf(a *ActionApprovalRequest) (*ReleaseEvidence, error) {
	if _, err := ReleaseWindowOf(a); err != nil {
		return nil, err
	}
	if a.State == ApprovalPending || (a.State == ApprovalExpired && a.DecidedAt == nil) {
		return nil, nil
	}
	if a.AuthorityBasis != ReleaseWindowAuthorityBasis {
		return nil, invalid("release window %s was not decided under %s", a.ID, ReleaseWindowAuthorityBasis)
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(a.Reason)))
	dec.DisallowUnknownFields()
	var e ReleaseEvidence
	if err := dec.Decode(&e); err != nil {
		return nil, invalid("release window %s: evidence unreadable", a.ID)
	}
	reason, digest, err := e.Encode()
	if err != nil {
		return nil, invalid("release window %s: %v", a.ID, err)
	}
	switch {
	case reason != a.Reason:
		return nil, invalid("release window %s: evidence is not canonical", a.ID)
	case digest != a.DecidedContextDigest:
		return nil, invalid("release window %s: evidence does not reproduce its digest", a.ID)
	case e.ArgsDigest != a.ArgsDigest:
		return nil, invalid("release window %s: evidence names another request", a.ID)
	}
	return &e, nil
}
