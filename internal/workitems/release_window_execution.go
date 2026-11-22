package workitems

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Release window execution (sync-window write path, S3).
//
// An approved release.window is spent by ONE dispatch of release-window-pr.yml.
// The lifecycle is approved -> in_flight -> executed, with a failed dispatch
// going back to approved so the owner's decision is not burned by a GitHub
// outage:
//
//	ClaimReleaseWindowApproval   approved -> in_flight   (one compare-and-set)
//	SettleReleaseWindowApproval  in_flight -> executed   (the dispatch was accepted)
//	                             in_flight -> approved   (it was not)
//
// The generic consume, reserve and settle paths refuse this kind (it is a
// dedicated kind), so these are the only way to spend it.
//
// Two properties make a retry safe without a second human decision:
//   - the claim is bound to the requester, the intent hash and the expiry, and
//     only one caller wins;
//   - the workflow refuses a window whose branch or open pull request already
//     exists, so a dispatch repeated after an outcome nobody saw (a timeout
//     after GitHub accepted it) opens nothing twice.
//
// A claim that is never settled (the process died between the claim and the
// settle) is claimable again after ReleaseWindowReclaimAfter. A settle is bound
// to the claim it ends (its reserved_at), so a slow caller whose claim was
// taken over cannot move the row under the new owner of it.

// ReleaseWindowReclaimAfter is how long an in-flight claim blocks a retry.
const ReleaseWindowReclaimAfter = 10 * time.Minute

// ClaimReleaseWindowApproval spends an approved release.window request for one
// dispatch: one atomic compare-and-set from approved (or a stale in_flight) to
// in_flight that holds only for the request's own requester, while the stored
// intent hash equals the presented one, and the request has not expired. On a
// refusal the row is read back to name the reason; the refusal itself never
// depends on that read. A request of another requester reads as not found.
func (s *Store) ClaimReleaseWindowApproval(ctx context.Context, id, caller, intentHash string, reclaimAfter time.Duration) (*ActionApprovalRequest, error) {
	if err := checkText("intent_hash", intentHash, MaxApprovalFieldBytes, true); err != nil {
		return nil, err
	}
	if err := checkText("requested_by", caller, MaxExternalIDBytes, true); err != nil {
		return nil, err
	}
	if reclaimAfter <= 0 {
		return nil, invalid("the reclaim bound must be positive")
	}
	now := s.now()
	out, err := scanActionApproval(s.pool.QueryRow(ctx, `UPDATE action_approval_requests
		SET state='in_flight', consumed_at=$4, reserved_at=$4
		WHERE id=$1 AND action_kind=$5 AND requested_by=$2 AND intent_hash=$3
		  AND expires_at > $4 AND (fresh_until IS NULL OR fresh_until > $4)
		  AND (state='approved' OR (state='in_flight' AND reserved_at < $6))
		RETURNING `+actionApprovalColumns, id, caller, intentHash, now, ActionKindReleaseWindow, now.Add(-reclaimAfter)), now)
	if err == nil {
		return out, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("workitems: claim release window approval: %w", err)
	}
	cur, err := s.getActionApproval(ctx, s.pool, id, "")
	if err != nil {
		return nil, err
	}
	if cur.RequestedBy != caller {
		return nil, fmt.Errorf("workitems: action approval %s: %w", id, ErrApprovalNotFound)
	}
	if cur.ActionKind != ActionKindReleaseWindow {
		return nil, fmt.Errorf("%w: %s", ErrApprovalKindNotSpendable, id)
	}
	// An expired request can never be claimed again, whatever state it is in:
	// say so, instead of telling the caller to retry an in-flight claim that
	// the expiry guard in the UPDATE will refuse for good.
	if !cur.ExpiresAt.After(now) {
		return nil, fmt.Errorf("%w: %s", ErrApprovalExpired, id)
	}
	if cur.State == ApprovalInFlight {
		return nil, fmt.Errorf("%w: %s", ErrApprovalInFlight, id)
	}
	if err := ConsumeStateRefusal(cur); err != nil {
		return nil, err
	}
	if cur.IntentHash != intentHash {
		return nil, fmt.Errorf("%w: %s", ErrApprovalIntentMismatch, id)
	}
	if cur.FreshUntil != nil && !cur.FreshUntil.After(now) {
		return nil, fmt.Errorf("%w: %s was decided too long ago (fresh until %s)",
			ErrApprovalStale, id, cur.FreshUntil.Format(time.RFC3339))
	}
	// Approved, matching and unexpired now, but the UPDATE saw otherwise: the
	// clock moved between the two statements. Refuse rather than retry; the
	// caller presents it again.
	return nil, fmt.Errorf("%w: %s changed while claiming it", ErrApprovalNotApproved, id)
}

// SettleReleaseWindowApproval ends the claim ClaimReleaseWindowApproval made:
// in_flight to executed when the dispatch was accepted, or back to approved
// when it was not, so the decision stays usable. It is one compare-and-set
// bound to the claim's own reservation (its reserved_at), so a caller whose
// claim was taken over after ReleaseWindowReclaimAfter cannot move the row.
// A row that is not that claim is ErrApprovalNotConsumed (or
// ErrApprovalExecuted), and is left as it is.
func (s *Store) SettleReleaseWindowApproval(ctx context.Context, claim *ActionApprovalRequest, succeeded bool) (*ActionApprovalRequest, error) {
	if claim == nil || claim.ReservedAt == nil || claim.ActionKind != ActionKindReleaseWindow || claim.State != ApprovalInFlight {
		return nil, invalid("a settle needs the in-flight claim it ends")
	}
	now := s.now()
	q := `UPDATE action_approval_requests SET state='approved', consumed_at=NULL, reserved_at=NULL
		WHERE id=$1 AND state='in_flight' AND requested_by=$2 AND action_kind=$3 AND reserved_at=$4
		RETURNING ` + actionApprovalColumns
	args := []any{claim.ID, claim.RequestedBy, ActionKindReleaseWindow, *claim.ReservedAt}
	if succeeded {
		q = `UPDATE action_approval_requests SET state='executed', executed_at=$5
			WHERE id=$1 AND state='in_flight' AND requested_by=$2 AND action_kind=$3 AND reserved_at=$4
			RETURNING ` + actionApprovalColumns
		args = append(args, now)
	}
	out, err := scanActionApproval(s.pool.QueryRow(ctx, q, args...), now)
	if err == nil {
		return out, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("workitems: settle release window approval: %w", err)
	}
	cur, err := s.getActionApproval(ctx, s.pool, claim.ID, "")
	if err != nil {
		return nil, err
	}
	if cur.State == ApprovalExecuted {
		return nil, fmt.Errorf("%w: %s", ErrApprovalExecuted, claim.ID)
	}
	return nil, fmt.Errorf("%w: %s is %s, not the claim being settled", ErrApprovalNotConsumed, claim.ID, cur.State)
}
