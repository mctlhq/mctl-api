package workitems

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// approvedWindow opens a window request and has the owner approve it.
func approvedWindow(t *testing.T, s *Store, base string) *ActionApprovalRequest {
	t.Helper()
	a := newPendingWindow(t, s, base)
	got, err := s.DecideReleaseWindowApproval(context.Background(), ReleaseWindowDecisionInput{ID: a.ID, DecidedBy: "oidc:owner",
		DecidedByPrincipalID: "prn_owner", Approve: true, Evidence: evidenceFor(a)})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	return got
}

const rwRequester = "oidc:a" // rwInput's requester

func TestClaimAndSettleReleaseWindowApproval(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	a := approvedWindow(t, s, rwBase)

	claim, err := s.ClaimReleaseWindowApproval(ctx, a.ID, rwRequester, a.IntentHash, ReleaseWindowReclaimAfter)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if claim.State != ApprovalInFlight || claim.ReservedAt == nil || claim.ConsumedAt == nil {
		t.Fatalf("claimed row: %+v", claim)
	}
	// While claimed, nobody else can claim it.
	if _, err := s.ClaimReleaseWindowApproval(ctx, a.ID, rwRequester, a.IntentHash, ReleaseWindowReclaimAfter); !errors.Is(err, ErrApprovalInFlight) {
		t.Fatalf("second claim: %v, want ErrApprovalInFlight", err)
	}
	done, err := s.SettleReleaseWindowApproval(ctx, claim, true)
	if err != nil || done.State != ApprovalExecuted || done.ExecutedAt == nil {
		t.Fatalf("settle: %+v %v", done, err)
	}
	// Spent once.
	if _, err := s.ClaimReleaseWindowApproval(ctx, a.ID, rwRequester, a.IntentHash, ReleaseWindowReclaimAfter); !errors.Is(err, ErrApprovalConsumed) {
		t.Fatalf("claim after execution: %v, want ErrApprovalConsumed", err)
	}
	// An executed row keeps its decision.
	if ev, err := ReleaseWindowDecisionOf(done); err != nil || ev == nil {
		t.Fatalf("an executed row lost its decision: %v %v", ev, err)
	}
}

// A dispatch that was not accepted leaves the owner's decision usable.
func TestFailedDispatchDoesNotBurnTheApproval(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	a := approvedWindow(t, s, rwBase)
	claim, err := s.ClaimReleaseWindowApproval(ctx, a.ID, rwRequester, a.IntentHash, ReleaseWindowReclaimAfter)
	if err != nil {
		t.Fatal(err)
	}
	back, err := s.SettleReleaseWindowApproval(ctx, claim, false)
	if err != nil || back.State != ApprovalApproved || back.ReservedAt != nil || back.ConsumedAt != nil {
		t.Fatalf("settle(false): %+v %v, want approved with no reservation", back, err)
	}
	if ev, err := ReleaseWindowDecisionOf(back); err != nil || ev == nil {
		t.Fatalf("the decision did not survive: %v %v", ev, err)
	}
	if _, err := s.ClaimReleaseWindowApproval(ctx, a.ID, rwRequester, a.IntentHash, ReleaseWindowReclaimAfter); err != nil {
		t.Fatalf("claim after a failed dispatch: %v", err)
	}
}

func TestClaimReleaseWindowApprovalRefusals(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	claim := func(id, caller, hash string) error {
		_, err := s.ClaimReleaseWindowApproval(ctx, id, caller, hash, ReleaseWindowReclaimAfter)
		return err
	}

	pending := newPendingWindow(t, s, rwBase)
	if err := claim(pending.ID, rwRequester, pending.IntentHash); !errors.Is(err, ErrApprovalNotApproved) {
		t.Errorf("pending: %v, want ErrApprovalNotApproved", err)
	}

	denied := newPendingWindow(t, s, "e"+rwBase[1:])
	if _, err := s.DecideReleaseWindowApproval(ctx, ReleaseWindowDecisionInput{ID: denied.ID, DecidedBy: "oidc:owner",
		DecidedByPrincipalID: "prn_owner", Evidence: evidenceFor(denied)}); err != nil {
		t.Fatal(err)
	}
	if err := claim(denied.ID, rwRequester, denied.IntentHash); !errors.Is(err, ErrApprovalDenied) {
		t.Errorf("denied: %v, want ErrApprovalDenied", err)
	}

	a := approvedWindow(t, s, "d"+rwBase[1:])
	if err := claim(a.ID, "oidc:someone-else", a.IntentHash); !errors.Is(err, ErrApprovalNotFound) {
		t.Errorf("another requester: %v, want ErrApprovalNotFound", err)
	}
	if err := claim(a.ID, rwRequester, "sha256:"+rwBase+rwBase[:24]); !errors.Is(err, ErrApprovalIntentMismatch) {
		t.Errorf("wrong intent hash: %v, want ErrApprovalIntentMismatch", err)
	}
	if err := claim(a.ID, "", a.IntentHash); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty caller: %v, want ErrInvalid", err)
	}
	if _, err := s.ClaimReleaseWindowApproval(ctx, a.ID, rwRequester, a.IntentHash, 0); !errors.Is(err, ErrInvalid) {
		t.Errorf("no reclaim bound: %v, want ErrInvalid", err)
	}
	if err := claim("aar_00000000000000000000000000000000", rwRequester, a.IntentHash); !errors.Is(err, ErrApprovalNotFound) {
		t.Errorf("no such request: %v, want ErrApprovalNotFound", err)
	}

	// An approved request that has expired is not spent.
	if _, err := s.pool.Exec(ctx, `UPDATE action_approval_requests SET expires_at = now() - interval '1 minute' WHERE id = $1`, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := claim(a.ID, rwRequester, a.IntentHash); !errors.Is(err, ErrApprovalExpired) {
		t.Errorf("expired: %v, want ErrApprovalExpired", err)
	}

	// A release grant is not a window.
	grant := newPendingRelease(t, s, "9.5.0")
	if _, err := s.DecideReleaseApproval(ctx, ReleaseDecisionInput{ID: grant.ID, DecidedBy: "oidc:owner",
		DecidedByPrincipalID: "prn_owner", Approve: true, Evidence: evidenceFor(grant)}); err != nil {
		t.Fatal(err)
	}
	if err := claim(grant.ID, rwRequester, grant.IntentHash); !errors.Is(err, ErrApprovalKindNotSpendable) {
		t.Errorf("grant row: %v, want ErrApprovalKindNotSpendable", err)
	}
}

// However many callers race, one claim wins.
func TestClaimReleaseWindowApprovalHasOneWinner(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	a := approvedWindow(t, s, rwBase)
	const n = 12
	var wg sync.WaitGroup
	results := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, results[i] = s.ClaimReleaseWindowApproval(ctx, a.ID, rwRequester, a.IntentHash, ReleaseWindowReclaimAfter)
		}(i)
	}
	wg.Wait()
	wins := 0
	for _, err := range results {
		switch {
		case err == nil:
			wins++
		case !errors.Is(err, ErrApprovalInFlight):
			t.Errorf("a loser got %v, want ErrApprovalInFlight", err)
		}
	}
	if wins != 1 {
		t.Fatalf("%d callers won the claim, want exactly 1", wins)
	}
}

// A claim nobody settled is claimable again after the reclaim bound, and the
// old owner of it can no longer move the row.
func TestStaleClaimIsReclaimedAndTheOldOwnerCannotSettle(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	a := approvedWindow(t, s, rwBase)
	first, err := s.ClaimReleaseWindowApproval(ctx, a.ID, rwRequester, a.IntentHash, ReleaseWindowReclaimAfter)
	if err != nil {
		t.Fatal(err)
	}
	// Not yet stale: nobody else gets it.
	if _, err := s.ClaimReleaseWindowApproval(ctx, a.ID, rwRequester, a.IntentHash, ReleaseWindowReclaimAfter); !errors.Is(err, ErrApprovalInFlight) {
		t.Fatalf("fresh claim reclaimed: %v", err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE action_approval_requests SET reserved_at = now() - interval '11 minutes' WHERE id = $1`, a.ID); err != nil {
		t.Fatal(err)
	}
	second, err := s.ClaimReleaseWindowApproval(ctx, a.ID, rwRequester, a.IntentHash, ReleaseWindowReclaimAfter)
	if err != nil {
		t.Fatalf("reclaim of a stale claim: %v", err)
	}
	if second.ReservedAt == nil || !second.ReservedAt.After(*first.ReservedAt) {
		t.Fatalf("the reclaim did not take a new reservation: %v vs %v", second.ReservedAt, first.ReservedAt)
	}
	// The first caller finally answers: it must not move the row, either way.
	for _, ok := range []bool{false, true} {
		if _, err := s.SettleReleaseWindowApproval(ctx, first, ok); !errors.Is(err, ErrApprovalNotConsumed) {
			t.Fatalf("old owner settle(%v): %v, want ErrApprovalNotConsumed", ok, err)
		}
	}
	if cur, _ := s.ActionApproval(ctx, a.ID); cur.State != ApprovalInFlight {
		t.Fatalf("the old owner moved the row to %s", cur.State)
	}
	if done, err := s.SettleReleaseWindowApproval(ctx, second, true); err != nil || done.State != ApprovalExecuted {
		t.Fatalf("the new owner settle: %+v %v", done, err)
	}
	// And a settle on an executed row says so.
	if _, err := s.SettleReleaseWindowApproval(ctx, second, true); !errors.Is(err, ErrApprovalExecuted) {
		t.Fatalf("settle twice: %v, want ErrApprovalExecuted", err)
	}
}

func TestSettleReleaseWindowApprovalNeedsTheClaim(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	a := approvedWindow(t, s, rwBase)
	for name, c := range map[string]*ActionApprovalRequest{
		"nil":          nil,
		"not claimed":  a,
		"no timestamp": {ID: a.ID, ActionKind: ActionKindReleaseWindow, State: ApprovalInFlight, RequestedBy: rwRequester},
		"other kind":   {ID: a.ID, ActionKind: ActionKindReleaseGrant, State: ApprovalInFlight, RequestedBy: rwRequester, ReservedAt: &time.Time{}},
	} {
		if _, err := s.SettleReleaseWindowApproval(ctx, c, true); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}

// Every generic path still refuses an approved window.
func TestApprovedReleaseWindowIsNotSpendableByAnyGenericPath(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	a := approvedWindow(t, s, rwBase)
	calls := map[string]error{}
	_, calls["consume"] = s.ConsumeActionApproval(ctx, a.ID, a.IntentHash)
	_, calls["consume-deploy"] = s.ConsumeDeployApproval(ctx, a.ID, a.IntentHash)
	_, calls["mark"] = s.MarkActionApprovalExecuted(ctx, a.ID, a.Target, a.ArtifactHash, a.RequestedBy)
	_, calls["reserve"] = s.ReserveActionApproval(ctx, a.ID, a.Target, a.ArtifactHash, a.RequestedBy, time.Hour)
	_, calls["settle"] = s.SettleActionApproval(ctx, a.ID, a.RequestedBy, true)
	for name, err := range calls {
		if err == nil {
			t.Errorf("%s on an approved release.window row succeeded", name)
		}
	}
	if cur, _ := s.ActionApproval(ctx, a.ID); cur.State != ApprovalApproved {
		t.Errorf("a generic path moved the row to %s", cur.State)
	}
}

// An in-flight claim whose request has expired can never be claimed again, so
// the answer is "expired, ask again", not "in flight, retry later".
func TestExpiredInFlightClaimReportsExpiredNotInFlight(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	a := approvedWindow(t, s, rwBase)
	if _, err := s.ClaimReleaseWindowApproval(ctx, a.ID, rwRequester, a.IntentHash, ReleaseWindowReclaimAfter); err != nil {
		t.Fatal(err)
	}
	// Still inside its window: the honest answer is in flight.
	if _, err := s.ClaimReleaseWindowApproval(ctx, a.ID, rwRequester, a.IntentHash, ReleaseWindowReclaimAfter); !errors.Is(err, ErrApprovalInFlight) {
		t.Fatalf("live claim: %v, want ErrApprovalInFlight", err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE action_approval_requests SET expires_at = now() - interval '1 minute', reserved_at = now() - interval '11 minutes' WHERE id = $1`, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimReleaseWindowApproval(ctx, a.ID, rwRequester, a.IntentHash, ReleaseWindowReclaimAfter); !errors.Is(err, ErrApprovalExpired) {
		t.Fatalf("expired in-flight claim: %v, want ErrApprovalExpired", err)
	}
}

// Past its expiry, a window that was already executed still says executed: the
// expiry answer is only for a claim that is stuck in flight.
func TestExpiredExecutedWindowStillReportsExecuted(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	a := approvedWindow(t, s, rwBase)
	claim, err := s.ClaimReleaseWindowApproval(ctx, a.ID, rwRequester, a.IntentHash, ReleaseWindowReclaimAfter)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SettleReleaseWindowApproval(ctx, claim, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE action_approval_requests SET expires_at = now() - interval '1 minute' WHERE id = $1`, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimReleaseWindowApproval(ctx, a.ID, rwRequester, a.IntentHash, ReleaseWindowReclaimAfter); !errors.Is(err, ErrApprovalConsumed) {
		t.Fatalf("expired executed window: %v, want ErrApprovalConsumed", err)
	}
}
