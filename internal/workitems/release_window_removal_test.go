package workitems

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// rmWindow is the window named by the vectors below: the first real window,
// the one on labs-portfolio.
func rmWindow() ReleaseWindow {
	return ReleaseWindow{Project: "apps", Applications: []string{"labs-portfolio"}, Schedule: "0 3 * * 0", Duration: "1h", BaseSHA: rwBase}
}

// The removal hashes below were produced by mctl-gitops
// scripts/release-window-insert.py (`hash-remove PROJECT`), not by this package.
// release-window-removal-pr.yml refuses unless its hash equals the approved
// one, so a Go encoding that drifts from the Python one would make every
// approved removal unappliable; this is the test that notices.
func TestRemovalSHA256MatchesTheWorkflowScript(t *testing.T) {
	for _, c := range []struct {
		name string
		w    ReleaseWindow
		want string
	}{
		{"labs-portfolio", rmWindow(), "5cd82b2271abd883ee222722b9395be5187fbdd717c8e27bf2f3249140f52e9e"},
		{"two apps", rwWindow(), "1d75f1a22ea5723c7d83eee2888844dc93043f58ead7f271169dd96ae551d145"},
		{"platform", ReleaseWindow{Project: "platform", Applications: []string{"admins-mctl-api"},
			Schedule: "30 1 * * 1-5", Duration: "1h30m", BaseSHA: rwBase},
			"180de8a36c840e7e099bb6e37655a3a18d98eafbf3b1c321a54d907c0404540d"},
	} {
		got, err := c.w.RemovalSHA256()
		if err != nil || got != c.want {
			t.Errorf("%s: RemovalSHA256 = %q, %v; the workflow script gives %s", c.name, got, err, c.want)
		}
	}
}

// An approval to add a window must never be spendable as an approval to lift it.
func TestRemovalIsNotTheAdditionForTheSameWindow(t *testing.T) {
	w := rmWindow()
	add, _ := w.WindowSHA256()
	rem, _ := w.RemovalSHA256()
	addID, _ := w.ReleaseWindowID()
	remID, _ := w.ReleaseWindowRemovalID()
	addDigest, _ := ReleaseWindowArgsDigest(w)
	remDigest, _ := ReleaseWindowRemovalArgsDigest(w)
	addKey, _ := ReleaseWindowIdempotencyKey(w)
	remKey, _ := ReleaseWindowRemovalIdempotencyKey(w)
	if add == rem || addID == remID || addDigest == remDigest || addKey == remKey {
		t.Fatalf("add and removal of one window must differ everywhere: %s/%s %s/%s %s/%s", add, rem, addID, remID, addDigest, remDigest)
	}
	if !strings.HasPrefix(remID, "r-") || !releaseWindowRemovalIDRe.MatchString(remID) {
		t.Fatalf("removal id %q", remID)
	}
	if addIn, _ := ReleaseWindowIntent(w); addIn.ActionKind == ActionKindReleaseWindowRemoval {
		t.Fatal("the add intent has the removal kind")
	}
}

func TestRemovalHashBindsProjectAndWindow(t *testing.T) {
	a := rmWindow()
	ha, _ := a.RemovalSHA256()
	for name, mutate := range map[string]func(*ReleaseWindow){
		"project":  func(w *ReleaseWindow) { w.Project = "platform" },
		"schedule": func(w *ReleaseWindow) { w.Schedule = "0 4 * * 0" },
		"duration": func(w *ReleaseWindow) { w.Duration = "2h" },
		"apps":     func(w *ReleaseWindow) { w.Applications = []string{"labs-portfolio", "labs-web"} },
	} {
		b := rmWindow()
		mutate(&b)
		if hb, err := b.RemovalSHA256(); err != nil || hb == ha {
			t.Errorf("%s: a different window hashed the same (%v)", name, err)
		}
	}
	// The same shape rules as an addition: not a window the workflow would take.
	bad := rmWindow()
	bad.Project = "default"
	if _, err := bad.RemovalSHA256(); !errors.Is(err, ErrInvalid) {
		t.Errorf("default project: %v, want ErrInvalid", err)
	}
	bad = rmWindow()
	bad.Applications = []string{"b", "a"}
	if _, err := bad.RemovalSHA256(); !errors.Is(err, ErrInvalid) {
		t.Errorf("unsorted applications: %v, want ErrInvalid", err)
	}
}

func rmRow(t *testing.T, w ReleaseWindow) *ActionApprovalRequest {
	t.Helper()
	in, err := ReleaseWindowRemovalIntent(w)
	if err != nil {
		t.Fatal(err)
	}
	return &ActionApprovalRequest{ID: "aar_x", ExecutionID: in.ExecutionID, ActionKind: in.ActionKind,
		Target: in.Target, ArgsDigest: in.ArgsDigest, ArtifactHash: in.ArtifactHash}
}

func TestReleaseWindowRemovalOfRoundTripsAndRejectsTampering(t *testing.T) {
	w := rmWindow()
	got, err := ReleaseWindowRemovalOf(rmRow(t, w))
	if err != nil || fmt.Sprint(got) != fmt.Sprint(w) {
		t.Fatalf("round trip: %v %v, want %v", got, err, w)
	}
	other := rmWindow()
	other.Duration = "2h"
	otherIn, _ := ReleaseWindowRemovalIntent(other)
	tamper := map[string]func(*ActionApprovalRequest){
		"add kind":       func(a *ActionApprovalRequest) { a.ActionKind = ActionKindReleaseWindow },
		"grant kind":     func(a *ActionApprovalRequest) { a.ActionKind = ActionKindReleaseGrant },
		"window swapped": func(a *ActionApprovalRequest) { a.Target = otherIn.Target },
		"digest swapped": func(a *ActionApprovalRequest) { a.ArgsDigest = otherIn.ArgsDigest },
		"hash swapped":   func(a *ActionApprovalRequest) { a.ArtifactHash = otherIn.ArtifactHash },
		"base moved":     func(a *ActionApprovalRequest) { a.ExecutionID = strings.Repeat("f", 40) },
		"project in head": func(a *ActionApprovalRequest) {
			a.Target = strings.Replace(a.Target, "apps/", "platform/", 1)
		},
		"id of an addition": func(a *ActionApprovalRequest) { a.Target = strings.Replace(a.Target, "/r-", "/w-", 1) },
		"no window":         func(a *ActionApprovalRequest) { a.Target = "apps/r-000000000000" },
	}
	for name, mutate := range tamper {
		a := rmRow(t, w)
		mutate(a)
		if _, err := ReleaseWindowRemovalOf(a); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: ReleaseWindowRemovalOf = %v, want ErrInvalid", name, err)
		}
	}
	if _, err := ReleaseWindowRemovalOf(nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("nil row: %v", err)
	}
	// Neither reader accepts the other's row.
	if _, err := ReleaseWindowOf(rmRow(t, w)); !errors.Is(err, ErrInvalid) {
		t.Errorf("the add reader accepted a removal row: %v", err)
	}
	if _, err := ReleaseWindowRemovalOf(rwRow(t, w)); !errors.Is(err, ErrInvalid) {
		t.Errorf("the removal reader accepted an add row: %v", err)
	}
}

func rmInput(s *Store, w ReleaseWindow, requester string) ActionApprovalInput {
	in, _ := ReleaseWindowRemovalIntent(w)
	key, _ := ReleaseWindowRemovalIdempotencyKey(w)
	id, _ := w.ReleaseWindowRemovalID()
	return ActionApprovalInput{
		ActionIntent: in, RequestedBy: requester, RequestedByPrincipalID: "prn_requester",
		IdempotencyKey: key, ExpiresAt: s.now().Add(time.Hour),
		RiskLevel: "high", IntentSource: "release-window-removal:" + w.Project + "/" + id,
		SideEffect: "write", PolicyDecision: "require_approval", PolicyReasons: []string{ReleaseWindowRemovalPolicyRuleID},
	}
}

func newPendingRemoval(t *testing.T, s *Store, base string) *ActionApprovalRequest {
	t.Helper()
	w := rmWindow()
	w.BaseSHA = base
	a, _, err := s.CreateReleaseWindowRemovalApproval(context.Background(), w, rmInput(s, w, rwRequester))
	if err != nil {
		t.Fatalf("CreateReleaseWindowRemovalApproval: %v", err)
	}
	return a
}

func TestCreateReleaseWindowRemovalApprovalBindsTheWindow(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := rmWindow()
	w.BaseSHA = "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1"
	a, created, err := s.CreateReleaseWindowRemovalApproval(ctx, w, rmInput(s, w, rwRequester))
	if err != nil || !created || a.State != ApprovalPending || a.ActionKind != ActionKindReleaseWindowRemoval {
		t.Fatalf("create: %+v created=%v err=%v", a, created, err)
	}
	// Same window, same requester, same main: the same request.
	again, created, err := s.CreateReleaseWindowRemovalApproval(ctx, w, rmInput(s, w, rwRequester))
	if err != nil || created || again.ID != a.ID {
		t.Fatalf("replay: %+v created=%v err=%v", again, created, err)
	}
	// An intent that is not derived from the window is refused.
	bad := rmInput(s, w, rwRequester)
	bad.ArgsDigest = "sha256:" + strings.Repeat("0", 64)
	if _, _, err := s.CreateReleaseWindowRemovalApproval(ctx, w, bad); !errors.Is(err, ErrInvalid) {
		t.Errorf("foreign digest: %v, want ErrInvalid", err)
	}
	bad = rmInput(s, w, rwRequester)
	bad.IdempotencyKey = "release-window-removal:other"
	if _, _, err := s.CreateReleaseWindowRemovalApproval(ctx, w, bad); !errors.Is(err, ErrInvalid) {
		t.Errorf("foreign idempotency key: %v, want ErrInvalid", err)
	}
	// An addition's input cannot create a removal row, nor the reverse.
	addIn := rwInput(s, w, rwRequester)
	if _, _, err := s.CreateReleaseWindowRemovalApproval(ctx, w, addIn); !errors.Is(err, ErrInvalid) {
		t.Errorf("add input for a removal: %v, want ErrInvalid", err)
	}
	if _, _, err := s.CreateReleaseWindowApproval(ctx, w, rmInput(s, w, rwRequester)); !errors.Is(err, ErrInvalid) {
		t.Errorf("removal input for an addition: %v, want ErrInvalid", err)
	}
	// An add request and a removal request for one window are two rows.
	add, _, err := s.CreateReleaseWindowApproval(ctx, w, rwInput(s, w, rwRequester))
	if err != nil || add.ID == a.ID {
		t.Fatalf("add alongside removal: %+v %v", add, err)
	}
}

func TestRemovalAndAdditionDecidePathsRefuseEachOther(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	add := newPendingWindow(t, s, "c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2")
	rem := newPendingRemoval(t, s, "c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2")
	in := func(a *ActionApprovalRequest) ReleaseWindowDecisionInput {
		return ReleaseWindowDecisionInput{ID: a.ID, DecidedBy: "oidc:owner", DecidedByPrincipalID: "prn_owner", Approve: true, Evidence: evidenceFor(a)}
	}
	if _, err := s.DecideReleaseWindowApproval(ctx, in(rem)); !errors.Is(err, ErrApprovalKindNotSpendable) {
		t.Errorf("the add decide path on a removal: %v, want ErrApprovalKindNotSpendable", err)
	}
	if _, err := s.DecideReleaseWindowRemovalApproval(ctx, in(add)); !errors.Is(err, ErrApprovalKindNotSpendable) {
		t.Errorf("the removal decide path on an addition: %v, want ErrApprovalKindNotSpendable", err)
	}
	for _, a := range []*ActionApprovalRequest{add, rem} {
		if cur, _ := s.ActionApproval(ctx, a.ID); cur.State != ApprovalPending {
			t.Errorf("a cross-kind decision moved %s to %s", a.ID, cur.State)
		}
	}
	// A removal is not a release grant decision either.
	if _, err := s.DecideReleaseApproval(ctx, ReleaseDecisionInput{ID: rem.ID, DecidedBy: "oidc:owner",
		DecidedByPrincipalID: "prn_owner", Approve: true, Evidence: evidenceFor(rem)}); !errors.Is(err, ErrApprovalKindNotSpendable) {
		t.Errorf("the grant decide path on a removal: %v, want ErrApprovalKindNotSpendable", err)
	}
}

func approvedRemoval(t *testing.T, s *Store, base string) *ActionApprovalRequest {
	t.Helper()
	a := newPendingRemoval(t, s, base)
	got, err := s.DecideReleaseWindowRemovalApproval(context.Background(), ReleaseWindowDecisionInput{ID: a.ID, DecidedBy: "oidc:owner",
		DecidedByPrincipalID: "prn_owner", Approve: true, Evidence: evidenceFor(a)})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	return got
}

func TestDecideRemovalRecordsEvidenceUnderTheRemovalBasis(t *testing.T) {
	s := newStoreForTest(t)
	got := approvedRemoval(t, s, "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3")
	if got.State != ApprovalApproved || got.AuthorityBasis != ReleaseWindowRemovalAuthorityBasis ||
		got.AuthorityBasis == ReleaseWindowAuthorityBasis {
		t.Fatalf("decided row: %+v", got)
	}
	if ev, err := ReleaseWindowRemovalDecisionOf(got); err != nil || ev == nil {
		t.Fatalf("ReleaseWindowRemovalDecisionOf: %v %v", ev, err)
	}
	// The add reader does not read a removal's decision, and a removal decided
	// under the add basis is not a removal decision.
	if _, err := ReleaseWindowDecisionOf(got); err == nil {
		t.Error("the add decision reader accepted a removal")
	}
	forged := *got
	forged.AuthorityBasis = ReleaseWindowAuthorityBasis
	if _, err := ReleaseWindowRemovalDecisionOf(&forged); !errors.Is(err, ErrInvalid) {
		t.Errorf("a removal decided under the add basis: %v, want ErrInvalid", err)
	}
}

func TestClaimAndSettleRemovalApproval(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	a := approvedRemoval(t, s, "c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4")
	claim, err := s.ClaimReleaseWindowRemovalApproval(ctx, a.ID, rwRequester, a.IntentHash, ReleaseWindowReclaimAfter)
	if err != nil || claim.State != ApprovalInFlight {
		t.Fatalf("claim: %+v %v", claim, err)
	}
	if _, err := s.ClaimReleaseWindowRemovalApproval(ctx, a.ID, rwRequester, a.IntentHash, ReleaseWindowReclaimAfter); !errors.Is(err, ErrApprovalInFlight) {
		t.Fatalf("second claim: %v, want ErrApprovalInFlight", err)
	}
	// The add settle path cannot end a removal's claim.
	if _, err := s.SettleReleaseWindowApproval(ctx, claim, true); !errors.Is(err, ErrInvalid) {
		t.Fatalf("the add settle on a removal claim: %v, want ErrInvalid", err)
	}
	back, err := s.SettleReleaseWindowRemovalApproval(ctx, claim, false)
	if err != nil || back.State != ApprovalApproved {
		t.Fatalf("a failed dispatch must hand the decision back: %+v %v", back, err)
	}
	claim, err = s.ClaimReleaseWindowRemovalApproval(ctx, a.ID, rwRequester, a.IntentHash, ReleaseWindowReclaimAfter)
	if err != nil {
		t.Fatalf("re-claim: %v", err)
	}
	done, err := s.SettleReleaseWindowRemovalApproval(ctx, claim, true)
	if err != nil || done.State != ApprovalExecuted {
		t.Fatalf("settle: %+v %v", done, err)
	}
	if _, err := s.ClaimReleaseWindowRemovalApproval(ctx, a.ID, rwRequester, a.IntentHash, ReleaseWindowReclaimAfter); !errors.Is(err, ErrApprovalConsumed) {
		t.Fatalf("claim after execution: %v, want ErrApprovalConsumed", err)
	}
}

func TestClaimRefusesTheOtherKindAndTheOtherRequester(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	rem := approvedRemoval(t, s, "c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5")
	add := approvedWindow(t, s, "c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5")
	if _, err := s.ClaimReleaseWindowApproval(ctx, rem.ID, rwRequester, rem.IntentHash, ReleaseWindowReclaimAfter); err == nil {
		t.Error("the add claim spent a removal approval")
	}
	if _, err := s.ClaimReleaseWindowRemovalApproval(ctx, add.ID, rwRequester, add.IntentHash, ReleaseWindowReclaimAfter); err == nil {
		t.Error("the removal claim spent an add approval")
	}
	if _, err := s.ClaimReleaseWindowRemovalApproval(ctx, rem.ID, "oidc:someone-else", rem.IntentHash, ReleaseWindowReclaimAfter); !errors.Is(err, ErrApprovalNotFound) {
		t.Errorf("another requester: %v, want ErrApprovalNotFound", err)
	}
	for _, a := range []*ActionApprovalRequest{rem, add} {
		if cur, _ := s.ActionApproval(ctx, a.ID); cur.State != ApprovalApproved {
			t.Errorf("a refused claim moved %s to %s", a.ID, cur.State)
		}
	}
}

// A removal row is in the release.* namespace, so no generic path spends it.
func TestApprovedRemovalIsNotSpendableByAnyGenericPath(t *testing.T) {
	s := newStoreForTest(t)
	if !isDedicatedKind(ActionKindReleaseWindowRemoval) {
		t.Fatal("release.window.removal is not a dedicated kind")
	}
	a := approvedRemoval(t, s, "c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6")
	ctx := context.Background()
	calls := map[string]error{}
	_, calls["consume"] = s.ConsumeActionApproval(ctx, a.ID, a.IntentHash)
	_, calls["consume-deploy"] = s.ConsumeDeployApproval(ctx, a.ID, a.IntentHash)
	_, calls["mark"] = s.MarkActionApprovalExecuted(ctx, a.ID, a.Target, a.ArtifactHash, a.RequestedBy)
	_, calls["reserve"] = s.ReserveActionApproval(ctx, a.ID, a.Target, a.ArtifactHash, a.RequestedBy, time.Hour)
	_, calls["settle"] = s.SettleActionApproval(ctx, a.ID, a.RequestedBy, true)
	for name, err := range calls {
		if err == nil {
			t.Errorf("%s on an approved release.window.removal row succeeded", name)
		}
	}
	if cur, _ := s.ActionApproval(ctx, a.ID); cur.State != ApprovalApproved {
		t.Errorf("a generic path moved the row to %s", cur.State)
	}
}
