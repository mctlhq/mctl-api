package workitems

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func newPendingWindow(t *testing.T, s *Store, base string) *ActionApprovalRequest {
	t.Helper()
	w := rwWindow()
	w.BaseSHA = base
	a, _, err := s.CreateReleaseWindowApproval(context.Background(), w, rwInput(s, w, "oidc:a"))
	if err != nil {
		t.Fatalf("CreateReleaseWindowApproval: %v", err)
	}
	return a
}

func TestDecideReleaseWindowApprovalRecordsEvidence(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	a := newPendingWindow(t, s, rwBase)
	if e, err := ReleaseWindowDecisionOf(a); err != nil || e != nil {
		t.Fatalf("a pending window has a decision: %v %v", e, err)
	}
	ev := evidenceFor(a)
	got, err := s.DecideReleaseWindowApproval(ctx, ReleaseWindowDecisionInput{ID: a.ID, DecidedBy: "oidc:owner",
		DecidedByPrincipalID: "prn_owner", Approve: true, Evidence: ev})
	if err != nil {
		t.Fatalf("DecideReleaseWindowApproval: %v", err)
	}
	if got.State != ApprovalApproved || got.DecidedByPrincipalID != "prn_owner" || got.AuthorityBasis != ReleaseWindowAuthorityBasis {
		t.Fatalf("decided row: %+v", got)
	}
	back, err := ReleaseWindowDecisionOf(got)
	if err != nil || back == nil || back.ClientID != ev.ClientID || strings.Join(back.AMR, ",") != "mfa,pwd,user" {
		t.Fatalf("ReleaseWindowDecisionOf: %+v %v", back, err)
	}
	// Decided once.
	if _, err := s.DecideReleaseWindowApproval(ctx, ReleaseWindowDecisionInput{ID: a.ID, DecidedBy: "oidc:owner",
		DecidedByPrincipalID: "prn_owner", Evidence: ev}); !errors.Is(err, ErrApprovalAlreadyDecided) {
		t.Fatalf("second decision: %v, want ErrApprovalAlreadyDecided", err)
	}

	r := newPendingWindow(t, s, strings.Repeat("e", 40))
	rej, err := s.DecideReleaseWindowApproval(ctx, ReleaseWindowDecisionInput{ID: r.ID, DecidedBy: "oidc:owner",
		DecidedByPrincipalID: "prn_owner", Evidence: evidenceFor(r)})
	if err != nil || rej.State != ApprovalDenied {
		t.Fatalf("reject: %v %v", rej, err)
	}
	if e, err := ReleaseWindowDecisionOf(rej); err != nil || e == nil {
		t.Fatalf("a rejection carries no evidence: %v %v", e, err)
	}
}

func TestDecideReleaseWindowApprovalRefusals(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	a := newPendingWindow(t, s, rwBase)
	decide := func(in ReleaseWindowDecisionInput) error {
		_, err := s.DecideReleaseWindowApproval(ctx, in)
		return err
	}
	base := ReleaseWindowDecisionInput{ID: a.ID, DecidedBy: "oidc:owner", DecidedByPrincipalID: "prn_owner", Approve: true, Evidence: evidenceFor(a)}

	in := base
	in.DecidedByPrincipalID = ""
	if err := decide(in); !errors.Is(err, ErrApprovalDeciderUnresolved) {
		t.Errorf("unresolved decider: %v", err)
	}
	in = base
	in.Evidence.ArgsDigest = "sha256:" + strings.Repeat("e", 64)
	if err := decide(in); !errors.Is(err, ErrApprovalTargetMismatch) {
		t.Errorf("shown another request: %v", err)
	}
	for name, mutate := range map[string]func(*ReleaseEvidence){
		"no amr":       func(e *ReleaseEvidence) { e.AMR = nil },
		"no auth_time": func(e *ReleaseEvidence) { e.AuthTime = 0 },
		"no client":    func(e *ReleaseEvidence) { e.ClientID = "" },
		"other schema": func(e *ReleaseEvidence) { e.Schema = "v0" },
		"no subject":   func(e *ReleaseEvidence) { e.Subject = "" },
	} {
		in := base
		mutate(&in.Evidence)
		if err := decide(in); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
	if cur, _ := s.ActionApproval(ctx, a.ID); cur.State != ApprovalPending {
		t.Fatalf("a refused decision moved the row: %s", cur.State)
	}
}

// A window request is decided only by the window decide path, and a release
// grant only by the grant's: neither path moves the other's rows.
func TestReleaseWindowAndGrantDecidePathsRefuseEachOther(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	win := newPendingWindow(t, s, rwBase)
	grant := newPendingRelease(t, s, "9.4.0")

	_, err := s.DecideReleaseApproval(ctx, ReleaseDecisionInput{ID: win.ID, DecidedBy: "oidc:owner",
		DecidedByPrincipalID: "prn_owner", Approve: true, Evidence: evidenceFor(win)})
	if !errors.Is(err, ErrApprovalKindNotSpendable) {
		t.Errorf("grant decide path on a window row: %v, want ErrApprovalKindNotSpendable", err)
	}
	_, err = s.DecideReleaseWindowApproval(ctx, ReleaseWindowDecisionInput{ID: grant.ID, DecidedBy: "oidc:owner",
		DecidedByPrincipalID: "prn_owner", Approve: true, Evidence: evidenceFor(grant)})
	if !errors.Is(err, ErrApprovalKindNotSpendable) {
		t.Errorf("window decide path on a grant row: %v, want ErrApprovalKindNotSpendable", err)
	}
	for _, id := range []string{win.ID, grant.ID} {
		if cur, _ := s.ActionApproval(ctx, id); cur.State != ApprovalPending {
			t.Errorf("a cross-kind decision moved %s to %s", id, cur.State)
		}
	}
	// And the readers: a window row is not a grant decision, nor the reverse.
	if _, err := ReleaseDecisionOf(win); err == nil {
		t.Error("ReleaseDecisionOf accepted a window row")
	}
	if _, err := ReleaseWindowDecisionOf(grant); err == nil {
		t.Error("ReleaseWindowDecisionOf accepted a grant row")
	}
}

// A decided window whose evidence or basis was edited is not a decision.
func TestReleaseWindowDecisionOfRefusesTamperedEvidence(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	a := newPendingWindow(t, s, rwBase)
	d, err := s.DecideReleaseWindowApproval(ctx, ReleaseWindowDecisionInput{ID: a.ID, DecidedBy: "oidc:owner",
		DecidedByPrincipalID: "prn_owner", Approve: true, Evidence: evidenceFor(a)})
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*ActionApprovalRequest){
		"amr edited":      func(r *ActionApprovalRequest) { r.Reason = strings.Replace(r.Reason, `"mfa",`, ``, 1) },
		"digest edited":   func(r *ActionApprovalRequest) { r.DecidedContextDigest = "sha256:" + strings.Repeat("0", 64) },
		"grant basis":     func(r *ActionApprovalRequest) { r.AuthorityBasis = ReleaseAuthorityBasis },
		"not canonical":   func(r *ActionApprovalRequest) { r.Reason = " " + r.Reason },
		"unknown field":   func(r *ActionApprovalRequest) { r.Reason = strings.Replace(r.Reason, `{`, `{"x":1,`, 1) },
		"reason replaced": func(r *ActionApprovalRequest) { r.Reason = "approved" },
		"other args": func(r *ActionApprovalRequest) {
			r.Reason = strings.Replace(r.Reason, d.ArgsDigest, "sha256:"+strings.Repeat("f", 64), 1)
		},
	} {
		cp := *d
		mutate(&cp)
		if _, err := ReleaseWindowDecisionOf(&cp); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
	if e, err := ReleaseWindowDecisionOf(d); err != nil || e == nil {
		t.Fatalf("the untouched row stopped reading: %v %v", e, err)
	}
}

// A row whose columns no longer reproduce its digests is not decidable, even
// when the digest the decider was shown is still the row's own.
func TestDecideReleaseWindowApprovalRefusesAnInconsistentRow(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	a := newPendingWindow(t, s, rwBase)
	if _, err := s.pool.Exec(ctx, `UPDATE action_approval_requests SET artifact_hash = $2 WHERE id = $1`,
		a.ID, "sha256:"+strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	_, err := s.DecideReleaseWindowApproval(ctx, ReleaseWindowDecisionInput{ID: a.ID, DecidedBy: "oidc:owner",
		DecidedByPrincipalID: "prn_owner", Approve: true, Evidence: evidenceFor(a)})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("decide on an inconsistent row: %v, want ErrInvalid", err)
	}
	if cur, _ := s.ActionApproval(ctx, a.ID); cur.State != ApprovalPending {
		t.Fatalf("an inconsistent row was decided: %s", cur.State)
	}
}
