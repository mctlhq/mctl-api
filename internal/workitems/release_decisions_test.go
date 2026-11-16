package workitems

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func evidenceFor(a *ActionApprovalRequest) ReleaseEvidence {
	return ReleaseEvidence{Schema: ReleaseEvidenceSchema, ArgsDigest: a.ArgsDigest,
		Issuer: "https://auth.example", Subject: "3001", ClientID: "release-page",
		AuthTime: 1_800_000_000, AMR: []string{"mfa", "pwd", "user"}}
}

func newPendingRelease(t *testing.T, s *Store, version string) *ActionApprovalRequest {
	t.Helper()
	art := releaseArtifactForTest(version)
	a, _, err := s.CreateReleaseApproval(context.Background(), art, releaseInput(s, art, "oidc:a"))
	if err != nil {
		t.Fatalf("CreateReleaseApproval: %v", err)
	}
	return a
}

func TestDecideReleaseApprovalRecordsEvidence(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	a := newPendingRelease(t, s, "9.1.0")
	if e, err := ReleaseDecisionOf(a); err != nil || e != nil {
		t.Fatalf("a pending grant has a decision: %v %v", e, err)
	}
	ev := evidenceFor(a)
	got, err := s.DecideReleaseApproval(ctx, ReleaseDecisionInput{ID: a.ID, DecidedBy: "oidc:owner",
		DecidedByPrincipalID: "prn_owner", Approve: true, Evidence: ev})
	if err != nil {
		t.Fatalf("DecideReleaseApproval: %v", err)
	}
	if got.State != ApprovalApproved || got.DecidedByPrincipalID != "prn_owner" || got.AuthorityBasis != ReleaseAuthorityBasis {
		t.Fatalf("decided row: %+v", got)
	}
	back, err := ReleaseDecisionOf(got)
	if err != nil || back == nil || back.ClientID != ev.ClientID || strings.Join(back.AMR, ",") != "mfa,pwd,user" {
		t.Fatalf("ReleaseDecisionOf: %+v %v", back, err)
	}
	// Decided once.
	if _, err := s.DecideReleaseApproval(ctx, ReleaseDecisionInput{ID: a.ID, DecidedBy: "oidc:owner",
		DecidedByPrincipalID: "prn_owner", Evidence: ev}); !errors.Is(err, ErrApprovalAlreadyDecided) {
		t.Fatalf("second decision: %v, want ErrApprovalAlreadyDecided", err)
	}

	r := newPendingRelease(t, s, "9.1.1")
	rej, err := s.DecideReleaseApproval(ctx, ReleaseDecisionInput{ID: r.ID, DecidedBy: "oidc:owner",
		DecidedByPrincipalID: "prn_owner", Evidence: evidenceFor(r)})
	if err != nil || rej.State != ApprovalDenied {
		t.Fatalf("reject: %v %v", rej, err)
	}
	if e, err := ReleaseDecisionOf(rej); err != nil || e == nil {
		t.Fatalf("a rejection carries no evidence: %v %v", e, err)
	}
}

func TestDecideReleaseApprovalRefusals(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	a := newPendingRelease(t, s, "9.2.0")
	decide := func(in ReleaseDecisionInput) error {
		_, err := s.DecideReleaseApproval(ctx, in)
		return err
	}
	base := ReleaseDecisionInput{ID: a.ID, DecidedBy: "oidc:owner", DecidedByPrincipalID: "prn_owner", Approve: true, Evidence: evidenceFor(a)}

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
		"no amr":        func(e *ReleaseEvidence) { e.AMR = nil },
		"unsorted amr":  func(e *ReleaseEvidence) { e.AMR = []string{"pwd", "mfa"} },
		"no auth_time":  func(e *ReleaseEvidence) { e.AuthTime = 0 },
		"no client":     func(e *ReleaseEvidence) { e.ClientID = "" },
		"other schema":  func(e *ReleaseEvidence) { e.Schema = "v0" },
		"no subject":    func(e *ReleaseEvidence) { e.Subject = "" },
		"bad amr value": func(e *ReleaseEvidence) { e.AMR = []string{"mfa", "x y"} },
		"duplicate amr": func(e *ReleaseEvidence) { e.AMR = []string{"mfa", "mfa"} },
	} {
		in := base
		mutate(&in.Evidence)
		if err := decide(in); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
	// Not a release row.
	gen, _, err := s.CreateActionApproval(ctx, ActionApprovalInput{
		ActionIntent: ActionIntent{ExecutionID: "ex_1", ActionKind: "service.deploy", Target: "t/s",
			ArgsDigest: "sha256:" + strings.Repeat("1", 64), PolicyRuleID: "r", PolicyVersion: "1"},
		RequestedBy: "oidc:a", IdempotencyKey: "k-generic", ExpiresAt: a.ExpiresAt,
		RiskLevel: "high", IntentSource: "execution:ex_1", SideEffect: "write", PolicyDecision: "require_approval", PolicyReasons: []string{"r"},
	})
	if err != nil {
		t.Fatalf("generic create: %v", err)
	}
	in = base
	in.ID = gen.ID
	in.Evidence.ArgsDigest = gen.ArgsDigest
	if err := decide(in); !errors.Is(err, ErrApprovalKindNotSpendable) {
		t.Errorf("generic row: %v, want ErrApprovalKindNotSpendable", err)
	}
	if cur, _ := s.ActionApproval(ctx, a.ID); cur.State != ApprovalPending {
		t.Fatalf("a refused decision moved the row: %s", cur.State)
	}
}

// A decided row whose evidence was edited is not a decision.
func TestReleaseDecisionOfRefusesTamperedEvidence(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	a := newPendingRelease(t, s, "9.3.0")
	d, err := s.DecideReleaseApproval(ctx, ReleaseDecisionInput{ID: a.ID, DecidedBy: "oidc:owner",
		DecidedByPrincipalID: "prn_owner", Approve: true, Evidence: evidenceFor(a)})
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*ActionApprovalRequest){
		"amr edited":    func(r *ActionApprovalRequest) { r.Reason = strings.Replace(r.Reason, `"mfa",`, ``, 1) },
		"digest edited": func(r *ActionApprovalRequest) { r.DecidedContextDigest = "sha256:" + strings.Repeat("0", 64) },
		"basis edited":  func(r *ActionApprovalRequest) { r.AuthorityBasis = DeployAuthorityBasis },
		"not canonical": func(r *ActionApprovalRequest) { r.Reason = " " + r.Reason },
		"unknown field": func(r *ActionApprovalRequest) { r.Reason = strings.Replace(r.Reason, `{`, `{"x":1,`, 1) },
		"other args": func(r *ActionApprovalRequest) {
			r.Reason = strings.Replace(r.Reason, d.ArgsDigest, "sha256:"+strings.Repeat("f", 64), 1)
		},
		"reason replaced": func(r *ActionApprovalRequest) { r.Reason = "approved" },
	} {
		r := *d
		mutate(&r)
		if e, err := ReleaseDecisionOf(&r); err == nil {
			t.Errorf("%s: accepted %+v", name, e)
		}
	}
	// Evidence of another request, re-encoded with its own digest: canonical
	// and self-consistent, but not about this row.
	other := evidenceFor(a)
	other.ArgsDigest = "sha256:" + strings.Repeat("f", 64)
	reason, digest, err := other.Encode()
	if err != nil {
		t.Fatal(err)
	}
	r := *d
	r.Reason, r.DecidedContextDigest = reason, digest
	if e, err := ReleaseDecisionOf(&r); err == nil {
		t.Errorf("evidence of another request: accepted %+v", e)
	}
}
