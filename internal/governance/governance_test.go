package governance

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func complete() *workitems.ActionApprovalRequest {
	fresh := t0.Add(time.Hour)
	return &workitems.ActionApprovalRequest{
		ID: "aar_1", ExecutionID: "we_1", ActionKind: "github.merge_pr", Target: "o/r#1",
		ArgsDigest: "sha256:a", PolicyRuleID: "p", PolicyVersion: "v1", IntentHash: "sha256:i",
		RiskLevel: "high", SideEffect: "write", IntentSource: "execution:we_1",
		PolicyDecision: "require_approval", PolicyReasons: []string{"r.one"},
		ExpiresAt: t0.Add(2 * time.Hour), FreshUntil: &fresh, DecidedByPrincipalID: "prn_a",
	}
}

type checker struct{ err error }

func (checker) ResolvePrincipal(context.Context, auth.Identity) (string, error) { return "", nil }
func (c checker) CheckHumanPrincipal(context.Context, string) error             { return c.err }

type plainResolver struct{}

func (plainResolver) ResolvePrincipal(context.Context, auth.Identity) (string, error) { return "", nil }

func live(c auth.PrincipalResolver) LiveAuthority {
	return LiveAuthority{
		PrincipalMode: true, Admins: map[string]bool{"prn_a": true}, Checker: c,
		Policies: PolicySet{"p": {Version: "v1"}}, Now: t0,
	}
}

func TestContextDigestChangesWithEveryMandatoryField(t *testing.T) {
	base := DecisionContextOf(complete(), Live{})
	if base.ContextDigest != DecisionContextOf(complete(), Live{}).ContextDigest {
		t.Fatal("digest is not stable")
	}
	for name, mutate := range map[string]func(a *workitems.ActionApprovalRequest){
		"intent_hash":     func(a *workitems.ActionApprovalRequest) { a.IntentHash = "x" },
		"target":          func(a *workitems.ActionApprovalRequest) { a.Target = "x" },
		"args_digest":     func(a *workitems.ActionApprovalRequest) { a.ArgsDigest = "x" },
		"artifact_hash":   func(a *workitems.ActionApprovalRequest) { a.ArtifactHash = "x" },
		"risk_level":      func(a *workitems.ActionApprovalRequest) { a.RiskLevel = "low" },
		"side_effect":     func(a *workitems.ActionApprovalRequest) { a.SideEffect = "read" },
		"intent_source":   func(a *workitems.ActionApprovalRequest) { a.IntentSource = "x" },
		"policy_rule_id":  func(a *workitems.ActionApprovalRequest) { a.PolicyRuleID = "x" },
		"policy_version":  func(a *workitems.ActionApprovalRequest) { a.PolicyVersion = "v2" },
		"policy_decision": func(a *workitems.ActionApprovalRequest) { a.PolicyDecision = "x" },
		"policy_reasons":  func(a *workitems.ActionApprovalRequest) { a.PolicyReasons = []string{"r.two"} },
	} {
		a := complete()
		mutate(a)
		if DecisionContextOf(a, Live{}).ContextDigest == base.ContextDigest {
			t.Errorf("digest unchanged when %s changes", name)
		}
	}
}

func TestDecisionContextOfReportsMissingFields(t *testing.T) {
	if c := DecisionContextOf(complete(), Live{}); !c.ContextComplete || len(c.MissingFields) != 0 {
		t.Fatalf("complete context = %+v", c)
	}
	a := complete()
	a.SideEffect, a.IntentSource, a.PolicyReasons = "", "", nil
	c := DecisionContextOf(a, Live{})
	want := []string{"side_effect", "intent_source", "policy.reasons"}
	if c.ContextComplete || len(c.MissingFields) != len(want) {
		t.Fatalf("missing = %v", c.MissingFields)
	}
	for i := range want {
		if c.MissingFields[i] != want[i] {
			t.Fatalf("missing = %v, want %v", c.MissingFields, want)
		}
	}
}

func TestRiskIsTheRegistrysForARegisteredKind(t *testing.T) {
	a := complete()
	a.ActionKind, a.RiskLevel = "mctl-agents-approve", "low"
	got := DecisionContextOf(a, Live{Registry: operations.NewRegistry()}).RiskLevel
	if got != "medium" {
		t.Fatalf("risk = %q, want the registry's medium", got)
	}
}

func TestFillCreateContext(t *testing.T) {
	reg := operations.NewRegistry()
	intent := workitems.ActionIntent{ExecutionID: "we_1", ActionKind: "mctl-agents-approve", PolicyRuleID: DevLoopPolicyRule, PolicyVersion: "v1"}
	c, err := FillCreateContext(CreateContext{}, intent, reg, Policies)
	if err != nil || c.RiskLevel != "medium" || c.SideEffect != "write" || c.PolicyDecision != "require_approval" ||
		len(c.PolicyReasons) == 0 || c.IntentSource != "execution:we_1" {
		t.Fatalf("filled = %+v, %v", c, err)
	}
	if _, err := FillCreateContext(CreateContext{RiskLevel: "low"}, intent, reg, Policies); !errors.Is(err, ErrContextInvalid) {
		t.Fatalf("downgraded risk err = %v", err)
	}
	intent.WorkItemID = "wi_9"
	if c, _ := FillCreateContext(CreateContext{}, intent, reg, Policies); c.IntentSource != "work_item:wi_9" {
		t.Fatalf("intent_source = %q", c.IntentSource)
	}
}

func TestRevalidate(t *testing.T) {
	boom := errors.New("store down")
	for name, tc := range map[string]struct {
		mutA func(*workitems.ActionApprovalRequest)
		mutL func(*LiveAuthority)
		want error
	}{
		"pass": {},
		"context changed (F6)": {
			mutA: func(a *workitems.ActionApprovalRequest) {
				a.DecidedContextDigest = DecisionContextOf(a, Live{}).ContextDigest
				a.SideEffect = "destructive"
			},
			want: ErrContextChanged,
		},
		"context unchanged": {
			mutA: func(a *workitems.ActionApprovalRequest) {
				a.DecidedContextDigest = DecisionContextOf(a, Live{}).ContextDigest
			},
		},
		"stale (F4)": {mutL: func(l *LiveAuthority) { l.Now = t0.Add(2 * time.Hour) }, want: ErrApprovalStale},
		"legacy row, no fresh_until": {
			mutA: func(a *workitems.ActionApprovalRequest) { a.FreshUntil = nil },
			mutL: func(l *LiveAuthority) { l.Now = t0.Add(90 * time.Minute) },
		},
		"no decider principal (F3)": {mutA: func(a *workitems.ActionApprovalRequest) { a.DecidedByPrincipalID = "" }, want: ErrAuthorityRevoked},
		"no decider principal, legacy mode": {
			mutA: func(a *workitems.ActionApprovalRequest) { a.DecidedByPrincipalID = "" },
			mutL: func(l *LiveAuthority) { l.PrincipalMode = false },
		},
		"removed from admins (F3)":         {mutL: func(l *LiveAuthority) { l.Admins = map[string]bool{} }, want: ErrAuthorityRevoked},
		"admin set ignored in legacy mode": {mutL: func(l *LiveAuthority) { l.PrincipalMode = false; l.Admins = nil }},
		"disabled (F3)":                    {mutL: func(l *LiveAuthority) { l.Checker = checker{auth.ErrPrincipalDisabled} }, want: ErrDeciderDisabled},
		"not human (F3)":                   {mutL: func(l *LiveAuthority) { l.Checker = checker{auth.ErrIdentityRefused} }, want: ErrDeciderDisabled},
		"disabled, legacy mode still checked": {
			mutL: func(l *LiveAuthority) { l.PrincipalMode = false; l.Checker = checker{auth.ErrPrincipalDisabled} },
			want: ErrDeciderDisabled,
		},
		"store down":      {mutL: func(l *LiveAuthority) { l.Checker = checker{boom} }, want: ErrAuthorityUnavailable},
		"no kind checker": {mutL: func(l *LiveAuthority) { l.Checker = plainResolver{} }, want: ErrAuthorityUnavailable},
		"no resolver":     {mutL: func(l *LiveAuthority) { l.Checker = nil }, want: ErrAuthorityUnavailable},
		"policy drift (F9)": {
			mutL: func(l *LiveAuthority) { l.Policies = PolicySet{"p": {Version: "v2"}} },
			want: ErrPolicyDrift,
		},
		"unregistered rule passes": {mutL: func(l *LiveAuthority) { l.Policies = PolicySet{} }},
		"unregistered rule, strict": {
			mutL: func(l *LiveAuthority) { l.Policies = PolicySet{}; l.StrictPolicy = true },
			want: ErrPolicyUnavailable,
		},
		"unregistered rule, strict, other rules registered": {
			mutL: func(l *LiveAuthority) { l.Policies = PolicySet{"q": {Version: "v1"}}; l.StrictPolicy = true },
			want: ErrPolicyUnregistered,
		},
		"legacy approved row without digest, incomplete (spend)": {
			mutA: func(a *workitems.ActionApprovalRequest) { a.DecidedContextDigest = ""; a.SideEffect = "" },
			want: ErrSpendContextIncomplete,
		},
	} {
		t.Run(name, func(t *testing.T) {
			a, l := complete(), live(checker{})
			if tc.mutA != nil {
				tc.mutA(a)
			}
			if tc.mutL != nil {
				tc.mutL(&l)
			}
			_, err := Revalidate(context.Background(), a, l)
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestRevalidateChecksInOrder(t *testing.T) {
	a, l := complete(), live(checker{auth.ErrPrincipalDisabled})
	l.Now = t0.Add(2 * time.Hour)                // stale
	l.Policies = PolicySet{"p": {Version: "v2"}} // and drifted
	if _, err := Revalidate(context.Background(), a, l); !errors.Is(err, ErrApprovalStale) {
		t.Fatalf("freshness must be checked before authority and policy, got %v", err)
	}
}

func TestPoliciesCheck(t *testing.T) {
	if s, err := Policies.Check(DevLoopPolicyRule, "v1"); err != nil || s != PolicyOK {
		t.Fatalf("v1 = %q, %v", s, err)
	}
	if _, err := Policies.Check(DevLoopPolicyRule, "v0"); !errors.Is(err, ErrPolicyDrift) {
		t.Fatalf("v0 err = %v", err)
	}
}
