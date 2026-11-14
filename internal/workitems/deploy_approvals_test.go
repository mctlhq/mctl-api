package workitems

import (
	"context"
	"errors"
	"testing"
	"time"
)

func deployInput(s *Store, requester string) ActionApprovalInput {
	return ActionApprovalInput{
		ActionIntent: ActionIntent{
			ExecutionID: storeTestExecution, ActionKind: ActionKindDeployApply, Target: "acme/web",
			ArgsDigest: "sha256:plan", PolicyRuleID: DeployApplyPolicyRuleID, PolicyVersion: DeployApplyPolicyVersion,
			ArtifactHash: "sha256:plan",
		},
		RequestedBy: requester, RequestedByPrincipalID: "prn_requester",
		IdempotencyKey: DeployIdempotencyKey(storeTestExecution), ExpiresAt: s.now().Add(time.Hour),
		RiskLevel: "medium", IntentSource: "deploy_plan:" + storeTestExecution,
		SideEffect: "write", PolicyDecision: "require_approval", PolicyReasons: []string{"rule"},
	}
}

// Deploy kinds are created, decided and spent only through their own
// methods: the generic ones refuse them in every state they can be in.
func TestGenericPathsRefuseDeployKinds(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()

	for _, kind := range []string{ActionKindDeployApply, "deploy.other", "deploy."} {
		in := deployInput(s, "oidc:a")
		in.ActionKind = kind
		if _, _, err := s.CreateActionApproval(ctx, in); !errors.Is(err, ErrApprovalKindNotCreatable) {
			t.Errorf("generic create of %q: %v, want ErrApprovalKindNotCreatable", kind, err)
		}
	}

	check := func(t *testing.T, a *ActionApprovalRequest, state string) {
		t.Helper()
		calls := map[string]error{}
		_, calls["decide"] = s.DecideActionApproval(ctx, ActionDecisionInput{ID: a.ID, DecidedBy: "oidc:other",
			DecidedByPrincipalID: "prn_other", Decision: DecisionApprove})
		_, calls["consume"] = s.ConsumeActionApproval(ctx, a.ID, a.IntentHash)
		_, calls["mark"] = s.MarkActionApprovalExecuted(ctx, a.ID, a.Target, a.ArtifactHash, a.RequestedBy)
		_, calls["reserve"] = s.ReserveActionApproval(ctx, a.ID, a.Target, a.ArtifactHash, a.RequestedBy, time.Hour)
		_, calls["settle"] = s.SettleActionApproval(ctx, a.ID, a.RequestedBy, true)
		for name, err := range calls {
			if !errors.Is(err, ErrApprovalKindNotSpendable) {
				t.Errorf("%s on a %s deploy row: %v, want ErrApprovalKindNotSpendable", name, state, err)
			}
		}
		cur, err := s.ActionApproval(ctx, a.ID)
		if err != nil || cur.State != state {
			t.Errorf("a generic path moved the row: %v %v, want %s", cur, err, state)
		}
	}

	a, created, err := s.CreateDeployApproval(ctx, deployInput(s, "oidc:a"))
	if err != nil || !created {
		t.Fatalf("CreateDeployApproval: %v %v", created, err)
	}
	check(t, a, ApprovalPending)
	if _, err := s.DecideDeployApproval(ctx, ActionDecisionInput{ID: a.ID, DecidedBy: "oidc:owner",
		DecidedByPrincipalID: "prn_owner", Decision: DecisionApprove}); err != nil {
		t.Fatalf("DecideDeployApproval: %v", err)
	}
	check(t, a, ApprovalApproved)
	if _, err := s.ConsumeDeployApproval(ctx, a.ID, a.IntentHash); err != nil {
		t.Fatalf("ConsumeDeployApproval: %v", err)
	}
	check(t, a, ApprovalConsumed)
}

// The deploy methods hold to their own kind and record what the spend
// re-checks.
func TestDeployApprovalMethods(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()

	for name, mutate := range map[string]func(*ActionApprovalInput){
		"kind":     func(in *ActionApprovalInput) { in.ActionKind = "github.merge_pr" },
		"policy":   func(in *ActionApprovalInput) { in.PolicyRuleID = "merge-needs-human" },
		"key":      func(in *ActionApprovalInput) { in.IdempotencyKey = "free-form" },
		"workitem": func(in *ActionApprovalInput) { in.WorkItemID = "wi_x" },
	} {
		in := deployInput(s, "oidc:"+name)
		mutate(&in)
		if _, _, err := s.CreateDeployApproval(ctx, in); err == nil {
			t.Errorf("CreateDeployApproval with a foreign %s succeeded", name)
		}
	}

	// A generic row is not decided or spent through the deploy methods.
	g := createApproval(t, s, approvalInput(s, "k-generic"))
	if _, err := s.DecideDeployApproval(ctx, ActionDecisionInput{ID: g.ID, DecidedBy: "oidc:owner",
		DecidedByPrincipalID: "prn_owner", Decision: DecisionApprove}); !errors.Is(err, ErrApprovalKindNotSpendable) {
		t.Errorf("DecideDeployApproval on a generic row: %v", err)
	}

	a, _, err := s.CreateDeployApproval(ctx, deployInput(s, "oidc:a"))
	if err != nil {
		t.Fatal(err)
	}
	// A decider with no principal cannot be re-checked at spend.
	if _, err := s.DecideDeployApproval(ctx, ActionDecisionInput{ID: a.ID, DecidedBy: "oidc:owner",
		Decision: DecisionApprove}); !errors.Is(err, ErrApprovalDeciderUnresolved) {
		t.Fatalf("decide without a principal: %v", err)
	}
	// The requester's own principal may decide (presence is checked by the
	// page), and the owner basis is recorded whatever the caller passed.
	got, err := s.DecideDeployApproval(ctx, ActionDecisionInput{ID: a.ID, DecidedBy: "oidc:a",
		DecidedByPrincipalID: "prn_requester", Decision: DecisionApprove, AuthorityBasis: "platform_admin"})
	if err != nil {
		t.Fatalf("decide by the requester's principal: %v", err)
	}
	if got.AuthorityBasis != DeployAuthorityBasis || got.DecidedByPrincipalID != "prn_requester" {
		t.Fatalf("recorded basis %q decider %q", got.AuthorityBasis, got.DecidedByPrincipalID)
	}
	if _, err := s.ConsumeDeployApproval(ctx, a.ID, "sha256:other"); err == nil {
		t.Fatal("spent with another intent hash")
	}
	if _, err := s.ConsumeDeployApproval(ctx, a.ID, a.IntentHash); err != nil {
		t.Fatalf("ConsumeDeployApproval: %v", err)
	}
	if _, err := s.ConsumeDeployApproval(ctx, a.ID, a.IntentHash); err == nil {
		t.Fatal("spent twice")
	}
}
