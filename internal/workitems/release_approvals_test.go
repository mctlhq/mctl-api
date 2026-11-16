package workitems

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func releaseArtifactForTest(version string) ReleaseArtifact {
	return ReleaseArtifact{
		Repository:  "mctlhq/mctl-api",
		Version:     version,
		TagCommit:   strings.Repeat("a", 40),
		ImageDigest: "sha256:" + strings.Repeat("b", 64),
	}
}

func releaseInput(s *Store, art ReleaseArtifact, requester string) ActionApprovalInput {
	return ActionApprovalInput{
		ActionIntent: ReleaseIntent(art),
		RequestedBy:  requester, RequestedByPrincipalID: "prn_requester",
		IdempotencyKey: ReleaseIdempotencyKey(art), ExpiresAt: s.now().Add(time.Hour),
		RiskLevel: "high", IntentSource: "release:" + ReleaseTarget(art.Repository, art.Version),
		SideEffect: "write", PolicyDecision: "require_approval", PolicyReasons: []string{ReleaseGrantPolicyRuleID},
	}
}

// Release kinds are created only through CreateReleaseApproval, and nothing
// in this slice decides or spends them: every generic path refuses them,
// and so does the deploy decide path.
func TestGenericPathsRefuseReleaseKinds(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	art := releaseArtifactForTest("9.0.1")

	for _, kind := range []string{ActionKindReleaseGrant, "release.other", "release."} {
		in := releaseInput(s, art, "oidc:a")
		in.ActionKind = kind
		if _, _, err := s.CreateActionApproval(ctx, in); !errors.Is(err, ErrApprovalKindNotCreatable) {
			t.Errorf("generic create of %q: %v, want ErrApprovalKindNotCreatable", kind, err)
		}
	}

	a, created, err := s.CreateReleaseApproval(ctx, art, releaseInput(s, art, "oidc:a"))
	if err != nil || !created {
		t.Fatalf("CreateReleaseApproval: %v %v", created, err)
	}
	calls := map[string]error{}
	_, calls["decide"] = s.DecideActionApproval(ctx, ActionDecisionInput{ID: a.ID, DecidedBy: "oidc:other",
		DecidedByPrincipalID: "prn_other", Decision: DecisionApprove})
	_, calls["decide-deploy"] = s.DecideDeployApproval(ctx, ActionDecisionInput{ID: a.ID, DecidedBy: "oidc:other",
		DecidedByPrincipalID: "prn_other", Decision: DecisionApprove})
	_, calls["consume"] = s.ConsumeActionApproval(ctx, a.ID, a.IntentHash)
	_, calls["consume-deploy"] = s.ConsumeDeployApproval(ctx, a.ID, a.IntentHash)
	_, calls["mark"] = s.MarkActionApprovalExecuted(ctx, a.ID, a.Target, a.ArtifactHash, a.RequestedBy)
	_, calls["reserve"] = s.ReserveActionApproval(ctx, a.ID, a.Target, a.ArtifactHash, a.RequestedBy, time.Hour)
	_, calls["settle"] = s.SettleActionApproval(ctx, a.ID, a.RequestedBy, true)
	for name, err := range calls {
		if err == nil {
			t.Errorf("%s on a pending release row succeeded", name)
		}
	}
	cur, err := s.ActionApproval(ctx, a.ID)
	if err != nil || cur.State != ApprovalPending {
		t.Errorf("a generic path moved the row: %v %v, want pending", cur, err)
	}
}

func TestCreateReleaseApprovalBindsTheArtifact(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	art := releaseArtifactForTest("9.0.2")

	bad := func(name string, mutate func(*ReleaseArtifact, *ActionApprovalInput)) {
		t.Helper()
		a, in := art, releaseInput(s, art, "oidc:a")
		mutate(&a, &in)
		if _, _, err := s.CreateReleaseApproval(ctx, a, in); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
	bad("intent from another digest", func(a *ReleaseArtifact, in *ActionApprovalInput) {
		in.ArgsDigest = "sha256:" + strings.Repeat("c", 64)
	})
	bad("artifact hash not the image", func(a *ReleaseArtifact, in *ActionApprovalInput) { in.ArtifactHash = "sha256:x" })
	bad("other target", func(a *ReleaseArtifact, in *ActionApprovalInput) { in.Target = "mctlhq/mctl-api@9.9.9" })
	bad("other policy", func(a *ReleaseArtifact, in *ActionApprovalInput) { in.PolicyRuleID = DeployApplyPolicyRuleID })
	bad("idempotency key not derived", func(a *ReleaseArtifact, in *ActionApprovalInput) { in.IdempotencyKey = "x" })
	bad("short commit", func(a *ReleaseArtifact, in *ActionApprovalInput) {
		a.TagCommit = "abc"
		in.ActionIntent = ReleaseIntent(*a)
	})
	bad("upper-case repository", func(a *ReleaseArtifact, in *ActionApprovalInput) {
		a.Repository = "MctlHQ/mctl-api"
		in.ActionIntent, in.IdempotencyKey = ReleaseIntent(*a), ReleaseIdempotencyKey(*a)
	})

	first, created, err := s.CreateReleaseApproval(ctx, art, releaseInput(s, art, "oidc:a"))
	if err != nil || !created {
		t.Fatalf("create: %v %v", created, err)
	}
	again, created, err := s.CreateReleaseApproval(ctx, art, releaseInput(s, art, "oidc:a"))
	if err != nil || created || again.ID != first.ID {
		t.Fatalf("replay: %v %v %v, want the stored row", again, created, err)
	}
	// The same version with another image is another request.
	moved := art
	moved.ImageDigest = "sha256:" + strings.Repeat("d", 64)
	other, created, err := s.CreateReleaseApproval(ctx, moved, releaseInput(s, moved, "oidc:a"))
	if err != nil || !created || other.ID == first.ID {
		t.Fatalf("moved tag: %v %v %v, want a new row", other, created, err)
	}

	list, err := s.ReleaseApprovals(ctx, art.Repository, art.Version, 0)
	if err != nil || len(list) != 2 || list[0].ID != other.ID {
		t.Fatalf("ReleaseApprovals: %v %v", list, err)
	}
	for _, row := range list {
		got, err := ReleaseArtifactOf(&row)
		if err != nil || got.Version != art.Version || got.ImageDigest != row.ArtifactHash {
			t.Errorf("ReleaseArtifactOf(%s): %+v %v", row.ID, got, err)
		}
	}
	if none, err := s.ReleaseApprovals(ctx, art.Repository, "9.0.3", 0); err != nil || len(none) != 0 {
		t.Errorf("another version: %v %v, want none", none, err)
	}
	if _, err := s.ReleaseApprovals(ctx, "x", art.Version, 0); !errors.Is(err, ErrInvalid) {
		t.Errorf("malformed repository: %v, want ErrInvalid", err)
	}
}

func TestReleaseArtifactOfRefusesInconsistentRows(t *testing.T) {
	art := releaseArtifactForTest("9.0.4")
	in := ReleaseIntent(art)
	row := ActionApprovalRequest{ID: "aar_x", ActionKind: in.ActionKind, Target: in.Target, ExecutionID: in.ExecutionID,
		ArtifactHash: in.ArtifactHash, ArgsDigest: in.ArgsDigest}
	if _, err := ReleaseArtifactOf(&row); err != nil {
		t.Fatalf("consistent row: %v", err)
	}
	for name, mutate := range map[string]func(*ActionApprovalRequest){
		"other kind":     func(r *ActionApprovalRequest) { r.ActionKind = ActionKindDeployApply },
		"no @ in target": func(r *ActionApprovalRequest) { r.Target = "mctlhq/mctl-api" },
		"digest swapped": func(r *ActionApprovalRequest) { r.ArtifactHash = "sha256:" + strings.Repeat("e", 64) },
		"commit swapped": func(r *ActionApprovalRequest) { r.ExecutionID = strings.Repeat("f", 40) },
	} {
		r := row
		mutate(&r)
		if _, err := ReleaseArtifactOf(&r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
