package api_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Direct deploys of agent-deploy tenants (mctl-api#1031): a tenant with
// tenant.profile: agent-deploy deploys through a plan and a human grant only.

// agentDeployGit is the grant fixture's reader with acme marked as given.
func agentDeployGit(profile string, err error) func(*mctlapi.Options) {
	return func(o *mctlapi.Options) {
		o.GitReader = &fakeGitReader{
			tenants:             []gitops.Tenant{{Name: "acme", Profile: profile}},
			services:            []gitops.Service{{Team: "acme", Name: "web"}},
			namespaceProfileErr: err,
		}
	}
}

func directDeploys() map[string]map[string]string {
	return map[string]map[string]string{
		"deploy-service onboard": {"action": "onboard", "team_name": "acme", "component_name": "web",
			"dockerfile_repo": "acme/web", "git_tag": "1.0.0"},
		"deploy-service deploy": {"action": "deploy", "team_name": "acme", "component_name": "web",
			"dockerfile_repo": "acme/web", "git_tag": "1.0.0"},
		"deploy-service update-config": {"action": "update-config", "team_name": "acme", "component_name": "web",
			"env_vars": "A=1"},
		"preview-deploy": {"team_name": "acme", "component_name": "web", "image_tag": "1.0.0"},
	}
}

func opPath(name string) string {
	op, _, _ := strings.Cut(name, " ")
	return "/api/v1/operations/" + op + "/execute"
}

// Every human caller is refused, the tenant owner and a platform admin
// included, on every gated operation; nothing is submitted, and the refusal
// is audited and names the plan route.
func TestAgentDeploy_DirectDeployRefusedForEveryHuman(t *testing.T) {
	f := newGrantFixture(t, faithfulValues, agentDeployGit(gitops.AgentDeployProfile, nil))
	for who, u := range map[string]*auth.User{"developer": f.dev, "owner": f.owner, "admin": f.root} {
		for name, body := range directDeploys() {
			w := postAs(t, f.router, opPath(name), body, u)
			if w.Code != http.StatusForbidden || errCode(t, w) != "agent_deploy_requires_plan" {
				t.Errorf("%s %s = %d %s, want 403 agent_deploy_requires_plan", who, name, w.Code, w.Body.String())
				continue
			}
			if !strings.Contains(w.Body.String(), "mctl_deploy_plan") {
				t.Errorf("%s %s: the refusal does not name the plan route: %s", who, name, w.Body.String())
			}
			e := f.log.List(1)[0]
			if e.Status != "denied" || !strings.Contains(e.Message, "agent_deploy_requires_plan") || e.UserID != u.ID {
				t.Errorf("%s %s audited as %+v", who, name, e)
			}
		}
	}
	if len(f.exec.submitted) != 0 {
		t.Fatalf("submitted = %v", f.exec.submitted)
	}
}

// The plan route is the way through: an owner-approved grant still applies.
func TestAgentDeploy_ApprovedPlanStillApplies(t *testing.T) {
	f := newGrantFixture(t, faithfulValues, agentDeployGit(gitops.AgentDeployProfile, nil))
	planID := f.newPlan(t, faithfulIntent())
	req := f.request(t, f.dev, planID, http.StatusCreated)
	id := req["approval"].(map[string]any)["id"].(string)
	digest := req["decision_context"].(map[string]any)["context_digest"].(string)
	if _, err := f.wi.DecideDeployApproval(context.Background(), workitems.ActionDecisionInput{
		ID: id, DecidedBy: "github:olga", DecidedByPrincipalID: grantOwnerPRN,
		Decision: workitems.DecisionApprove, ContextDigest: digest, FreshFor: time.Hour,
	}); err != nil {
		t.Fatalf("DecideDeployApproval: %v", err)
	}
	w := f.apply(t, f.dev, map[string]any{"plan_id": planID, "approval_id": id})
	assertStatus(t, w, http.StatusAccepted)
	if len(f.exec.submitted) != 1 || f.exec.submitted[0] != "preview-deploy" {
		t.Fatalf("submitted = %v", f.exec.submitted)
	}
}

// rollback-service stays allowed, so a bad deploy can be undone without a
// plan; an ordinary tenant is not touched by the gate at all.
func TestAgentDeploy_RollbackAndOrdinaryTenantsUnaffected(t *testing.T) {
	f := newGrantFixture(t, faithfulValues, agentDeployGit(gitops.AgentDeployProfile, nil))
	w := postAs(t, f.router, "/api/v1/operations/rollback-service/execute", map[string]string{
		"team_name": "acme", "component_name": "web", "target_tag": "0.9.0",
	}, f.owner)
	assertStatus(t, w, http.StatusAccepted)

	f = newGrantFixture(t, faithfulValues, agentDeployGit("", nil))
	w = postAs(t, f.router, opPath("preview-deploy"), directDeploys()["preview-deploy"], f.owner)
	assertStatus(t, w, http.StatusAccepted)
	if len(f.exec.submitted) != 1 {
		t.Fatalf("submitted = %v", f.exec.submitted)
	}
}

// A profile that cannot be read refuses the deploy instead of letting it
// through as ordinary, for the admin as for anyone.
func TestAgentDeploy_UnreadableProfileRefuses(t *testing.T) {
	f := newGrantFixture(t, faithfulValues, agentDeployGit("", errors.New("gitops checkout has never synced")))
	for name, body := range directDeploys() {
		for _, u := range []*auth.User{f.owner, f.root} {
			w := postAs(t, f.router, opPath(name), body, u)
			if w.Code != http.StatusServiceUnavailable || errCode(t, w) != "agent_deploy_profile_unavailable" {
				t.Errorf("%s by %s = %d %s, want 503 agent_deploy_profile_unavailable", name, u.ID, w.Code, w.Body.String())
			}
		}
	}
	if len(f.exec.submitted) != 0 {
		t.Fatalf("submitted = %v", f.exec.submitted)
	}
	if e := f.log.List(1)[0]; e.Status != "failed" {
		t.Fatalf("audited as %+v", e)
	}
}

// CI OIDC, authorized by its own gate, is the one caller that passes.
func TestAgentDeploy_CIDeployPasses(t *testing.T) {
	f := newCIFixtureFor(t, defaultRepos(), gitops.Tenant{Name: "labs", Profile: gitops.AgentDeployProfile})
	w := postAs(t, f.router, "/api/v1/operations/deploy-service/execute", ciBody(), ciUser())
	assertStatus(t, w, http.StatusAccepted)
	if len(f.exec.submitted) != 1 {
		t.Fatalf("submitted = %v", f.exec.submitted)
	}
}

// With no gitops reader the profile is unknown, and unknown is refused.
func TestAgentDeploy_NoReaderRefuses(t *testing.T) {
	f := newGrantFixture(t, faithfulValues, func(o *mctlapi.Options) { o.GitReader = nil })
	w := postAs(t, f.router, opPath("preview-deploy"), directDeploys()["preview-deploy"], f.root)
	if w.Code != http.StatusServiceUnavailable || errCode(t, w) != "agent_deploy_profile_unavailable" {
		t.Fatalf("preview-deploy with no reader = %d %s", w.Code, w.Body.String())
	}
	if len(f.exec.submitted) != 0 {
		t.Fatalf("submitted = %v", f.exec.submitted)
	}
}
