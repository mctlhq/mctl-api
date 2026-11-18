package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// mctl-agents-approve under the decide-page-only rule (owner decision
// 2026-11-18), against the real store. The grant env inherits the
// break-glass on from newDevLoopGrantEnv (its tests predate the rule), so
// each test here sets it explicitly.

// decidePageDenials counts the audited decide_page_required refusals of
// the operation.
func (g *grantEnv) decidePageDenials() int {
	n := 0
	entries := g.audit.List(1000)
	for i := range entries {
		e := &entries[i]
		if e.Operation == devLoopApprovalKind && e.Status == "denied" && e.RefusalCode == devLoopCodeDecidePageRequired {
			n++
		}
	}
	return n
}

// The worker path: once a person approved the grant, the DevLoop's agent
// run exercises it as X-MCTL-On-Behalf-Of: aar_... and the approve is
// submitted as the decider, with the break-glass OFF. The rule refuses a
// bearer DECISION; spending a decision already made is not one.
//
// The grant is decided here with the break-glass on, standing in for the
// decide page (whose approve is covered in handlers_devloop_decide_test.go);
// the flag is off for the exercise, which is the step under test.
func TestApprovalGrant_WorkerPathUnaffectedByTheDecidePageRule(t *testing.T) {
	g := newGrantEnv(t)
	run := g.grantedRun("dp-worker")
	g.h.opts.DevLoopBearerApproveEnabled = true
	g.decide(run.approval, "approve")
	g.h.opts.DevLoopBearerApproveEnabled = false

	res := g.execute(run.agent, run.approval, approveInput(run.slug))
	if res.code != http.StatusAccepted {
		t.Fatalf("grant-authorized approve with the break-glass off = %d %s, want 202", res.code, res.raw)
	}
	if g.submitted() != 1 || g.exec.submitted[0]["approver"] != "root" || g.exec.submitted[0][approvalRefParam] != run.approval {
		t.Fatalf("submitted = %v, want one approve as root spending %s", g.exec.submitted, run.approval)
	}
	if st := g.approvalState(run.approval)["state"]; st != "consumed" {
		t.Errorf("approval state = %v, want consumed", st)
	}
	if n := g.decidePageDenials(); n != 0 {
		t.Errorf("%d decide_page_required refusals on the worker path, want 0", n)
	}
}

// A human admin's token submitting the operation for a DevLoop whose grant
// is pending is refused with the grant and its decide_url, the grant stays
// pending, and nothing is submitted. That is the mctl_trigger_approve
// bypass this closes.
func TestApprovalGrant_DirectApproveOfAPendingGrantPointsAtThePage(t *testing.T) {
	g := newGrantEnv(t)
	g.h.opts.DevLoopBearerApproveEnabled = false
	g.h.devLoopDecide = newDevLoopDecider(&DevLoopDecideOptions{
		ProviderName: "zitadel", Issuer: "https://id.example", ClientID: testDecideClientID,
		ClientSecret: testDecideClientSecret, BaseURL: "https://api.example",
		Principals: &fakeSignInPrincipals{}, Authz: &auth.PrincipalAuthz{},
	})
	run := g.grantedRun("dp-direct")
	body := approveInput(run.slug)
	body[expectedContentDigestParam] = testContentDigest

	res := g.execute(g.decider, "", body)
	if res.code != http.StatusForbidden || res.body["code"] != devLoopCodeDecidePageRequired {
		t.Fatalf("direct approve = %d %s, want 403 %s", res.code, res.raw, devLoopCodeDecidePageRequired)
	}
	details, _ := res.body["details"].(map[string]any)
	read := g.readDevLoopApproval(g.decider, run.workflowID)
	if read.code != http.StatusOK || read.body["decide_url"] == nil {
		t.Fatalf("approval read = %d %s, want a decide_url", read.code, read.raw)
	}
	if details["approval_ref"] != run.approval || details["workflow_id"] != run.workflowID || details["decide_url"] != read.body["decide_url"] {
		t.Fatalf("details = %v, want approval_ref %s, workflow_id %s and decide_url %v", details, run.approval, run.workflowID, read.body["decide_url"])
	}
	if g.submitted() != 0 {
		t.Fatalf("a refused direct approve submitted %v", g.exec.submitted)
	}
	if st := g.approvalState(run.approval)["state"]; st != workitems.ApprovalPending {
		t.Fatalf("grant state = %v, want pending", st)
	}
	if n := g.decidePageDenials(); n != 1 {
		t.Fatalf("audited %d decide_page_required refusals, want 1", n)
	}

	// The break-glass restores the direct approve.
	g.h.opts.DevLoopBearerApproveEnabled = true
	if res := g.execute(g.decider, "", body); res.code != http.StatusAccepted || g.submitted() != 1 {
		t.Fatalf("break-glass direct approve = %d %s, submitted %d", res.code, res.raw, g.submitted())
	}
}

// mayDirectApproveProposal is a human admin acting directly, under the
// break-glass, or the decide page (whose context never reaches this route,
// but the predicate is the page's own). The route stops a surface or
// relayed caller and a non-admin before it, so their cases are pinned here.
func TestMayDirectApproveProposal(t *testing.T) {
	admin := auth.NewGitHubUser("root", []string{"admins"})
	surface := auth.NewSurfaceUser("telegram")
	surface.Groups = []string{"admins"}
	agent := auth.NewAgentUser("implementer", auth.AgentRun{})
	agent.Groups = []string{"admins"}
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	page := req.WithContext(withDecidePage(req.Context()))
	cases := []struct {
		name       string
		breakGlass bool
		r          *http.Request
		u          *auth.User
		want       bool
	}{
		{"admin, default", false, req, admin, false},
		{"admin, break-glass", true, req, admin, true},
		{"admin, decide page", false, page, admin, true},
		{"service, break-glass", true, req, auth.NewServiceUser(), false},
		{"surface with admins, break-glass", true, req, surface, false},
		{"agent with admins, break-glass", true, req, agent, false},
		{"non-admin, break-glass", true, req, auth.NewGitHubUser("dev", []string{"tests"}), false},
	}
	for _, c := range cases {
		h := &Handlers{opts: Options{DevLoopBearerApproveEnabled: c.breakGlass}}
		if got := h.mayDirectApproveProposal(c.r, c.u); got != c.want {
			t.Errorf("%s: mayDirectApproveProposal = %v, want %v", c.name, got, c.want)
		}
	}
}
