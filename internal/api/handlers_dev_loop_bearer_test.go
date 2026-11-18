package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// The decide-page-only rule (owner decision 2026-11-18): a bearer-token
// caller does not decide a DevLoop approval, because AI clients hold the
// owner's token too. These run on the decide env, whose break-glass is off.

func (d *decideEnv) bearerDenials() int {
	n := 0
	entries := d.audit.List(1000)
	for i := range entries {
		if entries[i].Operation == "dev-loop-approve" && entries[i].Status == "denied" &&
			strings.HasPrefix(entries[i].Message, devLoopCodeDecidePageRequired) {
			n++
		}
	}
	return n
}

func TestDevLoopApprove_BearerDecisionNeedsTheDecidePage(t *testing.T) {
	d := newDecideEnv(t)
	run := d.run("bearer")
	bind := map[string]any{"approval_ref": run.grant, "context_digest": run.link.Get("cd"), "content_digest": testContentDigest}

	res := d.approveDevLoop(rootAdmin, run.workflowID, bindingJSON(bind))
	if res.code != http.StatusForbidden || res.body["code"] != devLoopCodeDecidePageRequired {
		t.Fatalf("bearer approve = %d %s, want 403 %s", res.code, res.raw, devLoopCodeDecidePageRequired)
	}
	details, _ := res.body["details"].(map[string]any)
	want, ok := d.h.decideURL(run.workflowID, decisionBinding{
		ApprovalRef: run.grant, ContextDigest: run.link.Get("cd"), ContentDigest: testContentDigest,
	})
	if !ok || details["decide_url"] != want || details["approval_ref"] != run.grant {
		t.Fatalf("details = %v, want decide_url %q for %s", details, want, run.grant)
	}
	if d.fake.lastApprovePayload != nil {
		t.Fatalf("a refused bearer approve signalled %v", d.fake.lastApprovePayload)
	}
	if a := d.approvalState(run.grant); a["state"] != workitems.ApprovalPending {
		t.Fatalf("grant state = %v, want pending", a["state"])
	}
	if d.bearerDenials() != 1 {
		t.Fatalf("audited %d bearer denials, want 1", d.bearerDenials())
	}

	// Unbound, the same refusal: the binding is not what is missing.
	if res := d.approveDevLoop(rootAdmin, run.workflowID, ""); res.code != http.StatusForbidden || res.body["code"] != devLoopCodeDecidePageRequired {
		t.Fatalf("unbound bearer approve = %d %s", res.code, res.raw)
	}

	// The break-glass restores the bearer decision.
	d.h.opts.DevLoopBearerApproveEnabled = true
	if res := d.approveDevLoop(rootAdmin, run.workflowID, bindingJSON(bind)); res.code != http.StatusOK {
		t.Fatalf("break-glass approve = %d %s", res.code, res.raw)
	}
	if d.fake.lastApprovePayload["approval_ref"] != run.grant {
		t.Fatalf("break-glass signalled %v", d.fake.lastApprovePayload)
	}
	if a := d.approvalState(run.grant); a["state"] != workitems.ApprovalApproved {
		t.Fatalf("grant state = %v, want approved", a["state"])
	}
}

// With no grant at all, the legacy payload records the caller as the
// approver: a decision too, so refused without the break-glass, with no link
// to offer.
func TestDevLoopApprove_BearerLegacyApprovalNeedsTheBreakGlass(t *testing.T) {
	d := newDecideEnv(t)
	wf := "dev-loop-" + d.tenant + "-nogrant"
	res := d.approveDevLoop(rootAdmin, wf, "")
	if res.code != http.StatusForbidden || res.body["code"] != devLoopCodeDecidePageRequired {
		t.Fatalf("legacy bearer approve = %d %s, want 403", res.code, res.raw)
	}
	if details, _ := res.body["details"].(map[string]any); details["decide_url"] != nil {
		t.Fatalf("a legacy refusal offered a link: %v", details)
	}
	if d.fake.lastApprovePayload != nil {
		t.Fatalf("a refused legacy approve signalled %v", d.fake.lastApprovePayload)
	}

	d.h.opts.DevLoopBearerApproveEnabled = true
	if res := d.approveDevLoop(rootAdmin, wf, ""); res.code != http.StatusOK {
		t.Fatalf("break-glass legacy approve = %d %s", res.code, res.raw)
	}
	if d.fake.lastApprovePayload["approver"] != rootAdmin.ID {
		t.Fatalf("break-glass legacy signalled %v", d.fake.lastApprovePayload)
	}
}

// A grant the person approved on the page is re-sent as its approval_ref by
// a bearer call without the break-glass: that decides nothing, and it is how
// a decision whose signal was lost reaches the run.
func TestDevLoopApprove_BearerResendsAPageDecision(t *testing.T) {
	d := newDecideEnv(t)
	run := d.run("resend")
	ck, form := d.signedIn(run)
	if rec := d.confirm(ck, form, "approve"); rec.Code != http.StatusOK {
		t.Fatalf("page approve = %d %s", rec.Code, rec.Body.String())
	}
	d.fake.lastApprovePayload = nil
	bind := map[string]any{"approval_ref": run.grant, "context_digest": run.link.Get("cd"), "content_digest": testContentDigest}
	res := d.approveDevLoop(rootAdmin, run.workflowID, bindingJSON(bind))
	if res.code != http.StatusOK || d.fake.lastApprovePayload["approval_ref"] != run.grant {
		t.Fatalf("re-send = %d %s, signalled %v", res.code, res.raw, d.fake.lastApprovePayload)
	}
}

// The service principal is still refused as not a human admin, whatever the
// break-glass says.
func TestDevLoopApprove_NonHumanStillRefused(t *testing.T) {
	d := newDecideEnv(t)
	run := d.run("svc")
	for _, on := range []bool{false, true} {
		d.h.opts.DevLoopBearerApproveEnabled = on
		res := d.approveDevLoop(auth.NewServiceUser(), run.workflowID, "")
		if res.code != http.StatusForbidden || res.body["code"] != aarCodeDeciderForbidden {
			t.Fatalf("break-glass %v: service approve = %d %s, want 403 %s", on, res.code, res.raw, aarCodeDeciderForbidden)
		}
	}
	if d.fake.lastApprovePayload != nil {
		t.Fatalf("a service approve signalled %v", d.fake.lastApprovePayload)
	}
}

// The generic decision route does not approve a DevLoop grant from a bearer
// either, or it would be the way around the page; a deny stays open (the
// page's reject uses it).
func TestDecideActionApproval_DevLoopApproveNeedsTheDecidePage(t *testing.T) {
	d := newDecideEnv(t)
	run := d.run("generic")
	res := d.workItemsEnv.do(rootAdmin, "POST", "/api/v1/action-approvals/"+run.grant+"/decision", map[string]any{"decision": workitems.DecisionApprove})
	if res.code != http.StatusForbidden || res.body["code"] != devLoopCodeDecidePageRequired {
		t.Fatalf("generic approve = %d %s, want 403 %s", res.code, res.raw, devLoopCodeDecidePageRequired)
	}
	if a := d.approvalState(run.grant); a["state"] != workitems.ApprovalPending {
		t.Fatalf("grant state = %v, want pending", a["state"])
	}
	res = d.workItemsEnv.do(rootAdmin, "POST", "/api/v1/action-approvals/"+run.grant+"/decision", map[string]any{"decision": workitems.DecisionDeny, "reason": "no"})
	if res.code != http.StatusOK {
		t.Fatalf("generic deny = %d %s", res.code, res.raw)
	}
	if a := d.approvalState(run.grant); a["state"] != workitems.ApprovalDenied {
		t.Fatalf("grant state = %v, want denied", a["state"])
	}
}

// A closed DevLoop grant keeps its typed state refusal on the generic route:
// the page has nothing to offer for it, so decide_page_required would send
// the caller nowhere.
func TestDecideActionApproval_ClosedDevLoopGrantKeepsItsStateRefusal(t *testing.T) {
	d := newDecideEnv(t)
	run := d.run("closed")
	if res := d.workItemsEnv.do(rootAdmin, "POST", "/api/v1/action-approvals/"+run.grant+"/decision", map[string]any{"decision": workitems.DecisionDeny, "reason": "no"}); res.code != http.StatusOK {
		t.Fatalf("deny = %d %s", res.code, res.raw)
	}
	res := d.workItemsEnv.do(rootAdmin, "POST", "/api/v1/action-approvals/"+run.grant+"/decision", map[string]any{"decision": workitems.DecisionApprove})
	if res.code == http.StatusOK || res.body["code"] == devLoopCodeDecidePageRequired {
		t.Fatalf("approve of a denied grant = %d %s, want its state refusal", res.code, res.raw)
	}
}
