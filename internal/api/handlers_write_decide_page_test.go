package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// The decide-page-only rule (owner decision 2026-11-18) covers the
// mctl-agents-approve operation too: it flips a proposal to accepted, so a
// human admin's bearer token submitting it directly -- the REST execute
// route, and the MCP tool mctl_trigger_approve, which posts to that route --
// would approve without the decide page. AI clients hold that token. Only
// the grant path (the DevLoop worker exercising a grant the page approved,
// handlers_approval_grant_decide_page_test.go) and the break-glass
// DEVLOOP_BEARER_APPROVE_ENABLED submit it.

const directApprovePath = "/api/v1/operations/mctl-agents-approve/execute"

type refusal struct {
	Code    string                 `json:"code"`
	Error   string                 `json:"error"`
	Details map[string]interface{} `json:"details"`
}

func decodeRefusal(t *testing.T, raw []byte) refusal {
	t.Helper()
	var r refusal
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("decoding %s: %v", raw, err)
	}
	return r
}

// A well-formed direct approve by a human admin -- reviewed digest, no
// spoofed approver -- is refused by default with 403 decide_page_required,
// nothing is submitted, and the refusal is audited as a denied
// mctl-agents-approve carrying the code and the proposal's DevLoop.
func TestApprove_DirectApproveNeedsTheDecidePage(t *testing.T) {
	router, exec, logger := newApproveRouterWith(t, false, false)
	w := postAs(t, router, directApprovePath, map[string]string{
		"service": "mctl-web", "slug": "issue-42-fix-x", "expected_content_digest": reviewedDigest,
	}, adminUser)
	r := decodeRefusal(t, w.Body.Bytes())
	if w.Code != http.StatusForbidden || r.Code != "decide_page_required" {
		t.Fatalf("direct approve = %d %s, want 403 decide_page_required", w.Code, w.Body.String())
	}
	if len(exec.submittedParams) != 0 {
		t.Fatalf("a refused direct approve submitted %v", exec.submittedParams)
	}
	if r.Details["workflow_id"] != "dev-loop-mctlhq-mctl-web-42" {
		t.Errorf("details = %v, want the proposal's DevLoop workflow id", r.Details)
	}
	if _, ok := r.Details["decide_url"]; ok {
		t.Errorf("decide_url offered with no store and no page: %v", r.Details)
	}
	denied := entriesFor(logger, "mctl-agents-approve")
	if len(denied) != 1 || denied[0].Status != "denied" || denied[0].RefusalCode != "decide_page_required" ||
		denied[0].UserID != adminUser.ID || denied[0].Parameters["workflow_id"] != "dev-loop-mctlhq-mctl-web-42" {
		t.Fatalf("want one denied entry with refusal code decide_page_required, got %+v", denied)
	}
}

// The refusal comes before anything in the body is weighed: a body that
// would also fail a later check (no digest, a spoofed approver, a slug that
// names no DevLoop) gets the same 403, so a caller is never steered towards
// "fixing" its body into an approve.
func TestApprove_DirectApproveRefusedWhateverTheBody(t *testing.T) {
	for _, body := range []map[string]string{
		{"service": "mctl-web", "slug": "issue-43"},
		{"service": "mctl-web", "slug": "issue-43", "approver": "someone-else", "expected_content_digest": reviewedDigest},
		{"service": "mctl-web", "slug": "not-an-issue", "expected_content_digest": reviewedDigest},
	} {
		router, exec, _ := newApproveRouterWith(t, false, false)
		w := postAs(t, router, directApprovePath, body, adminUser)
		if r := decodeRefusal(t, w.Body.Bytes()); w.Code != http.StatusForbidden || r.Code != "decide_page_required" {
			t.Errorf("%v: %d %s, want 403 decide_page_required", body, w.Code, w.Body.String())
		}
		if len(exec.submittedParams) != 0 {
			t.Errorf("%v: submitted %v", body, exec.submittedParams)
		}
	}
}

// The break-glass restores the direct approve for a human admin acting
// directly, exactly as before the rule.
func TestApprove_DirectApproveWithTheBreakGlass(t *testing.T) {
	router, exec, logger := newApproveRouterWith(t, false, true)
	code, params := approveParams(t, router, exec, map[string]string{
		"service": "mctl-web", "slug": "issue-44", "expected_content_digest": reviewedDigest,
	}, adminUser)
	if *code != http.StatusAccepted || params["approver"] != adminUser.ID {
		t.Fatalf("break-glass direct approve = %d, approver %q; want 202 as %s", *code, params["approver"], adminUser.ID)
	}
	for _, e := range entriesFor(logger, "mctl-agents-approve") {
		if e.RefusalCode == "decide_page_required" {
			t.Errorf("break-glass approve audited a decide_page_required refusal: %+v", e)
		}
	}
}

// Even under the break-glass only a human admin acting directly may: an
// agent run credential that somehow carries the admins group is not a
// person deciding, and is refused with the same code. (A surface or relayed
// caller is stopped before this route; the agent path is the one a
// misconfigured group could carry this far.)
func TestApprove_BreakGlassIsForAHumanAdminOnly(t *testing.T) {
	agent := auth.NewAgentUser("implementer", auth.AgentRun{})
	agent.Groups = []string{"admins"}
	router, exec, _ := newApproveRouterWith(t, false, true)
	w := postAs(t, router, directApprovePath, map[string]string{
		"service": "mctl-web", "slug": "issue-45", "expected_content_digest": reviewedDigest,
	}, agent)
	if r := decodeRefusal(t, w.Body.Bytes()); w.Code != http.StatusForbidden || r.Code != "decide_page_required" {
		t.Fatalf("agent with admins under the break-glass = %d %s, want 403 decide_page_required", w.Code, w.Body.String())
	}
	if len(exec.submittedParams) != 0 {
		t.Fatalf("submitted %v", exec.submittedParams)
	}
}
