package api

import (
	"net/http"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// F6: a request lacking mandatory context cannot be approved, and stays
// pending; a deny is never gated.
func TestF6_IncompleteContextCannotBeApproved(t *testing.T) {
	e := newWorkItemsEnv(t)
	b := e.approvalBody("k-incomplete")
	delete(b, "side_effect")
	res := e.do(auth.NewServiceUser(), "POST", "/api/v1/action-approvals", b)
	if res.code != http.StatusCreated {
		t.Fatalf("create = %d %s", res.code, res.raw)
	}
	id := res.body["approval"].(map[string]any)["id"].(string)
	dc := res.body["decision_context"].(map[string]any)
	if dc["context_complete"] != false {
		t.Fatalf("decision_context = %v", dc)
	}

	res = e.decide(rootAdmin, id, "approve")
	if res.code != http.StatusUnprocessableEntity || code(res) != aarCodeContextIncomplete {
		t.Fatalf("approve = %d %s", res.code, res.raw)
	}
	if missing, _ := res.body["details"].(map[string]any)["missing_fields"].([]any); len(missing) != 1 || missing[0] != "side_effect" {
		t.Fatalf("details = %s", res.raw)
	}
	if got := e.approvalState(id)["state"]; got != "pending" {
		t.Fatalf("state = %v, want pending", got)
	}
	if res := e.decide(rootAdmin, id, "deny"); res.code != http.StatusOK {
		t.Fatalf("deny = %d %s", res.code, res.raw)
	}
}

// F6: the reviewer sees the mandatory context, and the decision is bound to
// the digest of what they saw.
func TestF6_DecisionBoundToContextDigest(t *testing.T) {
	e := newWorkItemsEnv(t)
	res := e.do(auth.NewServiceUser(), "POST", "/api/v1/action-approvals", e.approvalBody("k-digest"))
	if res.code != http.StatusCreated {
		t.Fatalf("create = %d %s", res.code, res.raw)
	}
	id := res.body["approval"].(map[string]any)["id"].(string)
	dc := res.body["decision_context"].(map[string]any)
	if dc["context_complete"] != true || dc["risk_level"] == "" || dc["side_effect"] == "" || dc["intent_source"] == "" {
		t.Fatalf("decision_context = %v", dc)
	}
	digest, _ := dc["context_digest"].(string)

	bad := e.do(rootAdmin, "POST", "/api/v1/action-approvals/"+id+"/decision",
		map[string]any{"decision": "approve", "context_digest": "sha256:other"})
	if bad.code != http.StatusConflict || code(bad) != aarCodeContextChanged {
		t.Fatalf("wrong digest = %d %s", bad.code, bad.raw)
	}
	ok := e.do(rootAdmin, "POST", "/api/v1/action-approvals/"+id+"/decision",
		map[string]any{"decision": "approve", "context_digest": digest})
	if ok.code != http.StatusOK {
		t.Fatalf("approve = %d %s", ok.code, ok.raw)
	}
	a := ok.body["approval"].(map[string]any)
	if a["decided_context_digest"] != digest || a["authority_basis"] != "platform_admin" || a["fresh_until"] == nil {
		t.Fatalf("captured = %v", a)
	}
}
