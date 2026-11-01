package operations

import "testing"

// mctlhq/mctl-agents#573, #904: the DevLoop forwards a dispatched execution
// request's surface and authenticated principal to mctl-agents-investigate.
// Undeclared, StripUndeclared dropped them and the investigator sealed the
// transition as unknown; declared, they must reach Argo, and only in a shape
// that cannot carry anything but a label or a principal token.

func investigateOp(t *testing.T) (*Registry, Operation) {
	t.Helper()
	r := NewRegistry()
	op, ok := r.Get("mctl-agents-investigate")
	if !ok {
		t.Fatal("mctl-agents-investigate is not registered")
	}
	return r, op
}

func TestInvestigateKeepsResumeProvenance(t *testing.T) {
	r, op := investigateOp(t)
	input := map[string]string{
		"issue_url":  validInvestigateIssueURL,
		"surface":    "mcp",
		"actor_kind": "human",
		"actor_id":   "github:mashkovd",
	}
	got, dropped := r.StripUndeclared(op, input)
	if len(dropped) != 0 {
		t.Fatalf("StripUndeclared dropped %v", dropped)
	}
	for _, name := range []string{"surface", "actor_kind", "actor_id"} {
		if got[name] != input[name] {
			t.Errorf("%s: got %q, want %q", name, got[name], input[name])
		}
	}
	if errs := r.ValidateInput(op, got); len(errs) != 0 {
		t.Fatalf("valid provenance refused: %v", errs)
	}
}

func TestInvestigateAcceptsEveryPrincipalShape(t *testing.T) {
	r, op := investigateOp(t)
	// principalOf (internal/api/handlers_work_items.go) and the support
	// producer's raw id.
	for _, id := range []string{
		"github:mashkovd", "oidc:312345678901234567", "service:mctl-agents",
		"agent:issue-investigator", "prn_01M6A1G2YVMJVS8D874BQG8Q8Y",
	} {
		in := map[string]string{"issue_url": validInvestigateIssueURL, "actor_id": id}
		if errs := r.ValidateInput(op, in); len(errs) != 0 {
			t.Errorf("actor_id %q refused: %v", id, errs)
		}
	}
}

func TestInvestigateRefusesMalformedProvenance(t *testing.T) {
	r, op := investigateOp(t)
	cases := []struct{ name, value string }{
		{"surface", "mcp; rm -rf /"},
		{"surface", "Telegram"},
		{"surface", "mcp/claude"},
		{"actor_kind", "human\n"},
		{"actor_id", "github:a b"},
		{"actor_id", "$(id)"},
		{"actor_id", ":leading-colon"},
	}
	for _, c := range cases {
		in := map[string]string{"issue_url": validInvestigateIssueURL, c.name: c.value}
		if errs := r.ValidateInput(op, in); len(errs) == 0 {
			t.Errorf("%s=%q accepted", c.name, c.value)
		}
	}
}

func TestInvestigateProvenanceIsOmittedWhenEmpty(t *testing.T) {
	_, op := investigateOp(t)
	for _, p := range op.Parameters {
		switch p.Name {
		case "surface", "actor_kind", "actor_id":
			if p.Required || !p.OmitWhenEmpty {
				t.Errorf("%s must be optional and OmitWhenEmpty", p.Name)
			}
		}
	}
}
