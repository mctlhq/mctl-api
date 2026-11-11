package api

import (
	"testing"

	"github.com/mctlhq/mctl-api/internal/governance"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// decisionCaptureFor records resource_owner for a Glovo kind and
// platform_admin for every other kind; a denial records no basis.
func TestDecisionCaptureForGlovoKind(t *testing.T) {
	h := &Handlers{}
	approve := workitems.ActionDecisionInput{Decision: workitems.DecisionApprove}
	if got := h.decisionCaptureFor(workitems.ActionKindGlovoPlaceOrderFake, approve, "d").AuthorityBasis; got != governance.AuthorityBasisResourceOwner {
		t.Fatalf("glovo basis %q", got)
	}
	if got := h.decisionCaptureFor("deploy.apply", approve, "d").AuthorityBasis; got != governance.AuthorityBasisPlatformAdmin {
		t.Fatalf("generic basis %q", got)
	}
	if got := h.decisionCapture(approve, "d").AuthorityBasis; got != governance.AuthorityBasisPlatformAdmin {
		t.Fatalf("decisionCapture basis %q", got)
	}
	if got := h.decisionCaptureFor(workitems.ActionKindGlovoPlaceOrderFake, workitems.ActionDecisionInput{Decision: workitems.DecisionDeny}, "d").AuthorityBasis; got != "" {
		t.Fatalf("deny basis %q", got)
	}
}
