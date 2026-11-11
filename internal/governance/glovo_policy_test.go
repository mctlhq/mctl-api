package governance

import (
	"errors"
	"testing"

	"github.com/mctlhq/mctl-api/internal/workitems"
)

// The Glovo owner-approval policy is registered at the version the database
// guard pins, so a strict-mode decision admits it and any other version drifts.
func TestGlovoOwnerApprovalPolicyRegistered(t *testing.T) {
	if got, err := Policies.Admit(workitems.GlovoPolicyRuleID, workitems.GlovoPolicyVersion, true); err != nil || got != PolicyOK {
		t.Fatalf("Admit registered Glovo policy: %q %v", got, err)
	}
	if _, err := Policies.Admit(workitems.GlovoPolicyRuleID, "2", true); !errors.Is(err, ErrPolicyDrift) {
		t.Fatalf("another version must drift: %v", err)
	}
	if AuthorityBasisResourceOwner != "resource_owner" {
		t.Fatalf("basis %q", AuthorityBasisResourceOwner)
	}
	p := Policies[workitems.GlovoPolicyRuleID]
	if p.Decision != "require_approval" || p.SideEffect != "write" {
		t.Fatalf("policy defaults %+v", p)
	}
}
