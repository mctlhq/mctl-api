package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/governance"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// The authority and decision-context contract for action approvals
// (mctl-api#700; docs/decision-context-contract.md). The package
// internal/governance holds the rules; this file wires them to the handlers.

// incompleteContextError carries the missing mandatory fields of a decision
// context to the 422 response.
type incompleteContextError struct{ missing []string }

func (e *incompleteContextError) Error() string {
	return governance.ErrContextIncomplete.Error() + ": missing " + strings.Join(e.missing, ", ")
}

func (e *incompleteContextError) Unwrap() error { return governance.ErrContextIncomplete }

func (h *Handlers) approvalPolicies() governance.PolicySet {
	if h.opts.Policies != nil {
		return h.opts.Policies
	}
	return governance.Policies
}

// policyStatusOf is the non-refusing policy status of an approval, for audit.
func (h *Handlers) policyStatusOf(a *workitems.ActionApprovalRequest) string {
	status, err := h.approvalPolicies().Check(a.PolicyRuleID, a.PolicyVersion)
	if err != nil {
		return governance.PolicyDrift
	}
	return status
}

func (h *Handlers) approvalNow() time.Time {
	if h.opts.Clock != nil {
		return h.opts.Clock()
	}
	return time.Now()
}

func (h *Handlers) maxDecisionAge() time.Duration {
	if h.opts.ApprovalMaxDecisionAge > 0 {
		return h.opts.ApprovalMaxDecisionAge
	}
	return governance.DefaultMaxDecisionAge
}

// devLoopPolicy is the policy a DevLoop approval grant is created under: one
// source of truth with governance.Policies.
func (h *Handlers) devLoopPolicy() (rule, version string) {
	rule = governance.DevLoopPolicyRule
	version = h.approvalPolicies()[rule].Version
	return rule, version
}

func (h *Handlers) liveContext() governance.Live {
	return governance.Live{Registry: h.opts.Registry}
}

func (h *Handlers) decisionContext(a *workitems.ActionApprovalRequest) governance.DecisionContext {
	return governance.DecisionContextOf(a, h.liveContext())
}

// writeApproval answers one approval with the decision context a reviewer is
// shown beside it.
func (h *Handlers) writeApproval(w http.ResponseWriter, status int, a *workitems.ActionApprovalRequest) {
	writeJSON(w, status, map[string]any{
		"schema_version":   workitems.ActionApprovalSchemaVersion,
		"approval":         a,
		"decision_context": h.decisionContext(a),
	})
}

// approvalWithContext is one listed approval with its decision context.
type approvalWithContext struct {
	*workitems.ActionApprovalRequest
	DecisionContext governance.DecisionContext `json:"decision_context"`
}

// guardDecision is the completeness and binding check of an approve. A deny
// is never gated. It returns the context digest to record. It has answered
// when ok is false; the request stays pending.
func (h *Handlers) guardDecision(w http.ResponseWriter, r *http.Request, user *auth.User, a *workitems.ActionApprovalRequest, decision, sentDigest string, bind *decisionBinding) (string, bool) {
	if decision != workitems.DecisionApprove {
		return "", true
	}
	if status, err := h.approvalPolicies().Admit(a.PolicyRuleID, a.PolicyVersion, h.opts.RequireRegisteredPolicy); err != nil {
		h.auditActionApprovalRefusal(r, user, "action_approval.decision_refused", a.ID, actionApprovalRefusalCode(err),
			map[string]string{"policy_status": status})
		writeActionApprovalError(w, err)
		return "", false
	}
	c := h.decisionContext(a)
	if !c.ContextComplete {
		err := &incompleteContextError{missing: c.MissingFields}
		h.auditActionApprovalRefusal(r, user, "action_approval.decision_refused", a.ID, aarCodeContextIncomplete)
		writeActionApprovalError(w, err)
		return "", false
	}
	if (sentDigest != "" && sentDigest != c.ContextDigest) ||
		(bind != nil && (bind.ContextDigest != c.ContextDigest || bind.ContentDigest != a.ArtifactHash)) {
		h.auditActionApprovalRefusal(r, user, "action_approval.decision_refused", a.ID, aarCodeContextChanged)
		writeActionApprovalError(w, governance.ErrContextChanged)
		return "", false
	}
	return c.ContextDigest, true
}

// decisionCapture is what a successful approve records beside the decision.
func (h *Handlers) decisionCapture(in workitems.ActionDecisionInput, digest string) workitems.ActionDecisionInput {
	if in.Decision == workitems.DecisionApprove {
		in.ContextDigest = digest
		in.AuthorityBasis = governance.AuthorityBasisPlatformAdmin
		in.AuthzMode = string(h.opts.TenantAuthzMode)
		in.FreshFor = h.maxDecisionAge()
	}
	return in
}

// revalidateApproval re-checks, right before the side effect, what the
// approval depended on. A refusal is audited and answered; the approval is
// not spent and nothing is submitted.
func (h *Handlers) revalidateApproval(w http.ResponseWriter, r *http.Request, user *auth.User, a *workitems.ActionApprovalRequest) (governance.Result, bool) {
	res, err := governance.Revalidate(r.Context(), a, governance.LiveAuthority{
		PrincipalMode: h.principalMode(),
		Mode:          string(h.opts.TenantAuthzMode),
		Admins:        h.opts.AdminPrincipals,
		Checker:       h.opts.Principals,
		Policies:      h.approvalPolicies(),
		StrictPolicy:  h.opts.RequireRegisteredPolicy,
		Registry:      h.opts.Registry,
		Now:           h.approvalNow(),
	})
	if err != nil {
		if code := actionApprovalRefusalCode(err); code != "" {
			h.auditActionApprovalRefusal(r, user, "action_approval.consume_refused", a.ID, code,
				map[string]string{"policy_status": res.PolicyStatus})
		}
		writeActionApprovalError(w, err)
		return res, false
	}
	return res, true
}
