package api

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// Direct deploys for agent-deploy tenants (mctl-api#1031).
//
// A tenant whose values carry tenant.profile: agent-deploy is deployed only
// through a stored plan (mctl_deploy_plan), a grant a live owner decided on
// a fresh-sign-in page (mctl_request_deploy_approval) and the apply route
// (mctl_deploy_apply), which submits preview-deploy itself. Without this
// gate the grant was optional: deploy_service and create_preview reach the
// generic execute path and submit on tenant membership alone.
//
// Scope, decided by the owner on 2026-11-14 (mctl-api#1031): deploy-service
// on every action, and preview-deploy. rollback-service stays allowed, so a
// bad deploy can be undone without a plan. Only CI OIDC passes; there is no
// admin pass.

const (
	// codeAgentDeployRequiresPlan refuses a direct deploy or preview of an
	// agent-deploy tenant.
	codeAgentDeployRequiresPlan = "agent_deploy_requires_plan"
	// codeAgentDeployProfileUnavailable is the answer when the tenant's
	// profile could not be read: the deploy is refused, not let through.
	codeAgentDeployProfileUnavailable = "agent_deploy_profile_unavailable"
)

// agentDeployGated reports whether opName is refused for agent-deploy
// tenants on the generic execute path.
func agentDeployGated(opName string) bool {
	return opName == ciDeployOperation || opName == previewDeployOp
}

// refuseAgentDeployDirect writes the refusal and returns false when the
// namespace belongs to an agent-deploy tenant, or when that cannot be
// established. It returns true only for a namespace read and found ordinary,
// or owned by no tenant at all.
func (h *Handlers) refuseAgentDeployDirect(w http.ResponseWriter, r *http.Request, user *auth.User, op operations.Operation, namespace string) bool {
	deny := func(status string, msg string) {
		h.logAudit(r, audit.Entry{
			UserID:    user.ID,
			Operation: op.Name,
			Status:    status,
			RiskLevel: string(op.RiskLevel),
			Message:   msg,
		})
	}
	if h.opts.GitReader == nil {
		deny("failed", "agent-deploy profile of "+namespace+" unreadable: no gitops reader")
		writeErrorCode(w, http.StatusServiceUnavailable, codeAgentDeployProfileUnavailable,
			"the tenant's deploy profile could not be read; try again later", nil)
		return false
	}
	profile, _, err := h.opts.GitReader.NamespaceProfile(namespace)
	if err != nil {
		slog.Warn("agent-deploy profile unreadable; direct deploy refused",
			"operation", op.Name, "namespace", namespace, "error", err)
		deny("failed", "agent-deploy profile of "+namespace+" unreadable")
		writeErrorCode(w, http.StatusServiceUnavailable, codeAgentDeployProfileUnavailable,
			"the tenant's deploy profile could not be read; try again later", nil)
		return false
	}
	if profile != gitops.AgentDeployProfile {
		return true
	}
	deny("denied", fmt.Sprintf("denied:%s: %s on agent-deploy tenant %s", codeAgentDeployRequiresPlan, op.Name, namespace))
	writeErrorCode(w, http.StatusForbidden, codeAgentDeployRequiresPlan,
		"tenant "+namespace+" deploys through an approved plan only: create one with mctl_deploy_plan, "+
			"request a grant with mctl_request_deploy_approval, and apply it with mctl_deploy_apply "+
			"once an owner has approved it", nil)
	return false
}
