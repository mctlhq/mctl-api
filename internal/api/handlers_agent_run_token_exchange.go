package api

// Agent run token exchange (mctlhq/mctl-agents#737): an agent pod trades its
// projected ServiceAccount token for a scoped run token, so the run needs no
// static credential to get one. What the token may do is never the pod's to
// say: the agent, scope and execution all come from the verified binding
// (k8s.AgentRunBinder), and the request body is ignored.

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/k8s"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// AgentRunBinder verifies an agent pod's projected ServiceAccount token.
// Implemented by *k8s.AgentRunBinder.
type AgentRunBinder interface {
	Bind(ctx context.Context, token string) (*k8s.AgentRunBinding, error)
}

// MaxExchangedAgentRunTokenTTL caps an exchanged token's lifetime; within
// it, the run's own deadline is the limit.
const MaxExchangedAgentRunTokenTTL = 2 * time.Hour

// minExchangedAgentRunTokenTTL: a run with less than this left gets no
// token, rather than one that expires mid-call.
const minExchangedAgentRunTokenTTL = time.Minute

// agentRunBindTimeout bounds the cluster reads one exchange makes. The route
// is unauthenticated and sits outside the authenticated group's timeout, so
// a wedged API server must not let its requests pile up.
const agentRunBindTimeout = 10 * time.Second

// agentRunTokenSelfRevokeRoute is relative to /api/v1.
const agentRunTokenSelfRevokeRoute = "/agent-run-tokens/self/revoke"

const (
	artCodeExchangeUnavailable = "agent_run_exchange_unavailable"
	artCodeExchangeRefused     = "agent_run_exchange_refused"
	artCodeRunEnded            = "agent_run_ended"
	artCodeNotARunToken        = "not_an_agent_run_token"
)

// ExchangeAgentRunToken handles POST /api/v1/agent-run-tokens/exchange. The
// bearer is the pod's projected ServiceAccount token. A token Kubernetes
// does not authenticate is 401; one that authenticates but does not bind to
// an agent run is 403; a cluster that cannot be read is 503, never a
// refusal and never a token.
func (h *Handlers) ExchangeAgentRunToken(w http.ResponseWriter, r *http.Request) {
	if h.opts.AgentRunBinder == nil || h.opts.WorkItems == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, artCodeExchangeUnavailable, "agent run token exchange is not configured", nil)
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	token = strings.TrimSpace(token)
	if !ok || token == "" {
		writeError(w, http.StatusUnauthorized, "a ServiceAccount bearer token is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), agentRunBindTimeout)
	defer cancel()
	binding, err := h.opts.AgentRunBinder.Bind(ctx, token)
	var refusal *k8s.BindingRefusedError
	switch {
	case errors.As(err, &refusal):
		if refusal.Unauthenticated {
			// No identity was established, so a row would record nothing
			// but "someone sent a bad token", and would let any caller grow
			// the audit table. Logged instead.
			slog.Info("agent run token exchange: token not authenticated", "reason", refusal.Reason, "remote", r.RemoteAddr)
			writeErrorCode(w, http.StatusUnauthorized, artCodeExchangeRefused, "the ServiceAccount token was not accepted", nil)
			return
		}
		// A verified ServiceAccount token that binds to no run is the
		// security event worth keeping.
		h.auditAgentRunTokenRefusalBy(r, agentRunIssuer{UserID: "k8s:unbound", Actor: "k8s:unbound", Exchange: true}, "", refusal.Reason)
		writeErrorCode(w, http.StatusForbidden, artCodeExchangeRefused, "the token does not bind to an agent run: "+refusal.Reason, nil)
		return
	case err != nil:
		slog.Error("agent run token exchange: cluster read failed", "error", err)
		writeErrorCode(w, http.StatusServiceUnavailable, artCodeExchangeUnavailable, "the agent run could not be verified", nil)
		return
	}

	actor := "k8s:system:serviceaccount:" + binding.Namespace + ":" + binding.ServiceAccount
	iss := agentRunIssuer{UserID: actor, Actor: actor, Exchange: true}
	ttl := MaxExchangedAgentRunTokenTTL
	if !binding.Deadline.IsZero() {
		if left := time.Until(binding.Deadline); left < ttl {
			ttl = left.Truncate(time.Second)
		}
	}
	if ttl < minExchangedAgentRunTokenTTL {
		h.auditAgentRunTokenRefusalBy(r, iss, binding.Agent, artCodeRunEnded)
		writeErrorCode(w, http.StatusForbidden, artCodeRunEnded, "the run's deadline has passed", nil)
		return
	}

	h.issueAgentRunToken(w, r, iss, agentRunTokenBody{
		Agent: binding.Agent, ExecutionID: binding.ExecutionID, Scope: binding.Scope,
		WithoutExecution: binding.ExecutionID == "",
	}, ttl, map[string]string{
		"pod": binding.Pod, "workflow": binding.Workflow, "template": binding.Template,
	})
}

// RevokeOwnAgentRunToken handles POST /api/v1/agent-run-tokens/self/revoke:
// a run token revokes itself when its run is done. It names no token; the
// one presented is the one revoked, so no run can revoke another's.
func (h *Handlers) RevokeOwnAgentRunToken(w http.ResponseWriter, r *http.Request) {
	if h.opts.WorkItems == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, artCodeUnavailable, "work-items store not configured", nil)
		return
	}
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	agentName, isAgent := user.AgentName()
	if !isAgent || user.AgentRunID() == "" {
		writeErrorCode(w, http.StatusBadRequest, artCodeNotARunToken, "only an agent run token can revoke itself", nil)
		return
	}
	if err := h.opts.WorkItems.RevokeAgentRunToken(r.Context(), user.AgentRunID()); err != nil {
		slog.Error("agent run token: self revoke failed", "token_id", user.AgentRunID(), "error", err)
		writeErrorCode(w, http.StatusInternalServerError, "agent_run_token_revoke_failed", "revoke failed", nil)
		return
	}
	h.logAudit(r, audit.Entry{
		UserID: user.ID, Operation: "agent_run_token.revoke", Status: "succeeded",
		RiskLevel: string(operations.RiskLow),
		Parameters: map[string]string{
			"token_id": user.AgentRunID(), "agent": agentName,
			"execution_id": user.ExecutionID(), "work_item_id": user.WorkItemID(),
		},
	})
	w.WriteHeader(http.StatusNoContent)
}
