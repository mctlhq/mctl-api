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
	"github.com/mctlhq/mctl-api/internal/workitems"
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
	artCodeGrantNotFound       = "agent_run_grant_not_found"
	artCodeGrantUnusable       = "agent_run_grant_unusable"
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

	grantID := ""
	if binding.GrantTarget != "" {
		if grantID, ok = h.resolveRunGrant(w, r, iss, binding); !ok {
			return
		}
	}

	h.issueAgentRunToken(w, r, iss, agentRunTokenBody{
		Agent: binding.Agent, ExecutionID: binding.ExecutionID, Scope: binding.Scope,
		WithoutExecution: binding.ExecutionID == "", GrantID: grantID,
	}, ttl, map[string]string{
		"pod": binding.Pod, "workflow": binding.Workflow, "template": binding.Template,
	})
}

// resolveRunGrant finds the one DevLoop grant a run submitted for a proposal
// may act on: the newest one spent for that <service>/<slug>, requested by the
// control worker, decided by a human, bound to proposal content. A store that
// answers with none, or with one that fails a check, is a refusal; a store
// that cannot answer is 503, never a refusal and never a token. It refuses
// (and has answered) when ok is false.
func (h *Handlers) resolveRunGrant(w http.ResponseWriter, r *http.Request, iss agentRunIssuer, binding *k8s.AgentRunBinding) (string, bool) {
	ctx, cancel := context.WithTimeout(r.Context(), agentRunBindTimeout)
	defer cancel()
	a, err := h.opts.WorkItems.NewestSpentActionApproval(ctx, devLoopApprovalKind, binding.GrantTarget, principalOf(auth.NewServiceUser()))
	switch {
	case errors.Is(err, workitems.ErrApprovalNotFound):
		h.auditAgentRunTokenRefusalBy(r, iss, binding.Agent, artCodeGrantNotFound)
		writeErrorCode(w, http.StatusForbidden, artCodeGrantNotFound, "no decided grant has been spent for "+binding.GrantTarget, nil)
		return "", false
	case err != nil:
		slog.Error("agent run token exchange: grant read failed", "target", binding.GrantTarget, "error", err)
		writeErrorCode(w, http.StatusServiceUnavailable, artCodeExchangeUnavailable, "the run's grant could not be read", nil)
		return "", false
	}
	if _, human := approverName(a.DecidedBy); !human || !contentDigestRE.MatchString(a.ArtifactHash) {
		h.auditAgentRunTokenRefusalBy(r, iss, binding.Agent, artCodeGrantUnusable)
		writeErrorCode(w, http.StatusForbidden, artCodeGrantUnusable, "the newest grant for "+binding.GrantTarget+" has no human decider or no content digest", nil)
		return "", false
	}
	return a.ID, true
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
