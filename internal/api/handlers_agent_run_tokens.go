// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

// Agent run tokens (mctl-api#376): an execution-scoped credential that lets
// one agent run authenticate as a first-class, non-admin, per-execution
// principal instead of the one static admin service principal every agent
// run authenticates as today. Minting itself stays on that static
// credential -- isDirectService only -- so it is the one remaining place the
// broad credential is exercised, and it, like every refusal, is audited.

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// maxAgentRunTokenBodyBytes bounds a request body: agent, execution_id and a
// short permissions list are at most a few hundred bytes together.
const maxAgentRunTokenBodyBytes = 4 << 10

// Typed error codes a client can branch on.
const (
	artCodeUnavailable         = "agent_run_tokens_unavailable"
	artCodeRequesterForbidden  = "agent_run_token_requester_forbidden"
	artCodeAgentUnknown        = "agent_unknown"
	artCodeExecutionNotFound   = "execution_not_found"
	artCodeExecutionTerminal   = "execution_terminal"
	artCodeInvalidTTL          = "invalid_ttl"
	artCodeScopeUnknown        = "agent_scope_unknown"
	artCodeScopeNotForAgent    = "agent_scope_not_for_agent"
	artCodePrincipalDisabled   = "agent_principal_disabled"
	artCodeIdentityRefused     = "agent_identity_refused"
	artCodeRegistryUnavailable = "agent_registry_error"
)

type agentRunTokenBody struct {
	Agent       string   `json:"agent"`
	ExecutionID string   `json:"execution_id"`
	TTLSeconds  *int     `json:"ttl_seconds,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	// Scope names a server-defined auth.AgentScope (mctlhq/mctl-agents#737).
	Scope string `json:"scope,omitempty"`
	// WithoutExecution is set only by the exchange, never decoded from a
	// request: see workitems.MintAgentRunTokenInput.
	WithoutExecution bool `json:"-"`
}

// auditAgentRunTokenRefusal records a refused mint: the typed code and the
// agent name only, in the shape auditActionApprovalRefusal already uses.
func (h *Handlers) auditAgentRunTokenRefusal(r *http.Request, user *auth.User, agent, code string) {
	h.auditAgentRunTokenRefusalBy(r, issuerOf(user), agent, code)
}

func (h *Handlers) auditAgentRunTokenRefusalBy(r *http.Request, iss agentRunIssuer, agent, code string) {
	op := "agent_run_token.mint_refused"
	if iss.Exchange {
		op = "agent_run_token.exchange_refused"
	}
	h.logAudit(r, audit.Entry{
		UserID:    iss.UserID,
		Operation: op,
		Parameters: map[string]string{
			"agent":  agent,
			"reason": code,
			"actor":  iss.Actor,
		},
		Status:    "failed",
		RiskLevel: string(operations.RiskMedium),
	})
}

// agentRunIssuer is who a run token is issued on the word of: the service
// principal minting directly, or a verified agent pod exchanging its
// ServiceAccount token (handlers_agent_run_token_exchange.go).
type agentRunIssuer struct {
	UserID      string
	Actor       string
	PrincipalID string
	Exchange    bool
}

func issuerOf(user *auth.User) agentRunIssuer {
	return agentRunIssuer{UserID: user.ID, Actor: principalOf(user), PrincipalID: user.PrincipalID()}
}

// agentRunTokenErrorCode maps a MintAgentRunToken store error to its status
// and typed code.
func agentRunTokenErrorCode(err error) (code string, status int) {
	switch {
	case errors.Is(err, workitems.ErrNotFound):
		return artCodeExecutionNotFound, http.StatusNotFound
	case errors.Is(err, workitems.ErrExecutionTerminal):
		return artCodeExecutionTerminal, http.StatusConflict
	case errors.Is(err, workitems.ErrAgentRunTokenTTL):
		return artCodeInvalidTTL, http.StatusBadRequest
	default:
		return "agent_run_token_mint_failed", http.StatusInternalServerError
	}
}

// MintAgentRunToken handles POST /api/v1/agent-run-tokens. Only the
// mctl-agent service principal acting directly may mint. It refuses an
// unregistered agent (400 agent_unknown), a terminal or unknown execution
// (409 / 404), and caps ttl_seconds at
// workitems.MaxAgentRunTokenTTL (default workitems.DefaultAgentRunTokenTTL).
// The plaintext token is returned exactly once and is never logged, audited,
// or recoverable afterwards.
func (h *Handlers) MintAgentRunToken(w http.ResponseWriter, r *http.Request) {
	if h.opts.WorkItems == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, artCodeUnavailable, "work-items store not configured", nil)
		return
	}
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !isDirectService(user) {
		h.auditAgentRunTokenRefusal(r, user, "", artCodeRequesterForbidden)
		writeErrorCode(w, http.StatusForbidden, artCodeRequesterForbidden,
			"only the service principal acting directly may mint an agent run token", nil)
		return
	}

	var body agentRunTokenBody
	if !decodeWorkItemBodyLimit(w, r, &body, maxAgentRunTokenBodyBytes) {
		return
	}
	if body.Agent == "" || body.ExecutionID == "" {
		writeErrorCode(w, http.StatusBadRequest, wiCodeInvalid, "agent and execution_id are required", nil)
		return
	}

	ttl := workitems.DefaultAgentRunTokenTTL
	if body.TTLSeconds != nil {
		// Validated in raw seconds, before the multiplication below that can
		// overflow int64 for an absurdly large ttl_seconds and wrap into a
		// small or negative Duration -- which would then pass the store's
		// own ttl > MaxAgentRunTokenTTL check unnoticed.
		maxSeconds := int(workitems.MaxAgentRunTokenTTL / time.Second)
		if *body.TTLSeconds <= 0 || *body.TTLSeconds > maxSeconds {
			writeErrorCode(w, http.StatusBadRequest, artCodeInvalidTTL, "ttl_seconds must be positive and at most 86400", nil)
			return
		}
		ttl = time.Duration(*body.TTLSeconds) * time.Second
	}

	h.issueAgentRunToken(w, r, issuerOf(user), body, ttl, nil)
}

// issueAgentRunToken checks the agent and scope a run token is asked for,
// mints it, audits it with extra, and writes the one response that carries
// the plaintext token. Shared by the direct mint and the pod exchange.
func (h *Handlers) issueAgentRunToken(w http.ResponseWriter, r *http.Request, iss agentRunIssuer, body agentRunTokenBody, ttl time.Duration, extra map[string]string) {
	if h.opts.AgentRegistry != nil {
		known, err := h.opts.AgentRegistry.HasDefinition(r.Context(), body.Agent)
		if err != nil {
			slog.Error("agent run token: check agent registry", "error", err)
			h.auditAgentRunTokenRefusalBy(r, iss, body.Agent, artCodeRegistryUnavailable)
			writeErrorCode(w, http.StatusInternalServerError, artCodeRegistryUnavailable, "agent registry error", nil)
			return
		}
		if !known {
			h.auditAgentRunTokenRefusalBy(r, iss, body.Agent, artCodeAgentUnknown)
			writeErrorCode(w, http.StatusBadRequest, artCodeAgentUnknown, "agent "+strconv.Quote(body.Agent)+" is not registered", nil)
			return
		}
	}

	// The scope's content is the server's; the caller only names one, and
	// only one defined for this agent.
	if body.Scope != "" {
		scope, ok := auth.LookupAgentScope(body.Scope)
		if !ok {
			h.auditAgentRunTokenRefusalBy(r, iss, body.Agent, artCodeScopeUnknown)
			writeErrorCode(w, http.StatusBadRequest, artCodeScopeUnknown, "scope "+strconv.Quote(body.Scope)+" is not defined", nil)
			return
		}
		if !scope.AdmitsAgent(body.Agent) {
			h.auditAgentRunTokenRefusalBy(r, iss, body.Agent, artCodeScopeNotForAgent)
			writeErrorCode(w, http.StatusBadRequest, artCodeScopeNotForAgent,
				"scope "+strconv.Quote(body.Scope)+" is not defined for agent "+strconv.Quote(body.Agent), nil)
			return
		}
	}

	// The agent's own principal, resolved (and provisioned on first sight)
	// through the same shared resolver every other identity uses, not a
	// bespoke path. "" when the principal store is unavailable (phase 1
	// degrades rather than failing the mint).
	agentUser := auth.NewAgentUser(body.Agent, auth.AgentRun{})
	if err := auth.AttachPrincipal(r.Context(), h.opts.Principals, agentUser); err != nil {
		switch {
		case errors.Is(err, auth.ErrPrincipalDisabled):
			h.auditAgentRunTokenRefusalBy(r, iss, body.Agent, artCodePrincipalDisabled)
			writeErrorCode(w, http.StatusForbidden, artCodePrincipalDisabled, "the agent principal is disabled", nil)
			return
		case errors.Is(err, auth.ErrIdentityRefused):
			h.auditAgentRunTokenRefusalBy(r, iss, body.Agent, artCodeIdentityRefused)
			writeErrorCode(w, http.StatusForbidden, artCodeIdentityRefused, "the agent identity is refused", nil)
			return
		}
		slog.Warn("agent run token: agent principal not resolved; minting without one", "agent", body.Agent, "error", err)
	}

	row, secret, err := h.opts.WorkItems.MintAgentRunToken(r.Context(), workitems.MintAgentRunTokenInput{
		Agent: body.Agent, AgentPrincipalID: agentUser.PrincipalID(), ExecutionID: body.ExecutionID,
		Permissions: body.Permissions, Scope: body.Scope, TTL: ttl, IssuedByPrincipalID: iss.PrincipalID,
		WithoutExecution: body.WithoutExecution,
	})
	if err != nil {
		code, status := agentRunTokenErrorCode(err)
		h.auditAgentRunTokenRefusalBy(r, iss, body.Agent, code)
		if status == http.StatusInternalServerError {
			slog.Error("agent run token: mint failed", "agent", body.Agent, "execution_id", body.ExecutionID, "error", err)
			writeErrorCode(w, status, code, "agent run token mint failed", nil)
			return
		}
		writeErrorCode(w, status, code, err.Error(), nil)
		return
	}

	params := map[string]string{
		"token_id":               row.ID,
		"agent":                  row.Agent,
		"agent_principal_id":     row.AgentPrincipalID,
		"execution_id":           row.ExecutionID,
		"work_item_id":           row.WorkItemID,
		"ttl_seconds":            strconv.Itoa(int(ttl.Seconds())),
		"expires_at":             row.ExpiresAt.Format(time.RFC3339),
		"permissions":            strings.Join(row.Permissions, ","),
		"scope":                  row.Scope,
		"issued_by_principal_id": row.IssuedByPrincipalID,
	}
	for k, v := range extra {
		params[k] = v
	}
	op := "agent_run_token.mint"
	if iss.Exchange {
		op = "agent_run_token.exchange"
	}
	h.logAudit(r, audit.Entry{
		UserID:     iss.UserID,
		Operation:  op,
		Parameters: params,
		Status:     "succeeded",
		RiskLevel:  string(operations.RiskMedium),
	})

	// The plaintext token appears here and nowhere else: never in the audit
	// entry above, never in a log line.
	writeJSON(w, http.StatusCreated, map[string]any{
		"token_id":     row.ID,
		"token":        secret,
		"agent":        row.Agent,
		"execution_id": row.ExecutionID,
		"work_item_id": row.WorkItemID,
		"expires_at":   row.ExpiresAt,
		"permissions":  row.Permissions,
		"scope":        row.Scope,
	})
}
