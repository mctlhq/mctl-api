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
	"slices"
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
	artCodeUnavailable           = "agent_run_tokens_unavailable"
	artCodeRequesterForbidden    = "agent_run_token_requester_forbidden"
	artCodeAgentUnknown          = "agent_unknown"
	artCodeExecutionNotFound     = "execution_not_found"
	artCodeExecutionTerminal     = "execution_terminal"
	artCodeInvalidTTL            = "invalid_ttl"
	artCodeScopeUnknown          = "agent_scope_unknown"
	artCodeScopeNotForAgent      = "agent_scope_not_for_agent"
	artCodePrincipalDisabled     = "agent_principal_disabled"
	artCodeIdentityRefused       = "agent_identity_refused"
	artCodeRegistryUnavailable   = "agent_registry_error"
	artCodeTenantRequired        = "agent_scope_tenant_required"
	artCodeTenantUnexpected      = "agent_scope_tenant_unexpected"
	artCodeTenantForbidden       = "agent_scope_tenant_forbidden"
	artCodeTenantNotFound        = "tenant_not_found"
	artCodeTenantLookupFailed    = "tenant_lookup_failed"
	artCodePermissionsUnexpected = "agent_scope_permissions_unexpected"
	artCodeExecutionForeign      = "execution_not_in_tenant"
)

type agentRunTokenBody struct {
	Agent       string   `json:"agent"`
	ExecutionID string   `json:"execution_id"`
	TTLSeconds  *int     `json:"ttl_seconds,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	// Scope names a server-defined auth.AgentScope (mctlhq/mctl-agents#737).
	Scope string `json:"scope,omitempty"`
	// Tenant binds a BoundTenant scope to the one tenant it may read.
	Tenant string `json:"tenant,omitempty"`
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

// isHumanMinter is a person, acting directly or relayed by a registered
// surface, who may mint a scope on a tenant member's word. An agent, a
// delegated agent request, the service principal and a bare surface are not.
func isHumanMinter(u *auth.User) bool {
	_, surface := u.Surface()
	_, delegated := u.DelegatingAgent()
	return !u.IsAgent() && !delegated && !u.IsService() && !surface && u.PrincipalID() != ""
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
	direct := isDirectService(user)
	if !direct && !isHumanMinter(user) {
		h.auditAgentRunTokenRefusal(r, user, "", artCodeRequesterForbidden)
		writeErrorCode(w, http.StatusForbidden, artCodeRequesterForbidden,
			"only the service principal acting directly may mint an agent run token", nil)
		return
	}

	var body agentRunTokenBody
	if !decodeWorkItemBodyLimit(w, r, &body, maxAgentRunTokenBodyBytes) {
		return
	}
	scope, _ := auth.LookupAgentScope(body.Scope)
	memberMint := scope != nil && scope.MintByTenantMember
	if !direct && !memberMint {
		h.auditAgentRunTokenRefusal(r, user, body.Agent, artCodeRequesterForbidden)
		writeErrorCode(w, http.StatusForbidden, artCodeRequesterForbidden,
			"only the service principal acting directly may mint an agent run token", nil)
		return
	}
	if memberMint && direct {
		// A scope minted on a tenant member's word is never minted on the
		// service principal's own.
		h.auditAgentRunTokenRefusal(r, user, body.Agent, artCodeRequesterForbidden)
		writeErrorCode(w, http.StatusForbidden, artCodeRequesterForbidden,
			"scope "+strconv.Quote(body.Scope)+" is minted for a tenant member, not the service principal", nil)
		return
	}
	if body.Agent == "" || body.ExecutionID == "" {
		writeErrorCode(w, http.StatusBadRequest, wiCodeInvalid, "agent and execution_id are required", nil)
		return
	}

	var extra map[string]string
	if memberMint {
		if body.Tenant == "" {
			h.auditAgentRunTokenRefusal(r, user, body.Agent, artCodeTenantRequired)
			writeErrorCode(w, http.StatusBadRequest, artCodeTenantRequired, "tenant is required for scope "+strconv.Quote(body.Scope), nil)
			return
		}
		// The scope's content is the server's: a member names the scope and
		// the tenant, nothing else. A permission list on top would be carried
		// verbatim onto the agent principal (HasPermission returns exactly
		// the minted list), so it is refused rather than ignored.
		if len(body.Permissions) > 0 {
			h.auditAgentRunTokenRefusal(r, user, body.Agent, artCodePermissionsUnexpected)
			writeErrorCode(w, http.StatusBadRequest, artCodePermissionsUnexpected,
				"permissions are not accepted for scope "+strconv.Quote(body.Scope)+"; the scope defines them", nil)
			return
		}
		if h.opts.GitReader == nil {
			writeErrorCode(w, http.StatusServiceUnavailable, artCodeUnavailable, "tenant lookup not configured", nil)
			return
		}
		// TenantExists, not GetTenant: it validates the name and the checkout
		// age, and it keeps "could not read" apart from "absent". Only a
		// definite absence is 404; a failed read is 503, never a refusal
		// dressed as not-found.
		exists, err := h.opts.GitReader.TenantExists(body.Tenant)
		if err != nil {
			slog.Error("agent run token: tenant lookup failed", "tenant", body.Tenant, "error", err)
			h.auditAgentRunTokenRefusal(r, user, body.Agent, artCodeTenantLookupFailed)
			writeErrorCode(w, http.StatusServiceUnavailable, artCodeTenantLookupFailed, "tenant lookup failed", nil)
			return
		}
		if !exists {
			h.auditAgentRunTokenRefusal(r, user, body.Agent, artCodeTenantNotFound)
			writeErrorCode(w, http.StatusNotFound, artCodeTenantNotFound, "tenant not found: "+body.Tenant, nil)
			return
		}
		member := slices.Contains(user.Groups, body.Tenant)
		if !member && !user.IsAdmin() {
			h.auditAgentRunTokenRefusal(r, user, body.Agent, artCodeTenantForbidden)
			writeErrorCode(w, http.StatusForbidden, artCodeTenantForbidden,
				"not a member of tenant "+strconv.Quote(body.Tenant), nil)
			return
		}
		// The execution the token binds to must be the bound tenant's own.
		// Otherwise a member could attach a support token to any live
		// execution (another tenant's work item, another agent's run) and
		// the row and the mint audit would attribute the token to that run.
		// An execution records no agent, so the agent half of that binding
		// cannot be checked here; the tenant half is what the row and the
		// gate rely on.
		corr, err := h.opts.WorkItems.ResolveExecution(r.Context(), body.ExecutionID)
		if err != nil {
			slog.Error("agent run token: resolve execution", "execution_id", body.ExecutionID, "error", err)
			h.auditAgentRunTokenRefusal(r, user, body.Agent, "agent_run_token_mint_failed")
			writeErrorCode(w, http.StatusInternalServerError, "agent_run_token_mint_failed", "agent run token mint failed", nil)
			return
		}
		if corr == nil {
			h.auditAgentRunTokenRefusal(r, user, body.Agent, artCodeExecutionNotFound)
			writeErrorCode(w, http.StatusNotFound, artCodeExecutionNotFound, "execution not found: "+body.ExecutionID, nil)
			return
		}
		if corr.Tenant != body.Tenant {
			h.auditAgentRunTokenRefusal(r, user, body.Agent, artCodeExecutionForeign)
			writeErrorCode(w, http.StatusForbidden, artCodeExecutionForeign,
				"execution "+strconv.Quote(body.ExecutionID)+" does not belong to tenant "+strconv.Quote(body.Tenant), nil)
			return
		}
		extra = map[string]string{
			"tenant":           body.Tenant,
			"via_principal_id": user.PrincipalID(),
			"admin_override":   strconv.FormatBool(!member),
		}
	}

	ttl := workitems.DefaultAgentRunTokenTTL
	maxTTL := workitems.MaxAgentRunTokenTTL
	if scope != nil {
		if scope.DefaultTTL > 0 {
			ttl = scope.DefaultTTL
		}
		if scope.MaxTTL > 0 {
			maxTTL = scope.MaxTTL
		}
	}
	if body.TTLSeconds != nil {
		// Validated in raw seconds, before the multiplication below that can
		// overflow int64 for an absurdly large ttl_seconds and wrap into a
		// small or negative Duration -- which would then pass the store's
		// own ttl > MaxAgentRunTokenTTL check unnoticed.
		maxSeconds := int(maxTTL / time.Second)
		if *body.TTLSeconds <= 0 || *body.TTLSeconds > maxSeconds {
			writeErrorCode(w, http.StatusBadRequest, artCodeInvalidTTL,
				"ttl_seconds must be positive and at most "+strconv.Itoa(maxSeconds), nil)
			return
		}
		ttl = time.Duration(*body.TTLSeconds) * time.Second
	}

	h.issueAgentRunToken(w, r, issuerOf(user), body, ttl, extra)
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

	// A tenant binding belongs to a BoundTenant scope and to nothing else; a
	// BoundTenant scope without one admits nothing, so it is never minted.
	var boundScope bool
	if sc, ok := auth.LookupAgentScope(body.Scope); ok {
		boundScope = sc.BoundTenant
	}
	if boundScope && body.Tenant == "" {
		h.auditAgentRunTokenRefusalBy(r, iss, body.Agent, artCodeTenantRequired)
		writeErrorCode(w, http.StatusBadRequest, artCodeTenantRequired, "scope "+strconv.Quote(body.Scope)+" requires a tenant", nil)
		return
	}
	if !boundScope && body.Tenant != "" {
		h.auditAgentRunTokenRefusalBy(r, iss, body.Agent, artCodeTenantUnexpected)
		writeErrorCode(w, http.StatusBadRequest, artCodeTenantUnexpected, "tenant is not accepted for this scope", nil)
		return
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

	viaPrincipal := ""
	if body.Tenant != "" {
		viaPrincipal = iss.PrincipalID
	}
	row, secret, err := h.opts.WorkItems.MintAgentRunToken(r.Context(), workitems.MintAgentRunTokenInput{
		Agent: body.Agent, AgentPrincipalID: agentUser.PrincipalID(), ExecutionID: body.ExecutionID,
		Permissions: body.Permissions, Scope: body.Scope, TTL: ttl, IssuedByPrincipalID: iss.PrincipalID,
		WithoutExecution: body.WithoutExecution, Tenant: body.Tenant, ViaPrincipalID: viaPrincipal,
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
	resp := map[string]any{
		"token_id":     row.ID,
		"token":        secret,
		"agent":        row.Agent,
		"execution_id": row.ExecutionID,
		"work_item_id": row.WorkItemID,
		"expires_at":   row.ExpiresAt,
		"permissions":  row.Permissions,
		"scope":        row.Scope,
	}
	if row.Tenant != "" {
		resp["tenant"] = row.Tenant
	}
	writeJSON(w, http.StatusCreated, resp)
}
