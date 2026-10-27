package api

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	mctlmcp "github.com/mctlhq/mctl-api/internal/mcp"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// agentScopeGate enforces a scoped agent run token's route list
// (auth.AgentScope, mctlhq/mctl-agents#737): a request outside it is
// refused with agent_scope_denied and one audit entry. It runs ahead of
// agentPrincipalGate, so a scoped run cannot leave its scope by delegating.
//
// For the direct service principal it also serves the observe stage: a
// request naming a scope in auth.AgentScopeShadowHeader is counted as the
// scope would have decided it, and the scope is kept on the context so the
// in-process MCP server carries it onto its tools' REST calls. That header
// never changes how the request is authorized. In shadow, a route bound to
// the run's own work item is admitted whatever the id, since the static
// token carries no work item to compare with, and counted allow_unbound.
func (h *Handlers) agentScopeGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			next.ServeHTTP(w, r)
			return
		}
		if user.IsAgent() {
			if user.AgentScopeName() == "" {
				// An unscoped run token keeps the narrow behaviour it had.
				next.ServeHTTP(w, r)
				return
			}
			// Every run may revoke its own token, whatever its scope.
			if r.Method == http.MethodPost && r.URL.Path == "/api/v1"+agentRunTokenSelfRevokeRoute {
				next.ServeHTTP(w, r)
				return
			}
			scope, ok := user.AgentScope()
			// A scope name the server no longer defines admits nothing.
			boundTenant, _ := user.BoundTenant()
			allowed := ok && scope.Allows(auth.AgentScopeRequest{
				Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(),
				WorkItemID: user.WorkItemID(), ExecutionID: user.ExecutionID(), Tenant: boundTenant,
			})
			mctlmcp.AgentScopeDecisions.WithLabelValues(user.AgentScopeName(), "enforce", "rest", mctlmcp.AgentScopeVerdict(allowed)).Inc()
			audited := ok && scope.AuditRequests
			if !allowed {
				agentName, _ := user.AgentName()
				entry := audit.Entry{
					UserID: user.ID, Operation: audit.OperationAgentScopeDenied, Status: "denied",
					RiskLevel: string(operations.RiskMedium),
					Parameters: map[string]string{
						"agent": agentName, "scope": user.AgentScopeName(), "route": r.Method + " " + r.URL.Path,
						"execution_id": user.ExecutionID(), "work_item_id": user.WorkItemID(), "agent_run_id": user.AgentRunID(),
						"bound_tenant": boundTenant,
					},
				}
				if audited {
					entry.Tenant = boundTenant
					entry.PrincipalID = user.AgentRunRequestedBy()
					entry.ViaPrincipalID = user.PrincipalID()
					entry.ViaExecutionID = user.ExecutionID()
				}
				h.logAudit(r, entry)
				writeErrorCode(w, http.StatusForbidden, mctlmcp.AgentScopeCodeDenied,
					r.Method+" "+r.URL.Path+" is outside the "+user.AgentScopeName()+" scope of this agent run", nil)
				return
			}
			// The MCP transport is audited per tool call in the MCP layer
			// (AuditScopedToolCall), denials included; a row for the outer
			// POST /mcp would give every tool call two rows, and
			// initialize, tools/list and the GET stream rows of their own.
			if audited && r.URL.Path != "/mcp" && !h.isFoldedLoopbackChild(r, user) {
				h.serveAudited(w, r, next, user, boundTenant)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if name := strings.TrimSpace(r.Header.Get(auth.AgentScopeShadowHeader)); name != "" && isDirectService(user) {
			if scope, ok := auth.LookupAgentScope(name); ok && scope.BoundTenant {
				// A static token carries no bound tenant, so the scope
				// cannot be judged: counted apart, never as an allow.
				mctlmcp.AgentScopeDecisions.WithLabelValues(scope.Name, "shadow", "rest", "shadow_unbound_tenant").Inc()
			} else if ok {
				bound, boundExec := shadowBinding(scope, r.Method, r.URL.Path)
				allowed := scope.AllowsRoute(r.Method, r.URL.Path, bound, boundExec)
				verdict := mctlmcp.AgentScopeVerdict(allowed)
				if allowed && bound != "" {
					// Admitted only because shadow cannot check the work
					// item: counted apart, so the observe stage does not
					// read it as a clean allow.
					verdict = "allow_unbound"
				}
				mctlmcp.AgentScopeDecisions.WithLabelValues(scope.Name, "shadow", "rest", verdict).Inc()
				if !allowed {
					slog.Info("agent scope shadow: route would be refused", "scope", scope.Name, "method", r.Method, "path", r.URL.Path)
				}
				r = r.WithContext(auth.WithShadowAgentScope(r.Context(), scope.Name))
			}
		}
		next.ServeHTTP(w, r)
	})
}

// shadowBinding returns the work item and execution ids a bound route of
// scope names in path, so a shadowed request is judged as if the run were
// bound to them.
func shadowBinding(scope *auth.AgentScope, method, path string) (workItemID, executionID string) {
	for _, route := range scope.Routes {
		if !route.BindWorkItem || route.Method != method {
			continue
		}
		m := route.Pattern.FindStringSubmatch(path)
		if len(m) < 2 {
			continue
		}
		if route.BindExecution && len(m) > 2 {
			return m[1], m[2]
		}
		return m[1], ""
	}
	return "", ""
}

// isFoldedLoopbackChild reports whether r is a loopback call of an open MCP
// tool call of the same run, whose row already lists it. Every condition
// must hold, so a forged or stale header never suppresses a row.
func (h *Handlers) isFoldedLoopbackChild(r *http.Request, user *auth.User) bool {
	id := r.Header.Get(mctlmcp.AuditParentHeader)
	if id == "" || h.opts.MCPServer == nil || !isLoopbackRemote(r) {
		return false
	}
	runID, ok := h.opts.MCPServer.OpenAuditParent(id)
	return ok && runID != "" && runID == user.AgentRunID()
}

// serveAudited serves an admitted support-scope request and writes its one
// audit row afterwards, metadata only. The row is written even if a handler
// panics (recorded as a 500).
func (h *Handlers) serveAudited(w http.ResponseWriter, r *http.Request, next http.Handler, user *auth.User, boundTenant string) {
	ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
	panicked := true
	defer func() {
		status := ww.Status()
		if status == 0 {
			status = http.StatusOK
		}
		if panicked {
			status = http.StatusInternalServerError
		}
		result := "succeeded"
		if status >= 400 {
			result = "failed"
		}
		entry := h.supportEntry(user, boundTenant, result)
		entry.Parameters["layer"] = "rest"
		entry.Parameters["route"] = r.Method + " " + r.URL.Path
		entry.Parameters["http_status"] = strconv.Itoa(status)
		h.logAudit(r, entry)
	}()
	next.ServeHTTP(ww, r)
	panicked = false
}

// supportEntry is the metadata common to every support.request row.
func (h *Handlers) supportEntry(user *auth.User, boundTenant, status string) audit.Entry {
	agentName, _ := user.AgentName()
	return audit.Entry{
		UserID: user.ID, Operation: audit.OperationSupportRequest, Status: status,
		RiskLevel: string(operations.RiskLow), Tenant: boundTenant,
		PrincipalID: user.AgentRunRequestedBy(), ViaPrincipalID: user.PrincipalID(), ViaExecutionID: user.ExecutionID(),
		Parameters: map[string]string{
			"agent": agentName, "scope": user.AgentScopeName(),
			"agent_run_id": user.AgentRunID(), "work_item_id": user.WorkItemID(),
		},
	}
}

// AuditScopedToolCall implements mctlmcp.ScopedCallAuditor: one row per MCP
// tool call made under an audited scope.
func (h *Handlers) AuditScopedToolCall(ctx context.Context, rec mctlmcp.ScopedToolCallRecord) {
	user := auth.UserFromContext(ctx)
	if user == nil {
		return
	}
	boundTenant, _ := user.BoundTenant()
	status := rec.Result
	if rec.Verdict == "denied" {
		status = "denied"
	}
	entry := h.supportEntry(user, boundTenant, status)
	if rec.EntryID != "" {
		entry.ID = rec.EntryID
	}
	entry.Parameters["layer"] = "mcp"
	entry.Parameters["tool"] = rec.Tool
	if len(rec.Loopback) > 0 {
		entry.Parameters["loopback"] = strings.Join(rec.Loopback, "; ")
	}
	if rec.LoopbackTruncated {
		entry.Parameters["loopback_truncated"] = "true"
	}
	h.logAuditCtx(ctx, entry)
}

// ListSupportAudit serves GET /api/v1/audit/support: the support rows of a
// tenant and/or an execution, newest first. Admin only.
func (h *Handlers) ListSupportAudit(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !user.IsAdmin() {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}
	q := r.URL.Query()
	f := audit.SupportFilter{Tenant: q.Get("tenant"), ExecutionID: q.Get("execution_id"), Limit: 100}
	if f.Tenant == "" && f.ExecutionID == "" {
		writeError(w, http.StatusBadRequest, "tenant or execution_id is required")
		return
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		f.Limit = n
	}
	if f.Limit > 500 {
		f.Limit = 500
	}
	if v := q.Get("before"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "before must be an RFC 3339 time")
			return
		}
		f.Before = t
	}
	reader, ok := h.opts.AuditLog.(audit.SupportReader)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "support audit read is not available")
		return
	}
	entries, err := reader.ListSupport(r.Context(), f)
	if err != nil {
		slog.Error("support audit read failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "support audit read failed")
		return
	}
	items := make([]supportAuditItem, 0, len(entries))
	for i := range entries {
		e := &entries[i]
		items = append(items, supportAuditItem{
			Entry: audit.RedactEntry(*e), Tenant: e.Tenant, UserPrincipalID: e.PrincipalID,
			ViaPrincipalID: e.ViaPrincipalID, ViaExecutionID: e.ViaExecutionID,
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "count": len(items)})
}

// supportAuditItem exposes the fields audit.Entry keeps out of its JSON.
type supportAuditItem struct {
	audit.Entry
	Tenant          string `json:"tenant"`
	UserPrincipalID string `json:"userPrincipalId"`
	ViaPrincipalID  string `json:"viaPrincipalId"`
	ViaExecutionID  string `json:"viaExecutionId"`
}
