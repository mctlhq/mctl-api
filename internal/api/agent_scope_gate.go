package api

import (
	"log/slog"
	"net/http"
	"strings"

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
			allowed := ok && scope.AllowsRoute(r.Method, r.URL.Path, user.WorkItemID(), user.ExecutionID())
			mctlmcp.AgentScopeDecisions.WithLabelValues(user.AgentScopeName(), "enforce", "rest", mctlmcp.AgentScopeVerdict(allowed)).Inc()
			if !allowed {
				agentName, _ := user.AgentName()
				h.logAudit(r, audit.Entry{
					UserID: user.ID, Operation: "agent_scope.denied", Status: "denied",
					RiskLevel: string(operations.RiskMedium),
					Parameters: map[string]string{
						"agent": agentName, "scope": user.AgentScopeName(), "route": r.Method + " " + r.URL.Path,
						"execution_id": user.ExecutionID(), "work_item_id": user.WorkItemID(), "agent_run_id": user.AgentRunID(),
					},
				})
				writeErrorCode(w, http.StatusForbidden, mctlmcp.AgentScopeCodeDenied,
					r.Method+" "+r.URL.Path+" is outside the "+user.AgentScopeName()+" scope of this agent run", nil)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if name := strings.TrimSpace(r.Header.Get(auth.AgentScopeShadowHeader)); name != "" && isDirectService(user) {
			if scope, ok := auth.LookupAgentScope(name); ok {
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
