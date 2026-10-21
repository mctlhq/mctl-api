package mcp

import (
	"context"
	"fmt"
	"log/slog"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// Agent run scopes on the MCP surface (mctlhq/mctl-agents#737). A run token
// minted with a scope may call only the tools that scope names; the REST
// calls an admitted tool makes come back through the API's agent scope gate
// with the same token, so the route list applies to them as well.

// AgentScopeCodeDenied is the refusal code for a call outside a run's scope.
const AgentScopeCodeDenied = "agent_scope_denied"

// AgentScopeDecisions counts every scope decision, enforced or shadowed, by
// layer (rest, mcp). Shared with the API package, which owns the REST
// layer, so there is one series to read for the observe stage.
var AgentScopeDecisions = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "mctl_agent_scope_decisions_total",
	Help: "Agent run scope decisions by scope, mode (enforce, shadow), layer (rest, mcp) and verdict (allow, deny).",
}, []string{"scope", "mode", "layer", "verdict"})

func init() { prometheus.MustRegister(AgentScopeDecisions) }

func verdictLabel(allowed bool) string {
	if allowed {
		return "allow"
	}
	return "deny"
}

// agentScopeMiddleware refuses a scoped run's call to a tool outside its
// scope, and counts what a shadowing service call would have been refused.
func (s *Server) agentScopeMiddleware(next server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		tool := req.Params.Name
		user := auth.UserFromContext(ctx)
		if scope, ok := user.AgentScope(); ok {
			allowed := scope.AllowsTool(tool)
			AgentScopeDecisions.WithLabelValues(scope.Name, "enforce", "mcp", verdictLabel(allowed)).Inc()
			if !allowed {
				slog.Warn("agent scope: tool refused", "scope", scope.Name, "tool", tool,
					"execution_id", user.ExecutionID(), "agent_run_id", user.AgentRunID())
				return mcplib.NewToolResultError(fmt.Sprintf(
					"%s: %s is outside the %q scope of this agent run", AgentScopeCodeDenied, tool, scope.Name)), nil
			}
			return next(ctx, req)
		}
		if name := auth.ShadowAgentScopeFromContext(ctx); name != "" {
			if scope, ok := auth.LookupAgentScope(name); ok {
				allowed := scope.AllowsTool(tool)
				AgentScopeDecisions.WithLabelValues(scope.Name, "shadow", "mcp", verdictLabel(allowed)).Inc()
				if !allowed {
					slog.Info("agent scope shadow: tool would be refused", "scope", scope.Name, "tool", tool)
				}
			}
		}
		return next(ctx, req)
	}
}
