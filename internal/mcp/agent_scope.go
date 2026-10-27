package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/google/uuid"
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
	Help: "Agent run scope decisions by scope, mode (enforce, shadow), layer (rest, mcp) and verdict (allow, deny, allow_unbound).",
}, []string{"scope", "mode", "layer", "verdict"})

func init() { prometheus.MustRegister(AgentScopeDecisions) }

// AgentScopeVerdict is the verdict label for an allow/deny decision.
func AgentScopeVerdict(allowed bool) string {
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
		if name := user.AgentScopeName(); user.IsAgent() && name != "" {
			// A scope name the server no longer defines admits nothing, the
			// same as the REST gate: this layer stays closed on its own.
			scope, ok := user.AgentScope()
			boundTenant, _ := user.BoundTenant()
			allowed := ok && scope.AllowsToolCall(tool, req.GetArguments(), boundTenant)
			AgentScopeDecisions.WithLabelValues(name, "enforce", "mcp", AgentScopeVerdict(allowed)).Inc()
			audited := ok && scope.AuditRequests
			var auditor ScopedCallAuditor
			if audited {
				if h := s.scopedAuditor.Load(); h != nil {
					auditor = h.a
				}
				if auditor == nil {
					// Never serve an unaudited read.
					AgentScopeDecisions.WithLabelValues(name, "enforce", "mcp", "deny").Inc()
					slog.Error("agent scope: no auditor configured, tool refused", "scope", name, "tool", tool)
					return mcplib.NewToolResultError(fmt.Sprintf(
						"%s: audit unavailable for the %q scope", AgentScopeCodeDenied, name)), nil
				}
			}
			if !allowed {
				slog.Warn("agent scope: tool refused", "scope", name, "tool", tool,
					"execution_id", user.ExecutionID(), "agent_run_id", user.AgentRunID())
				if auditor != nil {
					auditor.AuditScopedToolCall(ctx, ScopedToolCallRecord{Tool: tool, Verdict: "denied"})
				}
				return mcplib.NewToolResultError(fmt.Sprintf(
					"%s: %s is outside the %q scope of this agent run", AgentScopeCodeDenied, tool, name)), nil
			}
			if auditor == nil {
				return next(ctx, req)
			}
			id := uuid.NewString()
			col := &loopbackCollector{}
			s.auditParents.Store(id, user.AgentRunID())
			res, err := func() (res *mcplib.CallToolResult, err error) {
				defer func() {
					// Close the parent and write the row even if the tool panics.
					s.auditParents.Delete(id)
					result := "succeeded"
					if rec := recover(); rec != nil {
						result = "failed"
						auditor.AuditScopedToolCall(ctx, ScopedToolCallRecord{
							EntryID: id, Tool: tool, Verdict: "allowed", Result: result, Loopback: col.list(), LoopbackTruncated: col.truncated(),
						})
						panic(rec)
					}
					if err != nil || res == nil || res.IsError {
						result = "failed"
					}
					auditor.AuditScopedToolCall(ctx, ScopedToolCallRecord{
						EntryID: id, Tool: tool, Verdict: "allowed", Result: result, Loopback: col.list(), LoopbackTruncated: col.truncated(),
					})
				}()
				return next(withLoopbackCollector(ctx, id, col), req)
			}()
			return res, err
		}
		if name := auth.ShadowAgentScopeFromContext(ctx); name != "" {
			if scope, ok := auth.LookupAgentScope(name); ok && scope.BoundTenant {
				AgentScopeDecisions.WithLabelValues(scope.Name, "shadow", "mcp", "shadow_unbound_tenant").Inc()
			} else if ok {
				allowed := scope.AllowsTool(tool)
				AgentScopeDecisions.WithLabelValues(scope.Name, "shadow", "mcp", AgentScopeVerdict(allowed)).Inc()
				if !allowed {
					slog.Info("agent scope shadow: tool would be refused", "scope", scope.Name, "tool", tool)
				}
			}
		}
		return next(ctx, req)
	}
}

// ScopedToolCallRecord is what the auditor learns of one tool call made under
// an audited scope. It holds no argument values and no result.
type ScopedToolCallRecord struct {
	EntryID string
	Tool    string
	// Verdict is "allowed" or "denied".
	Verdict string
	// Result is "succeeded" or "failed" for an allowed call.
	Result string
	// Loopback lists the REST calls the tool made, "METHOD /path STATUS".
	Loopback          []string
	LoopbackTruncated bool
}

// ScopedCallAuditor writes the audit row of a scoped tool call.
type ScopedCallAuditor interface {
	AuditScopedToolCall(ctx context.Context, rec ScopedToolCallRecord)
}

type scopedAuditorHolder struct{ a ScopedCallAuditor }

// SetScopedCallAuditor wires the sink for audited scopes. Until it is set,
// a call under such a scope is refused.
func (s *Server) SetScopedCallAuditor(a ScopedCallAuditor) {
	if a == nil {
		s.scopedAuditor.Store(nil)
		return
	}
	s.scopedAuditor.Store(&scopedAuditorHolder{a: a})
}

// OpenAuditParent reports the agent run of the open audited tool call id.
func (s *Server) OpenAuditParent(id string) (runID string, ok bool) {
	v, ok := s.auditParents.Load(id)
	if !ok {
		return "", false
	}
	runID, _ = v.(string)
	return runID, true
}

// AuditParentHeader names the open tool call a loopback REST request belongs to.
const AuditParentHeader = "X-Mctl-Audit-Parent"

const maxLoopbackRecords = 10

type loopbackCollector struct {
	mu    sync.Mutex
	id    string
	items []string
	cut   bool
}

func (c *loopbackCollector) add(item string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.items) >= maxLoopbackRecords {
		c.cut = true
		return
	}
	c.items = append(c.items, item)
}

func (c *loopbackCollector) list() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.items...)
}

func (c *loopbackCollector) truncated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cut
}

type loopbackCollectorKey struct{}

func withLoopbackCollector(ctx context.Context, id string, c *loopbackCollector) context.Context {
	c.id = id
	return context.WithValue(ctx, loopbackCollectorKey{}, c)
}

func loopbackCollectorFromContext(ctx context.Context) *loopbackCollector {
	c, _ := ctx.Value(loopbackCollectorKey{}).(*loopbackCollector)
	return c
}
