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

package auth

import (
	"context"
	"net/http"
	"regexp"
	"strings"
)

// Agent run scopes (mctlhq/mctl-agents#737).
//
// A run token minted without a scope keeps the narrow behaviour it always
// had: no tenant, no admin, only the permissions it lists. A run token
// minted with a scope is how an agent run replaces the static admin service
// token for its own calls: the scope, held here on the server and never
// described by the caller, names the routes and MCP tools the run may reach
// and whether it may read every tenant's data. Everything a scope does not
// name is refused, so a route or tool added to mctl-api tomorrow is closed
// to scoped runs until a scope lists it.

// AgentScopeInvestigate is the scope of an issue-investigator run: reads
// across tenants, its own work item, and no mutation.
const AgentScopeInvestigate = "investigate"

// AgentScope is one server-defined run scope.
type AgentScope struct {
	Name string
	// Agents lists the registered agents a token with this scope may be
	// minted for.
	Agents []string
	// ReadAllTenants lets HasTenantAccess admit every tenant. It is safe
	// only because Routes admits nothing but reads and the run's own work
	// item: the tenant check is not where a scoped run's writes are
	// stopped, the route list is.
	ReadAllTenants bool
	Routes         []AgentScopeRoute
	// Tool reports whether an mctl MCP tool may be called.
	Tool func(name string) bool
}

// AgentScopeRoute admits one method on paths matching Pattern. With
// BindWorkItem, Pattern's first submatch must equal the run's own work
// item id.
type AgentScopeRoute struct {
	Method       string
	Pattern      *regexp.Regexp
	BindWorkItem bool
}

// readVerbs and readTools mirror mctl-agents' policy checkpoint
// (orchestrator/policy_checkpoint.py _READ_VERBS, _READ_TOOLS): the tools
// it allows without an approval, minus the incident mutations. Both
// spellings are accepted, `mctl_<verb>_...` and a bare `<verb>_...`.
var (
	readVerbs = []string{"get_", "list_", "read_", "search_", "describe_"}
	readTools = []string{"whoami", "incident_summary", "resolve_agent"}
)

// IsReadTool reports whether an mctl MCP tool name is a read by the
// checkpoint's naming rule.
func IsReadTool(name string) bool {
	bare := strings.TrimPrefix(name, "mctl_")
	for _, v := range readVerbs {
		if strings.HasPrefix(bare, v) && len(bare) > len(v) {
			return true
		}
	}
	for _, t := range readTools {
		if bare == t {
			return true
		}
	}
	return false
}

func getRoute(pattern string) AgentScopeRoute {
	return AgentScopeRoute{Method: http.MethodGet, Pattern: regexp.MustCompile(pattern)}
}

// mcpRoutes admit the MCP transport. What a call through it may do is
// decided per tool (AgentScope.Tool), and every REST call a tool makes
// comes back through the route list with the same token.
var mcpRoutes = []AgentScopeRoute{
	{Method: http.MethodPost, Pattern: regexp.MustCompile(`^/mcp$`)},
	{Method: http.MethodGet, Pattern: regexp.MustCompile(`^/mcp$`)},
	{Method: http.MethodDelete, Pattern: regexp.MustCompile(`^/mcp$`)},
}

var agentScopes = map[string]*AgentScope{
	AgentScopeInvestigate: {
		Name:           AgentScopeInvestigate,
		Agents:         []string{"issue-investigator"},
		ReadAllTenants: true,
		Tool:           IsReadTool,
		Routes: append(append([]AgentScopeRoute(nil), mcpRoutes...),
			getRoute(`^/api/v1/whoami$`),
			getRoute(`^/api/v1/identity/self$`),
			getRoute(`^/api/v1/tenants(/[^/]+)?$`),
			getRoute(`^/api/v1/services(/[^/]+/[^/]+)?$`),
			getRoute(`^/api/v1/status/[^/]+/[^/]+$`),
			getRoute(`^/api/v1/workflows(/[^/]+(/logs)?)?$`),
			getRoute(`^/api/v1/previews$`),
			getRoute(`^/api/v1/resources/[^/]+$`),
			getRoute(`^/api/v1/logs/[^/]+/[^/]+$`),
			getRoute(`^/api/v1/agent-runs$`),
			getRoute(`^/api/v1/platform-skills(/[^/]+)?$`),
			getRoute(`^/api/v1/repos$`),
			getRoute(`^/api/v1/domains$`),
			getRoute(`^/api/v1/incidents(/summary|/[^/]+)?$`),
			getRoute(`^/api/v1/roadmap/(epics|epic-status|ready)$`),
			getRoute(`^/api/v1/lifecycle/ownership(/record|/batch|/conflict)?$`),
			getRoute(`^/api/v1/lifecycle/events$`),
			getRoute(`^/api/v1/operations(/[^/]+)?$`),
			// The run's own work item and everything under it.
			AgentScopeRoute{
				Method: http.MethodGet, BindWorkItem: true,
				Pattern: regexp.MustCompile(`^/api/v1/work-items/([^/]+)(/.*)?$`),
			},
		),
	},
}

// LookupAgentScope returns the scope named name.
func LookupAgentScope(name string) (*AgentScope, bool) {
	s, ok := agentScopes[name]
	return s, ok
}

// AdmitsAgent reports whether a token with this scope may be minted for
// agent.
func (s *AgentScope) AdmitsAgent(agent string) bool {
	for _, a := range s.Agents {
		if a == agent {
			return true
		}
	}
	return false
}

// AllowsRoute reports whether method+path is in the scope for a run bound
// to workItemID. An empty workItemID never matches a bound route.
func (s *AgentScope) AllowsRoute(method, path, workItemID string) bool {
	for _, r := range s.Routes {
		if r.Method != method {
			continue
		}
		m := r.Pattern.FindStringSubmatch(path)
		if m == nil {
			continue
		}
		if r.BindWorkItem && (workItemID == "" || len(m) < 2 || m[1] != workItemID) {
			continue
		}
		return true
	}
	return false
}

// AllowsTool reports whether an mctl MCP tool may be called in the scope.
func (s *AgentScope) AllowsTool(name string) bool {
	return s.Tool != nil && s.Tool(name)
}

// AgentScopeName is the scope the run token was minted with, or "" for an
// unscoped run token and every other principal.
func (u *User) AgentScopeName() string {
	if u == nil || u.agent == "" {
		return ""
	}
	return u.agentScope
}

// AgentScope returns the scope this principal's run token carries, and
// false for an unscoped run token and every other principal.
func (u *User) AgentScope() (*AgentScope, bool) {
	name := u.AgentScopeName()
	if name == "" {
		return nil, false
	}
	return LookupAgentScope(name)
}

// AgentScopeShadowHeader is how a run still on the static service token
// says which scope it will move to (mctlhq/mctl-agents#737 observe stage).
// It is a claim, used only to count what the scope would have refused; it
// never changes how a request is authorized.
const AgentScopeShadowHeader = "X-Mctl-Agent-Scope-Shadow"

type shadowScopeKey struct{}

// WithShadowAgentScope records the scope a request is shadowing, so the
// in-process MCP server can carry it onto the REST calls its tools make.
func WithShadowAgentScope(ctx context.Context, scope string) context.Context {
	return context.WithValue(ctx, shadowScopeKey{}, scope)
}

// ShadowAgentScopeFromContext returns the scope WithShadowAgentScope
// recorded, or "".
func ShadowAgentScopeFromContext(ctx context.Context) string {
	s, _ := ctx.Value(shadowScopeKey{}).(string)
	return s
}
