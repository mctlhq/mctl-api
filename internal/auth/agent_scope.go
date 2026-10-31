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
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
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
// across tenants, its own work item, and one write: sealing the context
// snapshot of its own execution.
const AgentScopeInvestigate = "investigate"

// AgentScopeSupport is the scope of a tenant support run: reads of exactly
// one tenant, the one the token was minted for, and nothing else.
const AgentScopeSupport = "support"

// AgentScope is one server-defined run scope.
type AgentScope struct {
	Name string
	// Agents lists the registered agents a token with this scope may be
	// minted for.
	Agents []string
	// ReadAllTenants lets HasTenantAccess admit every tenant. It is safe
	// only because Routes admits nothing but reads and writes bound to the
	// run's own work item and execution: the tenant check is not where a
	// scoped run's writes are stopped, the route list is.
	ReadAllTenants bool
	// BoundTenant means a token with this scope is minted for exactly one
	// tenant and every check compares against it. Mutually exclusive with
	// ReadAllTenants.
	BoundTenant bool
	// MintByTenantMember lets a human member of the bound tenant (or an
	// admin) mint the scope, instead of the service principal.
	MintByTenantMember bool
	// AuditRequests writes one audit row for every request a token with
	// this scope makes, reads and refusals included.
	AuditRequests bool
	// DefaultTTL and MaxTTL override the workitems defaults when non-zero.
	DefaultTTL, MaxTTL time.Duration
	Routes             []AgentScopeRoute
	// Deny is checked before Routes: a match refuses the request whatever
	// Routes admit. An empty Method matches every method. Bindings are
	// ignored, so a deny entry refuses the path for every work item, the
	// run's own included.
	Deny []AgentScopeRoute
	// Tool reports whether an mctl MCP tool may be called.
	Tool func(name string) bool
}

// AgentScopeRoute admits one method on paths matching Pattern. With
// BindWorkItem, Pattern's first submatch must equal the run's own work
// item id; with BindExecution, its second must equal the run's own
// execution id.
type AgentScopeRoute struct {
	Method        string
	Pattern       *regexp.Regexp
	BindWorkItem  bool
	BindExecution bool
	// BindTenant requires the named submatch "tenant" to equal the bound
	// tenant.
	BindTenant bool
	// RequireTenantQuery names a query key a list route must carry, equal to
	// the bound tenant.
	RequireTenantQuery string
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
// checkpoint's naming rule. The rule is held to the tools' recorded
// read-only annotations by a test in internal/mcp
// (TestReadToolsAreRecordedReadOnly), so a tool named like a read but
// recorded as anything else fails the build instead of widening a scope.
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

// agentDeniedTools are MCP tools (bare names) no agent scope may call, even
// though IsReadTool classifies them as reads: raw WorkItem intents are
// human-authored instructions (mctl-api#880, owner decision).
var agentDeniedTools = map[string]bool{"list_work_item_intents": true}

// agentDeniedRoutes mirror agentDeniedTools on REST (mctl-api#880).
var agentDeniedRoutes = []AgentScopeRoute{
	{Pattern: regexp.MustCompile(`^/api/v1/work-items/[^/]+/intents(/.*)?$`)},
}

func getRoute(pattern string) AgentScopeRoute {
	return AgentScopeRoute{Method: http.MethodGet, Pattern: regexp.MustCompile(pattern)}
}

func tenantRoute(pattern string) AgentScopeRoute {
	r := getRoute(pattern)
	r.BindTenant = true
	return r
}

func listRoute(pattern, queryKey string) AgentScopeRoute {
	r := getRoute(pattern)
	r.RequireTenantQuery = queryKey
	return r
}

// supportTools are the MCP tools (without the mctl_ prefix) a support run
// may call. Each is also a read under IsReadTool.
var supportTools = map[string]bool{
	"whoami": true, "get_service_status": true, "list_services": true, "get_service_logs": true,
	"get_service_config": true, "list_workflows": true, "get_workflow_status": true,
	"get_workflow_logs": true, "get_resource_usage": true, "list_incidents": true,
	"get_incident": true, "incident_summary": true, "list_operations": true, "get_operation": true,
	"list_domains": true, "list_platform_skills": true, "read_platform_skill": true,
	"get_service_pods": true, "list_namespace_events": true,
}

// SupportToolNames returns the sorted bare names of the support tool list.
func SupportToolNames() []string {
	names := make([]string, 0, len(supportTools))
	for n := range supportTools {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// supportTenantTools are the supportTools that take a tenant argument, and
// so must carry the bound tenant.
var supportTenantTools = map[string]bool{
	"get_service_status": true, "list_services": true, "get_service_logs": true,
	"get_service_config": true, "list_workflows": true, "get_resource_usage": true,
	"list_incidents": true, "list_domains": true,
	"get_service_pods": true, "list_namespace_events": true,
}

// tenantQueryKeys are the query parameters that name a tenant. On a
// tenant-bound scope each must be absent or equal the bound tenant, once.
var tenantQueryKeys = []string{"team", "tenant", "team_name", "namespace"}

// tenantToolArgs are the MCP tool arguments that name a tenant.
var tenantToolArgs = []string{"team", "team_name", "tenant"}

// mcpRoutes admit the MCP transport. What a tools/call may do is decided
// per tool (AgentScope.Tool), and every REST call a tool makes comes back
// through the route list with the same token. resources/* and prompts/*
// are not scope-checked: today they serve only static text and the
// operations catalog; one that reads tenant data needs its own check.
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
		Deny:           agentDeniedRoutes,
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
			getRoute(`^/api/v1/pods/[^/]+/[^/]+$`),
			getRoute(`^/api/v1/events/[^/]+$`),
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
			// Sealing what its own execution saw, so the run needs no
			// static service token for it (mctlhq/mctl-agents#717).
			AgentScopeRoute{
				Method: http.MethodPost, BindWorkItem: true, BindExecution: true,
				Pattern: regexp.MustCompile(`^/api/v1/work-items/([^/]+)/executions/([^/]+)/snapshot$`),
			},
		),
	},
	AgentScopeSupport: {
		Name: AgentScopeSupport, Agents: []string{"mctl-support"},
		BoundTenant: true, MintByTenantMember: true, AuditRequests: true,
		DefaultTTL: 10 * time.Minute, MaxTTL: time.Hour,
		Deny: agentDeniedRoutes,
		Tool: func(n string) bool { return IsReadTool(n) && supportTools[strings.TrimPrefix(n, "mctl_")] },
		Routes: append(append([]AgentScopeRoute(nil), mcpRoutes...),
			getRoute(`^/api/v1/whoami$`),
			tenantRoute(`^/api/v1/status/(?P<tenant>[^/]+)/[^/]+$`),
			tenantRoute(`^/api/v1/services/(?P<tenant>[^/]+)/[^/]+$`),
			tenantRoute(`^/api/v1/logs/(?P<tenant>[^/]+)/[^/]+$`),
			tenantRoute(`^/api/v1/resources/(?P<tenant>[^/]+)$`),
			tenantRoute(`^/api/v1/pods/(?P<tenant>[^/]+)/[^/]+$`),
			tenantRoute(`^/api/v1/events/(?P<tenant>[^/]+)$`),
			listRoute(`^/api/v1/services$`, "team"),
			listRoute(`^/api/v1/workflows$`, "team"),
			listRoute(`^/api/v1/domains$`, "team"),
			listRoute(`^/api/v1/incidents$`, "tenant"),
			// The owning tenant is read from the data and checked in the handler.
			getRoute(`^/api/v1/workflows/[^/]+(/logs)?$`),
			getRoute(`^/api/v1/incidents/(summary|[^/]+)$`),
			// Static catalog, and HasTenantAccess-filtered.
			getRoute(`^/api/v1/operations(/[^/]+)?$`),
			getRoute(`^/api/v1/platform-skills(/[^/]+)?$`),
		),
	},
}

// LookupAgentScope returns the scope named name.
func LookupAgentScope(name string) (*AgentScope, bool) {
	s, ok := agentScopes[name]
	return s, ok
}

// AgentScopeNames returns the name of every defined scope, sorted.
func AgentScopeNames() []string {
	names := make([]string, 0, len(agentScopes))
	for n := range agentScopes {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
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

// AgentScopeRequest is one request judged against a scope.
type AgentScopeRequest struct {
	Method, Path string
	Query        url.Values
	WorkItemID   string
	ExecutionID  string
	// Tenant is the tenant a BoundTenant token is bound to.
	Tenant string
}

// AllowsRoute reports whether method+path is in the scope for a run bound
// to workItemID and executionID. An empty id never matches a route bound
// to it. It carries no query and no tenant, so a BoundTenant scope refuses
// everything through it.
func (s *AgentScope) AllowsRoute(method, path, workItemID, executionID string) bool {
	return s.Allows(AgentScopeRequest{Method: method, Path: path, WorkItemID: workItemID, ExecutionID: executionID})
}

// Allows reports whether the request is in the scope. For a BoundTenant
// scope it also requires every tenant-naming query parameter to equal the
// bound tenant exactly once, every BindTenant path segment to equal it, and
// RequireTenantQuery list filters to be present.
func (s *AgentScope) Allows(req AgentScopeRequest) bool {
	if s.BoundTenant {
		if req.Tenant == "" {
			return false
		}
		for _, k := range tenantQueryKeys {
			vals := req.Query[k]
			if len(vals) > 1 || (len(vals) == 1 && vals[0] != req.Tenant) {
				return false
			}
		}
	}
	for _, d := range s.Deny {
		if (d.Method == "" || d.Method == req.Method) && d.Pattern.MatchString(req.Path) {
			return false
		}
	}
	for _, r := range s.Routes {
		if r.Method != req.Method {
			continue
		}
		m := r.Pattern.FindStringSubmatch(req.Path)
		if m == nil {
			continue
		}
		if r.BindWorkItem && (req.WorkItemID == "" || len(m) < 2 || m[1] != req.WorkItemID) {
			continue
		}
		if r.BindExecution && (req.ExecutionID == "" || len(m) < 3 || m[2] != req.ExecutionID) {
			continue
		}
		if s.BoundTenant {
			if r.BindTenant {
				idx := r.Pattern.SubexpIndex("tenant")
				if idx < 0 || idx >= len(m) || m[idx] != req.Tenant {
					continue
				}
			}
			if r.RequireTenantQuery != "" {
				if vals := req.Query[r.RequireTenantQuery]; len(vals) != 1 || vals[0] != req.Tenant {
					continue
				}
			}
		}
		return true
	}
	return false
}

// AllowsToolCall reports whether an mctl MCP tool may be called with args.
// For a BoundTenant scope the tool predicate must pass, every present
// tenant argument must equal tenant, and a tool that takes a tenant must
// carry one.
func (s *AgentScope) AllowsToolCall(name string, args map[string]any, tenant string) bool {
	if !s.AllowsTool(name) {
		return false
	}
	if !s.BoundTenant {
		return true
	}
	if tenant == "" {
		return false
	}
	for _, k := range tenantToolArgs {
		if v, ok := args[k]; ok {
			if str, isStr := v.(string); !isStr || str != tenant {
				return false
			}
		}
	}
	if supportTenantTools[strings.TrimPrefix(name, "mctl_")] {
		has := false
		for _, k := range tenantToolArgs {
			if _, ok := args[k]; ok {
				has = true
			}
		}
		if !has {
			return false
		}
	}
	return true
}

// AllowsTool reports whether an mctl MCP tool may be called in the scope.
func (s *AgentScope) AllowsTool(name string) bool {
	if agentDeniedTools[strings.TrimPrefix(name, "mctl_")] {
		return false
	}
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

// AuditedAgentScope returns the scope of this principal's run token when
// that scope asks for every request to be audited.
func (u *User) AuditedAgentScope() (*AgentScope, bool) {
	scope, ok := u.AgentScope()
	if !ok || !scope.AuditRequests {
		return nil, false
	}
	return scope, true
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
