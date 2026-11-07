package auth

import (
	"net/http"
	"net/url"
	"regexp"
	"testing"
)

func TestIsReadTool(t *testing.T) {
	for name, want := range map[string]bool{
		"mctl_get_logs":             true,
		"get_logs":                  true,
		"mctl_list_services":        true,
		"mctl_search_audit":         true,
		"mctl_describe_operation":   true,
		"mctl_whoami":               true,
		"mctl_incident_summary":     true,
		"mctl_resolve_agent":        true,
		"mctl_resolve_incident":     false,
		"mctl_acknowledge_incident": false,
		"mctl_deploy_service":       false,
		"mctl_erpact_list_sites":    false,
		"mctl_get_":                 false,
		"mctl_trigger_issue":        false,
		"":                          false,
	} {
		if got := IsReadTool(name); got != want {
			t.Errorf("IsReadTool(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestInvestigateScope_Routes(t *testing.T) {
	s, ok := LookupAgentScope(AgentScopeInvestigate)
	if !ok {
		t.Fatal("investigate scope not defined")
	}
	for _, c := range []struct {
		method, path, workItem string
		want                   bool
	}{
		// Sealing its own execution's snapshot is the one write.
		{http.MethodPost, "/api/v1/work-items/wi_a/executions/we_1/snapshot", "wi_a", true},
		{http.MethodPost, "/api/v1/work-items/wi_a/executions/we_2/snapshot", "wi_a", false},
		{http.MethodPost, "/api/v1/work-items/wi_b/executions/we_1/snapshot", "wi_a", false},
		{http.MethodPost, "/api/v1/work-items/wi_a/executions/we_1/snapshot", "", false},
		{http.MethodPost, "/api/v1/work-items/wi_a/executions", "wi_a", false},
		{http.MethodGet, "/api/v1/tenants", "wi_a", true},
		{http.MethodGet, "/api/v1/logs/admins/mctl-api", "wi_a", true},
		{http.MethodGet, "/api/v1/work-items/wi_a", "wi_a", true},
		{http.MethodGet, "/api/v1/work-items/wi_a/executions/we_1/snapshot", "wi_a", true},
		{http.MethodGet, "/api/v1/work-items/wi_b", "wi_a", false},
		{http.MethodGet, "/api/v1/work-items/wi_a", "", false},
		{http.MethodGet, "/api/v1/work-items", "wi_a", false},
		{http.MethodGet, "/api/v1/audit", "wi_a", false},
		{http.MethodGet, "/api/v1/tenants/erpact/sites", "wi_a", false},
		{http.MethodPost, "/api/v1/tenants", "wi_a", false},
		{http.MethodPost, "/api/v1/incidents/x/resolve", "wi_a", false},
		{http.MethodPost, "/api/v1/operations/deploy-service/execute", "wi_a", false},
		{http.MethodPost, "/mcp", "wi_a", true},
		{http.MethodGet, "/api/v1/work-items/wi_a/intents", "wi_a", false},
		{http.MethodGet, "/api/v1/work-items/wi_a/intents/1", "wi_a", false},
		{http.MethodGet, "/api/v1/work-items/wi_a/intents/", "wi_a", false},
		{http.MethodHead, "/api/v1/work-items/wi_a/intents", "wi_a", false},
		{http.MethodGet, "/api/v1/work-items/wi_a/snapshots", "wi_a", true},
		{http.MethodGet, "/api/v1/work-items/wi_a/execution-requests", "wi_a", true},
	} {
		if got := s.AllowsRoute(c.method, c.path, c.workItem, "we_1"); got != c.want {
			t.Errorf("AllowsRoute(%s %s, %q) = %v, want %v", c.method, c.path, c.workItem, got, c.want)
		}
	}
	if s.AllowsRoute(http.MethodPost, "/api/v1/work-items/wi_a/executions/we_1/snapshot", "wi_a", "") {
		t.Error("a run bound to no execution may seal a snapshot")
	}
	if !s.AdmitsAgent("issue-investigator") || s.AdmitsAgent("implementer") {
		t.Error("investigate scope must be for issue-investigator only")
	}
}

func TestScopedAgent_TenantAccessAndAdmin(t *testing.T) {
	scoped := NewAgentUser("issue-investigator", AgentRun{WorkItemID: "wi_a", Scope: AgentScopeInvestigate})
	if !scoped.HasTenantAccess("admins") || !scoped.HasTenantAccess("erpact") {
		t.Error("a scoped investigate run must read every tenant")
	}
	if scoped.IsAdmin() {
		t.Error("a scoped run must never be an admin")
	}
	unscoped := NewAgentUser("issue-investigator", AgentRun{WorkItemID: "wi_a"})
	if unscoped.HasTenantAccess("admins") {
		t.Error("an unscoped run token must keep no tenant")
	}
	unknown := NewAgentUser("issue-investigator", AgentRun{Scope: "no-such-scope"})
	if unknown.HasTenantAccess("admins") {
		t.Error("an unknown scope must grant no tenant")
	}
	// The scope rides on the agent field: a non-agent principal never has one.
	if _, ok := (&User{ID: "alice", agentScope: AgentScopeInvestigate}).AgentScope(); ok {
		t.Error("a non-agent principal reported a scope")
	}
}

func TestScopesTenantBindingIsExclusive(t *testing.T) {
	for _, n := range AgentScopeNames() {
		s, _ := LookupAgentScope(n)
		if s.BoundTenant && s.ReadAllTenants {
			t.Errorf("scope %s is both BoundTenant and ReadAllTenants", n)
		}
	}
	s, ok := LookupAgentScope(AgentScopeSupport)
	if !ok || s.ReadAllTenants || !s.BoundTenant {
		t.Fatalf("support scope = %+v, want BoundTenant and not ReadAllTenants", s)
	}
}

func TestSupportScope_ToolList(t *testing.T) {
	s, _ := LookupAgentScope(AgentScopeSupport)
	for _, n := range SupportToolNames() {
		if !IsReadTool(n) {
			t.Errorf("support tool %s is not a read tool", n)
		}
		if !s.AllowsTool("mctl_" + n) {
			t.Errorf("support scope refuses its own tool %s", n)
		}
	}
	for _, n := range []string{"mctl_deploy_service", "mctl_resolve_incident", "mctl_list_tenants", "mctl_get_dev_loop"} {
		if s.AllowsTool(n) {
			t.Errorf("support scope admits %s", n)
		}
	}
}

func TestSupportScope_Allows(t *testing.T) {
	s, _ := LookupAgentScope(AgentScopeSupport)
	q := func(kv ...string) url.Values {
		v := url.Values{}
		for i := 0; i+1 < len(kv); i += 2 {
			v.Add(kv[i], kv[i+1])
		}
		return v
	}
	for _, c := range []struct {
		name, method, path, tenant string
		query                      url.Values
		want                       bool
	}{
		{"own status", "GET", "/api/v1/status/labs/app", "labs", nil, true},
		{"own logs", "GET", "/api/v1/logs/labs/app", "labs", nil, true},
		{"own resources", "GET", "/api/v1/resources/labs", "labs", nil, true},
		{"own pods", "GET", "/api/v1/pods/labs/app", "labs", nil, true},
		{"other pods", "GET", "/api/v1/pods/karabu/app", "labs", nil, false},
		{"own events", "GET", "/api/v1/events/labs", "labs", nil, true},
		{"other events", "GET", "/api/v1/events/karabu", "labs", nil, false},
		{"events post", "POST", "/api/v1/events/labs", "labs", nil, false},
		{"other status", "GET", "/api/v1/status/karabu/app", "labs", nil, false},
		{"case differs", "GET", "/api/v1/status/Labs/app", "labs", nil, false},
		{"suffixed", "GET", "/api/v1/status/labs2/app", "labs", nil, false},
		{"empty bound tenant", "GET", "/api/v1/status/labs/app", "", nil, false},
		{"list with filter", "GET", "/api/v1/services", "labs", q("team", "labs"), true},
		{"list without filter", "GET", "/api/v1/services", "labs", nil, false},
		{"list other filter", "GET", "/api/v1/services", "labs", q("team", "karabu"), false},
		{"list duplicate filter", "GET", "/api/v1/services", "labs", q("team", "labs", "team", "karabu"), false},
		{"incidents tenant filter", "GET", "/api/v1/incidents", "labs", q("tenant", "labs"), true},
		{"incidents wrong key", "GET", "/api/v1/incidents", "labs", q("team", "labs"), false},
		{"stray namespace param", "GET", "/api/v1/status/labs/app", "labs", q("namespace", "other"), false},
		{"data-derived workflow", "GET", "/api/v1/workflows/wf-1", "labs", nil, true},
		{"tenants not listed", "GET", "/api/v1/tenants", "labs", nil, false},
		{"previews not listed", "GET", "/api/v1/previews", "labs", nil, false},
		{"agent-runs not listed", "GET", "/api/v1/agent-runs", "labs", nil, false},
		{"mcp post", "POST", "/mcp", "labs", nil, true},
		{"write route", "POST", "/api/v1/operations/deploy-service/execute", "labs", nil, false},
		{"put", "PUT", "/api/v1/services/labs/app", "labs", nil, false},
		{"delete", "DELETE", "/api/v1/services/labs/app", "labs", nil, false},
	} {
		got := s.Allows(AgentScopeRequest{Method: c.method, Path: c.path, Query: c.query, Tenant: c.tenant})
		if got != c.want {
			t.Errorf("%s: Allows = %v, want %v", c.name, got, c.want)
		}
	}
	if s.AllowsRoute("GET", "/api/v1/status/labs/app", "", "") {
		t.Error("AllowsRoute with no tenant admitted a bound scope")
	}
}

func TestSupportScope_AllowsToolCall(t *testing.T) {
	s, _ := LookupAgentScope(AgentScopeSupport)
	for _, c := range []struct {
		name string
		tool string
		args map[string]any
		want bool
	}{
		{"own team", "mctl_get_service_status", map[string]any{"team": "labs", "service": "x"}, true},
		{"other team", "mctl_get_service_status", map[string]any{"team": "karabu"}, false},
		{"list without tenant", "mctl_list_services", map[string]any{}, false},
		{"list own", "mctl_list_incidents", map[string]any{"tenant": "labs"}, true},
		{"team_name other", "mctl_get_service_logs", map[string]any{"team_name": "karabu"}, false},
		{"tenant other on any tool", "mctl_whoami", map[string]any{"tenant": "karabu"}, false},
		{"non-string tenant", "mctl_list_domains", map[string]any{"team": 5}, false},
		{"no tenant tool", "mctl_get_incident", map[string]any{"id": "x"}, true},
		{"pods own", "mctl_get_service_pods", map[string]any{"team": "labs", "service": "x"}, true},
		{"pods other", "mctl_get_service_pods", map[string]any{"team": "karabu", "service": "x"}, false},
		{"events no team", "mctl_list_namespace_events", map[string]any{}, false},
		{"events own", "mctl_list_namespace_events", map[string]any{"team": "labs"}, true},
		{"write tool", "mctl_deploy_service", map[string]any{"team_name": "labs"}, false},
	} {
		if got := s.AllowsToolCall(c.tool, c.args, "labs"); got != c.want {
			t.Errorf("%s: AllowsToolCall = %v, want %v", c.name, got, c.want)
		}
	}
	if s.AllowsToolCall("mctl_whoami", nil, "") {
		t.Error("empty bound tenant admitted a tool")
	}
}

func TestHasTenantAccess_BoundAgent(t *testing.T) {
	u := NewAgentUser("mctl-support", AgentRun{Scope: AgentScopeSupport, Tenant: "labs"})
	if !u.HasTenantAccess("labs") {
		t.Error("bound agent refused its own tenant")
	}
	for _, other := range []string{"", "karabu", "Labs", "admins"} {
		if u.HasTenantAccess(other) {
			t.Errorf("bound agent admitted %q", other)
		}
	}
	u.Groups = []string{"karabu"}
	if u.HasTenantAccess("karabu") {
		t.Error("bound agent admitted a tenant through a group")
	}
	unbound := NewAgentUser("mctl-support", AgentRun{Scope: AgentScopeSupport})
	if unbound.HasTenantAccess("labs") || unbound.HasTenantAccess("") {
		t.Error("bound scope with no tenant admitted a tenant")
	}
	if _, ok := unbound.BoundTenant(); ok {
		t.Error("BoundTenant true for an empty tenant")
	}
	inv := NewAgentUser("issue-investigator", AgentRun{Scope: AgentScopeInvestigate})
	if !inv.HasTenantAccess("anything") {
		t.Error("investigate scope no longer reads every tenant")
	}
	if got, _ := NewAgentUser("mctl-support", AgentRun{Scope: AgentScopeSupport, Tenant: "labs", RequestedBy: "p1"}).BoundTenant(); got != "labs" {
		t.Errorf("BoundTenant = %q", got)
	}
}

func TestAgentScope_AuditRequests(t *testing.T) {
	sup, _ := LookupAgentScope(AgentScopeSupport)
	inv, _ := LookupAgentScope(AgentScopeInvestigate)
	if !sup.AuditRequests || inv.AuditRequests {
		t.Fatalf("support=%v investigate=%v, want true/false", sup.AuditRequests, inv.AuditRequests)
	}
}

func TestAgentScopes_RefuseWorkItemIntents(t *testing.T) {
	if !IsReadTool("mctl_list_work_item_intents") {
		t.Fatal("expected the naming rule to classify the intents tool as a read")
	}
	for _, name := range AgentScopeNames() {
		s, _ := LookupAgentScope(name)
		for _, tool := range []string{"mctl_list_work_item_intents", "list_work_item_intents"} {
			if s.AllowsTool(tool) {
				t.Errorf("scope %s allows %s", name, tool)
			}
		}
		if s.AllowsRoute(http.MethodGet, "/api/v1/work-items/wi_a/intents", "wi_a", "we_1") {
			t.Errorf("scope %s allows the intents route", name)
		}
	}
}

// A scope that admits work-item reads but declares no Deny (for example a
// future BoundTenant scope) must still refuse intents: the route deny list
// is global, like the tool deny list.
func TestAgentScopes_IntentDenyIsGlobal(t *testing.T) {
	bare := &AgentScope{
		Name: "test-bare", BoundTenant: true,
		Routes: []AgentScopeRoute{{Method: http.MethodGet, BindWorkItem: true,
			Pattern: regexp.MustCompile(`^/api/v1/work-items/([^/]+)(/.*)?$`)}},
	}
	req := AgentScopeRequest{Method: http.MethodGet, WorkItemID: "wi_a", Tenant: "acme"}
	req.Path = "/api/v1/work-items/wi_a/snapshots"
	if !bare.Allows(req) {
		t.Fatal("the test scope should admit its own work item's snapshots")
	}
	req.Path = "/api/v1/work-items/wi_a/intents"
	if bare.Allows(req) {
		t.Error("a scope without Deny admits intents")
	}
}

func TestInvestigateScope_DenyIsLoadBearing(t *testing.T) {
	s, _ := LookupAgentScope(AgentScopeInvestigate)
	cp := *s
	cp.Deny = nil
	saved := agentDeniedRoutes
	t.Cleanup(func() { agentDeniedRoutes = saved })
	agentDeniedRoutes = nil
	admitted := cp.AllowsRoute(http.MethodGet, "/api/v1/work-items/wi_a/intents", "wi_a", "we_1")
	agentDeniedRoutes = saved
	if !admitted {
		t.Error("without the deny lists the bound route should admit intents")
	}
	if s.AllowsRoute(http.MethodGet, "/api/v1/work-items/wi_a/intents", "wi_a", "we_1") {
		t.Error("the real scope must refuse intents")
	}
}

func TestImplementScope_Routes(t *testing.T) {
	s, ok := LookupAgentScope(AgentScopeImplement)
	if !ok {
		t.Fatal("implement scope not defined")
	}
	if !s.AdmitsAgent("implementer") || s.AdmitsAgent("issue-investigator") || s.AdmitsAgent("shepherd") {
		t.Error("implement scope must be for implementer only")
	}
	if s.BoundTenant || !s.ReadAllTenants {
		t.Error("implement scope reads every tenant and is not tenant-bound")
	}
	if !s.Tool("mctl_list_services") || s.Tool("mctl_deploy_service") || s.Tool("mctl_resolve_incident") {
		t.Error("implement scope must admit read tools and no write or governed tool")
	}
	for _, c := range []struct {
		method, path, workItem string
		want                   bool
	}{
		// The approval routes the implementer uses. Whose approval it is, is
		// the handlers' decision (execution-bound, mctl-agents#717 S4).
		{http.MethodPost, "/api/v1/action-approvals", "wi_a", true},
		{http.MethodGet, "/api/v1/action-approvals/aar_1", "wi_a", true},
		{http.MethodPost, "/api/v1/action-approvals/aar_1/consume", "wi_a", true},
		{http.MethodPost, "/api/v1/action-approvals/aar_1/execute", "wi_a", true},
		// A decision is a human's; the list is not used.
		{http.MethodPost, "/api/v1/action-approvals/aar_1/decision", "wi_a", false},
		{http.MethodGet, "/api/v1/action-approvals", "wi_a", false},
		{http.MethodPut, "/api/v1/action-approvals/aar_1", "wi_a", false},
		{http.MethodDelete, "/api/v1/action-approvals/aar_1", "wi_a", false},
		{http.MethodPost, "/api/v1/action-approvals/aar_1/extra", "wi_a", false},
		{http.MethodPost, "/api/v1/action-approvals/aar_1/execute/x", "wi_a", false},
		// Work-item reads of its own item only, and no writes under it.
		{http.MethodGet, "/api/v1/work-items/wi_a", "wi_a", true},
		{http.MethodGet, "/api/v1/work-items/wi_b", "wi_a", false},
		{http.MethodGet, "/api/v1/work-items/wi_a/intents", "wi_a", false},
		{http.MethodPost, "/api/v1/work-items/wi_a/executions/we_1/snapshot", "wi_a", false},
		{http.MethodPost, "/api/v1/work-items/wi_a/executions", "wi_a", false},
		{http.MethodPatch, "/api/v1/work-items/wi_a", "wi_a", false},
		// Reads and the MCP transport, as investigate.
		{http.MethodGet, "/api/v1/tenants", "wi_a", true},
		{http.MethodPost, "/mcp", "wi_a", true},
		// Nothing else: the claims routes do not exist yet, and a route
		// added tomorrow stays closed until this scope lists it.
		{http.MethodPost, "/api/v1/lifecycle/claims/acquire", "wi_a", false},
		{http.MethodPost, "/api/v1/lifecycle/ownership/acquire", "wi_a", false},
		{http.MethodPost, "/api/v1/agents/dev-loop/x/approve", "wi_a", false},
		{http.MethodPost, "/api/v1/operations/deploy-service/execute", "wi_a", false},
		{http.MethodPost, "/api/v1/evidence/records", "wi_a", false},
	} {
		if got := s.AllowsRoute(c.method, c.path, c.workItem, "we_1"); got != c.want {
			t.Errorf("AllowsRoute(%s %s) = %v, want %v", c.method, c.path, got, c.want)
		}
	}
}

// Every REST write the implement scope admits is on the approval routes, so
// a new write added to the scope is a deliberate edit of this test.
func TestImplementScope_WritesAreApprovalsOnly(t *testing.T) {
	s, _ := LookupAgentScope(AgentScopeImplement)
	want := map[string]bool{
		"POST ^/api/v1/action-approvals$":               true,
		"POST ^/api/v1/action-approvals/[^/]+/consume$": true,
		"POST ^/api/v1/action-approvals/[^/]+/execute$": true,
		"POST ^/mcp$":   true,
		"DELETE ^/mcp$": true,
	}
	for _, r := range s.Routes {
		if r.Method == http.MethodGet {
			continue
		}
		key := r.Method + " " + r.Pattern.String()
		if !want[key] {
			t.Errorf("implement scope admits an unexpected write route: %s", key)
		}
		delete(want, key)
	}
	for k := range want {
		t.Errorf("implement scope no longer lists %s", k)
	}
}

// POST /action-approvals/{id}/execute marks a consumed approval executed,
// and which approval is the handlers' decision. Only the implement scope
// may list it, along with the other approval routes (mctl-api#906 open
// design point).
func TestOnlyImplementScopeListsApprovalWrites(t *testing.T) {
	probes := []string{
		"/api/v1/action-approvals",
		"/api/v1/action-approvals/aar_1",
		"/api/v1/action-approvals/aar_1/consume",
		"/api/v1/action-approvals/aar_1/execute",
		"/api/v1/action-approvals/aar_1/decision",
	}
	for _, name := range AgentScopeNames() {
		s, _ := LookupAgentScope(name)
		for _, p := range probes {
			for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
				// Any binding id a route could be bound to.
				admitted := false
				for _, wi := range []string{"", "wi_a"} {
					for _, ex := range []string{"", "we_1", "aar_1", "execute"} {
						if s.Allows(AgentScopeRequest{Method: m, Path: p, WorkItemID: wi, ExecutionID: ex, Tenant: "t"}) {
							admitted = true
						}
					}
				}
				if name == AgentScopeImplement {
					continue
				}
				if admitted {
					t.Errorf("scope %s admits %s %s: only implement may list the action-approval routes", name, m, p)
				}
			}
		}
	}
	s, _ := LookupAgentScope(AgentScopeImplement)
	if !s.AllowsRoute(http.MethodPost, "/api/v1/action-approvals/aar_1/execute", "wi_a", "we_1") {
		t.Fatal("implement scope must list execute")
	}
}

// The review scope (mctl-api#917) reaches whoami and the worker receipt
// route and nothing else: no other route, method or path variant, no MCP
// endpoint and no tool. It is minted for review-worker only, by the service
// principal only, and reads no tenant.
func TestReviewScope_RoutesToolsAndMinting(t *testing.T) {
	s, ok := LookupAgentScope(AgentScopeReview)
	if !ok {
		t.Fatal("review scope not defined")
	}
	for _, c := range []struct {
		method, path string
		want         bool
	}{
		{http.MethodGet, "/api/v1/whoami", true},
		{http.MethodPost, "/api/v1/review-receipts", true},
		{http.MethodGet, "/api/v1/review-receipts", false},
		{http.MethodPost, "/api/v1/review-receipts/manual", false},
		{http.MethodPost, "/api/v1/review-receipts/", false},
		{http.MethodPost, "/api/v1/review-requests", false},
		{http.MethodGet, "/api/v1/review-requests/rr_0000000000000000", false},
		{http.MethodGet, "/api/v1/review-gate", false},
		{http.MethodPost, "/api/v1/whoami", false},
		{http.MethodPost, "/mcp", false},
		{http.MethodGet, "/mcp", false},
		{http.MethodGet, "/api/v1/tenants", false},
		{http.MethodGet, "/api/v1/work-items/wi_a", false},
		{http.MethodPost, "/api/v1/work-items/wi_a/executions", false},
		{http.MethodPost, "/api/v1/work-items/wi_a/executions/we_1/snapshot", false},
		{http.MethodGet, "/api/v1/executions/we_1/provenance", false},
		{http.MethodPost, "/api/v1/agent-run-tokens", false},
		{http.MethodGet, "/api/v1/work-items/wi_a/intents", false},
		{http.MethodPost, "/api/v1/operations/deploy-service/execute", false},
	} {
		if got := s.AllowsRoute(c.method, c.path, "wi_a", "we_1"); got != c.want {
			t.Errorf("AllowsRoute(%s %s) = %v, want %v", c.method, c.path, got, c.want)
		}
	}
	for _, tool := range []string{"mctl_whoami", "whoami", "mctl_get_review_gate", "mctl_submit_review_assertion",
		"mctl_list_services", "mctl_deploy_service", "mctl_get_work_item", ""} {
		if s.AllowsTool(tool) || s.AllowsToolCall(tool, nil, "acme") {
			t.Errorf("review scope allows tool %q", tool)
		}
	}
	if !s.AdmitsAgent("review-worker") || s.AdmitsAgent("implementer") || s.AdmitsAgent("issue-investigator") || s.AdmitsAgent("") {
		t.Errorf("review scope agents = %v, want review-worker only", s.Agents)
	}
	if s.ReadAllTenants || s.BoundTenant || s.MintByTenantMember || !s.AuditRequests {
		t.Errorf("review scope = %+v, want no tenant reach, service-only minting, every request audited", s)
	}
	u := NewAgentUser("review-worker", AgentRun{Scope: AgentScopeReview, ExecutionID: "we_1"})
	if u.HasTenantAccess("acme") || u.IsAdmin() {
		t.Error("a review run reaches a tenant or is admin")
	}
}

// The shepherd scope (mctlhq/mctl-gitops#1980) reaches the dev-loop liveness
// read and whoami and nothing else: not the dev-loop writes, no MCP endpoint,
// no tool, and no tenant.
func TestShepherdScope_RoutesAndTools(t *testing.T) {
	s, ok := LookupAgentScope(AgentScopeShepherd)
	if !ok {
		t.Fatal("shepherd scope not defined")
	}
	for _, c := range []struct {
		method, path string
		want         bool
	}{
		{http.MethodGet, "/api/v1/whoami", true},
		{http.MethodGet, "/api/v1/agents/dev-loop/dev-loop-mctlhq-mctl-api-1", true},
		{http.MethodPost, "/api/v1/agents/dev-loop/dev-loop-mctlhq-mctl-api-1", false},
		{http.MethodPost, "/api/v1/agents/dev-loop/start", false},
		{http.MethodPost, "/api/v1/agents/dev-loop/dev-loop-mctlhq-mctl-api-1/approve", false},
		{http.MethodPost, "/api/v1/agents/dev-loop/dev-loop-mctlhq-mctl-api-1/abandon", false},
		{http.MethodGet, "/api/v1/agents/dev-loop/dev-loop-mctlhq-mctl-api-1/approve", false},
		{http.MethodGet, "/api/v1/agents/dev-loop/", false},
		{http.MethodGet, "/api/v1/agents/dev-loop", false},
		{http.MethodGet, "/api/v1/action-approvals/aar_1", false},
		{http.MethodGet, "/api/v1/tenants", false},
		{http.MethodGet, "/api/v1/work-items/wi_a", false},
		{http.MethodGet, "/api/v1/workflows", false},
		{http.MethodPost, "/api/v1/operations/deploy-service/execute", false},
		{http.MethodPost, "/api/v1/agent-run-tokens", false},
		{http.MethodPost, "/mcp", false},
		{http.MethodGet, "/mcp", false},
	} {
		if got := s.AllowsRoute(c.method, c.path, "wi_a", "we_1"); got != c.want {
			t.Errorf("AllowsRoute(%s %s) = %v, want %v", c.method, c.path, got, c.want)
		}
	}
	for _, tool := range []string{"mctl_whoami", "whoami", "mctl_get_dev_loop", "mctl_list_services", "mctl_deploy_service", ""} {
		if s.AllowsTool(tool) || s.AllowsToolCall(tool, nil, "acme") {
			t.Errorf("shepherd scope allows tool %q", tool)
		}
	}
	if !s.AdmitsAgent("shepherd") || s.AdmitsAgent("implementer") || s.AdmitsAgent("") {
		t.Error("shepherd scope must be minted for the shepherd agent only")
	}
	if s.ReadAllTenants || s.BoundTenant || s.MintByTenantMember {
		t.Error("shepherd scope must read no tenant and be minted by the service principal only")
	}
}
