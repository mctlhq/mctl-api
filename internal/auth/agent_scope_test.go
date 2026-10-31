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
