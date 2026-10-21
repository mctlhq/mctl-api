package auth

import (
	"net/http"
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
	} {
		if got := s.AllowsRoute(c.method, c.path, c.workItem); got != c.want {
			t.Errorf("AllowsRoute(%s %s, %q) = %v, want %v", c.method, c.path, c.workItem, got, c.want)
		}
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
