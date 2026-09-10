package mcp

import (
	"sort"
	"testing"
)

// TestEveryToolDeclaresItsAnnotations is the record the portal allowlist is
// derived from (mctlhq/mctl-api#276). mcp-go's defaults when a hint is
// absent are readOnly=false and destructive=true, which is the wrong shape
// for a read and a silent one for a write, so every tool states both
// explicitly. A new tool without them fails here rather than shipping as
// "unknown, assume destructive" — or worse, as read-only by omission on a
// surface that decides exposure from the hint.
func TestEveryToolDeclaresItsAnnotations(t *testing.T) {
	tools := NewServer("http://localhost:8080", "").NewMCPServer().ListTools()
	if len(tools) < 70 {
		t.Fatalf("only %d tools enumerated; the registration this test relies on has changed", len(tools))
	}
	var missing []string
	for name, st := range tools {
		a := st.Tool.Annotations
		if a.ReadOnlyHint == nil || a.DestructiveHint == nil {
			missing = append(missing, name)
			continue
		}
		if *a.ReadOnlyHint && *a.DestructiveHint {
			missing = append(missing, name+" (readOnly and destructive at once)")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("tools without an explicit readOnlyHint and destructiveHint: %v", missing)
	}
}

// TestReadOnlyToolsAreTheRecordedSet pins the read-only classification as
// data, so a change to it is a visible diff rather than a side effect of
// editing a tool. The portal's allowlist for this server is a subset of this
// list and never anything outside it.
func TestReadOnlyToolsAreTheRecordedSet(t *testing.T) {
	want := []string{
		"mctl_get_dev_loop", "mctl_get_incident", "mctl_get_openclaw_sizing_recommendation", "mctl_get_operation",
		"mctl_get_resource_usage", "mctl_get_service_config", "mctl_get_service_logs", "mctl_get_service_status",
		"mctl_get_tenant", "mctl_get_workflow_logs", "mctl_get_workflow_status", "mctl_grant_repo_access",
		"mctl_incident_summary", "mctl_list_agent_executions", "mctl_list_agent_versions", "mctl_list_domains",
		"mctl_list_incidents", "mctl_list_openclaw_identity", "mctl_list_openclaw_skills", "mctl_list_operations",
		"mctl_list_platform_skills", "mctl_list_previews", "mctl_list_recent_agent_runs", "mctl_list_recent_operations",
		"mctl_list_repos", "mctl_list_services", "mctl_list_tenant_skill_bindings", "mctl_list_tenants",
		"mctl_list_workflows", "mctl_read_openclaw_identity", "mctl_read_openclaw_skill", "mctl_read_platform_skill",
		"mctl_resolve_agent", "mctl_whoami",
	}
	var got []string
	for name, st := range NewServer("http://localhost:8080", "").NewMCPServer().ListTools() {
		if a := st.Tool.Annotations; a.ReadOnlyHint != nil && *a.ReadOnlyHint {
			got = append(got, name)
		}
	}
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("read-only set has %d tools, recorded %d:\n got  %v\n want %v", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("read-only set differs at %q vs %q:\n got  %v\n want %v", got[i], want[i], got, want)
		}
	}
}
