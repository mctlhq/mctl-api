package mcp

import "testing"

func TestAgentAssetToolsCallTheirRoutes(t *testing.T) {
	ts, calls := workItemBackend(t, 200, `{"ok":true}`)
	r := callRoadmapTool(t, (*Server).toolListAgentAssets, ts.URL, map[string]any{})
	if r.IsError {
		t.Fatal(resultText(t, r))
	}
	if got := (*calls)[len(*calls)-1].line; got != "GET /api/v1/agent-assets" {
		t.Errorf("called %q", got)
	}
	r = callRoadmapTool(t, (*Server).toolGetAgentPreflight, ts.URL, map[string]any{"agent_name": "issue-investigator", "environment": "production"})
	if r.IsError {
		t.Fatal(resultText(t, r))
	}
	if got := (*calls)[len(*calls)-1].line; got != "GET /api/v1/agents/issue-investigator/preflight" {
		t.Errorf("called %q", got)
	}
}

func TestPreflightToolForwardsSelectors(t *testing.T) {
	var raw string
	ts := queryBackend(t, &raw)
	r := callRoadmapTool(t, (*Server).toolGetAgentPreflight, ts, map[string]any{
		"agent_name": "a", "definition_version": "1", "profile": "p", "profile_version": "2.0.0",
	})
	if r.IsError {
		t.Fatal(resultText(t, r))
	}
	if want := "definition_version=1&profile=p&profile_version=2.0.0"; raw != want {
		t.Errorf("query = %q, want %q", raw, want)
	}
}
