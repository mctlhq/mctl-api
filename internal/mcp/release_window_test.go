package mcp

import (
	"net/http"
	"strings"
	"testing"
)

func TestProposeReleaseWindowCallOneRequests(t *testing.T) {
	ts, calls := workItemBackend(t, http.StatusCreated, `{"ok":true}`)
	r := callRoadmapTool(t, (*Server).toolProposeReleaseWindow, ts.URL, map[string]any{
		"project": "apps", "applications": []any{"labs-mctl-web"}, "schedule": "0 22 * * 5", "duration": "48h"})
	if r.IsError {
		t.Fatal(resultText(t, r))
	}
	c := (*calls)[len(*calls)-1]
	if c.line != "POST /api/v1/release/windows" || c.auth != "Bearer test-token" {
		t.Fatalf("called %q auth %q", c.line, c.auth)
	}
	if strings.Join(c.keys, ",") != "applications,duration,project,schedule" {
		t.Errorf("body keys %v", c.keys)
	}
}

func TestProposeReleaseWindowCallTwoExecutes(t *testing.T) {
	ts, calls := workItemBackend(t, http.StatusOK, `{"status":"dispatched"}`)
	r := callRoadmapTool(t, (*Server).toolProposeReleaseWindow, ts.URL, map[string]any{"approval_id": "aar_0123456789abcdef0123456789abcdef"})
	if r.IsError {
		t.Fatal(resultText(t, r))
	}
	c := (*calls)[len(*calls)-1]
	if c.line != "POST /api/v1/release/windows/aar_0123456789abcdef0123456789abcdef/execute" || len(c.keys) != 0 {
		t.Fatalf("called %q with body keys %v", c.line, c.keys)
	}
}

// The second call carries nothing but the approval id: window fields next to
// it are refused, so a spend can never also change what is spent.
func TestProposeReleaseWindowCallTwoRefusesWindowFields(t *testing.T) {
	ts, calls := workItemBackend(t, http.StatusOK, `{}`)
	for _, k := range []string{"project", "schedule", "duration"} {
		r := callRoadmapTool(t, (*Server).toolProposeReleaseWindow, ts.URL, map[string]any{"approval_id": "aar_x", k: "apps"})
		if !r.IsError {
			t.Errorf("approval_id with %s was accepted", k)
		}
	}
	r := callRoadmapTool(t, (*Server).toolProposeReleaseWindow, ts.URL, map[string]any{"approval_id": "aar_x", "applications": []any{"a"}})
	if !r.IsError {
		t.Error("approval_id with applications was accepted")
	}
	if len(*calls) != 0 {
		t.Fatalf("a refused call reached the API: %v", *calls)
	}
}

func TestProposeReleaseWindowSurfacesTheAPIRefusal(t *testing.T) {
	ts, _ := workItemBackend(t, http.StatusConflict, `{"error":{"code":"release_window_not_decided","message":"the owner has not decided"}}`)
	r := callRoadmapTool(t, (*Server).toolProposeReleaseWindow, ts.URL, map[string]any{"approval_id": "aar_0123456789abcdef0123456789abcdef"})
	if !r.IsError || !strings.Contains(resultText(t, r), "release_window_not_decided") {
		t.Fatalf("refusal lost its code: %v", resultText(t, r))
	}
}
