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

package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// roadmapBackend records every request and answers with status/body.
func roadmapBackend(t *testing.T, status int, body string) (*httptest.Server, *[]string) {
	t.Helper()
	var seen []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(ts.Close)
	return ts, &seen
}

func callRoadmapTool(t *testing.T, build func(*Server) (mcplib.Tool, server.ToolHandlerFunc), apiURL string, args map[string]any) *mcplib.CallToolResult {
	t.Helper()
	tool, handler := build(NewServer(apiURL, "test-token"))
	result, err := handler(context.Background(), mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{Name: tool.Name, Arguments: args},
	})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	return result
}

func TestGetReadyWorkItemsToolBuildsTheQuery(t *testing.T) {
	cases := []struct {
		args map[string]any
		want string
	}{
		{map[string]any{}, "GET /api/v1/roadmap/ready"},
		{map[string]any{"required_only": false}, "GET /api/v1/roadmap/ready?required_only=false"},
		{map[string]any{"required_only": true}, "GET /api/v1/roadmap/ready?required_only=true"},
		{map[string]any{"required_only": "false"}, "GET /api/v1/roadmap/ready?required_only=false"},
		{map[string]any{"epic": "mctlhq/.github#42", "required_only": false}, "GET /api/v1/roadmap/ready?epic=mctlhq%2F.github%2342&required_only=false"},
		{map[string]any{"epic": "  "}, "GET /api/v1/roadmap/ready"},
	}
	for _, c := range cases {
		ts, seen := roadmapBackend(t, http.StatusOK, `{"epics":[]}`)
		result := callRoadmapTool(t, (*Server).toolGetReadyWorkItems, ts.URL, c.args)
		if result.IsError || len(*seen) != 1 || (*seen)[0] != c.want {
			t.Errorf("args %v: requests %v, want %q (error=%v)", c.args, *seen, c.want, result.IsError)
		}
	}
	ts, seen := roadmapBackend(t, http.StatusOK, `{}`)
	if result := callRoadmapTool(t, (*Server).toolGetReadyWorkItems, ts.URL, map[string]any{"required_only": 1}); !result.IsError || len(*seen) != 0 {
		t.Errorf("a non-boolean required_only was sent on: %v", *seen)
	}
}

func TestGetEpicStatusToolEncodesTheRootIssue(t *testing.T) {
	ts, seen := roadmapBackend(t, http.StatusOK, `{"epic":{}}`)
	result := callRoadmapTool(t, (*Server).toolGetEpicStatus, ts.URL, map[string]any{"epic": "mctlhq/.github#57"})
	if result.IsError || len(*seen) != 1 || (*seen)[0] != "GET /api/v1/roadmap/epic-status?epic=mctlhq%2F.github%2357" {
		t.Fatalf("requests %v", *seen)
	}
	if result := callRoadmapTool(t, (*Server).toolGetEpicStatus, ts.URL, map[string]any{}); !result.IsError {
		t.Error("a missing epic was not refused")
	}
}

func TestRoadmapToolsKeepUnavailableApartFromNotFound(t *testing.T) {
	unavailable, _ := roadmapBackend(t, http.StatusServiceUnavailable, `{"error":"no verified roadmap publication","code":"roadmap_unavailable"}`)
	for _, build := range []func(*Server) (mcplib.Tool, server.ToolHandlerFunc){(*Server).toolGetEpicStatus, (*Server).toolGetReadyWorkItems} {
		result := callRoadmapTool(t, build, unavailable.URL, map[string]any{"epic": "x"})
		if text := resultText(t, result); !result.IsError || !strings.Contains(text, "UNKNOWN") {
			t.Errorf("503 answered %q", text)
		}
	}
	notFound, _ := roadmapBackend(t, http.StatusNotFound, `{"error":"epic not found","code":"epic_not_found"}`)
	result := callRoadmapTool(t, (*Server).toolGetEpicStatus, notFound.URL, map[string]any{"epic": "x"})
	if text := resultText(t, result); !result.IsError || !strings.Contains(text, "Epic not found") || strings.Contains(text, "UNKNOWN") {
		t.Errorf("404 answered %q", text)
	}
}
