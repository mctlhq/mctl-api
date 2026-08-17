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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mctlhq/mctl-api/internal/operations"
)

func TestExtractStringParams(t *testing.T) {
	args := map[string]any{
		"team":   "billing",
		"count":  42,
		"flag":   true,
		"empty":  "",
		"action": "deploy",
	}
	result := extractStringParams(args)

	if result["team"] != "billing" {
		t.Errorf("team: got %q, want billing", result["team"])
	}
	if result["action"] != "deploy" {
		t.Errorf("action: got %q, want deploy", result["action"])
	}
	if result["empty"] != "" {
		t.Errorf("empty: got %q, want empty string", result["empty"])
	}
	// Non-string values should be dropped.
	if _, ok := result["count"]; ok {
		t.Error("non-string int value should be dropped")
	}
	if _, ok := result["flag"]; ok {
		t.Error("non-string bool value should be dropped")
	}
}

func TestNewMCPServer_ToolCount(t *testing.T) {
	srv := NewServer("http://localhost:8080", "")
	mcpSrv := srv.NewMCPServer()
	if mcpSrv == nil {
		t.Fatal("NewMCPServer returned nil")
	}
	// Verify the server was created without panicking (tool registration is validated at startup).
	// We can't easily count tools without reflection, but we can ensure the server is non-nil.
}

func TestToolDescriptions_NotEmpty(t *testing.T) {
	srv := NewServer("http://localhost:8080", "")

	tools := []struct {
		name string
		fn   func() interface{}
	}{
		{"toolListTenants", func() interface{} { t, _ := srv.toolListTenants(); return t }},
		{"toolListServices", func() interface{} { t, _ := srv.toolListServices(); return t }},
		{"toolDeployService", func() interface{} { t, _ := srv.toolDeployService(); return t }},
		{"toolCreateTenant", func() interface{} { t, _ := srv.toolCreateTenant(); return t }},
		{"toolRollbackService", func() interface{} { t, _ := srv.toolRollbackService(); return t }},
		{"toolCreatePreview", func() interface{} { t, _ := srv.toolCreatePreview(); return t }},
		{"toolDeletePreview", func() interface{} { t, _ := srv.toolDeletePreview(); return t }},
	}

	for _, tc := range tools {
		result := tc.fn()
		if result == nil {
			t.Errorf("%s returned nil tool", tc.name)
		}
	}
}

// TestToolDeployService_ExposesEveryOperationParameter guards against the
// MCP tool schema silently drifting from what the backend operation actually
// accepts: extractStringParams passes through any string argument regardless
// of the declared schema, so a parameter present in operations.Registry but
// missing from toolDeployService's WithString list is invisible to callers
// even though the backend would honor it (found in practice: dockerfile_path,
// image_tag, secret_env_vars, and skip_health_check were all already
// supported server-side but absent here).
func TestToolDeployService_ExposesEveryOperationParameter(t *testing.T) {
	srv := NewServer("http://localhost:8080", "")
	tool, _ := srv.toolDeployService()

	reg := operations.NewRegistry()
	op, ok := reg.Get("deploy-service")
	if !ok {
		t.Fatal("deploy-service operation not found in registry")
	}

	for _, p := range op.Parameters {
		if p.Name == "host" {
			// host is derived by the handler from component_type, never a
			// user-facing MCP parameter — see toolDeployService's handler.
			continue
		}
		if _, exposed := tool.InputSchema.Properties[p.Name]; !exposed {
			t.Errorf("operation parameter %q is not exposed on the mctl_deploy_service MCP tool schema", p.Name)
		}
	}
}

func TestNewServer(t *testing.T) {
	srv := NewServer("https://api.mctl.ai", "test-token")
	if srv == nil {
		t.Fatal("NewServer returned nil")
	}
	if srv.apiURL != "https://api.mctl.ai" {
		t.Errorf("apiURL: got %q", srv.apiURL)
	}
	if srv.apiToken != "test-token" {
		t.Errorf("apiToken: got %q", srv.apiToken)
	}
}

func TestNewServer_TrimsTrailingSlash(t *testing.T) {
	srv := NewServer("https://api.mctl.ai/", "")
	if srv.apiURL != "https://api.mctl.ai" {
		t.Errorf("trailing slash not trimmed: got %q", srv.apiURL)
	}
}

func TestAllToolsHaveTitleAnnotation(t *testing.T) {
	srv := NewServer("http://localhost:8080", "")
	mcpSrv := srv.NewMCPServer()

	// Send a tools/list request to get all registered tools.
	req := json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	resp := mcpSrv.HandleMessage(context.Background(), req)

	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal response: %v", err)
	}

	var result struct {
		Result struct {
			Tools []struct {
				Name        string `json:"name"`
				Annotations struct {
					Title string `json:"title"`
				} `json:"annotations"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("failed to unmarshal tools/list response: %v", err)
	}

	if len(result.Result.Tools) != 70 {
		t.Errorf("expected 70 tools, got %d", len(result.Result.Tools))
	}

	for _, tool := range result.Result.Tools {
		if tool.Annotations.Title == "" {
			t.Errorf("tool %q is missing title annotation", tool.Name)
		}
	}
}

func TestPromptsListExposesPlatformSkill(t *testing.T) {
	srv := NewServer("http://localhost:8080", "")
	mcpSrv := srv.NewMCPServer()

	req := json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"prompts/list"}`)
	resp := mcpSrv.HandleMessage(context.Background(), req)

	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal response: %v", err)
	}

	var result struct {
		Result struct {
			Prompts []struct {
				Name        string `json:"name"`
				Description string `json:"description"`
				Arguments   []struct {
					Name     string `json:"name"`
					Required bool   `json:"required"`
				} `json:"arguments"`
			} `json:"prompts"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("failed to unmarshal prompts/list response: %v", err)
	}

	if len(result.Result.Prompts) != 4 {
		t.Fatalf("expected 4 prompts, got %d", len(result.Result.Prompts))
	}
	var prompt struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Arguments   []struct {
			Name     string `json:"name"`
			Required bool   `json:"required"`
		} `json:"arguments"`
	}
	found := false
	for _, p := range result.Result.Prompts {
		if p.Name == "platform-skill" {
			prompt = p
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected platform-skill prompt in prompts list")
	}
	if prompt.Name != "platform-skill" {
		t.Errorf("prompt name: got %q, want %q", prompt.Name, "platform-skill")
	}
	if prompt.Description == "" {
		t.Error("prompt is missing a description")
	}
	if len(prompt.Arguments) != 1 || prompt.Arguments[0].Name != "skill" || !prompt.Arguments[0].Required {
		t.Errorf("expected a single required argument %q, got %+v", "skill", prompt.Arguments)
	}
}

func TestPromptPlatformSkill_GetReturnsContent(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/platform-skills/mctl-platform" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"metadata":{"name":"mctl-platform","title":"MCTL Platform","description":"Operating the mctl platform"},"content":"# mctl-platform\n\nSkill body."}`))
	}))
	defer backend.Close()

	srv := NewServer(backend.URL, "test-token")
	_, handler := srv.promptPlatformSkill()

	result, err := handler(context.Background(), mcplib.GetPromptRequest{
		Params: mcplib.GetPromptParams{Arguments: map[string]string{"skill": "mctl-platform"}},
	})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if result.Description != "Operating the mctl platform" {
		t.Errorf("description: got %q", result.Description)
	}
	if len(result.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(result.Messages))
	}
	text, ok := result.Messages[0].Content.(mcplib.TextContent)
	if !ok {
		t.Fatalf("expected text content, got %T", result.Messages[0].Content)
	}
	if text.Text != "# mctl-platform\n\nSkill body." {
		t.Errorf("content: got %q", text.Text)
	}
}

func TestPromptPlatformSkill_MissingArgument(t *testing.T) {
	srv := NewServer("http://localhost:8080", "")
	_, handler := srv.promptPlatformSkill()

	if _, err := handler(context.Background(), mcplib.GetPromptRequest{}); err == nil {
		t.Error("expected error for missing skill argument, got nil")
	}
}

func TestPromptPlatformSkill_ForwardsAPIError(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"access denied"}`))
	}))
	defer backend.Close()

	srv := NewServer(backend.URL, "test-token")
	_, handler := srv.promptPlatformSkill()

	_, err := handler(context.Background(), mcplib.GetPromptRequest{
		Params: mcplib.GetPromptParams{Arguments: map[string]string{"skill": "admin-only"}},
	})
	if err == nil {
		t.Fatal("expected error for forbidden skill, got nil")
	}
}

// TestToolCreateTenant_ExposesEveryOperationParameter is the create-tenant
// counterpart of the deploy-service guard above. It exists because
// allow_internet_egress was declared in the registry but absent from this
// tool's schema, so every MCP-created tenant silently took the registry
// default — which was "true", i.e. open internet egress, contradicting the
// tenant chart's documented closed-by-default policy.
func TestToolCreateTenant_ExposesEveryOperationParameter(t *testing.T) {
	srv := NewServer("http://localhost:8080", "")
	tool, _ := srv.toolCreateTenant()

	reg := operations.NewRegistry()
	op, ok := reg.Get("create-tenant")
	if !ok {
		t.Fatal("create-tenant operation not found in registry")
	}

	// Parameters the handler or caller supplies out of band rather than the
	// MCP client. creator_user_id is stamped from the authenticated identity;
	// the *_lim quotas are derived platform-side from the *_req values.
	internal := map[string]bool{
		"creator_user_id":  true,
		"quota_cpu_lim":    true,
		"quota_memory_lim": true,
	}

	for _, p := range op.Parameters {
		if internal[p.Name] {
			continue
		}
		if _, exposed := tool.InputSchema.Properties[p.Name]; !exposed {
			t.Errorf("operation parameter %q is not exposed on the mctl_create_tenant MCP tool schema", p.Name)
		}
	}
}
