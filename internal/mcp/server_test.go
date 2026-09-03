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
	"net/url"
	"strings"
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

	if len(result.Result.Tools) != 73 {
		t.Errorf("expected 73 tools, got %d", len(result.Result.Tools))
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

// callToolApproveDevLoop builds a CallToolRequest for toolApproveDevLoop with
// the given arguments and runs its handler.
func callToolApproveDevLoop(t *testing.T, apiURL string, args map[string]any) (*mcplib.CallToolResult, error) {
	t.Helper()
	srv := NewServer(apiURL, "test-token")
	_, handler := srv.toolApproveDevLoop()
	return handler(context.Background(), mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{
			Name:      "mctl_approve_dev_loop",
			Arguments: args,
		},
	})
}

func TestToolApproveDevLoop_PostsToDevLoopApprovePath(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]interface{}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"workflow_id":"dev-loop-mctlhq-mctl-telegram-296","signalled":"approve"}`))
	}))
	defer backend.Close()

	// "approver" is passed deliberately although the tool no longer declares
	// it: the assertion below is that such a value never reaches the request
	// body. The approver is the authenticated caller, established server-side
	// (gitops#986).
	result, err := callToolApproveDevLoop(t, backend.URL, map[string]any{
		"workflow_id": "dev-loop-mctlhq-mctl-telegram-296",
		"approver":    "someone-else",
		"reason":      "looks good",
	})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected a successful result, got error content: %+v", result.Content)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("expected POST, got %s", gotMethod)
	}
	wantPath := "/api/v1/agents/dev-loop/" + url.PathEscape("dev-loop-mctlhq-mctl-telegram-296") + "/approve"
	if gotPath != wantPath {
		t.Errorf("path: got %q, want %q", gotPath, wantPath)
	}
	if _, ok := gotBody["approver"]; ok {
		t.Errorf("a caller-supplied approver reached the request body: %v", gotBody["approver"])
	}
	if gotBody["reason"] != "looks good" {
		t.Errorf("body reason: got %v", gotBody["reason"])
	}
}

func TestToolApproveDevLoop_EscapesWorkflowID(t *testing.T) {
	var gotPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer backend.Close()

	workflowID := "dev-loop/mctlhq/mctl-telegram 296"
	_, err := callToolApproveDevLoop(t, backend.URL, map[string]any{"workflow_id": workflowID})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	wantPath := "/api/v1/agents/dev-loop/" + url.PathEscape(workflowID) + "/approve"
	if gotPath != wantPath {
		t.Errorf("escaped path: got %q, want %q", gotPath, wantPath)
	}
}

func TestToolApproveDevLoop_OmitsEmptyOptionalArgs(t *testing.T) {
	var gotBody map[string]interface{}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer backend.Close()

	_, err := callToolApproveDevLoop(t, backend.URL, map[string]any{
		"workflow_id": "dev-loop-mctlhq-mctl-telegram-1",
	})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if _, ok := gotBody["approver"]; ok {
		t.Errorf("expected no approver key when not supplied, got %v", gotBody["approver"])
	}
	if _, ok := gotBody["reason"]; ok {
		t.Errorf("expected no reason key when not supplied, got %v", gotBody["reason"])
	}
}

// TestToolApproveDevLoop_NeverHitsOperationsExecute is the MCP-layer
// counterpart of the issue's "does not call standalone mctl-agents-approve or
// implementer execution" acceptance criterion: this tool must always go
// through the dev-loop signal route, never the operations-execute route.
func TestToolApproveDevLoop_NeverHitsOperationsExecute(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/api/v1/operations/") {
			t.Errorf("unexpected request to operations-execute path: %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer backend.Close()

	_, err := callToolApproveDevLoop(t, backend.URL, map[string]any{
		"workflow_id": "dev-loop-mctlhq-mctl-telegram-1",
	})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
}

func TestToolApproveDevLoop_SurfacesErrorsWithoutPanic(t *testing.T) {
	for _, code := range []int{http.StatusNotFound, http.StatusBadGateway, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(code)
				_, _ = w.Write([]byte(`{"error":"stub failure"}`))
			}))
			defer backend.Close()

			result, err := callToolApproveDevLoop(t, backend.URL, map[string]any{
				"workflow_id": "dev-loop-mctlhq-mctl-telegram-1",
			})
			if err != nil {
				t.Fatalf("handler must not return a Go error, got: %v", err)
			}
			if result == nil || !result.IsError {
				t.Fatalf("expected a tool-level error result for HTTP %d, got %+v", code, result)
			}
		})
	}
}

// callToolTriggerReconcile builds a CallToolRequest for toolTriggerReconcile
// with the given arguments and runs its handler.
func callToolTriggerReconcile(t *testing.T, apiURL string, args map[string]any) (*mcplib.CallToolResult, error) {
	t.Helper()
	srv := NewServer(apiURL, "test-token")
	_, handler := srv.toolTriggerReconcile()
	return handler(context.Background(), mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{
			Name:      "mctl_trigger_reconcile",
			Arguments: args,
		},
	})
}

func TestToolTriggerReconcile_PostsToReconcileExecutePath(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"workflow_name":"mctl-agents-reconcile-abc123"}`))
	}))
	defer backend.Close()

	result, err := callToolTriggerReconcile(t, backend.URL, map[string]any{
		"service": "mctl-api",
		"dry_run": "true",
	})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected a successful result, got error content: %+v", result.Content)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("expected POST, got %s", gotMethod)
	}
	if gotPath != "/api/v1/operations/mctl-agents-reconcile/execute" {
		t.Errorf("path: got %q", gotPath)
	}
	if gotBody["service"] != "mctl-api" {
		t.Errorf("body service: got %v", gotBody["service"])
	}
	if gotBody["dry_run"] != "true" {
		t.Errorf("body dry_run: got %v", gotBody["dry_run"])
	}
}

func TestToolTriggerReconcile_OmitsAbsentArgs(t *testing.T) {
	var gotBody map[string]string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer backend.Close()

	_, err := callToolTriggerReconcile(t, backend.URL, map[string]any{})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if _, ok := gotBody["service"]; ok {
		t.Errorf("expected no service key when not supplied, got %v", gotBody["service"])
	}
	if _, ok := gotBody["dry_run"]; ok {
		t.Errorf("expected no dry_run key when not supplied, got %v", gotBody["dry_run"])
	}
}

func TestToolTriggerReconcile_SurfacesErrorsWithoutPanic(t *testing.T) {
	for _, code := range []int{http.StatusNotFound, http.StatusBadGateway, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(code)
				_, _ = w.Write([]byte(`{"error":"stub failure"}`))
			}))
			defer backend.Close()

			result, err := callToolTriggerReconcile(t, backend.URL, map[string]any{})
			if err != nil {
				t.Fatalf("handler must not return a Go error, got: %v", err)
			}
			if result == nil || !result.IsError {
				t.Fatalf("expected a tool-level error result for HTTP %d, got %+v", code, result)
			}
		})
	}
}

// callToolTriggerApprove builds a CallToolRequest for toolTriggerApprove with
// the given arguments and runs its handler.
func callToolTriggerApprove(t *testing.T, apiURL string, args map[string]any) (*mcplib.CallToolResult, error) {
	t.Helper()
	srv := NewServer(apiURL, "test-token")
	_, handler := srv.toolTriggerApprove()
	return handler(context.Background(), mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{
			Name:      "mctl_trigger_approve",
			Arguments: args,
		},
	})
}

func TestToolTriggerApprove_PostsToApproveExecutePath(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"workflow_name":"mctl-agents-approve-abc123"}`))
	}))
	defer backend.Close()

	result, err := callToolTriggerApprove(t, backend.URL, map[string]any{
		"service":  "mctl-api",
		"slug":     "issue-42-fix-foo",
		"approver": "mashkovd",
	})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected a successful result, got error content: %+v", result.Content)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("expected POST, got %s", gotMethod)
	}
	if gotPath != "/api/v1/operations/mctl-agents-approve/execute" {
		t.Errorf("path: got %q", gotPath)
	}
	if gotBody["service"] != "mctl-api" {
		t.Errorf("body service: got %v", gotBody["service"])
	}
	if gotBody["slug"] != "issue-42-fix-foo" {
		t.Errorf("body slug: got %v", gotBody["slug"])
	}
	// This is the gitops mctl-agents-approve path, which still takes an
	// explicit approver — unlike mctl_approve_dev_loop, where the approver
	// now comes from the credential (gitops#986).
	if gotBody["approver"] != "mashkovd" {
		t.Errorf("body approver: got %v", gotBody["approver"])
	}
}

// TestToolTriggerApprove_DoesNotHardcodeApprover guards the tool from
// defaulting or overriding the approver client-side: that defaulting is
// server-side per handlers_write.go's ExecuteOperation (input["approver"] =
// user.ID when empty), so the MCP layer must pass through exactly what the
// caller supplied, including nothing.
func TestToolTriggerApprove_DoesNotHardcodeApprover(t *testing.T) {
	var gotBody map[string]string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer backend.Close()

	_, err := callToolTriggerApprove(t, backend.URL, map[string]any{
		"service": "mctl-api",
		"slug":    "issue-42-fix-foo",
	})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if _, ok := gotBody["approver"]; ok {
		t.Errorf("expected no approver key when not supplied client-side, got %v", gotBody["approver"])
	}
}

func TestToolTriggerApprove_SurfacesErrorsWithoutPanic(t *testing.T) {
	for _, code := range []int{http.StatusNotFound, http.StatusBadGateway, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(code)
				_, _ = w.Write([]byte(`{"error":"stub failure"}`))
			}))
			defer backend.Close()

			result, err := callToolTriggerApprove(t, backend.URL, map[string]any{
				"service": "mctl-api",
				"slug":    "issue-42-fix-foo",
			})
			if err != nil {
				t.Fatalf("handler must not return a Go error, got: %v", err)
			}
			if result == nil || !result.IsError {
				t.Fatalf("expected a tool-level error result for HTTP %d, got %+v", code, result)
			}
		})
	}
}

// mcpExemptOperations lists non-HandlerOnly operations.Registry entries that
// are deliberately not exposed as MCP tools, with the reason recorded
// inline. HandlerOnly is the primary opt-out mechanism (see its doc comment
// in registry.go); this is the secondary, explicit opt-out the design calls
// for when a non-HandlerOnly operation still isn't meant to be MCP-facing.
var mcpExemptOperations = map[string]string{
	"smoke-test": "internal CI-only end-to-end operation exercised by the platform's own test suite, not an operator/agent-facing action",
}

// operationToTool maps every operations.Registry entry with HandlerOnly ==
// false (and not present in mcpExemptOperations) to the MCP tool name that
// submits it. This is the registry-to-MCP parity fixture:
// TestMCPToolsCoverEveryNonHandlerOnlyOperation fails loudly, naming the
// operation, if a registry entry is missing from this map or if the mapped
// tool name isn't actually registered.
var operationToTool = map[string]string{
	"deploy-service":             "mctl_deploy_service",
	"create-tenant":              "mctl_create_tenant",
	"provision-database":         "mctl_provision_database",
	"retire-service":             "mctl_retire_service",
	"delete-tenant":              "mctl_delete_tenant",
	"rollback-service":           "mctl_rollback_service",
	"preview-deploy":             "mctl_create_preview",
	"preview-delete":             "mctl_delete_preview",
	"add-custom-domain":          "mctl_add_custom_domain",
	"remove-custom-domain":       "mctl_remove_custom_domain",
	"mctl-agents-run":            "mctl_trigger_agents_run",
	"mctl-agents-mentor-only":    "mctl_trigger_mentor_only",
	"mctl-agents-single-service": "mctl_trigger_single_service",
	"mctl-agents-incidents":      "mctl_trigger_incident_responder",
	"mctl-agents-implement":      "mctl_trigger_implementer",
	"mctl-agents-shepherd":       "mctl_trigger_shepherd",
	"mctl-agents-investigate":    "mctl_trigger_issue",
	"mctl-agents-approve":        "mctl_trigger_approve",
	"mctl-agents-reconcile":      "mctl_trigger_reconcile",
}

// TestMCPToolsCoverEveryNonHandlerOnlyOperation is the registry-to-MCP
// parity guard: it fails if any operations.Registry entry with
// HandlerOnly == false (and not explicitly exempted via
// mcpExemptOperations) has no corresponding registered MCP tool. This is
// the systemic guard the issue asks for, so the next operation added to
// registry.go cannot silently ship without MCP coverage the way
// mctl-agents-approve and mctl-agents-reconcile did.
func TestMCPToolsCoverEveryNonHandlerOnlyOperation(t *testing.T) {
	reg := operations.NewRegistry()
	srv := NewServer("http://localhost:8080", "")
	mcpSrv := srv.NewMCPServer()

	req := json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	resp := mcpSrv.HandleMessage(context.Background(), req)

	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal response: %v", err)
	}

	var result struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("failed to unmarshal tools/list response: %v", err)
	}

	liveTools := make(map[string]bool, len(result.Result.Tools))
	for _, tool := range result.Result.Tools {
		liveTools[tool.Name] = true
	}

	for _, op := range reg.List() {
		if op.HandlerOnly {
			continue
		}
		if reason, exempt := mcpExemptOperations[op.Name]; exempt {
			t.Logf("skipping %q: exempt from MCP coverage (%s)", op.Name, reason)
			continue
		}
		toolName, mapped := operationToTool[op.Name]
		if !mapped {
			t.Errorf("registry operation %q has no MCP tool mapping in operationToTool (and/or no matching tool registered)", op.Name)
			continue
		}
		if !liveTools[toolName] {
			t.Errorf("registry operation %q maps to tool %q, but no such tool is registered in NewMCPServer()", op.Name, toolName)
		}
	}
}
