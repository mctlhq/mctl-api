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
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

// callRecoveryTool invokes one of the five recovery tools directly, mirroring
// callLifecycleTool in lifecycle_test.go.
func callRecoveryTool(
	t *testing.T, apiURL, toolName string,
	get func(*Server) (mcplib.Tool, mcpserver.ToolHandlerFunc),
	args map[string]any,
) *mcplib.CallToolResult {
	t.Helper()
	srv := NewServer(apiURL, "test-token")
	_, handler := get(srv)
	result, err := handler(context.Background(), mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{Name: toolName, Arguments: args},
	})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	return result
}

func baseRecoveryArgs() map[string]any {
	return map[string]any{
		"kind": "pull-request", "id": "mctlhq/mctl-web#42", "phase": "review-remediation",
		"expected_owner_type": "shepherd", "expected_owner_id": "cron",
		"expected_epoch": "7", "expected_version": "sha-abc",
		"reason": "wf pod OOMKilled at 03:12; no tick since",
	}
}

// TestDestructiveRecoveryToolsRequireConfirm proves mctl_fence_lifecycle_claim
// and mctl_request_lifecycle_handoff refuse without confirm="yes" and never
// reach the API.
func TestDestructiveRecoveryToolsRequireConfirm(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("the API must not be called without confirmation: %s", r.URL.Path)
	}))
	defer backend.Close()

	args := baseRecoveryArgs()
	result := callRecoveryTool(t, backend.URL, "mctl_fence_lifecycle_claim",
		(*Server).toolFenceLifecycleClaim, args)
	if !result.IsError {
		t.Fatal("fence without confirm succeeded")
	}
	if text := resultText(t, result); !strings.Contains(text, "Confirmation required") {
		t.Errorf("unexpected refusal message: %q", text)
	}

	handoffArgs := baseRecoveryArgs()
	handoffArgs["to_owner_type"] = "pr-steward"
	handoffArgs["to_owner_id"] = "steward"
	result = callRecoveryTool(t, backend.URL, "mctl_request_lifecycle_handoff",
		(*Server).toolRequestLifecycleHandoff, handoffArgs)
	if !result.IsError {
		t.Fatal("request-handoff without confirm succeeded")
	}
	if text := resultText(t, result); !strings.Contains(text, "Confirmation required") {
		t.Errorf("unexpected refusal message: %q", text)
	}
}

// TestRecoveryToolsPostPreconditionsVerbatim proves each mutating tool posts
// the exact precondition values to the expected path, with expected_epoch as
// a JSON NUMBER (the API rejects a string there).
func TestRecoveryToolsPostPreconditionsVerbatim(t *testing.T) {
	for _, tc := range []struct {
		name     string
		path     string
		extra    map[string]any
		get      func(*Server) (mcplib.Tool, mcpserver.ToolHandlerFunc)
		toolName string
	}{
		{
			name: "reconcile", path: "/api/v1/lifecycle/ownership/recovery/reconcile",
			get: (*Server).toolRequestLifecycleReconcile, toolName: "mctl_request_lifecycle_reconcile",
		},
		{
			name: "fence", path: "/api/v1/lifecycle/ownership/recovery/fence",
			extra: map[string]any{"confirm": "yes"},
			get:   (*Server).toolFenceLifecycleClaim, toolName: "mctl_fence_lifecycle_claim",
		},
		{
			name: "handoff-request", path: "/api/v1/lifecycle/ownership/recovery/handoff/request",
			extra: map[string]any{"confirm": "yes", "to_owner_type": "pr-steward", "to_owner_id": "steward"},
			get:   (*Server).toolRequestLifecycleHandoff, toolName: "mctl_request_lifecycle_handoff",
		},
		{
			name: "handoff-retry", path: "/api/v1/lifecycle/ownership/recovery/handoff/retry",
			get: (*Server).toolRetryLifecycleHandoff, toolName: "mctl_retry_lifecycle_handoff",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotPath string
			var gotBody map[string]any
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				_ = json.NewDecoder(r.Body).Decode(&gotBody)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"ok":true}`))
			}))
			defer backend.Close()

			args := baseRecoveryArgs()
			for k, v := range tc.extra {
				args[k] = v
			}
			result := callRecoveryTool(t, backend.URL, tc.toolName, tc.get, args)
			if result.IsError {
				t.Fatalf("unexpected error: %s", resultText(t, result))
			}
			if gotPath != tc.path {
				t.Errorf("posted to %q, want %q", gotPath, tc.path)
			}
			if gotBody["kind"] != "pull-request" || gotBody["id"] != "mctlhq/mctl-web#42" || gotBody["phase"] != "review-remediation" {
				t.Errorf("entity fields not sent verbatim: %+v", gotBody)
			}
			if gotBody["expected_owner_type"] != "shepherd" || gotBody["expected_owner_id"] != "cron" {
				t.Errorf("expected owner not sent verbatim: %+v", gotBody)
			}
			// json.Unmarshal into map[string]any decodes numbers as float64.
			if epoch, ok := gotBody["expected_epoch"].(float64); !ok || epoch != 7 {
				t.Errorf("expected_epoch was not sent as a JSON number 7: %#v", gotBody["expected_epoch"])
			}
			if gotBody["expected_version"] != "sha-abc" {
				t.Errorf("expected_version not sent verbatim: %+v", gotBody)
			}
			if gotBody["reason"] != "wf pod OOMKilled at 03:12; no tick since" {
				t.Errorf("reason not sent verbatim: %+v", gotBody)
			}
			if _, present := gotBody["confirm"]; present {
				t.Error("confirm must not be forwarded to the API; it is a client-side gate only")
			}
		})
	}
}

// TestFenceLifecycleClaim_EmptyVersionIsSentNotOmitted proves expected_version
// == "" is still sent as a present key, matching the API's "empty string
// matches an unset version" contract -- omitting the key entirely would be a
// different, invalid request.
func TestFenceLifecycleClaim_EmptyVersionIsSentNotOmitted(t *testing.T) {
	var gotBody map[string]any
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer backend.Close()

	args := baseRecoveryArgs()
	args["expected_version"] = ""
	args["confirm"] = "yes"
	result := callRecoveryTool(t, backend.URL, "mctl_fence_lifecycle_claim", (*Server).toolFenceLifecycleClaim, args)
	if result.IsError {
		t.Fatalf("unexpected error: %s", resultText(t, result))
	}
	v, present := gotBody["expected_version"]
	if !present {
		t.Fatal("expected_version key was omitted, not sent as an empty string")
	}
	if v != "" {
		t.Errorf("expected_version = %#v, want empty string", v)
	}
}

// TestRecoveryTool_NonIntegerEpochIsRefusedLocally proves a malformed epoch
// never reaches the API at all.
func TestRecoveryTool_NonIntegerEpochIsRefusedLocally(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("a non-integer expected_epoch must be refused before any API call")
	}))
	defer backend.Close()

	args := baseRecoveryArgs()
	args["expected_epoch"] = "not-a-number"
	result := callRecoveryTool(t, backend.URL, "mctl_retry_lifecycle_handoff", (*Server).toolRetryLifecycleHandoff, args)
	if !result.IsError {
		t.Fatal("non-integer epoch was accepted")
	}
	if text := resultText(t, result); !strings.Contains(text, "expected_epoch") {
		t.Errorf("unexpected error message: %q", text)
	}
}
