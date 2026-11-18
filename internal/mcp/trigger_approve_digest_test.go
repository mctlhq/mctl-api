package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// mctl-api#722: a direct approve must carry the digest of the content its
// approver reviewed, so the tool declares it as required and forwards it to
// the execute operation unchanged.
func TestToolTriggerApprove_ForwardsTheContentDigest(t *testing.T) {
	digest := "sha256:" + strings.Repeat("c", 64)
	var gotPath string
	var gotBody map[string]string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"workflowName":"wf-1"}`))
	}))
	defer backend.Close()

	tool, handler := NewServer(backend.URL, "test-token").toolTriggerApprove()
	if !slices.Contains(tool.InputSchema.Required, "expected_content_digest") {
		t.Errorf("expected_content_digest is not required: %v", tool.InputSchema.Required)
	}
	if _, ok := tool.InputSchema.Properties["expected_content_digest"]; !ok {
		t.Fatal("expected_content_digest is not declared")
	}

	result, err := handler(context.Background(), mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{
			Name: "mctl_trigger_approve",
			Arguments: map[string]any{
				"service": "mctl-web", "slug": "issue-722", "expected_content_digest": digest,
			},
		},
	})
	if err != nil || result.IsError {
		t.Fatalf("handler: err %v, result %+v", err, result)
	}
	if gotPath != "/api/v1/operations/mctl-agents-approve/execute" {
		t.Errorf("path = %q", gotPath)
	}
	if gotBody["expected_content_digest"] != digest {
		t.Errorf("forwarded digest = %q, want %q", gotBody["expected_content_digest"], digest)
	}
}

// The decide-page-only rule (owner decision 2026-11-18): the API refuses a
// bearer-token approve with 403 decide_page_required. The tool must hand
// that refusal back as an error that keeps the code and the decide page
// link, so the AI client gives the link to the person instead of retrying,
// and its description must say so.
func TestToolTriggerApprove_SurfacesTheDecidePageRefusal(t *testing.T) {
	const decideURL = "https://api.example/devloop/decide/dev-loop-mctlhq-mctl-web-7?grant=aar_x"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code":    "decide_page_required",
			"error":   "a proposal is approved on the DevLoop decide page only",
			"details": map[string]any{"workflow_id": "dev-loop-mctlhq-mctl-web-7", "decide_url": decideURL},
		})
	}))
	defer backend.Close()

	tool, handler := NewServer(backend.URL, "test-token").toolTriggerApprove()
	for _, want := range []string{"decide_page_required", "DEVLOOP_BEARER_APPROVE_ENABLED", "mctl_get_dev_loop_approval", "decide page only"} {
		if !strings.Contains(tool.Description, want) {
			t.Errorf("description does not mention %q", want)
		}
	}
	result, err := handler(context.Background(), mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{
			Name: "mctl_trigger_approve",
			Arguments: map[string]any{
				"service": "mctl-web", "slug": "issue-7", "expected_content_digest": "sha256:" + strings.Repeat("c", 64),
			},
		},
	})
	if err != nil || !result.IsError {
		t.Fatalf("handler: err %v, result %+v; want an error result", err, result)
	}
	text := result.Content[0].(mcplib.TextContent).Text
	if !strings.Contains(text, "decide_page_required") || !strings.Contains(text, decideURL) {
		t.Errorf("tool error = %q, want the code and the decide_url", text)
	}
}
