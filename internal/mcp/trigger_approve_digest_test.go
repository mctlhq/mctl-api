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
