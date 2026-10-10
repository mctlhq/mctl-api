package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// The API answers a reserved create-tenant name with 400 and the reason in
// "error" (internal/api TestCreateTenant_ReservedNameReasonIsInErrorField).
// doRequest surfaces only that field, so the tool result must carry it.
func TestToolCreateTenant_SurfacesReservedNameReason(t *testing.T) {
	var gotPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"validation failed: tenant_name: \"kube-system\" is reserved for platform use; choose a different name","validationErrors":["tenant_name: \"kube-system\" is reserved for platform use; choose a different name"]}`))
	}))
	defer backend.Close()

	_, handler := NewServer(backend.URL, "test-token").toolCreateTenant()
	result, err := handler(context.Background(), mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{
			Name:      "mctl_create_tenant",
			Arguments: map[string]any{"tenant_name": "kube-system"},
		},
	})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected an error result")
	}
	if gotPath != "/api/v1/operations/create-tenant/execute" {
		t.Errorf("path = %q", gotPath)
	}
	text := ""
	for _, c := range result.Content {
		if tc, ok := c.(mcplib.TextContent); ok {
			text += tc.Text
		}
	}
	if !strings.Contains(text, "reserved for platform use") {
		t.Errorf("tool result does not carry the reserved-name reason: %q", text)
	}
}
