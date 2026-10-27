package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

func TestDeployTools_CallExpectedPaths(t *testing.T) {
	var gotPath, gotQuery string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		_, _ = w.Write([]byte(`{}`))
	}))
	defer backend.Close()
	srv := NewServer(backend.URL, "test-token")

	_, analyze := srv.toolDeployAnalyze()
	res, err := analyze(context.Background(), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: map[string]any{
		"tenant": "acme", "repository": "Acme/App", "revision": "0123456789abcdef0123456789abcdef01234567", "dockerfile": "a b/Dockerfile",
	}}})
	if err != nil || res.IsError {
		t.Fatalf("%v %+v", err, res)
	}
	if gotPath != "/api/v1/deploy/analyze" || gotQuery != "dockerfile=a+b%2FDockerfile&repository=Acme%2FApp&revision=0123456789abcdef0123456789abcdef01234567&tenant=acme" {
		t.Fatalf("%s?%s", gotPath, gotQuery)
	}

	_, binding := srv.toolGetRepoBinding()
	res, err = binding(context.Background(), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: map[string]any{"repository": "Acme/App"}}})
	if err != nil || res.IsError {
		t.Fatalf("%v %+v", err, res)
	}
	if gotPath != "/api/v1/deploy/bindings" || gotQuery != "repository=Acme%2FApp" {
		t.Fatalf("%s?%s", gotPath, gotQuery)
	}
}
