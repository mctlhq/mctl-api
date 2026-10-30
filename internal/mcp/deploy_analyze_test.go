package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestDeployPlanTools_ForwardAndSurfaceCodes(t *testing.T) {
	var gotMethod, gotPath, gotSurface string
	var gotBody map[string]any
	status := http.StatusOK
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotSurface = r.Method, r.URL.Path, r.Header.Get("X-Mctl-Surface")
		gotBody = nil
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(status)
		if status >= 400 {
			_, _ = w.Write([]byte(`{"code":"prod_requires_promote","error":"production is reached only through promote"}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"dpl_1"}`))
	}))
	defer backend.Close()
	srv := NewServer(backend.URL, "test-token")

	_, plan := srv.toolDeployPlan()
	res, err := plan(context.Background(), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: map[string]any{
		"intent": map[string]any{"kind": "DeployIntent"}, "idempotency_key": "k1", "ttl_seconds": float64(120),
	}}})
	if err != nil || res.IsError {
		t.Fatalf("%v %+v", err, res)
	}
	if gotMethod != http.MethodPost || gotPath != "/api/v1/deploy/plan" || gotSurface != "mcp" {
		t.Fatalf("%s %s surface=%q", gotMethod, gotPath, gotSurface)
	}
	if gotBody["idempotency_key"] != "k1" || gotBody["ttl_seconds"] != float64(120) || gotBody["intent"] == nil {
		t.Fatalf("body = %v", gotBody)
	}

	_, get := srv.toolGetDeployPlan()
	res, err = get(context.Background(), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: map[string]any{"id": "dpl_1"}}})
	if err != nil || res.IsError {
		t.Fatalf("%v %+v", err, res)
	}
	if gotMethod != http.MethodGet || gotPath != "/api/v1/deploy/plans/dpl_1" {
		t.Fatalf("%s %s", gotMethod, gotPath)
	}

	status = http.StatusUnprocessableEntity
	res, _ = plan(context.Background(), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: map[string]any{"intent": map[string]any{}}}})
	text := ""
	for _, c := range res.Content {
		if tc, ok := c.(mcplib.TextContent); ok {
			text += tc.Text
		}
	}
	if !res.IsError || !strings.Contains(text, "prod_requires_promote") {
		t.Fatalf("error code not surfaced: %+v %q", res, text)
	}
	res, _ = plan(context.Background(), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: map[string]any{}}})
	if !res.IsError {
		t.Fatal("a missing intent must be a tool error")
	}
}
