package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// mctl-api#568 T1: the deploy-service host the MCP tool submits must be in
// the registry's form (lowercase, no root dot), and the none/auto defaults
// stay as they were.
func TestDeployService_HostIsNormalized(t *testing.T) {
	var mu sync.Mutex
	var got map[string]string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/operations/deploy-service/execute" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		m := map[string]string{}
		_ = json.NewDecoder(r.Body).Decode(&m)
		mu.Lock()
		got = m
		mu.Unlock()
		_, _ = w.Write([]byte(`{"workflowName":"wf"}`))
	}))
	defer backend.Close()
	_, handler := NewServer(backend.URL, "test-token").toolDeployService()

	cases := []struct {
		name string
		args map[string]any
		want string
	}{
		{"mixed case with root dot", map[string]any{"host": "API.Example.com."}, "api.example.com"},
		{"padded auto", map[string]any{"host": " auto "}, "auto"},
		{"upper-case auto", map[string]any{"host": "AUTO"}, "auto"},
		{"missing host, base-service", map[string]any{}, "auto"},
		{"missing host, worker-service", map[string]any{"component_type": "worker-service"}, "none"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := map[string]any{"team": "labs", "service": "api", "action": "deploy"}
			for k, v := range tc.args {
				args[k] = v
			}
			res, err := handler(context.Background(), mcplib.CallToolRequest{
				Params: mcplib.CallToolParams{Name: "mctl_deploy_service", Arguments: args},
			})
			if err != nil || res.IsError {
				t.Fatalf("handler: err=%v res=%+v", err, res)
			}
			mu.Lock()
			defer mu.Unlock()
			if got["host"] != tc.want {
				t.Errorf("host submitted = %q, want %q", got["host"], tc.want)
			}
		})
	}
}

// mctl-api#568 T2: team and service reach the domain registry and the
// domain workflows trimmed and lowercased, matching the REST path.
func TestDomainTools_NormalizeTeamAndService(t *testing.T) {
	t.Run("verify domain", func(t *testing.T) {
		var listQuery, verifyTeam string
		var wf map[string]string
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.Method == http.MethodGet && r.URL.Path == "/api/v1/domains":
				listQuery = r.URL.RawQuery
				_, _ = w.Write([]byte(`{"domains":[{"id":"d1","domain":"api.example.com","status":"pending"}]}`))
			case strings.HasSuffix(r.URL.Path, "/verify"):
				verifyTeam = r.URL.Query().Get("team")
				_, _ = w.Write([]byte(`{"verified":true}`))
			case strings.Contains(r.URL.Path, "/operations/add-custom-domain/execute"):
				_ = json.NewDecoder(r.Body).Decode(&wf)
				_, _ = w.Write([]byte(`{"workflowName":"wf"}`))
			default:
				t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
		}))
		defer backend.Close()
		res, err := callToolVerifyDomain(t, backend.URL, map[string]any{"team": " Labs ", "service": "API"})
		if err != nil || res.IsError {
			t.Fatalf("handler: err=%v res=%+v", err, res)
		}
		if listQuery != "team=labs&service=api" {
			t.Errorf("list query = %q, want team=labs&service=api", listQuery)
		}
		if verifyTeam != "labs" {
			t.Errorf("verify team = %q, want labs", verifyTeam)
		}
		if wf["team_name"] != "labs" || wf["service_name"] != "api" {
			t.Errorf("add-custom-domain params = %v, want team_name=labs service_name=api", wf)
		}
	})

	t.Run("remove domain, registry row", func(t *testing.T) {
		var listQuery, deletePath string
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.Method == http.MethodGet && r.URL.Path == "/api/v1/domains":
				listQuery = r.URL.RawQuery
				_, _ = w.Write([]byte(`{"domains":[{"id":"d1","domain":"api.example.com","status":"active"}]}`))
			case r.Method == http.MethodDelete:
				deletePath = r.URL.RequestURI()
				_, _ = w.Write([]byte(`{"status":"deleted"}`))
			default:
				t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
		}))
		defer backend.Close()
		res, err := callToolRemoveCustomDomain(t, backend.URL, map[string]any{
			"team": " Labs ", "service": "API", "domain": "api.example.com", "confirm": "yes",
		})
		if err != nil || res.IsError {
			t.Fatalf("handler: err=%v res=%+v", err, res)
		}
		if listQuery != "team=labs&service=api" {
			t.Errorf("list query = %q, want team=labs&service=api", listQuery)
		}
		if !strings.HasPrefix(deletePath, "/api/v1/domains/d1") || strings.Contains(deletePath, "Labs") {
			t.Errorf("delete call = %q, want /api/v1/domains/d1 with lowercase team", deletePath)
		}
	})

	t.Run("remove domain, legacy fallback", func(t *testing.T) {
		var wf map[string]string
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.Method == http.MethodGet && r.URL.Path == "/api/v1/domains":
				_, _ = w.Write([]byte(`{"domains":[]}`))
			case strings.Contains(r.URL.Path, "/operations/remove-custom-domain/execute"):
				_ = json.NewDecoder(r.Body).Decode(&wf)
				_, _ = w.Write([]byte(`{"workflowName":"wf"}`))
			default:
				t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
		}))
		defer backend.Close()
		res, err := callToolRemoveCustomDomain(t, backend.URL, map[string]any{
			"team": " Labs ", "service": "API", "domain": "api.example.com", "confirm": "yes",
		})
		if err != nil || res.IsError {
			t.Fatalf("handler: err=%v res=%+v", err, res)
		}
		if wf["team_name"] != "labs" || wf["service_name"] != "api" {
			t.Errorf("remove-custom-domain params = %v, want team_name=labs service_name=api", wf)
		}
	})
}
