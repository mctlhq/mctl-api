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
)

// The upstream answers 500 with a message carrying a URL with credentials and
// cluster-internal hosts. Handlers format that into "Failed to ...: %v", so
// only the shared middleware keeps it from the MCP client.
func TestToolErrors_UpstreamSecretsRedactedAcrossHandlers(t *testing.T) {
	const upstreamMsg = `{"error":"dial postgres://admin:hunter2@db.team-a.svc.cluster.local:5432/app: refused; fallback http://10.1.2.3:8080 and https://vault.internal:8200"}` //nolint:gosec // G101: synthetic credentials, the test asserts they are redacted
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(upstreamMsg))
	}))
	defer api.Close()
	s := NewServer(api.URL, "")
	srv := s.NewMCPServer()

	calls := []struct {
		tool string
		args map[string]any
	}{
		{"mctl_list_tenants", map[string]any{}},
		{"mctl_list_services", map[string]any{"team": "team-a"}},
		{"mctl_get_tenant", map[string]any{"name": "team-a"}},
		{"mctl_get_incident", map[string]any{"id": "inc-1"}},
		{"mctl_list_workflows", map[string]any{}},
		{"mctl_list_recent_operations", map[string]any{}},
	}
	for _, c := range calls {
		res, rpcErr := callTool(t, srv, c.tool, c.args)
		if res == nil {
			t.Errorf("%s: protocol-level error %q", c.tool, rpcErr)
			continue
		}
		if !res.IsError {
			t.Errorf("%s: expected an error result", c.tool)
			continue
		}
		text := resultText(t, res)
		if !strings.Contains(text, "Failed to") {
			t.Errorf("%s: message lost its readable prefix: %s", c.tool, text)
		}
		for _, leak := range []string{"hunter2", "admin:", "svc.cluster.local", "10.1.2.3", "vault.internal", api.URL} {
			if strings.Contains(text, leak) {
				t.Errorf("%s: error leaked %q: %s", c.tool, leak, text)
			}
		}
	}
}

func TestRedactErrorText(t *testing.T) {
	s := NewServer("http://api.example.test:9000", "")
	tests := []struct{ in, want string }{
		{"missing required argument: team", "missing required argument: team"},
		{"invalid issue_url: not a URL", "invalid issue_url: not a URL"},
		{"GET http://api.example.test:9000/x failed", "GET the mctl API/x failed"},
		{"dial https://u:p@example.com/x", "dial https://example.com/x"},
		{"dial tcp 192.168.1.5:5432", "dial tcp an internal host"},
		{"dial tcp 172.20.0.1", "dial tcp an internal host"},
		{"public 172.32.0.1 stays", "public 172.32.0.1 stays"},
		{"see https://docs.example.com/x", "see https://docs.example.com/x"},
	}
	for _, tc := range tests {
		if got := s.redactErrorText(tc.in); got != tc.want {
			t.Errorf("redactErrorText(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Successful results are never rewritten, even when they contain internal
// looking text: only error results are redacted.
func TestRedactToolErrors_SuccessUntouched(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"host":"db.team-a.svc.cluster.local"}`))
	}))
	defer api.Close()
	res, rpcErr := callTool(t, NewServer(api.URL, "").NewMCPServer(), "mctl_list_tenants", map[string]any{})
	if res == nil || res.IsError {
		t.Fatalf("expected success, got %+v %q", res, rpcErr)
	}
	if got := resultText(t, res); !strings.Contains(got, "db.team-a.svc.cluster.local") {
		t.Errorf("success result was rewritten: %s", got)
	}
}

// A success result may still embed an upstream error (the registry lookup
// warning of mctl_remove_custom_domain); it must be redacted at the site.
func TestRemoveCustomDomain_RegistryWarningRedacted(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/domains" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"dial postgres://admin:hunter2@db.team-a.svc.cluster.local:5432 refused"}`))
			return
		}
		_, _ = w.Write([]byte(`{"workflowName":"wf"}`))
	}))
	defer backend.Close()

	res, err := callToolRemoveCustomDomain(t, backend.URL, map[string]any{
		"team": "labs", "service": "svc", "domain": "api.example.com", "confirm": "yes",
	})
	if err != nil || res == nil || res.IsError {
		t.Fatalf("expected a success result, got %+v %v", res, err)
	}
	text := resultText(t, res)
	if !strings.Contains(text, "could not consult the domains registry") {
		t.Fatalf("warning missing: %s", text)
	}
	for _, leak := range []string{"hunter2", "admin:", "svc.cluster.local", backend.URL} {
		if strings.Contains(text, leak) {
			t.Errorf("warning leaked %q: %s", leak, text)
		}
	}
}

// Prompt handlers are not covered by the tool middleware, so the platform
// skill prompt must redact its own upstream errors.
func TestPromptPlatformSkill_UpstreamErrorRedacted(t *testing.T) {
	for name, body := range map[string]string{ //nolint:gosec // G101: synthetic credentials in the fixtures below
		"500":       `{"error":"dial postgres://admin:hunter2@db.team-a.svc.cluster.local:5432 refused"}`, //nolint:gosec // G101: synthetic credentials, the test asserts they are redacted
		"malformed": ``,
	} {
		t.Run(name, func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if name == "500" {
					w.WriteHeader(http.StatusInternalServerError)
				}
				_, _ = w.Write([]byte(body))
			}))
			defer api.Close()
			s := NewServer(api.URL, "tok")
			_, handler := s.promptPlatformSkill()
			_, err := handler(context.Background(), mcplib.GetPromptRequest{
				Params: mcplib.GetPromptParams{Arguments: map[string]string{"skill": "x"}},
			})
			if err == nil {
				t.Fatal("expected an error")
			}
			for _, leak := range []string{"hunter2", "admin:", "svc.cluster.local", api.URL} {
				if strings.Contains(err.Error(), leak) {
					t.Errorf("prompt error leaked %q: %v", leak, err)
				}
			}
		})
	}
}

// A URL whose userinfo splits the scheme from the host must not leave the
// configured API address behind once the credentials are stripped.
func TestRedactErrorText_UserinfoStrippedBeforeAPIURLMatch(t *testing.T) {
	s := NewServer("http://api.example.test:9000", "")
	got := s.redactErrorText("Get http://admin:pw@api.example.test:9000/x: refused")
	if strings.Contains(got, "api.example.test") || strings.Contains(got, "pw") {
		t.Fatalf("leaked the API address or the credential: %q", got)
	}
}

func TestRedactUpstream_NilErrorIsEmpty(t *testing.T) {
	if got := NewServer("http://api.example.test:9000", "").redactUpstream(nil); got != "" {
		t.Fatalf("redactUpstream(nil) = %q, want empty", got)
	}
}

// The redacted copy of a *TextContent stays a *TextContent, and the caller's
// original is not mutated.
func TestRedactToolErrors_PointerContentStaysPointer(t *testing.T) {
	s := NewServer("http://api.example.test:9000", "")
	orig := &mcplib.TextContent{Type: "text", Text: "dial postgres://u:pw@db.team-a.svc.cluster.local:5432 refused"}
	h := s.redactToolErrors(func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		return &mcplib.CallToolResult{IsError: true, Content: []mcplib.Content{orig}}, nil
	})
	res, err := h(context.Background(), mcplib.CallToolRequest{})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := res.Content[0].(*mcplib.TextContent)
	if !ok {
		t.Fatalf("content type = %T, want *mcplib.TextContent", res.Content[0])
	}
	if strings.Contains(got.Text, "pw") || strings.Contains(got.Text, "db.team-a") {
		t.Fatalf("not redacted: %q", got.Text)
	}
	if !strings.Contains(orig.Text, "pw") {
		t.Fatal("the caller's original content was mutated")
	}
}
