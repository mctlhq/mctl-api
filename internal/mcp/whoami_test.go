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
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// callWhoamiViaMCP drives mctl_whoami through the real MCP message-handling
// path (tools/call over HandleMessage), not the handler closure directly, so
// these tests exercise exactly what a client sees.
func callWhoamiViaMCP(t *testing.T, srv *Server) (text string, isError bool) {
	t.Helper()
	mcpSrv := srv.NewMCPServer()
	reqJSON := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"mctl_whoami","arguments":{}}}`
	resp := mcpSrv.HandleMessage(context.Background(), json.RawMessage(reqJSON))

	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal response: %v", err)
	}

	var result struct {
		Result struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("failed to unmarshal tools/call response: %v\nraw: %s", err, raw)
	}
	if len(result.Result.Content) == 0 {
		t.Fatalf("tools/call returned no content: %s", raw)
	}
	return result.Result.Content[0].Text, result.Result.IsError
}

// assertNoLoopback fails the test if text mentions localhost or a loopback
// literal address, in any casing.
func assertNoLoopback(t *testing.T, text string) {
	t.Helper()
	lower := strings.ToLower(text)
	for _, needle := range []string{"localhost", "127.0.0.1", "::1"} {
		if strings.Contains(lower, needle) {
			t.Errorf("response leaked loopback address %q: %s", needle, text)
		}
	}
}

// T1: No loopback through the production construction path, any port.
//
// Mutation check (verified by hand): putting s.apiURL back into the message
// makes this test fail on the "localhost" assertion, since NewInProcessServer
// builds apiURL as "http://localhost:<port>".
func TestToolWhoami_InProcessServer_NoLoopback(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/whoami" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"mashkovd","groups":["admins","ovk"],"isAdmin":true,"namespaces":["admins","ovk"]}`))
	}))
	defer backend.Close()

	_, port, err := net.SplitHostPort(strings.TrimPrefix(backend.URL, "http://"))
	if err != nil {
		t.Fatalf("failed to split backend host:port: %v", err)
	}

	srv := NewInProcessServer(port, "https://api.mctl.ai")

	text, isError := callWhoamiViaMCP(t, srv)
	if isError {
		t.Fatalf("expected success result, got error: %s", text)
	}

	assertNoLoopback(t, text)

	if !strings.Contains(text, "Authenticated to https://api.mctl.ai") {
		t.Errorf("expected 'Authenticated to https://api.mctl.ai' line, got: %s", text)
	}
	for _, want := range []string{
		"User: mashkovd",
		"Admin: true",
		"Teams: [admins ovk]",
		"Accessible namespaces: [admins ovk]",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("expected response to contain %q, got: %s", want, text)
		}
	}
}

// T2: Error path leaks nothing when the upstream call fails.
func TestToolWhoami_UpstreamFailure_NoLoopbackLeak(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	_, port, err := net.SplitHostPort(strings.TrimPrefix(backend.URL, "http://"))
	if err != nil {
		t.Fatalf("failed to split backend host:port: %v", err)
	}
	backend.Close() // close so nothing is listening on the port anymore

	srv := NewInProcessServer(port, "https://api.mctl.ai")

	text, isError := callWhoamiViaMCP(t, srv)
	if !isError {
		t.Fatalf("expected error result for a failed upstream call, got success: %s", text)
	}

	assertNoLoopback(t, text)
	if strings.Contains(text, "http://") {
		t.Errorf("error result leaked a raw upstream URL: %s", text)
	}
	if !strings.Contains(text, "Failed to get identity") {
		t.Errorf("expected error result to say identity retrieval failed, got: %s", text)
	}
}

// T3: isLoopbackURL unit table.
func TestIsLoopbackURL(t *testing.T) {
	tests := []struct {
		raw  string
		want bool
	}{
		{"http://localhost:8080", true},
		{"http://LOCALHOST:9999", true},
		{"http://127.0.0.1:8080", true},
		{"http://127.0.0.53", true},
		{"http://[::1]:8080", true},
		{"https://api.mctl.ai", false},
		{"https://mcp.mctl.ai/mcp", false},
		{"", false},
		{":://bad", false},
	}
	for _, tc := range tests {
		if got := isLoopbackURL(tc.raw); got != tc.want {
			t.Errorf("isLoopbackURL(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}

// T4: Fallback rendering omits the "Authenticated to" line (and its leading
// blank line) when no trustworthy public URL is configured, while identity
// fields still render.
func TestToolWhoami_FallbackRendering_NoPublicURL(t *testing.T) {
	tests := []struct {
		name      string
		publicURL string
	}{
		{"empty public URL", ""},
		{"loopback public URL", "http://localhost:8080"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"mashkovd","groups":["admins","ovk"],"isAdmin":true,"namespaces":["admins","ovk"]}`))
			}))
			defer backend.Close()

			_, port, err := net.SplitHostPort(strings.TrimPrefix(backend.URL, "http://"))
			if err != nil {
				t.Fatalf("failed to split backend host:port: %v", err)
			}

			srv := NewInProcessServer(port, tc.publicURL)

			text, isError := callWhoamiViaMCP(t, srv)
			if isError {
				t.Fatalf("expected success result, got error: %s", text)
			}

			if strings.Contains(text, "Authenticated to") {
				t.Errorf("expected no 'Authenticated to' line, got: %s", text)
			}
			if strings.HasPrefix(text, "\n") {
				t.Errorf("expected no leading blank line, got: %q", text)
			}
			for _, want := range []string{
				"User: mashkovd",
				"Admin: true",
				"Teams: [admins ovk]",
				"Accessible namespaces: [admins ovk]",
			} {
				if !strings.Contains(text, want) {
					t.Errorf("expected response to contain %q, got: %s", want, text)
				}
			}
		})
	}
}

// T5: Stdio path unchanged — NewServer("https://api.mctl.ai/", "tok") renders
// "Authenticated to https://api.mctl.ai" (trailing slash trimmed), pinning
// that cmd/mcp/main.go's only correct configuration does not regress.
func TestToolWhoami_StdioServer_TrimsTrailingSlash(t *testing.T) {
	srv := NewServer("https://api.mctl.ai/", "tok")
	if got := srv.displayURL(); got != "https://api.mctl.ai" {
		t.Errorf("displayURL() = %q, want %q", got, "https://api.mctl.ai")
	}

	// Functional check through the full MCP path: use a real backend for the
	// upstream REST call (httptest servers only ever bind to loopback, so they
	// cannot stand in for the public URL itself) while pinning publicURL to a
	// non-loopback value directly, mirroring how NewServer ties apiURL and
	// publicURL together for the stdio binary without requiring the test to
	// reach a live https://api.mctl.ai.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"mashkovd","groups":["admins"],"isAdmin":false,"namespaces":["admins"]}`))
	}))
	defer backend.Close()

	live := NewServer(backend.URL, "tok")
	live.publicURL = "https://api.mctl.ai"

	text, isError := callWhoamiViaMCP(t, live)
	if isError {
		t.Fatalf("expected success result, got error: %s", text)
	}
	if !strings.Contains(text, "Authenticated to https://api.mctl.ai") {
		t.Errorf("expected 'Authenticated to https://api.mctl.ai', got: %s", text)
	}
}
