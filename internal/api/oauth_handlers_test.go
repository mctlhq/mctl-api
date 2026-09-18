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

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
)

func TestHandleProtectedResourceMeta_ReturnsExpectedShape(t *testing.T) {
	h := &Handlers{opts: Options{OAuthServer: &auth.OAuthServer{BaseURL: "https://api.mctl.ai"}}}

	// The two registered paths describe DIFFERENT resources: the /mcp-suffixed
	// document must identify /mcp specifically, while the root document must
	// identify the REST API's base resource, not /mcp — a client challenged
	// on a non-MCP route (e.g. /api/v1/whoami) is pointed at the root
	// document and validates that its `resource` field matches what it was
	// actually accessing (RFC 9728 resource-identity check).
	cases := []struct {
		path         string
		wantResource string
	}{
		{"/.well-known/oauth-protected-resource", "https://api.mctl.ai"},
		{"/.well-known/oauth-protected-resource/mcp", "https://api.mctl.ai/mcp"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, c.path, nil)
		rec := httptest.NewRecorder()
		h.handleProtectedResourceMeta(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", c.path, rec.Code)
		}
		var meta ProtectedResourceMeta
		if err := json.NewDecoder(rec.Body).Decode(&meta); err != nil {
			t.Fatalf("%s: decode: %v", c.path, err)
		}
		if meta.Resource != c.wantResource {
			t.Errorf("%s: resource = %q, want %q", c.path, meta.Resource, c.wantResource)
		}
		if len(meta.AuthorizationServers) != 1 || meta.AuthorizationServers[0] != "https://api.mctl.ai" {
			t.Errorf("%s: authorization_servers = %v, want [https://api.mctl.ai]", c.path, meta.AuthorizationServers)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("%s: Content-Type = %q, want application/json", c.path, ct)
		}
	}
}

func TestHandleProtectedResourceMeta_NotFoundWithoutOAuthServer(t *testing.T) {
	h := &Handlers{opts: Options{}}
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()
	h.handleProtectedResourceMeta(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// A failed token exchange must name the client. Without client_id and
// client_name in this line a burst of invalid_grant said only that SOMEBODY's
// refresh had died, which is how the 2026-09-17 refresh-family revocation went
// undiagnosed until the refresh store's own WARN was correlated by hand.
func TestHandleOAuthToken_FailureLogsClientIdentity(t *testing.T) {
	srv := &auth.OAuthServer{BaseURL: "https://api.mctl.ai", JWTSecret: []byte("test-secret")}
	registered := srv.RegisterClient("Claude", []string{"https://claude.ai/api/mcp/auth_callback"})
	h := &Handlers{opts: Options{OAuthServer: srv}}

	anonymous := srv.RegisterClient("", []string{"https://claude.ai/api/mcp/auth_callback"})
	// One IP can reach this endpoint at 60 req/min without registering
	// anything, so an unbounded client_id would be a log-volume amplifier.
	oversized := strings.Repeat("a", maxEchoedValueLen*3)

	cases := []struct {
		name           string
		clientID       string
		wantClientID   string
		wantClientName string
	}{
		{"registered client", registered.ClientID, registered.ClientID, "Claude"},
		// An aged-out or never-registered id is not a gap in the signal: it
		// is the signal for that case, so it is asserted rather than skipped.
		{"unknown client", "no-such-client", "no-such-client", "unregistered"},
		// client_name is optional in RFC 7591, so "registered but anonymous"
		// is a third state and must not read as "unregistered".
		{"registered without a name", anonymous.ClientID, anonymous.ClientID, "unnamed"},
		{"oversized client_id is clipped", oversized, truncateEchoedValue(oversized), "unregistered"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			restore := swapDefaultLogger(&buf)
			defer restore()

			form := url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {"not-a-real-refresh-token"},
				"client_id":     {c.clientID},
			}
			req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			h.handleOAuthToken(rec, req)

			// The failure itself is the precondition: a 200 here would mean
			// the test never reached the arm it pins.
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (invalid_grant); body: %s", rec.Code, rec.Body.String())
			}

			var line struct {
				Msg        string `json:"msg"`
				ClientID   string `json:"client_id"`
				ClientName string `json:"client_name"`
			}
			var found bool
			for _, raw := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
				if raw == "" {
					continue
				}
				if err := json.Unmarshal([]byte(raw), &line); err != nil {
					t.Fatalf("log line is not JSON: %v (%s)", err, raw)
				}
				if line.Msg == "token exchange failed" {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("no %q log line; got:\n%s", "token exchange failed", buf.String())
			}
			if line.ClientID != c.wantClientID {
				t.Errorf("client_id = %q, want %q", line.ClientID, c.wantClientID)
			}
			if len(line.ClientID) > maxEchoedValueLen+len("...") {
				t.Errorf("client_id is %d bytes, want at most %d: the echo must stay bounded", len(line.ClientID), maxEchoedValueLen+len("..."))
			}
			if line.ClientName != c.wantClientName {
				t.Errorf("client_name = %q, want %q", line.ClientName, c.wantClientName)
			}
			// The presented refresh token is a credential; it must never ride
			// along in the diagnostic line that now names the client.
			if strings.Contains(buf.String(), "not-a-real-refresh-token") {
				t.Error("the presented refresh token must not be logged")
			}
		})
	}
}
