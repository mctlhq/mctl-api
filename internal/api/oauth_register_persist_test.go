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
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/auth/clientstore/clientstoretest"
)

// The Cloudflare MCP portal's two DCR callbacks (mctlhq/mctl-api#395).
const (
	portalCallback = "https://mcp.mctl.ai/servers-callback"
	dashCallback   = "https://dash.cloudflare.com/6a09f637d20e1f66a8e9d45ebe778058/one/access-controls/ai-controls/mcp-server/oauth-callback/api"
)

// newPortalOAuth is the server as production runs it once gitops lists the two
// portal callbacks as exact OAUTH_ALLOWED_REDIRECT_URIS entries and a database
// backs the registry. A nil store selects the in-memory registry.
func newPortalOAuth(store *clientstoretest.MemoryStore) *auth.OAuthServer {
	s := auth.NewOAuthServer(
		"https://api.mctl.ai", "gh-id", "gh-secret", []byte("jwt-secret"),
		[]string{"https://claude.ai/api/mcp/auth_callback", portalCallback, dashCallback}, nil,
	)
	if store != nil {
		s.ClientStore = store
	}
	return s
}

func decodeRegistration(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return body
}

const portalRegistration = `{"client_name":"Cloudflare MCP Portal","redirect_uris":["` + portalCallback + `","` + dashCallback + `"],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],"response_types":["code"]}`

// TestOAuthRegister_PortalRegistrationSurvivesRestart: the portal registers
// once in automatic mode and caches its client_id. After a rollout (a new
// server and router over the same database) that id must still resolve and
// still authorize with both callbacks.
func TestOAuthRegister_PortalRegistrationSurvivesRestart(t *testing.T) {
	store := clientstoretest.New()
	body := decodeRegistration(t, postRegister(NewRouter(Options{OAuthServer: newPortalOAuth(store)}), portalRegistration, ""))
	clientID, _ := body["client_id"].(string)
	if clientID == "" {
		t.Fatalf("no client_id in %v", body)
	}

	after := newPortalOAuth(store)
	c, ok := after.GetClient(clientID)
	if !ok {
		t.Fatal("client registered before the restart is unknown after it")
	}
	if c.ClientName != "Cloudflare MCP Portal" {
		t.Errorf("client_name = %q after restart", c.ClientName)
	}
	router := NewRouter(Options{OAuthServer: after})
	for _, cb := range []string{portalCallback, dashCallback} {
		q := url.Values{
			"client_id":             {clientID},
			"redirect_uri":          {cb},
			"response_type":         {"code"},
			"state":                 {"s"},
			"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
			"code_challenge_method": {"S256"},
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
		req.RemoteAddr = "192.0.2.1:1234"
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "https://github.com/login/oauth/authorize") {
			t.Errorf("authorize with %s after restart: status %d location %q", cb, rec.Code, rec.Header().Get("Location"))
		}
	}
}

// TestOAuthRegister_IdempotentWithStore: registering the same metadata again
// returns the same client instead of a new row.
func TestOAuthRegister_IdempotentWithStore(t *testing.T) {
	store := clientstoretest.New()
	router := NewRouter(Options{OAuthServer: newPortalOAuth(store)})
	first := decodeRegistration(t, postRegister(router, portalRegistration, ""))
	second := decodeRegistration(t, postRegister(router, portalRegistration, ""))
	if first["client_id"] != second["client_id"] {
		t.Errorf("re-registration client_id = %v, want %v", second["client_id"], first["client_id"])
	}
	if first["client_id_issued_at"] != second["client_id_issued_at"] {
		t.Errorf("re-registration moved client_id_issued_at: %v -> %v", first["client_id_issued_at"], second["client_id_issued_at"])
	}
	if store.Len() != 1 {
		t.Errorf("stored clients = %d, want 1", store.Len())
	}
}

// TestOAuthRegister_PortalCallbacksAreExactEntries: the two portal callbacks
// are exact allowlist entries, so anything that merely resembles them -- a
// longer path, a query, another Cloudflare account, the bare dashboard host --
// is still refused with invalid_redirect_uri, alone or mixed with a good one.
func TestOAuthRegister_PortalCallbacksAreExactEntries(t *testing.T) {
	for _, bad := range []string{
		"https://evil.example/cb",
		portalCallback + "/x",
		portalCallback + "?next=https://evil.example",
		"https://mcp.mctl.ai/servers-callback2",
		"http://mcp.mctl.ai/servers-callback",
		"https://dash.cloudflare.com/0000000000000000000000000000000/one/access-controls/ai-controls/mcp-server/oauth-callback/api",
		"https://dash.cloudflare.com/",
		dashCallback + "/extra",
	} {
		for _, uris := range [][]string{{bad}, {portalCallback, bad}} {
			raw, _ := json.Marshal(map[string]any{"client_name": "x", "redirect_uris": uris})
			store := clientstoretest.New()
			rec := postRegister(NewRouter(Options{OAuthServer: newPortalOAuth(store)}), string(raw), "")
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%v: status = %d, want 400", uris, rec.Code)
				continue
			}
			var body map[string]string
			_ = json.NewDecoder(rec.Body).Decode(&body)
			if body["error"] != "invalid_redirect_uri" {
				t.Errorf("%v: error = %q, want invalid_redirect_uri", uris, body["error"])
			}
			if store.Len() != 0 {
				t.Errorf("%v: a refused registration was stored", uris)
			}
		}
	}
}

// TestOAuthRegister_NoScopeGetsMctl: a registration that names no scope is
// granted "mctl", the only scope, and the response says so. Same without a
// store, and same when a client names some other scope.
func TestOAuthRegister_NoScopeGetsMctl(t *testing.T) {
	for name, store := range map[string]*clientstoretest.MemoryStore{"persisted": clientstoretest.New(), "in-memory": nil} {
		t.Run(name, func(t *testing.T) {
			router := NewRouter(Options{OAuthServer: newPortalOAuth(store)})
			body := decodeRegistration(t, postRegister(router, portalRegistration, ""))
			if body["scope"] != "mctl" {
				t.Errorf("scope = %v, want mctl", body["scope"])
			}
			other := decodeRegistration(t, postRegister(router, `{"client_name":"y","scope":"openid profile","redirect_uris":["`+portalCallback+`"]}`, ""))
			if other["scope"] != "mctl" {
				t.Errorf("scope for a client that named another scope = %v, want mctl", other["scope"])
			}
		})
	}
}

// TestOAuthRegister_StoreFailureIs500: a registration that could not be
// persisted must not hand out a client_id that will be forgotten.
func TestOAuthRegister_StoreFailureIs500(t *testing.T) {
	store := clientstoretest.New()
	store.Err = errors.New("db down")
	rec := postRegister(NewRouter(Options{OAuthServer: newPortalOAuth(store)}), portalRegistration, "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	_ = json.NewDecoder(rec.Body).Decode(&body)
	if body["error"] != "server_error" {
		t.Errorf("error = %q, want server_error", body["error"])
	}
}
