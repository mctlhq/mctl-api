// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/mctlhq/mctl-api/internal/auth"
)

func TestOAuthRegister_RejectsUnallowlistedRedirect(t *testing.T) {
	router := NewRouter(Options{OAuthServer: newTestOAuth()})
	rec := postRegister(router, `{"client_name":"evil","redirect_uris":["https://evil.com/cb"]}`, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "invalid_redirect_uri" {
		t.Errorf("error = %q, want invalid_redirect_uri", body["error"])
	}
	// The description must name the offending URI: it is the only signal an
	// operator gets about which allowlist entry a new MCP client needs, and
	// the DCR request body is gone by the time anyone investigates.
	if !strings.Contains(body["error_description"], "https://evil.com/cb") {
		t.Errorf("error_description = %q, want it to name the rejected redirect_uri", body["error_description"])
	}
}

func TestOAuthRegister_TruncatesOversizedRejectedRedirect(t *testing.T) {
	router := NewRouter(Options{OAuthServer: newTestOAuth()})
	long := "https://evil.com/" + strings.Repeat("a", maxShownRedirectURILen*3)
	rec := postRegister(router, `{"client_name":"evil","redirect_uris":["`+long+`"]}`, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	// Bounded so one request cannot inflate the response or the log line,
	// but still long enough to identify the client that sent it.
	if len(body["error_description"]) > maxShownRedirectURILen+64 {
		t.Errorf("error_description length = %d, want it bounded near %d", len(body["error_description"]), maxShownRedirectURILen)
	}
	if !strings.Contains(body["error_description"], "https://evil.com/") {
		t.Errorf("error_description = %q, want the leading portion of the URI retained", body["error_description"])
	}
}

func TestTruncateRedirectURI(t *testing.T) {
	short := "https://antigravity.google/oauth/callback"
	if got := truncateRedirectURI(short); got != short {
		t.Errorf("truncateRedirectURI(short) = %q, want it unchanged", got)
	}
	// Multi-byte runes straddling the cut must not be split in half, or the
	// result is invalid UTF-8 and json.Encode silently replaces bytes.
	multibyte := "https://evil.com/" + strings.Repeat("д", maxShownRedirectURILen)
	got := truncateRedirectURI(multibyte)
	if !utf8.ValidString(got) {
		t.Errorf("truncateRedirectURI produced invalid UTF-8: %q", got)
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("truncateRedirectURI(long) = %q, want a truncation marker", got)
	}
}

func TestOAuthRegister_AllowsLoopback(t *testing.T) {
	router := NewRouter(Options{OAuthServer: newTestOAuth()})
	rec := postRegister(router, `{"client_name":"cli","redirect_uris":["http://127.0.0.1:1234/callback"]}`, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 body=%s", rec.Code, rec.Body.String())
	}
}

func TestOAuthRegister_AllowsStaticAllowlist(t *testing.T) {
	router := NewRouter(Options{OAuthServer: newTestOAuth()})
	rec := postRegister(router, `{"client_name":"claude","redirect_uris":["https://claude.ai/api/mcp/auth_callback"]}`, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 body=%s", rec.Code, rec.Body.String())
	}
}

func TestOAuthRegister_RequiresInitialTokenWhenConfigured(t *testing.T) {
	router := NewRouter(Options{
		OAuthServer:            newTestOAuth(),
		OAuthRegistrationToken: "initial-access",
	})
	body := `{"client_name":"cli","redirect_uris":["http://127.0.0.1:9/callback"]}`

	rec := postRegister(router, body, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: status = %d, want 401", rec.Code)
	}
	rec = postRegister(router, body, "wrong")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: status = %d, want 401", rec.Code)
	}
	rec = postRegister(router, body, "initial-access")
	if rec.Code != http.StatusCreated {
		t.Fatalf("good token: status = %d, want 201 body=%s", rec.Code, rec.Body.String())
	}
}

func TestOAuthRegister_RateLimit(t *testing.T) {
	router := NewRouter(Options{OAuthServer: newTestOAuth()})
	body := `{"client_name":"cli","redirect_uris":["http://127.0.0.1:9/callback"]}`
	var last int
	for i := 0; i < 6; i++ {
		rec := postRegister(router, body, "")
		last = rec.Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("6th register status = %d, want 429", last)
	}
}

func newTestOAuth() *auth.OAuthServer {
	return auth.NewOAuthServer(
		"https://api.mctl.ai", "gh-id", "gh-secret", []byte("jwt-secret"),
		[]string{"https://claude.ai/api/mcp/auth_callback"}, nil,
	)
}

func postRegister(router http.Handler, body, bearer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.1:1234"
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}
