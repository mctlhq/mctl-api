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
	long := "https://evil.com/" + strings.Repeat("a", maxEchoedValueLen*3)
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
	if len(body["error_description"]) > maxEchoedValueLen+64 {
		t.Errorf("error_description length = %d, want it bounded near %d", len(body["error_description"]), maxEchoedValueLen)
	}
	if !strings.Contains(body["error_description"], "https://evil.com/") {
		t.Errorf("error_description = %q, want the leading portion of the URI retained", body["error_description"])
	}
}

func TestTruncateEchoedValue(t *testing.T) {
	short := "https://antigravity.google/oauth/callback"
	if got := truncateEchoedValue(short); got != short {
		t.Errorf("truncateEchoedValue(short) = %q, want it unchanged", got)
	}

	// Multi-byte runes straddling the cut must not be split in half, or the
	// result is invalid UTF-8 and json.Encode silently replaces bytes.
	multibyte := "https://evil.com/" + strings.Repeat("д", maxEchoedValueLen)
	got := truncateEchoedValue(multibyte)
	if !utf8.ValidString(got) {
		t.Errorf("truncateEchoedValue produced invalid UTF-8: %q", got)
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("truncateEchoedValue(long) = %q, want a truncation marker", got)
	}

	// An invalid byte anywhere before the cut must not cost us the whole
	// value. A validity-driven strip-from-the-end loop consumes the entire
	// string here and returns just the ellipsis, discarding the identifying
	// prefix exactly when the input is malformed and the operator most needs
	// to see what arrived.
	malformed := "https://evil.com/\xff" + strings.Repeat("a", maxEchoedValueLen*2)
	got = truncateEchoedValue(malformed)
	if !strings.HasPrefix(got, "https://evil.com/") {
		t.Errorf("truncateEchoedValue(malformed) = %q, want the identifying prefix retained", got)
	}
	if len(got) > maxEchoedValueLen+8 {
		t.Errorf("truncateEchoedValue(malformed) length = %d, want it bounded near %d", len(got), maxEchoedValueLen)
	}
}

func TestOAuthRegister_BoundsOversizedClientNameInLog(t *testing.T) {
	router := NewRouter(Options{OAuthServer: newTestOAuth()})
	name := strings.Repeat("n", maxEchoedValueLen*4)
	rec := postRegister(router, `{"client_name":"`+name+`","redirect_uris":["https://evil.com/cb"]}`, "")
	// client_name is unbounded in RFC 7591 just as redirect_uris is, so the
	// rejection path must bound it too or the log line is oversized anyway.
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 body=%s", rec.Code, rec.Body.String())
	}
	if got := truncateEchoedValue(name); len(got) > maxEchoedValueLen+8 {
		t.Errorf("logged client_name length = %d, want it bounded near %d", len(got), maxEchoedValueLen)
	}
}

func TestOAuthRegister_RejectsOversizedBody(t *testing.T) {
	router := NewRouter(Options{OAuthServer: newTestOAuth()})
	// The body cap must reject before the decoder buffers the whole document;
	// the 5/min/IP rate limit bounds how often a caller may try, not how much
	// each attempt costs.
	huge := `{"client_name":"` + strings.Repeat("x", maxOAuthFormBytes*2) + `","redirect_uris":["https://claude.ai/api/mcp/auth_callback"]}`
	rec := postRegister(router, huge, "")
	if rec.Code == http.StatusCreated {
		t.Fatalf("oversized registration body was accepted (status %d)", rec.Code)
	}
}

func TestOAuthRegister_SetsNoStore(t *testing.T) {
	router := NewRouter(Options{OAuthServer: newTestOAuth()})
	rec := postRegister(router, `{"client_name":"cli","redirect_uris":["http://127.0.0.1:1234/callback"]}`, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 body=%s", rec.Code, rec.Body.String())
	}
	// RFC 7591 §3.2: the response carries freshly minted client credentials.
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
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

	// A desktop MCP client that fans out across processes registers once per
	// process on a cold start, and they all share one IP. Ten in a burst must
	// go through, or the client can never reach a token — that is exactly how
	// the Antigravity CLI failed against the previous limit of 5.
	for i := 0; i < 10; i++ {
		if rec := postRegister(router, body, ""); rec.Code != http.StatusCreated {
			t.Fatalf("burst registration %d: status = %d, want 201", i+1, rec.Code)
		}
	}

	var last int
	for i := 0; i < 40; i++ {
		last = postRegister(router, body, "").Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("sustained registration status = %d, want 429 — the endpoint is unauthenticated and must still throttle", last)
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
