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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// forgeAccessToken signs an HS256 access token with the given aud. A Glovo
// token cannot be minted through /oauth/token yet, so the test signs one the
// way the verifier expects.
func forgeAccessToken(t *testing.T, secret []byte, iss, aud string) string {
	t.Helper()
	enc := base64.RawURLEncoding
	hdr, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	body, err := json.Marshal(map[string]any{"iss": iss, "sub": "dan", "aud": aud, "groups": []string{},
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	in := enc.EncodeToString(hdr) + "." + enc.EncodeToString(body)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(in))
	return in + "." + enc.EncodeToString(mac.Sum(nil))
}

// The Glovo gate is the only thing that keeps a Glovo-audience token off the
// authenticated routes; /mcp is mounted in the same group.
func TestGlovoAudienceGate_RefusesEveryRoute(t *testing.T) {
	const base = "https://api.example"
	secret := []byte("test-secret")
	o := auth.NewOAuthServer(base, "gh-client", "gh-secret", secret,
		[]string{testClientRedirect}, auth.NewGitHubValidator(nil))
	o.GlovoResource = auth.GlovoResourceIntended
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, err := o.ValidateJWT(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), u)))
		})
	}
	router := NewRouter(Options{OAuthServer: o, AuthMiddleware: mw,
		mcpHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })})
	call := func(method, path, bearer string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+bearer)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}
	glovo := forgeAccessToken(t, secret, base, auth.GlovoResourceIntended)
	apiTok := forgeAccessToken(t, secret, base, base)
	for _, rt := range [][2]string{
		{"GET", "/api/v1/whoami"},
		{"GET", "/api/v1/services"},
		{"POST", "/mcp"},
		{"GET", "/mcp"},
		{"DELETE", "/mcp"},
	} {
		rec := call(rt[0], rt[1], glovo)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("glovo token on %s %s = %d, want 401: %s", rt[0], rt[1], rec.Code, rec.Body.String())
			continue
		}
		if !strings.Contains(rec.Body.String(), `"invalid_token"`) || !strings.Contains(rec.Header().Get("WWW-Authenticate"), "invalid_token") {
			t.Errorf("%s %s: body %q, header %q; want invalid_token", rt[0], rt[1], rec.Body.String(), rec.Header().Get("WWW-Authenticate"))
		}
	}
	if rec := call("GET", "/api/v1/whoami", apiTok); rec.Code != http.StatusOK {
		t.Errorf("api token on whoami = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if rec := call("POST", "/mcp", apiTok); rec.Code != http.StatusOK {
		t.Errorf("api token on /mcp = %d, want it past the gate", rec.Code)
	}
}
