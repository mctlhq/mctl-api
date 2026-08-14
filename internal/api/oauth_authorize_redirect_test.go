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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// /oauth/authorize must never bounce the user agent to an unvalidated
// redirect_uri. oauthError answers with a 302 to whatever it is handed, so every
// error path that reports through redirect_uri has to sit behind the allowlist
// check — otherwise the endpoint is an open redirect off api.mctl.ai, usable for
// phishing hops even though no code is attached.
func TestAuthorizeRejectsUnvalidatedRedirectBeforeRedirecting(t *testing.T) {
	h := &Handlers{opts: Options{OAuthServer: auth.NewOAuthServer(
		"https://api.mctl.ai", "gh-client", "gh-secret", []byte("secret"),
		[]string{"https://claude.ai/api/mcp/auth_callback"}, nil,
	)}}

	// Each case previously reached an oauthError() before the allowlist check.
	cases := []struct {
		name  string
		query string
	}{
		{"bad response_type", "response_type=token&redirect_uri=https://evil.com/cb&state=x"},
		{"missing client_id", "response_type=code&redirect_uri=https://evil.com/cb&state=x"}, // reported directly: no client to scope the URI to
		{"missing state", "response_type=code&client_id=c&redirect_uri=https://evil.com/cb"},
		{"missing code_challenge", "response_type=code&client_id=c&state=x&redirect_uri=https://evil.com/cb"},
		{"userinfo loopback", "response_type=token&redirect_uri=http://evil.com@localhost/callback&state=x"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.handleOAuthAuthorize(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+tc.query, nil))

			if loc := rec.Header().Get("Location"); strings.Contains(loc, "evil.com") {
				t.Fatalf("redirected to unvalidated URI: Location=%q (status %d)", loc, rec.Code)
			}
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d — an unallowlisted redirect_uri must be reported directly", rec.Code, http.StatusBadRequest)
			}
		})
	}
}

// The reordering must not stop legitimate errors from being reported through an
// allowlisted redirect_uri, which is what OAuth clients rely on.
func TestAuthorizeStillReportsErrorsToAllowedRedirect(t *testing.T) {
	allowed := "https://claude.ai/api/mcp/auth_callback"
	h := &Handlers{opts: Options{OAuthServer: auth.NewOAuthServer(
		"https://api.mctl.ai", "gh-client", "gh-secret", []byte("secret"),
		[]string{allowed}, nil,
	)}}

	rec := httptest.NewRecorder()
	h.handleOAuthAuthorize(rec, httptest.NewRequest(http.MethodGet,
		"/oauth/authorize?response_type=token&client_id=c&state=x&redirect_uri="+allowed, nil))

	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, allowed) {
		t.Fatalf("Location = %q, want a redirect back to the allowlisted URI", loc)
	}
	if !strings.Contains(loc, "unsupported_response_type") {
		t.Errorf("Location = %q, want the error code carried back to the client", loc)
	}
}
