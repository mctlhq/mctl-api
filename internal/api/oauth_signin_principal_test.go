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
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-api/internal/auth"
)

type signinResolver struct {
	prn string
	err error
}

func (s signinResolver) ResolvePrincipal(context.Context, auth.Identity) (string, error) {
	return s.prn, s.err
}

// A sign-in mints for the principal it resolved. A disabled or refused
// principal stops it in every mode; any other failure stops it only in
// principal mode, where a token without a principal is refused anyway.
func TestSigninPrincipal(t *testing.T) {
	const prn = "prn_01JBBBBBBBBBBBBBBBBBBBBBBB"
	unresolved := errors.New("store down")
	tests := []struct {
		name          string
		resolver      auth.PrincipalResolver
		principalMode bool
		wantPRN       string
		wantStatus    int // 0: the sign-in goes on
	}{
		{"resolved", signinResolver{prn: prn}, false, prn, 0},
		{"resolved, principal mode", signinResolver{prn: prn}, true, prn, 0},
		{"disabled", signinResolver{err: auth.ErrPrincipalDisabled}, false, "", http.StatusForbidden},
		{"refused, principal mode", signinResolver{err: fmt.Errorf("x: %w", auth.ErrIdentityRefused)}, true, "", http.StatusForbidden},
		{"unresolved", signinResolver{err: unresolved}, false, "", 0},
		{"unresolved, principal mode", signinResolver{err: unresolved}, true, "", http.StatusServiceUnavailable},
		{"no resolver", nil, false, "", 0},
		{"no resolver, principal mode", nil, true, "", http.StatusServiceUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mode := TenantAuthzLegacy
			if tt.principalMode {
				mode = TenantAuthzPrincipal
			}
			h := &Handlers{opts: Options{TenantAuthzMode: mode, Principals: tt.resolver}}
			rec := httptest.NewRecorder()
			got, stopped := h.signinPrincipal(rec, httptest.NewRequest(http.MethodGet, "/oauth/callback", nil), githubSigninIdentity("alice", 4242))
			want := map[int]string{0: "", http.StatusForbidden: "principal_refused", http.StatusServiceUnavailable: "principal_unavailable"}[tt.wantStatus]
			if got != tt.wantPRN || stopped != want {
				t.Fatalf("got %q, %q; want %q, %q", got, stopped, tt.wantPRN, want)
			}
			if tt.wantStatus != 0 && rec.Code != tt.wantStatus {
				t.Fatalf("status %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

// fakeGitHub answers the two GitHub calls the OAuth callback makes: the
// code exchange and GET /user.
type fakeGitHub struct {
	login string
	id    int64
}

func (f fakeGitHub) RoundTrip(r *http.Request) (*http.Response, error) {
	var body string
	switch r.URL.Host + r.URL.Path {
	case "github.com/login/oauth/access_token":
		body = `{"access_token":"gh-token","token_type":"bearer"}`
	case "api.github.com/user":
		body = fmt.Sprintf(`{"login":%q,"id":%d}`, f.login, f.id)
	default:
		return nil, fmt.Errorf("unexpected request to %s", r.URL)
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

// The GitHub callback mints for the principal it resolved, counts a
// sign-in the principal stops, and mints no groups in principal mode.
func TestGitHubSigninCarriesThePrincipal(t *testing.T) {
	orig := http.DefaultTransport
	http.DefaultTransport = fakeGitHub{login: "mashkovd", id: 42}
	t.Cleanup(func() { http.DefaultTransport = orig })
	const prn = "prn_01JBBBBBBBBBBBBBBBBBBBBBBB"
	tests := []struct {
		name          string
		resolver      auth.PrincipalResolver
		principalMode bool
		wantStatus    int // 0: a code is issued
		result        string
		pid           any // the issued token's pid claim; nil when absent
		groups        bool
	}{
		{"resolved", signinResolver{prn: prn}, false, 0, "issued", prn, true},
		{"principal mode: groups decided per request", signinResolver{prn: prn}, true, 0, "issued", prn, false},
		{"unresolved outside principal mode", signinResolver{err: errors.New("store down")}, false, 0, "issued", nil, true},
		{"unresolved in principal mode", signinResolver{err: errors.New("store down")}, true, http.StatusServiceUnavailable, "principal_unavailable", nil, false},
		{"principal disabled", signinResolver{err: auth.ErrPrincipalDisabled}, false, http.StatusForbidden, "principal_refused", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newUpstreamHarness(t, OAuthUpstreamGitHub, nil)
			h.oauth.PrincipalMode = tt.principalMode
			mode := TenantAuthzLegacy
			if tt.principalMode {
				mode = TenantAuthzPrincipal
			}
			h.router = NewRouter(Options{OAuthServer: h.oauth, OAuthUpstream: OAuthUpstreamGitHub, TenantAuthzMode: mode, Principals: tt.resolver})
			counter := oauthUpstreamSignins.WithLabelValues(auth.UpstreamGitHub, tt.result)
			before := testutil.ToFloat64(counter)

			gh, _ := url.Parse(h.get(authorizeQuery("")).Header().Get("Location"))
			rec := h.get(githubCallbackPath + "?code=gh-code&state=" + url.QueryEscape(gh.Query().Get("state")))
			if n := testutil.ToFloat64(counter) - before; n != 1 {
				t.Errorf("%s +%v, want +1", tt.result, n)
			}
			if tt.wantStatus != 0 {
				if rec.Code != tt.wantStatus || rec.Header().Get("Location") != "" {
					t.Fatalf("callback = %d Location=%q, want %d and no code", rec.Code, rec.Header().Get("Location"), tt.wantStatus)
				}
				return
			}
			loc, _ := url.Parse(rec.Header().Get("Location"))
			access, _, err := h.oauth.ExchangeCode(context.Background(), loc.Query().Get("code"), testVerifier, "client", testClientRedirect)
			if err != nil {
				t.Fatalf("callback = %d %s: %v", rec.Code, rec.Body.String(), err)
			}
			claims := jwtClaims(t, access)
			g, _ := claims["groups"].([]any)
			if claims["sub"] != "mashkovd" || claims["pid"] != tt.pid || (len(g) > 0) != tt.groups {
				t.Fatalf("sub=%v pid=%v groups=%v, want mashkovd / %v / groups %v", claims["sub"], claims["pid"], g, tt.pid, tt.groups)
			}
		})
	}
}
