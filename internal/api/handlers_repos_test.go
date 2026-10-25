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

// captureBackstage stands in for the Backstage plugin and records what the
// handler sent upstream. Lives here (not handlers_domains_test.go, its
// original home) because the domains handlers moved to their own
// Postgres-backed store and no longer proxy to Backstage; this repos-sync
// test is the last caller left that still needs a Backstage stand-in.
func captureBackstage(t *testing.T) (*httptest.Server, *[]*http.Request) {
	t.Helper()
	var seen []*http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Clone(r.Context()))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"domains":[]}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

// SyncRepos must always attribute the sync to the authenticated caller
// (auth.UserFromContext), never to a "user" value supplied in the request
// body -- a caller-supplied user field would let any authenticated caller
// spoof another identity's sync.

func TestSyncReposIgnoresBodyUserOverridesWithAuthenticated(t *testing.T) {
	srv, seen := captureBackstage(t)
	h := &Handlers{opts: Options{BackstageInternalURL: srv.URL, BackstageGithubAppConnectToken: "t", GitReader: rolesOf("labs/real-caller=developer", "labs/u1=developer")}}

	req := withUser(
		httptest.NewRequest(http.MethodPost, "/api/v1/repos/sync",
			strings.NewReader(`{"team":"labs","user":"someone-else"}`)),
		auth.NewGitHubUser("real-caller", []string{"labs"}),
	)
	rec := httptest.NewRecorder()
	h.SyncRepos(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	if len(*seen) != 1 {
		t.Fatalf("expected exactly 1 upstream call, got %d", len(*seen))
	}
	if got := (*seen)[0].URL.Query().Get("user"); got != "real-caller" {
		t.Errorf("upstream user = %q, want %q (body-supplied user must be ignored)", got, "real-caller")
	}
}

func TestSyncReposDefaultsToAuthenticatedUserWhenBodyOmitsUser(t *testing.T) {
	srv, seen := captureBackstage(t)
	h := &Handlers{opts: Options{BackstageInternalURL: srv.URL, BackstageGithubAppConnectToken: "t", GitReader: rolesOf("labs/real-caller=developer", "labs/u1=developer")}}

	req := withUser(
		httptest.NewRequest(http.MethodPost, "/api/v1/repos/sync",
			strings.NewReader(`{"team":"labs"}`)),
		auth.NewGitHubUser("real-caller", []string{"labs"}),
	)
	rec := httptest.NewRecorder()
	h.SyncRepos(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	if len(*seen) != 1 {
		t.Fatalf("expected exactly 1 upstream call, got %d", len(*seen))
	}
	if got := (*seen)[0].URL.Query().Get("user"); got != "real-caller" {
		t.Errorf("upstream user = %q, want %q", got, "real-caller")
	}
}

func TestSyncReposNilUserUnauthorized(t *testing.T) {
	srv, seen := captureBackstage(t)
	h := &Handlers{opts: Options{BackstageInternalURL: srv.URL, BackstageGithubAppConnectToken: "t", GitReader: rolesOf("labs/real-caller=developer", "labs/u1=developer")}}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/repos/sync",
		strings.NewReader(`{"team":"labs"}`))
	rec := httptest.NewRecorder()
	h.SyncRepos(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%q", rec.Code, rec.Body.String())
	}
	if len(*seen) != 0 {
		t.Fatalf("expected zero upstream calls for an unauthenticated request, got %d", len(*seen))
	}
}

func TestSyncReposCrossTenantForbidden(t *testing.T) {
	srv, seen := captureBackstage(t)
	h := &Handlers{opts: Options{BackstageInternalURL: srv.URL, BackstageGithubAppConnectToken: "t", GitReader: rolesOf("labs/real-caller=developer", "labs/u1=developer")}}

	req := withUser(
		httptest.NewRequest(http.MethodPost, "/api/v1/repos/sync",
			strings.NewReader(`{"team":"other-team"}`)),
		auth.NewGitHubUser("u1", []string{"labs"}),
	)
	rec := httptest.NewRecorder()
	h.SyncRepos(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%q", rec.Code, rec.Body.String())
	}
	if len(*seen) != 0 {
		t.Fatalf("expected zero upstream calls for a cross-tenant request, got %d", len(*seen))
	}
}

func TestSyncReposMissingTeamBadRequest(t *testing.T) {
	srv, seen := captureBackstage(t)
	h := &Handlers{opts: Options{BackstageInternalURL: srv.URL, BackstageGithubAppConnectToken: "t", GitReader: rolesOf("labs/real-caller=developer", "labs/u1=developer")}}

	req := withUser(
		httptest.NewRequest(http.MethodPost, "/api/v1/repos/sync", strings.NewReader(`{}`)),
		auth.NewGitHubUser("u1", []string{"labs"}),
	)
	rec := httptest.NewRecorder()
	h.SyncRepos(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%q", rec.Code, rec.Body.String())
	}
	if len(*seen) != 0 {
		t.Fatalf("expected zero upstream calls for a missing team, got %d", len(*seen))
	}
}

// fakeGithubAppConnect models the plugin's user/service split: user-only
// routes refuse any static token, /service/* accept only the service token.
func fakeGithubAppConnect(t *testing.T, serviceToken string) (*httptest.Server, *[]*http.Request) {
	t.Helper()
	var seen []*http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Clone(r.Context()))
		w.Header().Set("Content-Type", "application/json")
		if !strings.Contains(r.URL.Path, "/service/") || r.Header.Get("Authorization") != "Bearer "+serviceToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"Authentication required"}`))
			return
		}
		_, _ = w.Write([]byte(`{"repos":["mctlhq/labs-app"],"url":"https://github.com/apps/x","state":"s"}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

func reposTestHandlers(url, token string) *Handlers {
	return &Handlers{opts: Options{
		BackstageInternalURL:           url,
		BackstageGithubAppConnectToken: token,
		GitReader:                      rolesOf("labs/real-caller=developer", "labs/u1=developer"),
	}}
}

func TestListReposAgainstServiceAuthBackstage(t *testing.T) {
	srv, seen := fakeGithubAppConnect(t, "svc")
	h := reposTestHandlers(srv.URL, "svc")
	req := withUser(httptest.NewRequest(http.MethodGet, "/api/v1/repos?team=labs", nil), auth.NewGitHubUser("u1", []string{"labs"}))
	rec := httptest.NewRecorder()
	h.ListRepos(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"repos"`) {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	if len(*seen) != 1 || (*seen)[0].URL.Path != githubAppConnectServiceReposPath {
		t.Fatalf("unexpected upstream calls: %v", *seen)
	}
}

func TestListReposNilUserAndCrossTenant(t *testing.T) {
	srv, seen := fakeGithubAppConnect(t, "svc")
	h := reposTestHandlers(srv.URL, "svc")
	rec := httptest.NewRecorder()
	h.ListRepos(rec, httptest.NewRequest(http.MethodGet, "/api/v1/repos?team=labs", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("nil user status=%d, want 401", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ListRepos(rec, withUser(httptest.NewRequest(http.MethodGet, "/api/v1/repos?team=other", nil), auth.NewGitHubUser("u1", []string{"labs"})))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant status=%d, want 403", rec.Code)
	}
	if len(*seen) != 0 {
		t.Fatalf("expected zero upstream calls, got %d", len(*seen))
	}
}

func TestListReposUpstreamCredentialRefusedIs502(t *testing.T) {
	srv, _ := fakeGithubAppConnect(t, "svc")
	h := reposTestHandlers(srv.URL, "wrong")
	req := withUser(httptest.NewRequest(http.MethodGet, "/api/v1/repos?team=labs", nil), auth.NewGitHubUser("u1", []string{"labs"}))
	rec := httptest.NewRecorder()
	h.ListRepos(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status=%d, want 502", rec.Code)
	}
}

func TestReposProxiesUnsetTokenIs503(t *testing.T) {
	srv, seen := fakeGithubAppConnect(t, "svc")
	h := reposTestHandlers(srv.URL, "")
	u := auth.NewGitHubUser("u1", []string{"labs"})
	reqs := map[string]func(){
		"list": func() {
			rec := httptest.NewRecorder()
			h.ListRepos(rec, withUser(httptest.NewRequest(http.MethodGet, "/api/v1/repos?team=labs", nil), u))
			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("list status=%d", rec.Code)
			}
		},
		"install-url": func() {
			rec := httptest.NewRecorder()
			h.GetRepoInstallURL(rec, withUser(httptest.NewRequest(http.MethodGet, "/api/v1/repos/install-url?team=labs&repo=a/b", nil), u))
			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("install-url status=%d", rec.Code)
			}
		},
		"sync": func() {
			rec := httptest.NewRecorder()
			h.SyncRepos(rec, withUser(httptest.NewRequest(http.MethodPost, "/api/v1/repos/sync", strings.NewReader(`{"team":"labs"}`)), u))
			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("sync status=%d", rec.Code)
			}
		},
	}
	for _, f := range reqs {
		f()
	}
	if len(*seen) != 0 {
		t.Fatalf("expected zero upstream calls, got %d", len(*seen))
	}
}

func TestReposProxiesSendBearerTokenOnServicePaths(t *testing.T) {
	srv, seen := fakeGithubAppConnect(t, "svc")
	h := reposTestHandlers(srv.URL, "svc")
	u := auth.NewGitHubUser("u1", []string{"labs"})
	h.ListRepos(httptest.NewRecorder(), withUser(httptest.NewRequest(http.MethodGet, "/api/v1/repos?team=labs", nil), u))
	h.GetRepoInstallURL(httptest.NewRecorder(), withUser(httptest.NewRequest(http.MethodGet, "/api/v1/repos/install-url?team=labs&repo=a/b", nil), u))
	h.SyncRepos(httptest.NewRecorder(), withUser(httptest.NewRequest(http.MethodPost, "/api/v1/repos/sync", strings.NewReader(`{"team":"labs"}`)), u))
	if len(*seen) != 3 {
		t.Fatalf("expected 3 upstream calls, got %d", len(*seen))
	}
	for _, r := range *seen {
		if !strings.Contains(r.URL.Path, "/service/") || r.Header.Get("Authorization") != "Bearer svc" {
			t.Errorf("bad upstream call %s auth=%q", r.URL.Path, r.Header.Get("Authorization"))
		}
	}
}

func TestGetRepoInstallURLUsesLoginAndRefusesWithout(t *testing.T) {
	srv, seen := fakeGithubAppConnect(t, "svc")
	h := reposTestHandlers(srv.URL, "svc")
	rec := httptest.NewRecorder()
	h.GetRepoInstallURL(rec, withUser(httptest.NewRequest(http.MethodGet, "/api/v1/repos/install-url?team=labs&repo=a/b", nil), auth.NewGitHubUser("u1", []string{"labs"})))
	if rec.Code != http.StatusOK || len(*seen) != 1 || (*seen)[0].URL.Query().Get("user") != "u1" {
		t.Fatalf("status=%d seen=%d", rec.Code, len(*seen))
	}
	// No GitHub login: a plain principal is not a proven GitHub identity.
	rec = httptest.NewRecorder()
	h.GetRepoInstallURL(rec, withUser(httptest.NewRequest(http.MethodGet, "/api/v1/repos/install-url?team=labs&repo=a/b", nil), &auth.User{ID: "zitadel-1", Groups: []string{"labs"}}))
	if rec.Code != http.StatusConflict || len(*seen) != 1 {
		t.Fatalf("status=%d seen=%d, want 409 and no extra call", rec.Code, len(*seen))
	}
}

// A failed or oversized upstream read must not be relayed as the upstream's
// 200: the caller would get a truncated repo list or broken JSON.
func TestReposProxyRefusesTruncatedOrOversizedBody(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"oversized": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"repos":["`))
			_, _ = w.Write([]byte(strings.Repeat("a", maxBackstageReposBody)))
			_, _ = w.Write([]byte(`"]}`))
		},
		"cut mid-body": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "1000")
			_, _ = w.Write([]byte(`{"repos":["mctlhq/a"`))
			if hj, ok := w.(http.Hijacker); ok {
				conn, _, _ := hj.Hijack()
				_ = conn.Close()
			}
		},
	}
	for name, handler := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(handler)
			t.Cleanup(srv.Close)
			h := reposTestHandlers(srv.URL, "svc")
			rec := httptest.NewRecorder()
			h.ListRepos(rec, withUser(httptest.NewRequest(http.MethodGet, "/api/v1/repos?team=labs", nil), auth.NewGitHubUser("u1", []string{"labs"})))
			if rec.Code != http.StatusBadGateway {
				t.Fatalf("status=%d, want 502; body=%.200q", rec.Code, rec.Body.String())
			}
		})
	}
}

// SyncRepos binds installations to a GitHub login, so a caller without a
// proven one is refused before any upstream call. Today the tenant-role check
// refuses such a sign-in first (403); the login check (409) is the backstop.
// Either is correct; what must never happen is an upstream sync.
func TestSyncReposRefusesWithoutGitHubLogin(t *testing.T) {
	srv, seen := fakeGithubAppConnect(t, "svc")
	h := reposTestHandlers(srv.URL, "svc")
	h.opts.GitReader = rolesOf("labs/zitadel-1=developer")
	rec := httptest.NewRecorder()
	h.SyncRepos(rec, withUser(httptest.NewRequest(http.MethodPost, "/api/v1/repos/sync", strings.NewReader(`{"team":"labs"}`)), &auth.User{ID: "zitadel-1", Groups: []string{"labs"}}))
	if (rec.Code != http.StatusForbidden && rec.Code != http.StatusConflict) || len(*seen) != 0 {
		t.Fatalf("status=%d seen=%d, want 403/409 and no upstream call; body=%q", rec.Code, len(*seen), rec.Body.String())
	}
}
