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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-api/internal/auth"
)

// The custom-domains plugin in mctl-portal requires authentication on /domains*
// (951d450, a domain-hijack fix). These tests pin the Authorization header onto
// every proxied call, so the handlers cannot silently regress to anonymous
// requests and start returning 401 "Missing credentials" again.

// captureBackstage stands in for the Backstage plugin and records what the
// handler sent upstream.
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

func TestDomainProxiesSendBearerToken(t *testing.T) {
	cases := []struct {
		name    string
		request *http.Request
		invoke  func(h *Handlers, w http.ResponseWriter, r *http.Request)
	}{
		{
			name:    "list",
			request: httptest.NewRequest(http.MethodGet, "/api/v1/domains?team=labs", nil),
			invoke:  func(h *Handlers, w http.ResponseWriter, r *http.Request) { h.ListDomains(w, r) },
		},
		{
			name: "add",
			request: httptest.NewRequest(http.MethodPost, "/api/v1/domains",
				strings.NewReader(`{"team":"labs","service":"genai-leader","domain":"genai-leader.mctl.ai"}`)),
			invoke: func(h *Handlers, w http.ResponseWriter, r *http.Request) { h.AddDomain(w, r) },
		},
		{
			// VerifyDomain now fails closed on a nil user (see RBAC tests
			// below), so this pins an admin in context — the point of this
			// test is purely "the bearer token reaches Backstage", not the
			// RBAC decision, and admin is the simplest way to reach the
			// proxy call unconditionally.
			name: "verify",
			request: withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains/abc/verify", nil),
				&auth.User{ID: "admin-user", Groups: []string{"admins"}}),
			invoke: func(h *Handlers, w http.ResponseWriter, r *http.Request) { h.VerifyDomain(w, r) },
		},
		{
			name: "delete",
			request: withUser(httptest.NewRequest(http.MethodDelete, "/api/v1/domains/abc", nil),
				&auth.User{ID: "admin-user", Groups: []string{"admins"}}),
			invoke: func(h *Handlers, w http.ResponseWriter, r *http.Request) { h.DeleteDomain(w, r) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, seen := captureBackstage(t)
			h := &Handlers{opts: Options{
				BackstageInternalURL: srv.URL,
				BackstageToken:       "test-token",
			}}

			rec := httptest.NewRecorder()
			tc.invoke(h, rec, tc.request)

			if len(*seen) != 1 {
				t.Fatalf("expected exactly 1 upstream call, got %d (status %d, body %q)",
					len(*seen), rec.Code, rec.Body.String())
			}
			if got := (*seen)[0].Header.Get("Authorization"); got != "Bearer test-token" {
				t.Errorf("upstream Authorization = %q, want %q — Backstage rejects anonymous /domains* calls",
					got, "Bearer test-token")
			}
		})
	}
}

// An unset token must not produce a malformed "Bearer " header; Backstage should
// reject the call on its own terms rather than on a header we invented.
func TestDomainProxiesOmitEmptyToken(t *testing.T) {
	srv, seen := captureBackstage(t)
	h := &Handlers{opts: Options{BackstageInternalURL: srv.URL}}

	h.ListDomains(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/domains?team=labs", nil))

	if len(*seen) != 1 {
		t.Fatalf("expected exactly 1 upstream call, got %d", len(*seen))
	}
	if _, ok := (*seen)[0].Header["Authorization"]; ok {
		t.Error("Authorization header set despite an empty BackstageToken")
	}
}

// withUser returns a shallow clone of req carrying u in its context.
func withUser(req *http.Request, u *auth.User) *http.Request {
	return req.WithContext(auth.WithUser(req.Context(), u))
}

// withURLParam attaches a chi route context so chi.URLParam(r, key) resolves
// to value. These tests invoke handlers directly (bypassing the real chi
// router), so without this chi.URLParam(r, "id") would just return "".
func withURLParam(req *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

// domainsBackstage stands in for the Backstage custom-domains plugin. GET
// .../domains?team=X list calls are answered from byTeam; every other call
// (the verify/delete proxy itself) gets a generic 200 OK. Every request is
// recorded for assertions on upstream call count.
func domainsBackstage(t *testing.T, byTeam map[string][]string) (*httptest.Server, *[]*http.Request) {
	t.Helper()
	var seen []*http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Clone(r.Context()))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/domains") {
			ids := byTeam[r.URL.Query().Get("team")]
			domains := make([]map[string]string, len(ids))
			for i, id := range ids {
				domains[i] = map[string]string{"id": id}
			}
			body, _ := json.Marshal(map[string]any{"domains": domains})
			_, _ = w.Write(body)
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

// The RBAC tests below cover the distinct code paths in authorizeDomainMutation.

func TestVerifyDomainCrossTenantForbidden(t *testing.T) {
	srv, seen := domainsBackstage(t, nil)
	h := &Handlers{opts: Options{BackstageInternalURL: srv.URL, BackstageToken: "t"}}

	req := withURLParam(withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains/abc/verify?team=other-team", nil),
		&auth.User{ID: "u1", Groups: []string{"labs"}}), "id", "abc")
	rec := httptest.NewRecorder()
	h.VerifyDomain(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%q", rec.Code, rec.Body.String())
	}
	if len(*seen) != 0 {
		t.Fatalf("expected zero upstream calls for a cross-tenant request, got %d", len(*seen))
	}
}

func TestVerifyDomainIDNotInTeamNotFound(t *testing.T) {
	srv, seen := domainsBackstage(t, map[string][]string{"labs": {"other-id"}})
	h := &Handlers{opts: Options{BackstageInternalURL: srv.URL, BackstageToken: "t"}}

	req := withURLParam(withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains/abc/verify?team=labs", nil),
		&auth.User{ID: "u1", Groups: []string{"labs"}}), "id", "abc")
	rec := httptest.NewRecorder()
	h.VerifyDomain(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%q", rec.Code, rec.Body.String())
	}
	if len(*seen) != 1 {
		t.Fatalf("expected exactly 1 upstream call (the list), got %d", len(*seen))
	}
}

func TestVerifyDomainOwnTeamSuccess(t *testing.T) {
	srv, seen := domainsBackstage(t, map[string][]string{"labs": {"abc"}})
	h := &Handlers{opts: Options{BackstageInternalURL: srv.URL, BackstageToken: "t"}}

	req := withURLParam(withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains/abc/verify?team=labs", nil),
		&auth.User{ID: "u1", Groups: []string{"labs"}}), "id", "abc")
	rec := httptest.NewRecorder()
	h.VerifyDomain(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	if len(*seen) != 2 {
		t.Fatalf("expected 2 upstream calls (list + verify), got %d", len(*seen))
	}
}

func TestDeleteDomainNoTeamResolvedViaGroups(t *testing.T) {
	srv, seen := domainsBackstage(t, map[string][]string{
		"labs":  {"other"},
		"infra": {"abc"},
	})
	h := &Handlers{opts: Options{BackstageInternalURL: srv.URL, BackstageToken: "t"}}

	req := withURLParam(withUser(httptest.NewRequest(http.MethodDelete, "/api/v1/domains/abc", nil),
		&auth.User{ID: "u1", Groups: []string{"labs", "infra"}}), "id", "abc")
	rec := httptest.NewRecorder()
	h.DeleteDomain(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	// 2 list calls (labs, then infra where "abc" is found) + 1 delete call.
	if len(*seen) != 3 {
		t.Fatalf("expected 3 upstream calls (2 lists + delete), got %d", len(*seen))
	}
}

func TestDeleteDomainNoTeamNotFound(t *testing.T) {
	srv, seen := domainsBackstage(t, map[string][]string{"labs": {"other"}})
	h := &Handlers{opts: Options{BackstageInternalURL: srv.URL, BackstageToken: "t"}}

	req := withURLParam(withUser(httptest.NewRequest(http.MethodDelete, "/api/v1/domains/abc", nil),
		&auth.User{ID: "u1", Groups: []string{"labs"}}), "id", "abc")
	rec := httptest.NewRecorder()
	h.DeleteDomain(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%q", rec.Code, rec.Body.String())
	}
	if len(*seen) != 1 {
		t.Fatalf("expected exactly 1 upstream call (the list), got %d", len(*seen))
	}
}

func TestVerifyDomainAdminBypassesOwnershipCheck(t *testing.T) {
	srv, seen := domainsBackstage(t, nil) // no team owns "abc" anywhere
	h := &Handlers{opts: Options{BackstageInternalURL: srv.URL, BackstageToken: "t"}}

	req := withURLParam(withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains/abc/verify?team=someone-elses-team", nil),
		&auth.User{ID: "admin-user", Groups: []string{"admins"}}), "id", "abc")
	rec := httptest.NewRecorder()
	h.VerifyDomain(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	if len(*seen) != 1 {
		t.Fatalf("expected exactly 1 upstream call (verify only, no ownership list call), got %d", len(*seen))
	}
}

func TestVerifyDomainNilUserUnauthorized(t *testing.T) {
	srv, seen := domainsBackstage(t, nil)
	h := &Handlers{opts: Options{BackstageInternalURL: srv.URL, BackstageToken: "t"}}

	rec := httptest.NewRecorder()
	h.VerifyDomain(rec, httptest.NewRequest(http.MethodPost, "/api/v1/domains/abc/verify", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%q", rec.Code, rec.Body.String())
	}
	if len(*seen) != 0 {
		t.Fatalf("expected zero upstream calls for an unauthenticated request, got %d", len(*seen))
	}
}

func TestDeleteDomainNilUserUnauthorized(t *testing.T) {
	srv, seen := domainsBackstage(t, nil)
	h := &Handlers{opts: Options{BackstageInternalURL: srv.URL, BackstageToken: "t"}}

	rec := httptest.NewRecorder()
	h.DeleteDomain(rec, httptest.NewRequest(http.MethodDelete, "/api/v1/domains/abc", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%q", rec.Code, rec.Body.String())
	}
	if len(*seen) != 0 {
		t.Fatalf("expected zero upstream calls for an unauthenticated request, got %d", len(*seen))
	}
}
