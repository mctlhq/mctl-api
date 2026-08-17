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
			name:    "verify",
			request: httptest.NewRequest(http.MethodPost, "/api/v1/domains/abc/verify", nil),
			invoke:  func(h *Handlers, w http.ResponseWriter, r *http.Request) { h.VerifyDomain(w, r) },
		},
		{
			name:    "delete",
			request: httptest.NewRequest(http.MethodDelete, "/api/v1/domains/abc", nil),
			invoke:  func(h *Handlers, w http.ResponseWriter, r *http.Request) { h.DeleteDomain(w, r) },
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
