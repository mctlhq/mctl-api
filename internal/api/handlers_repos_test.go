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

// SyncRepos must always attribute the sync to the authenticated caller
// (auth.UserFromContext), never to a "user" value supplied in the request
// body -- a caller-supplied user field would let any authenticated caller
// spoof another identity's sync.

func TestSyncReposIgnoresBodyUserOverridesWithAuthenticated(t *testing.T) {
	srv, seen := captureBackstage(t)
	h := &Handlers{opts: Options{BackstageInternalURL: srv.URL}}

	req := withUser(
		httptest.NewRequest(http.MethodPost, "/api/v1/repos/sync",
			strings.NewReader(`{"team":"labs","user":"someone-else"}`)),
		&auth.User{ID: "real-caller", Groups: []string{"labs"}},
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
	h := &Handlers{opts: Options{BackstageInternalURL: srv.URL}}

	req := withUser(
		httptest.NewRequest(http.MethodPost, "/api/v1/repos/sync",
			strings.NewReader(`{"team":"labs"}`)),
		&auth.User{ID: "real-caller", Groups: []string{"labs"}},
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
	h := &Handlers{opts: Options{BackstageInternalURL: srv.URL}}

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
	h := &Handlers{opts: Options{BackstageInternalURL: srv.URL}}

	req := withUser(
		httptest.NewRequest(http.MethodPost, "/api/v1/repos/sync",
			strings.NewReader(`{"team":"other-team"}`)),
		&auth.User{ID: "u1", Groups: []string{"labs"}},
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
	h := &Handlers{opts: Options{BackstageInternalURL: srv.URL}}

	req := withUser(
		httptest.NewRequest(http.MethodPost, "/api/v1/repos/sync", strings.NewReader(`{}`)),
		&auth.User{ID: "u1", Groups: []string{"labs"}},
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
