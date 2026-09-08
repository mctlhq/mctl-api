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
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/domains"
)

// mctl-api is the system of record for custom domains: internal/domains, a
// PostgreSQL-backed store, replaced the proxy to Backstage's custom-domains
// plugin. That plugin's write route required a Backstage user principal
// none of mctl-api's callers (GitHub PAT, Dex JWT, the static service token,
// the MCP tool with no session at all) could ever produce, which is why
// POST /api/v1/domains always came back 401 regardless of the caller's
// mctl-api credentials.

// newTestDomainStore connects to a real Postgres instance, matching the
// TEST_DATABASE_URL-gated pattern used across this repo (see
// internal/api/handlers_alerts_test.go) — there is no Postgres service in
// CI, so these tests only run when pointed at a local/ephemeral instance.
func newTestDomainStore(t *testing.T) *domains.Store {
	t.Helper()
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed handler test")
	}

	ctx := context.Background()
	s, err := domains.NewStore(ctx, connStr)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	cleanupPool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("cleanup pool: %v", err)
	}
	t.Cleanup(func() {
		_, _ = cleanupPool.Exec(ctx, "DELETE FROM custom_domains")
		cleanupPool.Close()
	})
	if _, err := cleanupPool.Exec(ctx, "DELETE FROM custom_domains"); err != nil {
		t.Fatalf("cleanup custom_domains: %v", err)
	}
	return s
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

// --- T6: every /api/v1/domains* route 503s with no store configured. These
// need no Postgres and always run.

func TestDomainRoutes_NilStore503(t *testing.T) {
	h := &Handlers{opts: Options{}}
	admin := &auth.User{ID: "admin", Groups: []string{"admins"}}

	cases := []struct {
		name   string
		invoke func(w http.ResponseWriter, r *http.Request)
		req    *http.Request
	}{
		{"list", h.ListDomains, withUser(httptest.NewRequest(http.MethodGet, "/api/v1/domains?team=labs", nil), admin)},
		{"add", h.AddDomain, withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains", strings.NewReader(`{"team":"labs","service":"svc","domain":"a.example.com"}`)), admin)},
		{"verify by id", h.VerifyDomain, withURLParam(withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains/abc/verify", nil), admin), "id", "abc")},
		{"verify by name", h.VerifyDomainByName, withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains/verify", strings.NewReader(`{"team":"labs","service":"svc","domain":"a.example.com"}`)), admin)},
		{"delete", h.DeleteDomain, withURLParam(withUser(httptest.NewRequest(http.MethodDelete, "/api/v1/domains/abc", nil), admin), "id", "abc")},
		{"patch status", h.UpdateDomainStatus, withURLParam(withUser(httptest.NewRequest(http.MethodPatch, "/api/v1/domains/abc", strings.NewReader(`{"status":"active"}`)), auth.NewServiceUser()), "id", "abc")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.invoke(rec, tc.req)
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503; body=%q", rec.Code, rec.Body.String())
			}
		})
	}
}

// --- Store-backed tests (skipped without TEST_DATABASE_URL).

func TestListDomains_NilUserUnauthorized(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store}}

	rec := httptest.NewRecorder()
	h.ListDomains(rec, httptest.NewRequest(http.MethodGet, "/api/v1/domains?team=labs", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%q", rec.Code, rec.Body.String())
	}
}

func TestAddDomain_NilUserUnauthorized(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store}}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"labs","service":"svc","domain":"a.example.com"}`))
	rec := httptest.NewRecorder()
	h.AddDomain(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%q", rec.Code, rec.Body.String())
	}
}

func TestAddDomain_NonMemberForbidden(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store}}

	req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"labs","service":"svc","domain":"a.example.com"}`)),
		&auth.User{ID: "u1", Groups: []string{"other-team"}})
	rec := httptest.NewRecorder()
	h.AddDomain(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%q", rec.Code, rec.Body.String())
	}
}

func TestAddDomain_PlatformDomainRejected(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store, PlatformDomain: "mctl.ai"}}

	req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"seerrsense","service":"web","domain":"seerrsense.mctl.ai"}`)),
		&auth.User{ID: "u1", Groups: []string{"seerrsense"}})
	rec := httptest.NewRecorder()
	h.AddDomain(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "ingress.hosts") {
		t.Errorf("expected the GitOps instruction (ingress.hosts) in the error body, got %q", rec.Body.String())
	}
}

func TestAddDomain_PlatformDomainRoot_Rejected(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store, PlatformDomain: "mctl.ai"}}

	req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"labs","service":"web","domain":"mctl.ai"}`)),
		&auth.User{ID: "u1", Groups: []string{"labs"}})
	rec := httptest.NewRecorder()
	h.AddDomain(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%q", rec.Code, rec.Body.String())
	}
}

func TestAddDomain_HappyPath(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store, PlatformDomain: "mctl.ai"}}

	req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"labs","service":"genai-leader","domain":"genai-leader.example.com"}`)),
		&auth.User{ID: "u1", Groups: []string{"labs"}})
	rec := httptest.NewRecorder()
	h.AddDomain(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%q", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["challenge_record"] != "_mctl-challenge.genai-leader.example.com" {
		t.Errorf("challenge_record = %v, want _mctl-challenge.genai-leader.example.com", resp["challenge_record"])
	}
	if resp["challenge_value"] == "" || resp["challenge_value"] == nil {
		t.Errorf("expected a non-empty challenge_value, got %v", resp["challenge_value"])
	}
	if resp["cname_target"] != "labs-genai-leader.mctl.ai" {
		t.Errorf("cname_target = %v, want labs-genai-leader.mctl.ai", resp["cname_target"])
	}
	if resp["status"] != domains.StatusPending {
		t.Errorf("status = %v, want pending", resp["status"])
	}
	if resp["created_by"] != "u1" {
		t.Errorf("created_by = %v, want u1", resp["created_by"])
	}
}

func TestAddDomain_IdempotentReRegistration(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store, PlatformDomain: "mctl.ai"}}
	user := &auth.User{ID: "u1", Groups: []string{"labs"}}

	body := `{"team":"labs","service":"svc","domain":"idempotent.example.com"}`

	rec1 := httptest.NewRecorder()
	h.AddDomain(rec1, withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains", strings.NewReader(body)), user))
	if rec1.Code != http.StatusCreated {
		t.Fatalf("first call status = %d, want 201; body=%q", rec1.Code, rec1.Body.String())
	}

	rec2 := httptest.NewRecorder()
	h.AddDomain(rec2, withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains", strings.NewReader(body)), user))
	if rec2.Code != http.StatusOK {
		t.Fatalf("second call status = %d, want 200; body=%q", rec2.Code, rec2.Body.String())
	}
}

func TestAddDomain_CrossTeamConflict(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store, PlatformDomain: "mctl.ai"}}

	rec1 := httptest.NewRecorder()
	h.AddDomain(rec1, withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"labs","service":"svc","domain":"conflict.example.com"}`)),
		&auth.User{ID: "u1", Groups: []string{"labs"}}))
	if rec1.Code != http.StatusCreated {
		t.Fatalf("first call status = %d, want 201; body=%q", rec1.Code, rec1.Body.String())
	}

	rec2 := httptest.NewRecorder()
	h.AddDomain(rec2, withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"infra","service":"other","domain":"conflict.example.com"}`)),
		&auth.User{ID: "u2", Groups: []string{"infra"}}))
	if rec2.Code != http.StatusConflict {
		t.Fatalf("second call status = %d, want 409; body=%q", rec2.Code, rec2.Body.String())
	}
	if strings.Contains(rec2.Body.String(), "labs") {
		t.Errorf("conflict response must not disclose the owning team, got %q", rec2.Body.String())
	}
}

func TestListDomains_FiltersByTeamAndAccess(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store, PlatformDomain: "mctl.ai"}}
	owner := &auth.User{ID: "u1", Groups: []string{"labs"}}

	h.AddDomain(httptest.NewRecorder(), withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"labs","service":"svc","domain":"list.example.com"}`)), owner))

	rec := httptest.NewRecorder()
	h.ListDomains(rec, withUser(httptest.NewRequest(http.MethodGet, "/api/v1/domains?team=labs", nil), owner))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "list.example.com") {
		t.Errorf("expected list.example.com in response, got %q", rec.Body.String())
	}

	forbidden := httptest.NewRecorder()
	h.ListDomains(forbidden, withUser(httptest.NewRequest(http.MethodGet, "/api/v1/domains?team=labs", nil),
		&auth.User{ID: "u2", Groups: []string{"other-team"}}))
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%q", forbidden.Code, forbidden.Body.String())
	}
}

func TestVerifyDomain_NilUserUnauthorized(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store}}

	req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/v1/domains/abc/verify", nil), "id", "abc")
	rec := httptest.NewRecorder()
	h.VerifyDomain(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%q", rec.Code, rec.Body.String())
	}
}

func TestVerifyDomain_UnknownIDNotFound(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store, DomainVerifier: domains.NewVerifierWithResolver(&negativeResolver{})}}

	req := withURLParam(withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains/does-not-exist/verify?team=labs", nil),
		&auth.User{ID: "u1", Groups: []string{"labs"}}), "id", "does-not-exist")
	rec := httptest.NewRecorder()
	h.VerifyDomain(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%q", rec.Code, rec.Body.String())
	}
}

func TestVerifyDomain_CrossTeamNotFound(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store, PlatformDomain: "mctl.ai", DomainVerifier: domains.NewVerifierWithResolver(&negativeResolver{})}}

	addRec := httptest.NewRecorder()
	h.AddDomain(addRec, withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"labs","service":"svc","domain":"crossteam.example.com"}`)),
		&auth.User{ID: "u1", Groups: []string{"labs"}}))
	var created map[string]interface{}
	_ = json.Unmarshal(addRec.Body.Bytes(), &created)
	id, _ := created["id"].(string)

	req := withURLParam(withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains/"+id+"/verify?team=other-team", nil),
		&auth.User{ID: "u2", Groups: []string{"other-team"}}), "id", id)
	rec := httptest.NewRecorder()
	h.VerifyDomain(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%q", rec.Code, rec.Body.String())
	}
}

// negativeResolver never finds a matching TXT or CNAME record, so Verify
// returns a negative verdict, not an error.
type negativeResolver struct{}

var errNoRecord = errors.New("no such record")

func (negativeResolver) LookupTXT(context.Context, string) ([]string, error) {
	return nil, errNoRecord
}
func (negativeResolver) LookupCNAME(context.Context, string) (string, error) {
	return "", errNoRecord
}

func TestVerifyDomainByName_NegativeVerdictIsNotAnError(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store, PlatformDomain: "mctl.ai", DomainVerifier: domains.NewVerifierWithResolver(&negativeResolver{})}}

	h.AddDomain(httptest.NewRecorder(), withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"labs","service":"svc","domain":"verify-negative.example.com"}`)),
		&auth.User{ID: "u1", Groups: []string{"labs"}}))

	req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains/verify",
		strings.NewReader(`{"team":"labs","service":"svc","domain":"verify-negative.example.com"}`)),
		&auth.User{ID: "u1", Groups: []string{"labs"}})
	rec := httptest.NewRecorder()
	h.VerifyDomainByName(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 even on a negative verdict; body=%q", rec.Code, rec.Body.String())
	}
	var result domains.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.Verified {
		t.Fatalf("expected verified=false, got %+v", result)
	}
	if result.ExpectedRecord == "" || result.ExpectedValue == "" || result.Reason == "" {
		t.Fatalf("expected reason/expected_record/expected_value to be populated, got %+v", result)
	}
}

func TestUpdateDomainStatus_HumanForbidden(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store, PlatformDomain: "mctl.ai"}}

	addRec := httptest.NewRecorder()
	h.AddDomain(addRec, withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"labs","service":"svc","domain":"patch.example.com"}`)),
		&auth.User{ID: "u1", Groups: []string{"labs"}}))
	var created map[string]interface{}
	_ = json.Unmarshal(addRec.Body.Bytes(), &created)
	id, _ := created["id"].(string)

	req := withURLParam(withUser(httptest.NewRequest(http.MethodPatch, "/api/v1/domains/"+id,
		strings.NewReader(`{"status":"active"}`)), &auth.User{ID: "admin", Groups: []string{"admins"}}), "id", id)
	rec := httptest.NewRecorder()
	h.UpdateDomainStatus(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a human admin token; body=%q", rec.Code, rec.Body.String())
	}
}

func TestUpdateDomainStatus_ServicePrincipalAllowed(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store, PlatformDomain: "mctl.ai"}}

	addRec := httptest.NewRecorder()
	h.AddDomain(addRec, withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"labs","service":"svc","domain":"patch-ok.example.com"}`)),
		&auth.User{ID: "u1", Groups: []string{"labs"}}))
	var created map[string]interface{}
	_ = json.Unmarshal(addRec.Body.Bytes(), &created)
	id, _ := created["id"].(string)

	req := withURLParam(withUser(httptest.NewRequest(http.MethodPatch, "/api/v1/domains/"+id,
		strings.NewReader(`{"status":"active"}`)), auth.NewServiceUser()), "id", id)
	rec := httptest.NewRecorder()
	h.UpdateDomainStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for the service principal; body=%q", rec.Code, rec.Body.String())
	}
}

func TestUpdateDomainStatus_InvalidStatusBadRequest(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store, PlatformDomain: "mctl.ai"}}

	addRec := httptest.NewRecorder()
	h.AddDomain(addRec, withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"labs","service":"svc","domain":"patch-bad.example.com"}`)),
		&auth.User{ID: "u1", Groups: []string{"labs"}}))
	var created map[string]interface{}
	_ = json.Unmarshal(addRec.Body.Bytes(), &created)
	id, _ := created["id"].(string)

	req := withURLParam(withUser(httptest.NewRequest(http.MethodPatch, "/api/v1/domains/"+id,
		strings.NewReader(`{"status":"bogus"}`)), auth.NewServiceUser()), "id", id)
	rec := httptest.NewRecorder()
	h.UpdateDomainStatus(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an invalid status value; body=%q", rec.Code, rec.Body.String())
	}
}

func TestDeleteDomain_NilUserUnauthorized(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store}}

	req := withURLParam(httptest.NewRequest(http.MethodDelete, "/api/v1/domains/abc", nil), "id", "abc")
	rec := httptest.NewRecorder()
	h.DeleteDomain(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%q", rec.Code, rec.Body.String())
	}
}

func TestDeleteDomain_OwnTeamSucceeds(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store, PlatformDomain: "mctl.ai"}}
	owner := &auth.User{ID: "u1", Groups: []string{"labs"}}

	addRec := httptest.NewRecorder()
	h.AddDomain(addRec, withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"labs","service":"svc","domain":"delete-me.example.com"}`)), owner))
	var created map[string]interface{}
	_ = json.Unmarshal(addRec.Body.Bytes(), &created)
	id, _ := created["id"].(string)

	req := withURLParam(withUser(httptest.NewRequest(http.MethodDelete, "/api/v1/domains/"+id, nil), owner), "id", id)
	rec := httptest.NewRecorder()
	h.DeleteDomain(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
}

func TestVerifyDomainAdminBypassesOwnershipCheck(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store, PlatformDomain: "mctl.ai", DomainVerifier: domains.NewVerifierWithResolver(&negativeResolver{})}}

	addRec := httptest.NewRecorder()
	h.AddDomain(addRec, withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"labs","service":"svc","domain":"admin-bypass.example.com"}`)),
		&auth.User{ID: "u1", Groups: []string{"labs"}}))
	var created map[string]interface{}
	_ = json.Unmarshal(addRec.Body.Bytes(), &created)
	id, _ := created["id"].(string)

	req := withURLParam(withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains/"+id+"/verify?team=someone-elses-team", nil),
		&auth.User{ID: "admin-user", Groups: []string{"admins"}}), "id", id)
	rec := httptest.NewRecorder()
	h.VerifyDomain(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
}
