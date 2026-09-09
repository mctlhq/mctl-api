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
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/domains"
	"github.com/mctlhq/mctl-api/internal/operations"
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

func TestNormalizeHostname(t *testing.T) {
	cases := map[string]string{
		"api.mctl.ai.":         "api.mctl.ai",
		"  API.MCTL.AI  ":      "api.mctl.ai",
		"api.mctl.ai":          "api.mctl.ai",
		"api.example.com....":  "api.example.com...",
		"":                     "",
		"\tapi.example.com.\n": "api.example.com",
	}
	for in, want := range cases {
		if got := normalizeHostname(in); got != want {
			t.Errorf("normalizeHostname(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateHostname(t *testing.T) {
	valid := []string{
		"api.example.com",
		"a.b",
		"xn--exmple-cua.com",
		strings.Repeat("a", 63) + ".com",
	}
	for _, domain := range valid {
		if err := validateHostname(domain); err != nil {
			t.Errorf("validateHostname(%q): expected no error, got %v", domain, err)
		}
	}

	invalid := []string{
		"foo bar.com",   // space
		"*.example.com", // wildcard
		"nodot",         // no dot
		"a/../b.com",    // path traversal characters
		"-leadinghyphen.com",
		"trailinghyphen-.com",
		"line\nbreak.com",                 // newline
		strings.Repeat("a", 254) + ".com", // too long overall
		strings.Repeat("a", 64) + ".com",  // label too long
	}
	for _, domain := range invalid {
		if err := validateHostname(domain); err == nil {
			t.Errorf("validateHostname(%q): expected an error, got none", domain)
		}
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

// TestAddDomain_PlatformDomainTrailingDotRejected pins the fix for a real
// bypass: "api.mctl.ai." is the same DNS name as "api.mctl.ai" but, before
// normalizeHostname stripped the trailing dot, matched neither
// isPlatformDomain comparison — letting a tenant self-register a hostname
// inside the platform domain, exactly what the guard exists to prevent.
func TestAddDomain_PlatformDomainTrailingDotRejected(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store, PlatformDomain: "mctl.ai"}}

	req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"labs","service":"web","domain":"api.mctl.ai."}`)),
		&auth.User{ID: "u1", Groups: []string{"labs"}})
	rec := httptest.NewRecorder()
	h.AddDomain(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%q", rec.Code, rec.Body.String())
	}
}

// TestAddDomain_UnnormalizedPlatformDomainConfigStillGuards pins the fix for
// platformDomain(): isPlatformDomain only lowercases the request host, so an
// uppercase or trailing-dot PLATFORM_DOMAIN previously matched neither
// comparison and silently let a tenant self-register inside the platform
// domain. Every other handler test already constructs Options with an
// already-normalized "mctl.ai", so this is the only test that would fail if
// platformDomain() stopped normalizing.
func TestAddDomain_UnnormalizedPlatformDomainConfigStillGuards(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store, PlatformDomain: "MCTL.AI."}}

	req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"labs","service":"web","domain":"api.mctl.ai"}`)),
		&auth.User{ID: "u1", Groups: []string{"labs"}})
	rec := httptest.NewRecorder()
	h.AddDomain(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (unnormalized PLATFORM_DOMAIN must still guard); body=%q", rec.Code, rec.Body.String())
	}
}

func TestAddDomain_InvalidHostnameRejected(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store, PlatformDomain: "mctl.ai"}}

	req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"labs","service":"web","domain":"foo bar"}`)),
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

// TestVerifyDomainByName_TrimsTeamAndServiceWhitespace pins the fix for an
// asymmetric-normalization 404: AddDomain has always trimmed team/service,
// but VerifyDomainByName compared the looked-up row's (trimmed) team/service
// against the request's raw values, so a payload with incidental whitespace
// (e.g. copy-pasted from a form) 404'd instead of matching the row it had
// just created.
func TestVerifyDomainByName_TrimsTeamAndServiceWhitespace(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store, PlatformDomain: "mctl.ai", DomainVerifier: domains.NewVerifierWithResolver(&negativeResolver{})}}

	h.AddDomain(httptest.NewRecorder(), withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"labs","service":"svc","domain":"verify-whitespace.example.com"}`)),
		&auth.User{ID: "u1", Groups: []string{"labs"}}))

	req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains/verify",
		strings.NewReader(`{"team":"labs ","service":" svc","domain":"verify-whitespace.example.com"}`)),
		&auth.User{ID: "u1", Groups: []string{"labs"}})
	rec := httptest.NewRecorder()
	h.VerifyDomainByName(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (whitespace in team/service must not 404 a domain that exists); body=%q", rec.Code, rec.Body.String())
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

// cnameResolver always answers LookupCNAME with target, so Verify succeeds
// via the CNAME fast path regardless of the (randomly generated) TXT
// verification token — unlike the TXT path, the CNAME target is
// deterministic ({team}-{service}.{platform_domain}), so a stub can match it
// without reaching into the store for the token.
type cnameResolver struct{ target string }

func (r cnameResolver) LookupTXT(context.Context, string) ([]string, error) {
	return nil, errNoRecord
}
func (r cnameResolver) LookupCNAME(context.Context, string) (string, error) {
	return r.target, nil
}

// TestVerifyDomain_PositiveVerdictMarksVerified fills the gap agy flagged on
// mctl-api#264: every other handler test wires a negativeResolver, so the
// handler's own positive path — VerifyDomain calling through to
// h.opts.DomainStore.MarkVerified and persisting the result — was untested
// end-to-end (the equivalent pre-rewrite test, TestVerifyDomainOwnTeamSuccess,
// was removed and never replaced when the Backstage proxy was rewritten in
// 48e5984). Covers a non-admin user verifying their own team's domain, by id.
func TestVerifyDomain_PositiveVerdictMarksVerified(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{
		DomainStore:    store,
		PlatformDomain: "mctl.ai",
		DomainVerifier: domains.NewVerifierWithResolver(cnameResolver{target: "labs-svc.mctl.ai"}),
	}}

	addRec := httptest.NewRecorder()
	h.AddDomain(addRec, withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"labs","service":"svc","domain":"verify-positive.example.com"}`)),
		&auth.User{ID: "u1", Groups: []string{"labs"}}))
	var created map[string]interface{}
	if err := json.Unmarshal(addRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode add response: %v", err)
	}
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatalf("expected a domain id in the add response, got %q", addRec.Body.String())
	}

	req := withURLParam(withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains/"+id+"/verify?team=labs", nil),
		&auth.User{ID: "u1", Groups: []string{"labs"}}), "id", id)
	rec := httptest.NewRecorder()
	h.VerifyDomain(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	var result domains.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode verify response: %v", err)
	}
	if !result.Verified || result.Method != domains.MethodCNAME {
		t.Fatalf("expected a verified CNAME result, got %+v", result)
	}

	stored, err := store.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("get after verify: %v", err)
	}
	if stored.Status != domains.StatusVerified || stored.VerifiedAt == nil {
		t.Fatalf("expected MarkVerified to have persisted status=verified with verified_at set, got %+v", stored)
	}
}

// txtResolver always answers LookupTXT with a captured value, mirroring
// cnameResolver's shape but for the TXT path — used to feed a real
// challenge_value (captured from an AddDomain response) back through
// verification rather than a value the test invented independently.
type txtResolver struct{ value string }

func (r txtResolver) LookupTXT(context.Context, string) ([]string, error) {
	return []string{r.value}, nil
}
func (r txtResolver) LookupCNAME(context.Context, string) (string, error) {
	return "", errNoRecord
}

// TestVerifyDomain_TXTPathMarksVerified covers the TXT verification path by
// id, feeding the challenge_value AddDomain actually minted back through a
// txtResolver stub — the CNAME-based positive-path test
// (TestVerifyDomain_PositiveVerdictMarksVerified) does not exercise the TXT
// branch of Verify at all.
func TestVerifyDomain_TXTPathMarksVerified(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store, PlatformDomain: "mctl.ai"}}
	user := &auth.User{ID: "u1", Groups: []string{"labs"}}

	addRec := httptest.NewRecorder()
	h.AddDomain(addRec, withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"labs","service":"svc","domain":"verify-txt.example.com"}`)), user))
	var created map[string]interface{}
	if err := json.Unmarshal(addRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode add response: %v", err)
	}
	id, _ := created["id"].(string)
	challengeValue, _ := created["challenge_value"].(string)
	if id == "" || challengeValue == "" {
		t.Fatalf("expected id and challenge_value in add response, got %q", addRec.Body.String())
	}

	h.opts.DomainVerifier = domains.NewVerifierWithResolver(txtResolver{value: challengeValue})

	req := withURLParam(withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains/"+id+"/verify?team=labs", nil), user), "id", id)
	rec := httptest.NewRecorder()
	h.VerifyDomain(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	var result domains.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode verify response: %v", err)
	}
	if !result.Verified || result.Method != domains.MethodTXT {
		t.Fatalf("expected a verified TXT result, got %+v", result)
	}

	stored, err := store.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("get after verify: %v", err)
	}
	if stored.Status != domains.StatusVerified || stored.VerifiedAt == nil {
		t.Fatalf("expected status=verified with verified_at set, got %+v", stored)
	}
}

// TestVerifyDomainByName_HappyPathMarksVerified is the by-name equivalent of
// TestVerifyDomain_TXTPathMarksVerified, driven through VerifyDomainByName
// instead of VerifyDomain.
func TestVerifyDomainByName_HappyPathMarksVerified(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store, PlatformDomain: "mctl.ai"}}
	user := &auth.User{ID: "u1", Groups: []string{"labs"}}

	addRec := httptest.NewRecorder()
	h.AddDomain(addRec, withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"labs","service":"svc","domain":"verify-byname-txt.example.com"}`)), user))
	var created map[string]interface{}
	if err := json.Unmarshal(addRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode add response: %v", err)
	}
	challengeValue, _ := created["challenge_value"].(string)
	if challengeValue == "" {
		t.Fatalf("expected challenge_value in add response, got %q", addRec.Body.String())
	}

	h.opts.DomainVerifier = domains.NewVerifierWithResolver(txtResolver{value: challengeValue})

	req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains/verify",
		strings.NewReader(`{"team":"labs","service":"svc","domain":"verify-byname-txt.example.com"}`)), user)
	rec := httptest.NewRecorder()
	h.VerifyDomainByName(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	var result domains.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode verify response: %v", err)
	}
	if !result.Verified || result.Method != domains.MethodTXT {
		t.Fatalf("expected a verified TXT result, got %+v", result)
	}

	stored, err := store.GetByDomain(context.Background(), "verify-byname-txt.example.com")
	if err != nil {
		t.Fatalf("get by domain after verify: %v", err)
	}
	if stored.Status != domains.StatusVerified || stored.VerifiedAt == nil {
		t.Fatalf("expected status=verified with verified_at set, got %+v", stored)
	}
}

// TestVerifyDomainByName_ServiceMismatchNotFound pins that a real service
// mismatch (not just case) still 404s, which the switch to EqualFold in the
// ownership gate must not have relaxed.
func TestVerifyDomainByName_ServiceMismatchNotFound(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store, PlatformDomain: "mctl.ai", DomainVerifier: domains.NewVerifierWithResolver(&negativeResolver{})}}
	user := &auth.User{ID: "u1", Groups: []string{"labs"}}

	h.AddDomain(httptest.NewRecorder(), withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"labs","service":"svc","domain":"service-mismatch.example.com"}`)), user))

	req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains/verify",
		strings.NewReader(`{"team":"labs","service":"other","domain":"service-mismatch.example.com"}`)), user)
	rec := httptest.NewRecorder()
	h.VerifyDomainByName(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%q", rec.Code, rec.Body.String())
	}
}

// TestVerifyDomainByName_MixedCaseTeamServiceStillMatches pins the EqualFold
// ownership-gate fix: a domain registered with mixed-case team/service must
// still be reachable by verify-by-name using lowercase values.
func TestVerifyDomainByName_MixedCaseTeamServiceStillMatches(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store, PlatformDomain: "mctl.ai", DomainVerifier: domains.NewVerifierWithResolver(&negativeResolver{})}}
	user := &auth.User{ID: "u1", Groups: []string{"labs"}}

	addRec := httptest.NewRecorder()
	h.AddDomain(addRec, withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"Labs","service":"SVC","domain":"mixed-case.example.com"}`)), user))
	if addRec.Code != http.StatusCreated {
		t.Fatalf("add status = %d, want 201; body=%q", addRec.Code, addRec.Body.String())
	}

	req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains/verify",
		strings.NewReader(`{"team":"labs","service":"svc","domain":"mixed-case.example.com"}`)), user)
	rec := httptest.NewRecorder()
	h.VerifyDomainByName(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (mixed-case team/service must still match); body=%q", rec.Code, rec.Body.String())
	}
}

// TestListDomains_IncludesChallengeForPending decodes the list response into
// a generic map (not strings.Contains) so it asserts on actual JSON keys
// rather than substring presence somewhere in the body.
func TestListDomains_IncludesChallengeForPending(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store, PlatformDomain: "mctl.ai"}}
	owner := &auth.User{ID: "u1", Groups: []string{"labs"}}

	h.AddDomain(httptest.NewRecorder(), withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"labs","service":"svc","domain":"list-pending.example.com"}`)), owner))

	rec := httptest.NewRecorder()
	h.ListDomains(rec, withUser(httptest.NewRequest(http.MethodGet, "/api/v1/domains?team=labs", nil), owner))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}

	var resp map[string][]map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	var found map[string]any
	for _, d := range resp["domains"] {
		if d["domain"] == "list-pending.example.com" {
			found = d
			break
		}
	}
	if found == nil {
		t.Fatalf("expected list-pending.example.com in response, got %q", rec.Body.String())
	}
	for _, key := range []string{"challenge_record", "challenge_value", "cname_target"} {
		if _, ok := found[key]; !ok {
			t.Errorf("expected key %q present for a pending domain, got %v", key, found)
		}
	}
}

// TestListDomains_OmitsChallengeForActive pins domainResponseFor's honesty
// fix: an active row's challenge fields must be absent (not just empty), and
// cname_target must still be present.
func TestListDomains_OmitsChallengeForActive(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store, PlatformDomain: "mctl.ai"}}
	owner := &auth.User{ID: "u1", Groups: []string{"labs"}}

	addRec := httptest.NewRecorder()
	h.AddDomain(addRec, withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"labs","service":"svc","domain":"list-active.example.com"}`)), owner))
	var created map[string]interface{}
	if err := json.Unmarshal(addRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode add response: %v", err)
	}
	id, _ := created["id"].(string)

	patchReq := withURLParam(withUser(httptest.NewRequest(http.MethodPatch, "/api/v1/domains/"+id,
		strings.NewReader(`{"status":"active"}`)), auth.NewServiceUser()), "id", id)
	patchRec := httptest.NewRecorder()
	h.UpdateDomainStatus(patchRec, patchReq)
	if patchRec.Code != http.StatusOK {
		t.Fatalf("patch status = %d, want 200; body=%q", patchRec.Code, patchRec.Body.String())
	}

	rec := httptest.NewRecorder()
	h.ListDomains(rec, withUser(httptest.NewRequest(http.MethodGet, "/api/v1/domains?team=labs", nil), owner))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}

	var resp map[string][]map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	var found map[string]any
	for _, d := range resp["domains"] {
		if d["domain"] == "list-active.example.com" {
			found = d
			break
		}
	}
	if found == nil {
		t.Fatalf("expected list-active.example.com in response, got %q", rec.Body.String())
	}
	for _, key := range []string{"challenge_record", "challenge_value"} {
		if _, ok := found[key]; ok {
			t.Errorf("expected key %q absent for an active domain, got %v", key, found)
		}
	}
	if _, ok := found["cname_target"]; !ok {
		t.Errorf("expected cname_target present for an active domain, got %v", found)
	}
}

// fakeDomainExecutor is a minimal WorkflowExecutor double for exercising
// DeleteDomain's ingress-cleanup trigger. The package api test files (unlike
// smoke_test.go's separate api_test package) have no shared fake executor to
// reuse.
type fakeDomainExecutor struct {
	submitted []map[string]string
	err       error
	// onSubmit, if set, runs synchronously inside Submit before it returns —
	// used to assert on state (e.g. that the row still exists) at the exact
	// moment of submission, not just before/after DeleteDomain returns.
	onSubmit func(params map[string]string)
}

func (f *fakeDomainExecutor) Submit(_ context.Context, _ operations.Operation, params map[string]string, _, namespace string) (*operations.SubmitResult, error) {
	if f.onSubmit != nil {
		f.onSubmit(params)
	}
	if f.err != nil {
		return nil, f.err
	}
	cp := make(map[string]string, len(params))
	for k, v := range params {
		cp[k] = v
	}
	f.submitted = append(f.submitted, cp)
	return &operations.SubmitResult{WorkflowName: "test-remove-custom-domain-workflow", Namespace: namespace}, nil
}

func (f *fakeDomainExecutor) GetWorkflowStatus(context.Context, string, string) (map[string]interface{}, error) {
	return nil, nil
}

func (f *fakeDomainExecutor) ListCronAgentRuns(context.Context, string, string, time.Time) ([]map[string]interface{}, error) {
	return nil, nil
}

// TestDeleteDomain_TriggersRemoveCustomDomain pins the delete/ingress
// convergence fix: deleting a row must submit remove-custom-domain with the
// row's own team/service/domain, and the submission must happen while the
// row still exists (checked from inside Submit itself, not just around the
// DeleteDomain call).
func TestDeleteDomain_TriggersRemoveCustomDomain(t *testing.T) {
	store := newTestDomainStore(t)
	exec := &fakeDomainExecutor{}
	h := &Handlers{opts: Options{
		DomainStore:    store,
		PlatformDomain: "mctl.ai",
		Executor:       exec,
		Registry:       operations.NewRegistry(),
	}}
	owner := &auth.User{ID: "u1", Groups: []string{"labs"}}

	addRec := httptest.NewRecorder()
	h.AddDomain(addRec, withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"labs","service":"svc","domain":"delete-triggers.example.com"}`)), owner))
	var created map[string]interface{}
	if err := json.Unmarshal(addRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode add response: %v", err)
	}
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatalf("expected an id in the add response, got %q", addRec.Body.String())
	}

	exec.onSubmit = func(map[string]string) {
		if _, err := store.Get(context.Background(), id); err != nil {
			t.Errorf("expected the row to still exist when Submit is called, got %v", err)
		}
	}

	req := withURLParam(withUser(httptest.NewRequest(http.MethodDelete, "/api/v1/domains/"+id, nil), owner), "id", id)
	rec := httptest.NewRecorder()
	h.DeleteDomain(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	if len(exec.submitted) != 1 {
		t.Fatalf("expected exactly one workflow submission, got %d", len(exec.submitted))
	}
	got := exec.submitted[0]
	if got["team_name"] != "labs" || got["service_name"] != "svc" || got["domain"] != "delete-triggers.example.com" {
		t.Errorf("submitted params = %v, want team_name=labs service_name=svc domain=delete-triggers.example.com", got)
	}

	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode delete response: %v", err)
	}
	if resp["workflow_name"] == "" {
		t.Errorf("expected workflow_name in the delete response, got %v", resp)
	}

	if _, err := store.Get(context.Background(), id); !errors.Is(err, domains.ErrNotFound) {
		t.Fatalf("expected the row to be gone after a successful submission, got err=%v", err)
	}
}

// TestDeleteDomain_SubmitFailureKeepsRow pins that a failed ingress-cleanup
// submission must not delete the row — otherwise the only record of what
// still needs manual cleanup is lost.
func TestDeleteDomain_SubmitFailureKeepsRow(t *testing.T) {
	store := newTestDomainStore(t)
	exec := &fakeDomainExecutor{err: errors.New("submit failed")}
	h := &Handlers{opts: Options{
		DomainStore:    store,
		PlatformDomain: "mctl.ai",
		Executor:       exec,
		Registry:       operations.NewRegistry(),
	}}
	owner := &auth.User{ID: "u1", Groups: []string{"labs"}}

	addRec := httptest.NewRecorder()
	h.AddDomain(addRec, withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"labs","service":"svc","domain":"delete-submit-fail.example.com"}`)), owner))
	var created map[string]interface{}
	if err := json.Unmarshal(addRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode add response: %v", err)
	}
	id, _ := created["id"].(string)

	req := withURLParam(withUser(httptest.NewRequest(http.MethodDelete, "/api/v1/domains/"+id, nil), owner), "id", id)
	rec := httptest.NewRecorder()
	h.DeleteDomain(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%q", rec.Code, rec.Body.String())
	}

	if _, err := store.Get(context.Background(), id); err != nil {
		t.Fatalf("expected the row to still exist after a failed submission, got %v", err)
	}
}

// TestDeleteDomain_InvalidServiceNeverReachesSubmit pins the P1 fix:
// triggerRemoveCustomDomain must validate team/service against the
// registry's declared pattern before calling Executor.Submit, the same way
// every other Submit call site does. Simulates a row that predates
// AddDomain's own team/service pattern validation (or was inserted some
// other way) by writing directly through the store, bypassing the handler.
func TestDeleteDomain_InvalidServiceNeverReachesSubmit(t *testing.T) {
	store := newTestDomainStore(t)
	exec := &fakeDomainExecutor{}
	h := &Handlers{opts: Options{
		DomainStore:    store,
		PlatformDomain: "mctl.ai",
		Executor:       exec,
		Registry:       operations.NewRegistry(),
	}}

	created, err := store.Create(context.Background(), &domains.Domain{
		ID:                uuid.New().String(),
		Team:              "labs",
		Service:           "../../../platform-gitops/services/other-team/api",
		Domain:            "path-traversal.example.com",
		VerificationToken: "test-token",
		CreatedBy:         "u1",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	owner := &auth.User{ID: "u1", Groups: []string{"labs"}}
	req := withURLParam(withUser(httptest.NewRequest(http.MethodDelete, "/api/v1/domains/"+created.ID, nil), owner), "id", created.ID)
	rec := httptest.NewRecorder()
	h.DeleteDomain(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%q", rec.Code, rec.Body.String())
	}
	if len(exec.submitted) != 0 {
		t.Fatalf("expected zero workflow submissions for an out-of-pattern service, got %+v", exec.submitted)
	}
	if _, err := store.Get(context.Background(), created.ID); err != nil {
		t.Fatalf("expected the row to still exist after a rejected submission, got %v", err)
	}
}

// TestDomainLifecycle_MixedCaseTeamRoundTrips pins the P2 fix: AddDomain
// lowercases team/service on write, so a caller spelling the team "Labs"
// must still be able to list and delete that same row later — before the
// fix, ListDomains and resolveDomainForMutation compared the raw ?team=
// param case-sensitively against the (already-lowercased) stored value,
// making the row invisible to list and 404-ing on delete.
func TestDomainLifecycle_MixedCaseTeamRoundTrips(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store, PlatformDomain: "mctl.ai"}}
	// Group membership is always canonical lowercase in practice (GitHub/Dex
	// group names); the mixed case being pinned here is in what the CALLER
	// types in the request body/query, not in group membership itself.
	owner := &auth.User{ID: "u1", Groups: []string{"labs"}}

	addRec := httptest.NewRecorder()
	h.AddDomain(addRec, withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"Labs","service":"Svc","domain":"mixed-case.example.com"}`)), owner))
	if addRec.Code != http.StatusCreated {
		t.Fatalf("add status = %d, want 201; body=%q", addRec.Code, addRec.Body.String())
	}
	var created map[string]interface{}
	if err := json.Unmarshal(addRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode add response: %v", err)
	}
	id, _ := created["id"].(string)

	listRec := httptest.NewRecorder()
	h.ListDomains(listRec, withUser(httptest.NewRequest(http.MethodGet, "/api/v1/domains?team=Labs", nil), owner))
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200; body=%q", listRec.Code, listRec.Body.String())
	}
	if !strings.Contains(listRec.Body.String(), "mixed-case.example.com") {
		t.Fatalf("expected mixed-case.example.com in list response for team=Labs, got %q", listRec.Body.String())
	}

	delReq := withURLParam(withUser(httptest.NewRequest(http.MethodDelete, "/api/v1/domains/"+id+"?team=Labs", nil), owner), "id", id)
	delRec := httptest.NewRecorder()
	h.DeleteDomain(delRec, delReq)
	if delRec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, want 200; body=%q", delRec.Code, delRec.Body.String())
	}
}

// TestDeleteDomain_NilExecutorSkipsCleanup mirrors
// TestDeleteDomain_OwnTeamSucceeds but with no executor configured, and
// additionally asserts on the new ingress_cleanup response field.
func TestDeleteDomain_NilExecutorSkipsCleanup(t *testing.T) {
	store := newTestDomainStore(t)
	h := &Handlers{opts: Options{DomainStore: store, PlatformDomain: "mctl.ai"}}
	owner := &auth.User{ID: "u1", Groups: []string{"labs"}}

	addRec := httptest.NewRecorder()
	h.AddDomain(addRec, withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"labs","service":"svc","domain":"delete-skip.example.com"}`)), owner))
	var created map[string]interface{}
	if err := json.Unmarshal(addRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode add response: %v", err)
	}
	id, _ := created["id"].(string)

	req := withURLParam(withUser(httptest.NewRequest(http.MethodDelete, "/api/v1/domains/"+id, nil), owner), "id", id)
	rec := httptest.NewRecorder()
	h.DeleteDomain(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode delete response: %v", err)
	}
	if resp["ingress_cleanup"] != "skipped" {
		t.Errorf("ingress_cleanup = %q, want %q", resp["ingress_cleanup"], "skipped")
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
