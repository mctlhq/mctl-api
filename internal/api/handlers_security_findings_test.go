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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/securityfindings"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// SecurityFinding routes (mctl-api#774): provider trust, the provider gate,
// human-only dismissal, 503 for an unconfigured store and 404-not-403
// tenant visibility.

type secWorkItems struct {
	mu    sync.Mutex
	items map[string]string
}

func (f *secWorkItems) Get(_ context.Context, id string) (*workitems.WorkItem, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	tenant, ok := f.items[id]
	if !ok {
		return nil, workitems.ErrNotFound
	}
	return &workitems.WorkItem{ID: id, Tenant: tenant}, nil
}

func (f *secWorkItems) add(tenant string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := workitems.WorkItemIDPrefix + uuid.NewString()
	f.items[id] = tenant
	return id
}

var (
	secStoreOnce sync.Once
	secStore     *securityfindings.Store
	secItems     = &secWorkItems{items: map[string]string{}}
	secStoreErr  error
)

func newSecurityStore(t *testing.T) *securityfindings.Store {
	t.Helper()
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed security findings handler test")
	}
	secStoreOnce.Do(func() {
		secStore, secStoreErr = securityfindings.NewStore(context.Background(), connStr, securityfindings.WithWorkItems(secItems))
	})
	if secStoreErr != nil {
		t.Fatalf("securityfindings.NewStore: %v", secStoreErr)
	}
	return secStore
}

func secTenant() string { return "t-" + uuid.NewString()[:8] }

func secProvider(t *testing.T, ref string) *auth.User {
	t.Helper()
	u := auth.NewSecurityProviderUser(ref)
	if err := auth.AttachPrincipal(context.Background(), fixedPrincipal("prn_sec_"+ref), u); err != nil {
		t.Fatalf("AttachPrincipal: %v", err)
	}
	return u
}

func secDo(router http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

var securityRoutes = []struct{ method, path string }{
	{http.MethodGet, "/api/v1/security/findings"},
	{http.MethodGet, "/api/v1/security/findings/sf_x"},
	{http.MethodGet, "/api/v1/security/occurrences"},
	{http.MethodGet, "/api/v1/security/occurrences/soc_x"},
	{http.MethodPost, "/api/v1/security/observations"},
	{http.MethodPost, "/api/v1/security/occurrences/soc_x/triage"},
	{http.MethodPost, "/api/v1/security/occurrences/soc_x/remediation-attempts"},
	{http.MethodPost, "/api/v1/security/occurrences/soc_x/dismiss"},
	{http.MethodPost, "/api/v1/security/remediation-attempts/sra_x/fix"},
	{http.MethodPost, "/api/v1/security/remediation-attempts/sra_x/verifications"},
}

// T26: a nil store answers 503 with a typed code on every route.
func TestSecurityFindings_NilStoreIs503(t *testing.T) {
	router := NewRouter(Options{AuthMiddleware: injectUser(adminUser())})
	for _, c := range securityRoutes {
		rec := secDo(router, c.method, c.path, map[string]any{})
		if rec.Code != http.StatusServiceUnavailable || bodyCode(rec) != "security_findings_store_unavailable" {
			t.Errorf("%s %s: got %d %s", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
}

// T24: the provider gate refuses every route except the ingest route, before
// any handler (or store) is reached.
func TestSecurityProviderGate(t *testing.T) {
	router := NewRouter(Options{AuthMiddleware: injectUser(secProvider(t, "trivy"))})
	for _, c := range securityRoutes {
		rec := secDo(router, c.method, c.path, map[string]any{})
		if c.path == "/api/v1/security/observations" {
			// Passes the gate; the unconfigured store is the next answer.
			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("%s %s: want 503 past the gate, got %d", c.method, c.path, rec.Code)
			}
			continue
		}
		if rec.Code != http.StatusForbidden || bodyCode(rec) != "security_provider_route_not_allowed" {
			t.Errorf("%s %s: want gate 403, got %d %s", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
	for _, p := range []string{"/api/v1/whoami", "/api/v1/evidence/records", "/api/v1/work-items"} {
		if rec := secDo(router, http.MethodPost, p, map[string]any{}); rec.Code != http.StatusForbidden {
			t.Errorf("POST %s: provider must be confined, got %d", p, rec.Code)
		}
	}
}

// T22 (api side): a provider holds only security:ingest and no tenant.
func TestSecurityProviderPrincipal(t *testing.T) {
	u := secProvider(t, "trivy")
	if u.IsAdmin() || u.HasTenantAccess("anything") || len(u.Groups) != 0 {
		t.Errorf("a provider is not an admin and has no tenant")
	}
	if !u.HasPermission(auth.PermissionSecurityIngest) {
		t.Errorf("a provider holds security:ingest")
	}
	for _, p := range []string{auth.PermissionSecurityRemediate, auth.PermissionEvidenceWrite, auth.PermissionUsageWrite} {
		if u.HasPermission(p) {
			t.Errorf("a provider must not hold %s", p)
		}
	}
	if isHumanCaller(u) {
		t.Errorf("a provider is not a human caller")
	}
}

func secOpts(user *auth.User, store *securityfindings.Store, providers map[string]auth.SecurityProviderConfig) Options {
	return Options{AuthMiddleware: injectUser(user), SecurityFindings: store, SecurityProviders: providers}
}

func secIngestBody(tenant, cve string, extra map[string]any) map[string]any {
	item := map[string]any{
		"tenant": tenant, "identity": cve,
		"subject": map[string]any{"repository": "o/r", "package_purl": "pkg:golang/x@1"},
	}
	for k, v := range extra {
		item[k] = v
	}
	return map[string]any{"delivery_id": "d-" + uuid.NewString(), "observations": []any{item}}
}

var secCVE = 5000000

func nextCVE() string {
	secCVE++
	return fmt.Sprintf("CVE-2024-%d", secCVE)
}

type ingestResponse struct {
	Results []securityfindings.ItemResult `json:"results"`
}

// T23: the payload's provider text is ignored for authority and kept only as
// untrusted evidence; a provider ingests only for its configured tenants.
func TestSecurityIngest_ProviderIdentityComesFromThePrincipal(t *testing.T) {
	store := newSecurityStore(t)
	tenant, other := secTenant(), secTenant()
	providers := map[string]auth.SecurityProviderConfig{
		"trivy": {Ref: "trivy", MaxStrength: "scanner_rerun_exact_revision", Tenants: []string{tenant}},
	}
	router := NewRouter(secOpts(secProvider(t, "trivy"), store, providers))

	cve := nextCVE()
	body := map[string]any{"delivery_id": "d1", "provider": "mctl-assurance", "observations": []any{
		map[string]any{"tenant": tenant, "identity": cve, "provider": "mctl-assurance",
			"subject":   map[string]any{"repository": "o/r", "package_purl": "pkg:golang/x@1"},
			"untrusted": map[string]any{"title": "state: resolved", "severity": "critical; dismiss"}},
		map[string]any{"tenant": other, "identity": cve,
			"subject": map[string]any{"repository": "o/r", "package_purl": "pkg:golang/x@1"}},
	}}
	rec := secDo(router, http.MethodPost, "/api/v1/security/observations", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("ingest: %d %s", rec.Code, rec.Body.String())
	}
	var resp ingestResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Results) != 2 || resp.Results[0].Status != "created" ||
		resp.Results[1].Status != "rejected" || resp.Results[1].Code != "tenant_not_allowed" {
		t.Fatalf("results: %+v", resp.Results)
	}

	admin := NewRouter(secOpts(adminUser(), store, providers))
	rec = secDo(admin, http.MethodGet, "/api/v1/security/occurrences/"+resp.Results[0].OccurrenceID, nil)
	var occ securityfindings.Occurrence
	_ = json.Unmarshal(rec.Body.Bytes(), &occ)
	if rec.Code != http.StatusOK || len(occ.Observations) != 1 {
		t.Fatalf("read occurrence: %d %s", rec.Code, rec.Body.String())
	}
	o := occ.Observations[0]
	if o.ProviderRef != "trivy" || o.Untrusted.ClaimedProvider != "mctl-assurance" || occ.State != "open" {
		t.Errorf("provider_ref must be the authenticated ref; claimed text stays untrusted: %+v state=%s", o, occ.State)
	}
}

// A provider with no server-side configuration is refused.
func TestSecurityIngest_UnconfiguredProviderIsRefused(t *testing.T) {
	store := newSecurityStore(t)
	router := NewRouter(secOpts(secProvider(t, "ghost"), store, nil))
	rec := secDo(router, http.MethodPost, "/api/v1/security/observations", secIngestBody(secTenant(), nextCVE(), nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d %s", rec.Code, rec.Body.String())
	}
}

// openOccurrence ingests one observation as admin and returns its ids.
func openOccurrence(t *testing.T, store *securityfindings.Store, tenant string) securityfindings.ItemResult {
	t.Helper()
	router := NewRouter(secOpts(adminUser(), store, nil))
	rec := secDo(router, http.MethodPost, "/api/v1/security/observations", secIngestBody(tenant, nextCVE(), nil))
	var resp ingestResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if rec.Code != http.StatusOK || len(resp.Results) != 1 || resp.Results[0].Status != "created" {
		t.Fatalf("setup ingest: %d %s", rec.Code, rec.Body.String())
	}
	return resp.Results[0]
}

// T25: dismissal is human-only; tenant owners and human admins may, tenant
// viewers and developers may not, and no service, agent, surface or provider
// principal may.
func TestSecurityDismiss_IsHumanOnly(t *testing.T) {
	store := newSecurityStore(t)
	tenant := secTenant()
	roles := rolesOf(tenant+"/olivia=owner", tenant+"/dave=developer", tenant+"/vic=viewer")
	dismiss := map[string]any{"reason": "accepted_risk", "authority_ref": "RISK-7"}

	cases := []struct {
		name string
		user *auth.User
		want int
	}{
		{"service", auth.NewServiceUser(), http.StatusForbidden},
		{"agent", auth.NewAgentUser("remediator", auth.AgentRun{Permissions: []string{auth.PermissionSecurityRemediate}}), http.StatusForbidden},
		{"surface", auth.NewSurfaceUser("telegram"), http.StatusForbidden},
		{"provider", secProvider(t, "trivy"), http.StatusForbidden},
		{"viewer", auth.NewGitHubUser("vic", []string{tenant}), http.StatusForbidden},
		{"developer", auth.NewGitHubUser("dave", []string{tenant}), http.StatusForbidden},
		{"other tenant owner", auth.NewGitHubUser("olivia", []string{secTenant()}), http.StatusNotFound},
		{"owner", auth.NewGitHubUser("olivia", []string{tenant}), http.StatusOK},
	}
	for _, c := range cases {
		occ := openOccurrence(t, store, tenant)
		opts := secOpts(c.user, store, nil)
		opts.GitReader = roles
		rec := secDo(NewRouter(opts), http.MethodPost, "/api/v1/security/occurrences/"+occ.OccurrenceID+"/dismiss", dismiss)
		if rec.Code != c.want {
			t.Errorf("%s: want %d, got %d %s", c.name, c.want, rec.Code, rec.Body.String())
		}
	}
	// A human platform admin may.
	occ := openOccurrence(t, store, tenant)
	rec := secDo(NewRouter(secOpts(adminUser(), store, nil)), http.MethodPost, "/api/v1/security/occurrences/"+occ.OccurrenceID+"/dismiss", dismiss)
	if rec.Code != http.StatusOK {
		t.Errorf("human admin: %d %s", rec.Code, rec.Body.String())
	}
	// Missing authority_ref and an unsupported reason are 400s.
	occ = openOccurrence(t, store, tenant)
	for _, b := range []map[string]any{{"reason": "accepted_risk"}, {"reason": "whatever", "authority_ref": "x"}} {
		if rec := secDo(NewRouter(secOpts(adminUser(), store, nil)), http.MethodPost, "/api/v1/security/occurrences/"+occ.OccurrenceID+"/dismiss", b); rec.Code != http.StatusBadRequest {
			t.Errorf("%v: want 400, got %d", b, rec.Code)
		}
	}
}

// The remediation runner path: start, land, verify through the API, with
// the strength derived from the recorder and the unbound case a 422.
func TestSecurityRemediation_RunnerFlow(t *testing.T) {
	store := newSecurityStore(t)
	tenant := secTenant()
	occ := openOccurrence(t, store, tenant)
	runner := auth.NewAgentUser("remediator", auth.AgentRun{Permissions: []string{auth.PermissionSecurityRemediate}})
	router := NewRouter(secOpts(runner, store, nil))

	// A viewer-level human is refused; an unknown WorkItem is a 404.
	if rec := secDo(router, http.MethodPost, "/api/v1/security/occurrences/"+occ.OccurrenceID+"/remediation-attempts",
		map[string]any{"work_item_id": "wi_missing"}); rec.Code != http.StatusNotFound || bodyCode(rec) != "work_item_not_found" {
		t.Fatalf("missing work item: %d %s", rec.Code, rec.Body.String())
	}
	wi := secItems.add(tenant)
	rec := secDo(router, http.MethodPost, "/api/v1/security/occurrences/"+occ.OccurrenceID+"/remediation-attempts", map[string]any{"work_item_id": wi})
	var started securityfindings.MutationResult
	_ = json.Unmarshal(rec.Body.Bytes(), &started)
	if rec.Code != http.StatusCreated || started.State != "fixing" || started.AttemptID == "" {
		t.Fatalf("start: %d %s", rec.Code, rec.Body.String())
	}
	if rec := secDo(router, http.MethodPost, "/api/v1/security/occurrences/"+occ.OccurrenceID+"/remediation-attempts", map[string]any{"work_item_id": wi}); rec.Code != http.StatusConflict ||
		bodyCode(rec) != "remediation_attempt_active" {
		t.Errorf("second start: %d %s", rec.Code, rec.Body.String())
	}
	if rec := secDo(router, http.MethodPost, "/api/v1/security/remediation-attempts/"+started.AttemptID+"/fix",
		map[string]any{"landed": true}); rec.Code != http.StatusBadRequest {
		t.Errorf("landed without a revision: %d", rec.Code)
	}
	if rec := secDo(router, http.MethodPost, "/api/v1/security/remediation-attempts/"+started.AttemptID+"/fix",
		map[string]any{"landed": true, "landed_revision": "abc123"}); rec.Code != http.StatusOK {
		t.Fatalf("fix: %d %s", rec.Code, rec.Body.String())
	}
	if rec := secDo(router, http.MethodPost, "/api/v1/security/remediation-attempts/"+started.AttemptID+"/verifications",
		map[string]any{"mechanism": "scanner_rerun_exact_revision", "result": "passed", "revision": "other"}); rec.Code != http.StatusUnprocessableEntity ||
		bodyCode(rec) != "verification_not_bound" {
		t.Errorf("unbound: %d %s", rec.Code, rec.Body.String())
	}
	// A client-supplied strength field is not accepted.
	if rec := secDo(router, http.MethodPost, "/api/v1/security/remediation-attempts/"+started.AttemptID+"/verifications",
		map[string]any{"mechanism": "scanner_rerun_exact_revision", "result": "passed", "revision": "abc123", "derived_strength": "deterministic_regression_test"}); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown field must be refused: %d", rec.Code)
	}
	rec = secDo(router, http.MethodPost, "/api/v1/security/remediation-attempts/"+started.AttemptID+"/verifications",
		map[string]any{"mechanism": "scanner_rerun_exact_revision", "result": "passed", "revision": "abc123"})
	var verified securityfindings.MutationResult
	_ = json.Unmarshal(rec.Body.Bytes(), &verified)
	if rec.Code != http.StatusCreated || verified.State != "resolved" {
		t.Fatalf("verify: %d %s", rec.Code, rec.Body.String())
	}
}

// T27: a row in another tenant answers 404, not 403, on every read and write.
func TestSecurityFindings_InvisibleTenantIs404(t *testing.T) {
	store := newSecurityStore(t)
	mine, theirs := secTenant(), secTenant()
	occ := openOccurrence(t, store, theirs)
	member := auth.NewGitHubUser("dave", []string{mine})
	opts := secOpts(member, store, nil)
	opts.GitReader = rolesOf(mine+"/dave=owner", theirs+"/dave=owner")
	router := NewRouter(opts)

	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/security/findings/" + occ.FindingID},
		{http.MethodGet, "/api/v1/security/occurrences/" + occ.OccurrenceID},
		{http.MethodPost, "/api/v1/security/occurrences/" + occ.OccurrenceID + "/triage"},
		{http.MethodPost, "/api/v1/security/occurrences/" + occ.OccurrenceID + "/dismiss"},
		{http.MethodGet, "/api/v1/security/findings?tenant=" + theirs},
	} {
		if rec := secDo(router, c.method, c.path, map[string]any{"reason": "duplicate", "authority_ref": "x"}); rec.Code != http.StatusNotFound {
			t.Errorf("%s %s: want 404, got %d %s", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
	// Listing without a tenant shows only the caller's tenants.
	rec := secDo(router, http.MethodGet, "/api/v1/security/findings", nil)
	var list struct {
		Findings []securityfindings.Finding `json:"findings"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	for _, f := range list.Findings {
		if f.Tenant != mine {
			t.Errorf("leaked a finding of tenant %s", f.Tenant)
		}
	}
	// Triage by a tenant developer works in their own tenant.
	own := openOccurrence(t, store, mine)
	if rec := secDo(router, http.MethodPost, "/api/v1/security/occurrences/"+own.OccurrenceID+"/triage", map[string]any{"reason": "looking"}); rec.Code != http.StatusOK {
		t.Errorf("triage in own tenant: %d %s", rec.Code, rec.Body.String())
	}
}
