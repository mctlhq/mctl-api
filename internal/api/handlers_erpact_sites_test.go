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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/erpactsites"
)

// fakeErpactDeployer is an ErpactDeployer test double. listErr/createErr let
// a test simulate the deployer being unreachable; createdNames records every
// name CreateSite was actually asked to create, so a test can assert a
// rejected request never reached the deployer at all.
type fakeErpactDeployer struct {
	sites        []erpactsites.Site
	listErr      error
	listCalls    int
	createHost   string
	createErr    error
	createdNames []string
}

func (f *fakeErpactDeployer) ListSites(context.Context) ([]erpactsites.Site, error) {
	f.listCalls++
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.sites, nil
}

func (f *fakeErpactDeployer) CreateSite(_ context.Context, name string) (string, error) {
	f.createdNames = append(f.createdNames, name)
	if f.createErr != nil {
		return "", f.createErr
	}
	return f.createHost, nil
}

// erpactBaseHostSite is the shared namespace's own infrastructure entry the
// deployer always lists first (no Status).
var erpactBaseHostSite = erpactsites.Site{Name: "erpact-shared-stteam.mctl.ai", Enabled: true}

func erpactTestHandlers(dep *fakeErpactDeployer, roles *stubRoles) *Handlers {
	return &Handlers{opts: Options{
		ErpactDeployer: dep,
		GitReader:      roles,
		AuditLog:       audit.NewLogger(),
	}}
}

func erpactOwner() *auth.User     { return auth.NewGitHubUser("olga-owner", []string{"erpact"}) }
func erpactDeveloper() *auth.User { return auth.NewGitHubUser("dan-dev", []string{"erpact"}) }
func erpactViewer() *auth.User    { return auth.NewGitHubUser("vic-viewer", []string{"erpact"}) }
func nonErpactMember() *auth.User { return auth.NewGitHubUser("outsider", []string{"acme"}) }

// --- Feature-off: every route 503s with no deployer configured.

func TestErpactSiteRoutes_NilDeployer503(t *testing.T) {
	h := &Handlers{opts: Options{}}
	user := erpactOwner()

	checks := []struct {
		name string
		do   func() *httptest.ResponseRecorder
	}{
		{"list", func() *httptest.ResponseRecorder {
			req := withUser(httptest.NewRequest(http.MethodGet, "/api/v1/tenants/erpact/sites", nil), user)
			w := httptest.NewRecorder()
			h.ListErpactSites(w, req)
			return w
		}},
		{"create", func() *httptest.ResponseRecorder {
			req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/tenants/erpact/sites", strings.NewReader(`{"name":"erpact-acme"}`)), user)
			w := httptest.NewRecorder()
			h.CreateErpactSite(w, req)
			return w
		}},
		{"status", func() *httptest.ResponseRecorder {
			req := withUser(httptest.NewRequest(http.MethodGet, "/api/v1/tenants/erpact/sites/erpact-acme/status", nil), user)
			req = withURLParam(req, "name", "erpact-acme")
			w := httptest.NewRecorder()
			h.GetErpactSiteStatus(w, req)
			return w
		}},
	}
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			w := c.do()
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("got %d, want 503", w.Code)
			}
		})
	}
}

// --- Access: a caller outside tenant erpact is refused, never told what
// exists inside it.

func TestListErpactSites_NonMemberNotFound(t *testing.T) {
	dep := &fakeErpactDeployer{sites: []erpactsites.Site{erpactBaseHostSite}}
	h := erpactTestHandlers(dep, erpactRoles())

	req := withUser(httptest.NewRequest(http.MethodGet, "/api/v1/tenants/erpact/sites", nil), nonErpactMember())
	w := httptest.NewRecorder()
	h.ListErpactSites(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", w.Code)
	}
	if dep.listCalls != 0 {
		t.Fatalf("deployer was called for a caller outside the tenant")
	}
}

func TestListErpactSites_NilUserUnauthorized(t *testing.T) {
	dep := &fakeErpactDeployer{}
	h := erpactTestHandlers(dep, erpactRoles())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/erpact/sites", nil)
	w := httptest.NewRecorder()
	h.ListErpactSites(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", w.Code)
	}
}

// --- List: filters the base host, maps to the short name, and a failed
// deployer read is an error, never an empty list.

func TestListErpactSites_FiltersBaseHostAndMapsShortName(t *testing.T) {
	dep := &fakeErpactDeployer{sites: []erpactsites.Site{
		erpactBaseHostSite,
		{Name: "erpact-acme.mctl.ai", Enabled: true, Status: "ACTIVE"},
		{Name: "erpact-bar2.mctl.ai", Enabled: true, Status: "CREATING"},
	}}
	h := erpactTestHandlers(dep, erpactRoles())

	req := withUser(httptest.NewRequest(http.MethodGet, "/api/v1/tenants/erpact/sites", nil), erpactOwner())
	w := httptest.NewRecorder()
	h.ListErpactSites(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Sites []erpactSiteResponse `json:"sites"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Sites) != 2 {
		t.Fatalf("got %d sites, want 2 (base host must be filtered): %+v", len(resp.Sites), resp.Sites)
	}
	if resp.Sites[0].Name != "erpact-acme" || resp.Sites[0].Host != "erpact-acme.mctl.ai" || resp.Sites[0].Status != "ACTIVE" {
		t.Fatalf("unexpected first entry: %+v", resp.Sites[0])
	}
}

func TestListErpactSites_DeployerErrorIsNotAnEmptyList(t *testing.T) {
	dep := &fakeErpactDeployer{listErr: errors.New("connection refused")}
	h := erpactTestHandlers(dep, erpactRoles())

	req := withUser(httptest.NewRequest(http.MethodGet, "/api/v1/tenants/erpact/sites", nil), erpactOwner())
	w := httptest.NewRecorder()
	h.ListErpactSites(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503 (a failed read must not read as an empty list)", w.Code)
	}
}

// --- Create: role gate. Only an owner may create; a developer or viewer is
// refused and the deployer is never called.

func TestCreateErpactSite_RoleGate(t *testing.T) {
	tests := []struct {
		name       string
		user       *auth.User
		wantStatus int
	}{
		{"owner allowed", erpactOwner(), http.StatusAccepted},
		{"developer forbidden", erpactDeveloper(), http.StatusForbidden},
		{"viewer forbidden", erpactViewer(), http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dep := &fakeErpactDeployer{createHost: "erpact-acme.mctl.ai"}
			h := erpactTestHandlers(dep, erpactRoles())

			req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/tenants/erpact/sites", strings.NewReader(`{"name":"erpact-acme"}`)), tt.user)
			w := httptest.NewRecorder()
			h.CreateErpactSite(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("got %d, want %d: %s", w.Code, tt.wantStatus, w.Body.String())
			}
			calledDeployer := len(dep.createdNames) > 0
			if tt.wantStatus == http.StatusAccepted && !calledDeployer {
				t.Fatalf("owner's create never reached the deployer")
			}
			if tt.wantStatus == http.StatusForbidden && calledDeployer {
				t.Fatalf("a refused caller's request reached the deployer")
			}
		})
	}
}

func TestCreateErpactSite_NonMemberNotFound(t *testing.T) {
	dep := &fakeErpactDeployer{}
	h := erpactTestHandlers(dep, erpactRoles())

	req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/tenants/erpact/sites", strings.NewReader(`{"name":"erpact-acme"}`)), nonErpactMember())
	w := httptest.NewRecorder()
	h.CreateErpactSite(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", w.Code)
	}
	if len(dep.createdNames) != 0 {
		t.Fatalf("deployer was called for a caller outside the tenant")
	}
}

// --- Create: name validation happens before the deployer is ever called.

func TestCreateErpactSite_NameValidation(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"missing prefix", "acme"},
		{"uppercase not allowed as-is but would still need the prefix", "ACME"},
		{"invalid characters", "erpact-ac me!"},
		{"reserved system name", "erpact-system"},
		{"empty", ""},
		{"too long", "erpact-" + strings.Repeat("a", 60)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dep := &fakeErpactDeployer{createHost: "erpact-acme.mctl.ai"}
			h := erpactTestHandlers(dep, erpactRoles())

			body := fmt.Sprintf(`{"name":%q}`, tt.input)
			req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/tenants/erpact/sites", strings.NewReader(body)), erpactOwner())
			w := httptest.NewRecorder()
			h.CreateErpactSite(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("got %d, want 400: %s", w.Code, w.Body.String())
			}
			if len(dep.createdNames) != 0 {
				t.Fatalf("an invalid name reached the deployer: %v", dep.createdNames)
			}
		})
	}
}

// --- Create: the site cap is enforced before the deployer is asked to
// create anything, and counts only real sites, not the base host.

func TestCreateErpactSite_CapReached(t *testing.T) {
	sites := []erpactsites.Site{erpactBaseHostSite}
	for i := 0; i < erpactSiteCap; i++ {
		sites = append(sites, erpactsites.Site{Name: fmt.Sprintf("erpact-site%d.mctl.ai", i), Status: "ACTIVE"})
	}
	dep := &fakeErpactDeployer{sites: sites, createHost: "erpact-acme.mctl.ai"}
	h := erpactTestHandlers(dep, erpactRoles())

	req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/tenants/erpact/sites", strings.NewReader(`{"name":"erpact-acme"}`)), erpactOwner())
	w := httptest.NewRecorder()
	h.CreateErpactSite(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("got %d, want 409 (cap reached): %s", w.Code, w.Body.String())
	}
	if len(dep.createdNames) != 0 {
		t.Fatalf("create reached the deployer despite the cap")
	}
}

func TestCreateErpactSite_BelowCapSucceeds(t *testing.T) {
	sites := []erpactsites.Site{erpactBaseHostSite}
	for i := 0; i < erpactSiteCap-1; i++ {
		sites = append(sites, erpactsites.Site{Name: fmt.Sprintf("erpact-site%d.mctl.ai", i), Status: "ACTIVE"})
	}
	dep := &fakeErpactDeployer{sites: sites, createHost: "erpact-acme.mctl.ai"}
	h := erpactTestHandlers(dep, erpactRoles())

	req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/tenants/erpact/sites", strings.NewReader(`{"name":"erpact-acme"}`)), erpactOwner())
	w := httptest.NewRecorder()
	h.CreateErpactSite(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("got %d, want 202 (one slot free): %s", w.Code, w.Body.String())
	}
}

// --- Create: a deployer-side conflict (name already exists, or deployer
// busy) maps to 409, not a generic 503.

func TestCreateErpactSite_DeployerConflictMapped(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"already exists", erpactsites.ErrSiteExists},
		{"deployer busy", erpactsites.ErrBusy},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dep := &fakeErpactDeployer{createErr: fmt.Errorf("wrapped: %w", tt.err)}
			h := erpactTestHandlers(dep, erpactRoles())

			req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/tenants/erpact/sites", strings.NewReader(`{"name":"erpact-acme"}`)), erpactOwner())
			w := httptest.NewRecorder()
			h.CreateErpactSite(w, req)

			if w.Code != http.StatusConflict {
				t.Fatalf("got %d, want 409: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestCreateErpactSite_HappyPathAudited(t *testing.T) {
	dep := &fakeErpactDeployer{createHost: "erpact-acme.mctl.ai"}
	auditLog := audit.NewLogger()
	h := &Handlers{opts: Options{ErpactDeployer: dep, GitReader: erpactRoles(), AuditLog: auditLog}}

	req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/tenants/erpact/sites", strings.NewReader(`{"name":"erpact-ACME"}`)), erpactOwner())
	w := httptest.NewRecorder()
	h.CreateErpactSite(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("got %d, want 202: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["name"] != "erpact-acme" || resp["host"] != "erpact-acme.mctl.ai" || resp["status"] != "creating" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	// The deployer prefixes its own SITE_HOST_PREFIX ("erpact-"), so it
	// must get the bare label: sending the full name created
	// "erpact-erpact-..." in prod on 2026-10-09.
	if len(dep.createdNames) != 1 || dep.createdNames[0] != "acme" {
		t.Fatalf("deployer received %v, want [acme] (lowercased, without the erpact- prefix)", dep.createdNames)
	}

	entries := auditLog.List(10)
	if len(entries) != 1 || entries[0].Operation != "erpact.create_site" || entries[0].UserID != "olga-owner" {
		t.Fatalf("unexpected audit entries: %+v", entries)
	}
}

// --- Status: looks a site up by its short name and is case-insensitive;
// an unknown name is 404.

func TestGetErpactSiteStatus_FindsByShortName(t *testing.T) {
	dep := &fakeErpactDeployer{sites: []erpactsites.Site{
		erpactBaseHostSite,
		{Name: "erpact-acme.mctl.ai", Status: "CREATING"},
	}}
	h := erpactTestHandlers(dep, erpactRoles())

	req := withUser(httptest.NewRequest(http.MethodGet, "/api/v1/tenants/erpact/sites/ERPACT-ACME/status", nil), erpactOwner())
	req = withURLParam(req, "name", "ERPACT-ACME")
	w := httptest.NewRecorder()
	h.GetErpactSiteStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200: %s", w.Code, w.Body.String())
	}
	var resp erpactSiteResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "CREATING" {
		t.Fatalf("got status %q, want CREATING", resp.Status)
	}
}

func TestGetErpactSiteStatus_UnknownNameNotFound(t *testing.T) {
	dep := &fakeErpactDeployer{sites: []erpactsites.Site{erpactBaseHostSite}}
	h := erpactTestHandlers(dep, erpactRoles())

	req := withUser(httptest.NewRequest(http.MethodGet, "/api/v1/tenants/erpact/sites/erpact-ghost/status", nil), erpactOwner())
	req = withURLParam(req, "name", "erpact-ghost")
	w := httptest.NewRecorder()
	h.GetErpactSiteStatus(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", w.Code)
	}
}

// --- Unit coverage for the name validator itself.

func TestValidateErpactSiteName(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"erpact-acme", "erpact-acme", false},
		{"erpact-ACME", "erpact-acme", false}, // normalized to lowercase
		{"  erpact-acme  ", "erpact-acme", false},
		{"acme", "", true},    // missing prefix
		{"erpact-", "", true}, // nothing after the prefix
		{"erpact-ac me", "", true},
		{"erpact-system", "", true}, // reserved
		{"erpact-root", "", true},   // reserved
		{"", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := validateErpactSiteName(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("validateErpactSiteName(%q) = %q, want an error", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateErpactSiteName(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("validateErpactSiteName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// A real site the deployer reports without a status yet must not be mistaken
// for the base host: it is listed, found by the status lookup, and counts
// against the cap.
func TestErpactSite_StatuslessRealSiteIsNotTheBaseHost(t *testing.T) {
	fresh := erpactsites.Site{Name: "erpact-fresh.mctl.ai", Enabled: true}

	t.Run("listed", func(t *testing.T) {
		h := erpactTestHandlers(&fakeErpactDeployer{sites: []erpactsites.Site{erpactBaseHostSite, fresh}}, erpactRoles())
		req := withUser(httptest.NewRequest(http.MethodGet, "/api/v1/tenants/erpact/sites", nil), erpactOwner())
		w := httptest.NewRecorder()
		h.ListErpactSites(w, req)
		var resp struct {
			Sites []erpactSiteResponse `json:"sites"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.Sites) != 1 || resp.Sites[0].Name != "erpact-fresh" {
			t.Fatalf("statusless real site missing from listing: %+v", resp.Sites)
		}
	})

	t.Run("status lookup finds it", func(t *testing.T) {
		h := erpactTestHandlers(&fakeErpactDeployer{sites: []erpactsites.Site{erpactBaseHostSite, fresh}}, erpactRoles())
		req := withUser(httptest.NewRequest(http.MethodGet, "/api/v1/tenants/erpact/sites/erpact-fresh/status", nil), erpactOwner())
		req = withURLParam(req, "name", "erpact-fresh")
		w := httptest.NewRecorder()
		h.GetErpactSiteStatus(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("got %d, want 200: %s", w.Code, w.Body.String())
		}
	})

	t.Run("counts against the cap", func(t *testing.T) {
		sites := []erpactsites.Site{erpactBaseHostSite}
		for i := 0; i < erpactSiteCap-1; i++ {
			sites = append(sites, erpactsites.Site{Name: fmt.Sprintf("erpact-s%d.mctl.ai", i), Enabled: true, Status: "ACTIVE"})
		}
		sites = append(sites, fresh)
		dep := &fakeErpactDeployer{sites: sites, createHost: "erpact-new.mctl.ai"}
		h := erpactTestHandlers(dep, erpactRoles())
		req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/tenants/erpact/sites", strings.NewReader(`{"name":"erpact-new"}`)), erpactOwner())
		w := httptest.NewRecorder()
		h.CreateErpactSite(w, req)
		if w.Code != http.StatusConflict {
			t.Fatalf("got %d, want 409 (cap): %s", w.Code, w.Body.String())
		}
	})
}

func TestValidateErpactSiteName_BaseHostIsReserved(t *testing.T) {
	if _, err := validateErpactSiteName("erpact-shared-stteam"); err == nil {
		t.Fatal("the shared base host's own name must not be creatable")
	}
}

// Two concurrent creates at 9 of 10 must not both succeed.
type racingDeployer struct {
	mu    sync.Mutex
	sites []erpactsites.Site
}

func (d *racingDeployer) ListSites(context.Context) ([]erpactsites.Site, error) {
	d.mu.Lock()
	out := append([]erpactsites.Site(nil), d.sites...)
	d.mu.Unlock()
	time.Sleep(20 * time.Millisecond) // widen the check-then-act window
	return out, nil
}

func (d *racingDeployer) CreateSite(_ context.Context, name string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sites = append(d.sites, erpactsites.Site{Name: name + ".mctl.ai", Enabled: true, Status: "CREATING"})
	return name + ".mctl.ai", nil
}

func TestCreateErpactSite_CapHoldsUnderConcurrency(t *testing.T) {
	d := &racingDeployer{sites: []erpactsites.Site{erpactBaseHostSite}}
	for i := 0; i < erpactSiteCap-1; i++ {
		d.sites = append(d.sites, erpactsites.Site{Name: fmt.Sprintf("erpact-s%d.mctl.ai", i), Status: "ACTIVE"})
	}
	h := &Handlers{opts: Options{ErpactDeployer: d, GitReader: erpactRoles(), AuditLog: audit.NewLogger()}}

	var wg sync.WaitGroup
	codes := make([]int, 2)
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := fmt.Sprintf(`{"name":"erpact-race%d"}`, i)
			req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/tenants/erpact/sites", strings.NewReader(body)), erpactOwner())
			w := httptest.NewRecorder()
			h.CreateErpactSite(w, req)
			codes[i] = w.Code
		}()
	}
	wg.Wait()
	created := 0
	for _, c := range codes {
		if c == http.StatusAccepted {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("got %d successful creates (codes %v), want exactly 1 at the cap boundary", created, codes)
	}
}

// The three routes, reached through the real router rather than by calling
// the handlers directly.
func TestErpactSiteRoutes_ThroughNewRouter(t *testing.T) {
	dep := &fakeErpactDeployer{
		sites:      []erpactsites.Site{erpactBaseHostSite, {Name: "erpact-acme.mctl.ai", Status: "ACTIVE"}},
		createHost: "erpact-new.mctl.ai",
	}
	as := func(u *auth.User) http.Handler {
		return NewRouter(Options{
			ErpactDeployer: dep,
			GitReader:      erpactRoles(),
			AuditLog:       audit.NewLogger(),
			AuthMiddleware: func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					next.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), u)))
				})
			},
		})
	}
	do := func(h http.Handler, method, path, body string) int {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}

	if c := do(as(erpactOwner()), http.MethodGet, "/api/v1/tenants/erpact/sites", ""); c != http.StatusOK {
		t.Fatalf("list as owner: got %d, want 200", c)
	}
	if c := do(as(erpactOwner()), http.MethodGet, "/api/v1/tenants/erpact/sites/erpact-acme/status", ""); c != http.StatusOK {
		t.Fatalf("status as owner: got %d, want 200", c)
	}
	// Owner-only since 2026-10-09: a member who is not an owner is refused.
	if c := do(as(erpactViewer()), http.MethodGet, "/api/v1/tenants/erpact/sites", ""); c != http.StatusForbidden {
		t.Fatalf("list as viewer: got %d, want 403", c)
	}
	if c := do(as(erpactViewer()), http.MethodGet, "/api/v1/tenants/erpact/sites/erpact-acme/status", ""); c != http.StatusForbidden {
		t.Fatalf("status as viewer: got %d, want 403", c)
	}
	if c := do(as(erpactViewer()), http.MethodPost, "/api/v1/tenants/erpact/sites", `{"name":"erpact-new"}`); c != http.StatusForbidden {
		t.Fatalf("create as viewer: got %d, want 403", c)
	}
	if c := do(as(erpactOwner()), http.MethodPost, "/api/v1/tenants/erpact/sites", `{"name":"erpact-new"}`); c != http.StatusAccepted {
		t.Fatalf("create as owner: got %d, want 202", c)
	}
	if c := do(as(nonErpactMember()), http.MethodGet, "/api/v1/tenants/erpact/sites", ""); c != http.StatusNotFound {
		t.Fatalf("list as outsider: got %d, want 404", c)
	}
}

// --- Create: an answer that never came is "unknown", not "failed". The
// deployer commits and pushes before it answers, so a timed-out create can
// still produce a site (prod, 2026-10-09).

func TestCreateErpactSite_TimeoutIsUnknownNotFailed(t *testing.T) {
	dep := &fakeErpactDeployer{createErr: fmt.Errorf("%w: deadline", erpactsites.ErrOutcomeUnknown)}
	auditLog := audit.NewLogger()
	h := &Handlers{opts: Options{ErpactDeployer: dep, GitReader: erpactRoles(), AuditLog: auditLog}}

	req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/tenants/erpact/sites", strings.NewReader(`{"name":"erpact-acme"}`)), erpactOwner())
	w := httptest.NewRecorder()
	h.CreateErpactSite(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("got %d, want 202: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["status"] != "unknown" || resp["name"] != "erpact-acme" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	entries := auditLog.List(10)
	if len(entries) != 1 || entries[0].Status != "unknown" {
		t.Fatalf("want one audit entry with status unknown, got %+v", entries)
	}
}

// --- Create: a name already in the listing is refused before the deployer
// is asked, so the answer does not depend on the deployer's error wording.

func TestCreateErpactSite_ExistingNameRefusedWithoutCallingDeployer(t *testing.T) {
	dep := &fakeErpactDeployer{sites: []erpactsites.Site{
		erpactBaseHostSite,
		{Name: "erpact-acme.mctl.ai", Status: "ACTIVE"},
	}}
	auditLog := audit.NewLogger()
	h := &Handlers{opts: Options{ErpactDeployer: dep, GitReader: erpactRoles(), AuditLog: auditLog}}

	req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/tenants/erpact/sites", strings.NewReader(`{"name":"ERPACT-ACME"}`)), erpactOwner())
	w := httptest.NewRecorder()
	h.CreateErpactSite(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("got %d, want 409: %s", w.Code, w.Body.String())
	}
	if len(dep.createdNames) != 0 {
		t.Fatalf("deployer must not be called, got %v", dep.createdNames)
	}
	// A refused attempt is still an audited attempt, like the cap refusal.
	entries := auditLog.List(10)
	if len(entries) != 1 || entries[0].Status != "failed" {
		t.Fatalf("want one failed audit entry for the refused duplicate, got %+v", entries)
	}
}

// --- List and status are owner-or-admin (2026-10-09): 404 for a non-member,
// 403 for a member who is not an owner, 503 when the role cannot be read.

func TestErpactListAndStatus_OwnerOrAdminOnly(t *testing.T) {
	dep := &fakeErpactDeployer{sites: []erpactsites.Site{{Name: "erpact-acme.mctl.ai", Status: "ACTIVE"}}}
	h := erpactTestHandlers(dep, erpactRoles())
	admin := auth.NewGitHubUser("some-admin", []string{"admins"})

	cases := []struct {
		name string
		user *auth.User
		want int
	}{
		{"owner", erpactOwner(), http.StatusOK},
		{"admin", admin, http.StatusOK},
		{"developer", erpactDeveloper(), http.StatusForbidden},
		{"viewer", erpactViewer(), http.StatusForbidden},
		{"outsider", nonErpactMember(), http.StatusNotFound},
		{"anonymous", nil, http.StatusUnauthorized},
	}
	for _, c := range cases {
		t.Run("list/"+c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/erpact/sites", nil)
			if c.user != nil {
				req = withUser(req, c.user)
			}
			w := httptest.NewRecorder()
			h.ListErpactSites(w, req)
			if w.Code != c.want {
				t.Fatalf("got %d, want %d: %s", w.Code, c.want, w.Body.String())
			}
		})
	}
}

func TestErpactListAndStatus_RoleReadFailureIsNotAPass(t *testing.T) {
	dep := &fakeErpactDeployer{sites: []erpactsites.Site{{Name: "erpact-acme.mctl.ai", Status: "ACTIVE"}}}
	// No GitReader: the role cannot be read.
	h := &Handlers{opts: Options{ErpactDeployer: dep, AuditLog: audit.NewLogger()}}

	req := withUser(httptest.NewRequest(http.MethodGet, "/api/v1/tenants/erpact/sites", nil), erpactOwner())
	w := httptest.NewRecorder()
	h.ListErpactSites(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("list: got %d, want 503", w.Code)
	}
	if dep.listCalls != 0 {
		t.Fatalf("deployer was queried despite an unreadable role")
	}
}

func TestIsTenantOwner(t *testing.T) {
	h := erpactTestHandlers(&fakeErpactDeployer{}, erpactRoles())
	admin := auth.NewGitHubUser("some-admin", []string{"admins"})
	cases := []struct {
		name string
		user *auth.User
		want bool
	}{
		{"owner", erpactOwner(), true},
		{"admin", admin, true},
		{"developer", erpactDeveloper(), false},
		{"viewer", erpactViewer(), false},
		{"outsider", nonErpactMember(), false},
		{"nil", nil, false},
	}
	for _, c := range cases {
		got, err := h.IsTenantOwner(c.user, erpactTenant)
		if err != nil || got != c.want {
			t.Errorf("%s: got (%v, %v), want (%v, nil)", c.name, got, err, c.want)
		}
	}

	noReader := &Handlers{opts: Options{}}
	if got, err := noReader.IsTenantOwner(erpactOwner(), erpactTenant); got || err == nil {
		t.Errorf("unreadable role: got (%v, %v), want (false, error)", got, err)
	}
}
