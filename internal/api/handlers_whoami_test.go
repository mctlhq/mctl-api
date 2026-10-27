package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
)

type whoamiResponse struct {
	ID         string   `json:"id"`
	Groups     []string `json:"groups"`
	IsAdmin    bool     `json:"isAdmin"`
	Namespaces []string `json:"namespaces"`
}

func callWhoami(t *testing.T, user *auth.User) whoamiResponse {
	t.Helper()

	h := &Handlers{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whoami", nil)
	if user != nil {
		req = req.WithContext(auth.WithUser(req.Context(), user))
	}
	rec := httptest.NewRecorder()

	h.Whoami(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Whoami status = %d, want %d (body: %s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	var got whoamiResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode whoami response: %v (body: %s)", err, rec.Body.String())
	}
	return got
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

// TestWhoamiIncludesAdminsNamespace guards the fix: "admins" used to be
// stripped from the namespaces list on the theory that it names a role rather
// than a tenant. It is both — platform-gitops/tenants/admins is a real tenant
// and the namespace runs mctl-agents-worker and the mctl-api workflows — so
// hiding it made whoami under-report where an admin can submit work.
func TestWhoamiIncludesAdminsNamespace(t *testing.T) {
	got := callWhoami(t, &auth.User{ID: "mashkovd", Groups: []string{"admins", "ovk"}})

	if !contains(got.Namespaces, "admins") {
		t.Errorf("namespaces = %v, want it to include \"admins\"", got.Namespaces)
	}
	if !contains(got.Namespaces, "ovk") {
		t.Errorf("namespaces = %v, want it to include \"ovk\"", got.Namespaces)
	}
	if len(got.Namespaces) != len(got.Groups) {
		t.Errorf("namespaces %v and groups %v should match; nothing is filtered out", got.Namespaces, got.Groups)
	}
	if !got.IsAdmin {
		t.Error("isAdmin = false for a user in the admins group")
	}
}

// TestWhoamiDeduplicatesGroups covers the uniquePreserveOrder path feeding
// both fields, so a duplicated group claim cannot inflate either list.
func TestWhoamiDeduplicatesGroups(t *testing.T) {
	got := callWhoami(t, &auth.User{ID: "dup", Groups: []string{"admins", "ovk", "admins"}})

	if len(got.Groups) != 2 {
		t.Errorf("groups = %v, want 2 unique entries", got.Groups)
	}
	if len(got.Namespaces) != 2 {
		t.Errorf("namespaces = %v, want 2 unique entries", got.Namespaces)
	}
	if got.Groups[0] != "admins" || got.Groups[1] != "ovk" {
		t.Errorf("groups = %v, want original order preserved", got.Groups)
	}
}

// TestWhoamiNonAdminUnaffected pins that the change is additive: a user with
// no admin membership sees exactly their own tenants, as before.
func TestWhoamiNonAdminUnaffected(t *testing.T) {
	got := callWhoami(t, &auth.User{ID: "tenant-user", Groups: []string{"ovk"}})

	if len(got.Namespaces) != 1 || got.Namespaces[0] != "ovk" {
		t.Errorf("namespaces = %v, want [ovk]", got.Namespaces)
	}
	if got.IsAdmin {
		t.Error("isAdmin = true for a user outside the admins group")
	}
}

func TestWhoamiRequiresAuthentication(t *testing.T) {
	h := &Handlers{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whoami", nil)
	rec := httptest.NewRecorder()

	h.Whoami(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// In principal mode admin is ADMIN_PRINCIPALS, not a group, and Apply
// keeps "admins" out of the groups; whoami still lists the namespace an
// admin can submit to.
func TestWhoamiPrincipalModeAdminListsAdminsNamespace(t *testing.T) {
	u := withPrincipal(t, auth.NewGitHubUser("mashkovd", []string{"admins"}), shadowPRN)
	p := &auth.PrincipalAuthz{Members: tenantsByPrincipal{shadowPRN: {"admins", "ovk"}}, Admins: map[string]bool{shadowPRN: true}}
	if err := p.Apply(u); err != nil {
		t.Fatal(err)
	}
	got := callWhoami(t, u)
	if !got.IsAdmin || !contains(got.Namespaces, "admins") || !contains(got.Namespaces, "ovk") || contains(got.Groups, "admins") {
		t.Fatalf("isAdmin=%v groups=%v namespaces=%v; want admin, groups without \"admins\", namespaces with it", got.IsAdmin, got.Groups, got.Namespaces)
	}
}

func whoamiRaw(t *testing.T, user *auth.User) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whoami", nil)
	req = req.WithContext(auth.WithUser(req.Context(), user))
	rec := httptest.NewRecorder()
	(&Handlers{}).Whoami(rec, req)
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return m
}

func TestWhoamiReportsBoundTenant(t *testing.T) {
	m := whoamiRaw(t, auth.NewAgentUser("mctl-support", auth.AgentRun{Scope: auth.AgentScopeSupport, Tenant: "labs"}))
	if m["boundTenant"] != "labs" {
		t.Errorf("boundTenant = %v, want labs", m["boundTenant"])
	}
}

func TestWhoamiOmitsBoundTenantWhenUnbound(t *testing.T) {
	cases := map[string]*auth.User{
		"human":        {ID: "u", Groups: []string{"ovk"}},
		"admin":        {ID: "a", Groups: []string{"admins"}},
		"investigate":  auth.NewAgentUser("issue-investigator", auth.AgentRun{Scope: auth.AgentScopeInvestigate}),
		"unscoped":     auth.NewAgentUser("x", auth.AgentRun{}),
		"empty tenant": auth.NewAgentUser("mctl-support", auth.AgentRun{Scope: auth.AgentScopeSupport}),
	}
	for name, u := range cases {
		t.Run(name, func(t *testing.T) {
			if _, ok := whoamiRaw(t, u)["boundTenant"]; ok {
				t.Error("boundTenant key present, want omitted")
			}
		})
	}
}
