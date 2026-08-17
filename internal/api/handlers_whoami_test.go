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
