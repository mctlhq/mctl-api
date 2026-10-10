package api_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// A reserved tenant name is refused with a 400 before anything is submitted,
// for a regular user and for an admin alike (the admin re-run path skips the
// existence check, not this one). The MCP mctl_create_tenant tool posts to
// this same endpoint.
func TestCreateTenant_ReservedNameRejectedBeforeSubmit(t *testing.T) {
	users := []struct {
		label string
		user  *auth.User
	}{{"user", newcomer}, {"admin", adminUser}}
	for _, name := range []string{"kube-system", "argocd", "vault", "kube-system-team", "my-system", "mctl-labs", "platform-x"} {
		for _, u := range users {
			t.Run(u.label+"/"+name, func(t *testing.T) {
				router, exec := createTenantRouter(t, &fakeGitReader{})
				w := postAs(t, router, createTenantPath, map[string]string{"tenant_name": name}, u.user)
				assertStatus(t, w, http.StatusBadRequest)
				if !strings.Contains(w.Body.String(), "reserved") {
					t.Errorf("expected a reserved-name validation error, got: %s", w.Body.String())
				}
				if len(exec.submitted) != 0 {
					t.Fatalf("a reserved name must not be submitted: %v", exec.submitted)
				}
			})
		}
	}
}

func TestCreateTenant_NearMissNameIsSubmitted(t *testing.T) {
	for _, name := range []string{"team-kube", "systems", "billing"} {
		t.Run(name, func(t *testing.T) {
			router, exec := createTenantRouter(t, &fakeGitReader{})
			w := postAs(t, router, createTenantPath, map[string]string{"tenant_name": name}, newcomer)
			assertStatus(t, w, http.StatusAccepted)
			if len(exec.submitted) != 1 {
				t.Fatalf("expected one submission, got %v", exec.submitted)
			}
		})
	}
}
