package api_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// create-tenant only ever makes a new tenant. For a name that already exists
// the workflow skips writing the tenant and carries on provisioning, so a
// non-admin is refused before anything is submitted.

const createTenantPath = "/api/v1/operations/create-tenant/execute"

func createTenantRouter(t *testing.T, git *fakeGitReader) (http.Handler, *fakeExecutor) {
	t.Helper()
	if git.tenants == nil {
		git.tenants = []gitops.Tenant{{Name: "taken", Members: []gitops.TenantMember{{UserID: "someone", Role: "owner"}}}}
	}
	exec := &fakeExecutor{}
	router := mctlapi.NewRouter(mctlapi.Options{
		Registry:  operations.NewRegistry(),
		GitReader: git,
		AuditLog:  audit.NewLogger(),
		Executor:  exec,
	})
	return router, exec
}

var newcomer = &auth.User{ID: "newcomer", Groups: []string{}}

func TestCreateTenant_ExistingTenantConflicts(t *testing.T) {
	router, exec := createTenantRouter(t, &fakeGitReader{})
	w := postAs(t, router, createTenantPath, map[string]string{"tenant_name": "taken"}, newcomer)
	assertStatus(t, w, http.StatusConflict)
	if !strings.Contains(w.Body.String(), "already exists") {
		t.Errorf("unexpected body: %s", w.Body.String())
	}
	if len(exec.submitted) != 0 {
		t.Fatalf("an existing tenant must not be submitted: %v", exec.submitted)
	}
}

func TestCreateTenant_NewTenantIsSubmitted(t *testing.T) {
	router, exec := createTenantRouter(t, &fakeGitReader{})
	w := postAs(t, router, createTenantPath, map[string]string{"tenant_name": "fresh"}, newcomer)
	assertStatus(t, w, http.StatusAccepted)
	if len(exec.submittedParams) != 1 || exec.submittedParams[0]["creator_user_id"] != "newcomer" {
		t.Fatalf("expected one submission as newcomer, got %v", exec.submittedParams)
	}
}

func TestCreateTenant_UncheckableRefuses(t *testing.T) {
	router, exec := createTenantRouter(t, &fakeGitReader{tenantExistsErr: errors.New("checking tenant: lstat /srv/gitops/platform-gitops/tenants/fresh: permission denied")})
	w := postAs(t, router, createTenantPath, map[string]string{"tenant_name": "fresh"}, newcomer)
	assertStatus(t, w, http.StatusServiceUnavailable)
	if strings.Contains(w.Body.String(), "/srv/gitops") || strings.Contains(w.Body.String(), "lstat") {
		t.Errorf("the 503 must not expose the checkout error: %s", w.Body.String())
	}
	if len(exec.submitted) != 0 {
		t.Fatalf("must not submit when existence cannot be checked: %v", exec.submitted)
	}
}

// Admins may re-run create-tenant on an existing tenant to finish or redo
// its provisioning; they are not checked.
func TestCreateTenant_AdminMayRerun(t *testing.T) {
	router, exec := createTenantRouter(t, &fakeGitReader{tenantExistsErr: errors.New("would refuse")})
	w := postAs(t, router, createTenantPath, map[string]string{"tenant_name": "taken"}, adminUser)
	assertStatus(t, w, http.StatusAccepted)
	if len(exec.submitted) != 1 {
		t.Fatalf("expected a submission, got %v", exec.submitted)
	}
}

func TestCreateTenant_ReservedNameRejected(t *testing.T) {
	for _, u := range []*auth.User{newcomer, adminUser} {
		router, exec := createTenantRouter(t, &fakeGitReader{})
		w := postAs(t, router, createTenantPath, map[string]string{"tenant_name": "argocd"}, u)
		assertStatus(t, w, http.StatusBadRequest)
		if !strings.Contains(w.Body.String(), "validationErrors") || !strings.Contains(w.Body.String(), "reserved") {
			t.Errorf("unexpected body: %s", w.Body.String())
		}
		if len(exec.submitted) != 0 {
			t.Fatalf("reserved name must not be submitted: %v", exec.submitted)
		}
	}
}
