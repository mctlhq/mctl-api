package api_test

import (
	"context"
	"errors"
	"net/http"
	"regexp"
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

type creatorPrincipal string

func (p creatorPrincipal) ResolvePrincipal(context.Context, auth.Identity) (string, error) {
	return string(p), nil
}

// The creator's owner entry is keyed by the principal the session resolved
// to (mctl-api#377), never by one the caller names; an unresolved principal
// sends none rather than whatever the body carried.
func TestCreateTenant_CreatorPrincipalComesFromTheSession(t *testing.T) {
	const pid = "prn_01M39HRB7JRXZ2PHW5VVB695YZ"
	const spoofed = "prn_01M45DR1GWC87109EH88VBJX25"
	resolved := auth.NewGitHubUser("newcomer", []string{})
	if err := auth.AttachPrincipal(context.Background(), creatorPrincipal(pid), resolved); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		user *auth.User
		want string
	}{
		{"resolved", resolved, pid},
		{"unresolved", auth.NewGitHubUser("newcomer", []string{}), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			router, exec := createTenantRouter(t, &fakeGitReader{})
			w := postAs(t, router, createTenantPath, map[string]string{
				"tenant_name":          "fresh",
				"creator_principal_id": spoofed,
			}, tc.user)
			assertStatus(t, w, http.StatusAccepted)
			if len(exec.submittedParams) != 1 {
				t.Fatalf("expected one submission, got %v", exec.submittedParams)
			}
			// ApplyDefaults sends an absent parameter as "", which the
			// workflow reads as "no principal".
			if got := exec.submittedParams[0]["creator_principal_id"]; got != tc.want {
				t.Errorf("creator_principal_id = %q, want %q", got, tc.want)
			}
		})
	}
}

// The registry's creator_principal_id pattern is a copy of the auth
// package's; the two must agree, or the handler would stamp an id that
// ValidateInput then rejects on a parameter no caller can see.
func TestCreateTenant_CreatorPrincipalPatternMatchesAuth(t *testing.T) {
	op, ok := operations.NewRegistry().Get("create-tenant")
	if !ok {
		t.Fatal("create-tenant not registered")
	}
	var pattern string
	for _, p := range op.Parameters {
		if p.Name == "creator_principal_id" {
			pattern = p.Pattern
		}
	}
	if pattern == "" {
		t.Fatal("create-tenant has no creator_principal_id parameter, or it has no pattern")
	}
	re := regexp.MustCompile(pattern)
	for _, id := range []string{
		"prn_01M39HRB7JRXZ2PHW5VVB695YZ",
		// Crockford base32 excludes I, L, O and U.
		"prn_01M39HRB7JRXZ2PHW5VVB695YI",
		"prn_01M39HRB7JRXZ2PHW5VVB695YL",
		"prn_01M39HRB7JRXZ2PHW5VVB695YO",
		"prn_01M39HRB7JRXZ2PHW5VVB695YU",
		"prn_01m39hrb7jrxz2phw5vvb695yz",
		"prn_01M39HRB7JRXZ2PHW5VVB695Y",
		"prn_01M39HRB7JRXZ2PHW5VVB695YZZ",
		"01M39HRB7JRXZ2PHW5VVB695YZ",
		"",
	} {
		if got, want := re.MatchString(id), auth.ValidPrincipalID(id); got != want {
			t.Errorf("%q: registry pattern says %v, auth.ValidPrincipalID says %v", id, got, want)
		}
	}
}
