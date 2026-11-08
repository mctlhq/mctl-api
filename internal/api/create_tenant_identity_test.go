package api_test

import (
	"net/http"
	"strings"
	"testing"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// mctl-api#568 T3: creator_user_id is forced from the session and spliced
// unquoted into the tenant YAML, so a sign-in identity outside its charset
// is refused before anything is submitted, with a cause the caller can act
// on and a denied audit entry. A valid identity is unaffected.
func TestCreateTenant_IdentityOutsideCreatorCharsetIsRefused(t *testing.T) {
	log := audit.NewLogger()
	exec := &fakeExecutor{}
	router := mctlapi.NewRouter(mctlapi.Options{
		Registry:  operations.NewRegistry(),
		GitReader: &fakeGitReader{},
		AuditLog:  log,
		Executor:  exec,
	})

	odd := resolvedUser(auth.NewGitHubUser("alice+x@example.com", []string{}))
	w := postAs(t, router, createTenantPath, map[string]string{"tenant_name": "fresh"}, odd)
	assertStatus(t, w, http.StatusBadRequest)
	body := w.Body.String()
	if !strings.Contains(body, "sign-in identity") || strings.Contains(body, "creator_user_id:") {
		t.Errorf("the 400 must name the identity format, not a parameter the caller never sent: %s", body)
	}
	if len(exec.submitted) != 0 {
		t.Fatalf("an unrecordable identity must not be submitted: %v", exec.submitted)
	}
	denied := 0
	for _, e := range log.List(100) {
		if e.Operation == "create-tenant" && e.Status == "denied" && e.UserID == "alice+x@example.com" {
			denied++
		}
	}
	if denied != 1 {
		t.Errorf("want exactly one denied create-tenant audit entry for the identity, got %d", denied)
	}

	ok := resolvedUser(auth.NewGitHubUser("alice.x@example.com", []string{}))
	w = postAs(t, router, createTenantPath, map[string]string{"tenant_name": "fresh"}, ok)
	assertStatus(t, w, http.StatusAccepted)
	if len(exec.submittedParams) != 1 || exec.submittedParams[0]["creator_user_id"] != "alice.x@example.com" {
		t.Fatalf("a valid identity must still be submitted as itself, got %v", exec.submittedParams)
	}
}
