package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/operations"
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

// The reasons are in "error" itself, not only in validationErrors: the MCP
// tools' doRequest reads only "error", so mctl_create_tenant would otherwise
// report a bare "validation failed".
func TestCreateTenant_ReservedNameReasonIsInErrorField(t *testing.T) {
	router, _ := createTenantRouter(t, &fakeGitReader{})
	w := postAs(t, router, createTenantPath, map[string]string{"tenant_name": "kube-system"}, newcomer)
	assertStatus(t, w, http.StatusBadRequest)
	var body struct {
		Error            string   `json:"error"`
		ValidationErrors []string `json:"validationErrors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(body.Error, "validation failed") || !strings.Contains(body.Error, "reserved") {
		t.Errorf("error = %q, want the validation failed prefix and the reserved reason", body.Error)
	}
	if len(body.ValidationErrors) != 1 || !strings.Contains(body.ValidationErrors[0], "reserved") {
		t.Errorf("validationErrors = %v", body.ValidationErrors)
	}
}

// refusingExecutor stands in for an Executor whose Submit-level backstop
// fires. Reaching it through the handler needs a name ValidateInput lets by,
// so this pins only the status mapping.
type refusingExecutor struct{ fakeExecutor }

func (refusingExecutor) Submit(_ context.Context, _ operations.Operation, _ map[string]string, _, _ string) (*operations.SubmitResult, error) {
	return nil, fmt.Errorf("submit: %w", operations.ErrReservedTenantName)
}

func TestCreateTenant_SubmitBackstopMapsTo400(t *testing.T) {
	router := mctlapi.NewRouter(mctlapi.Options{
		Registry:  operations.NewRegistry(),
		GitReader: &fakeGitReader{tenants: []gitops.Tenant{}},
		AuditLog:  audit.NewLogger(),
		Executor:  &refusingExecutor{},
	})
	w := postAs(t, router, createTenantPath, map[string]string{"tenant_name": "fresh"}, newcomer)
	assertStatus(t, w, http.StatusBadRequest)
}
