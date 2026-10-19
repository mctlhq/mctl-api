package api_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/principals"
)

func TestCreateTenantSignupGateCannotBeBypassedThroughOperations(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	ctx := context.Background()
	store, err := principals.NewStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	githubID := fmt.Sprint(time.Now().UnixNano())
	principal, err := store.Provision(ctx, auth.Identity{Provider: auth.ProviderGitHub, Subject: githubID, Display: "budget-customer", Kind: auth.KindHuman})
	if err != nil {
		t.Fatal(err)
	}
	user := auth.NewGitHubUser("budget-customer", nil)
	if err := auth.AttachPrincipal(ctx, creatorPrincipal(principal.ID), user); err != nil {
		t.Fatal(err)
	}
	signup := &mctlapi.SignupOptions{Store: store, Cohort: map[string]bool{}}
	log := audit.NewLogger()
	exec := &fakeExecutor{}
	reader := &fakeGitReader{tenants: []gitops.Tenant{}}
	router := mctlapi.NewRouter(mctlapi.Options{Registry: operations.NewRegistry(), GitReader: reader, AuditLog: log, Executor: exec, Signup: signup})
	body := map[string]string{"tenant_name": "budget-team", "workspace_profile": "starter", "quota_cpu_lim": "16", "quota_memory_lim": "16Gi"}
	denied := postAs(t, router, createTenantPath, body, user)
	assertStatus(t, denied, http.StatusConflict)
	if len(exec.submitted) != 0 {
		t.Fatal("uninvited customer submitted a workflow")
	}
	foundDenial := false
	for _, entry := range log.List(100) {
		if entry.Operation == "create-tenant" && entry.Status == "denied" {
			foundDenial = true
		}
	}
	if !foundDenial {
		t.Fatal("admission refusal was not audited")
	}

	signup.Cohort[githubID] = true
	acceptedCohort := postAs(t, router, createTenantPath, map[string]string{"tenant_name": "pilot-team"}, user)
	assertStatus(t, acceptedCohort, http.StatusAccepted)
	delete(signup.Cohort, githubID)
	acceptedAdmin := postAs(t, router, createTenantPath, map[string]string{"tenant_name": "admin-team"}, resolvedAdmin)
	assertStatus(t, acceptedAdmin, http.StatusAccepted)

	request := principals.SignupRequest{ID: uuid.NewString(), CreatedAt: time.Now().UTC(), Name: "Test", Email: "test@example.com", GitHub: "budget-customer", Project: "Test"}
	t.Cleanup(func() {
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = conn.Close(ctx) }()
		if _, err := conn.Exec(ctx, `DELETE FROM signup_requests WHERE id=$1`, request.ID); err != nil {
			t.Error(err)
		}
	})
	if err := store.SetSignupCapacity(ctx, 1, "admin", "Reviewed test resource capacity"); err != nil {
		t.Fatal(err)
	}
	if err := store.ImportSignup(ctx, request); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DecideSignup(ctx, request.ID, "approved", githubID, "budget-customer", "admin", "Welcome"); err != nil {
		t.Fatal(err)
	}
	reader.tenants = []gitops.Tenant{{Name: "budget"}}
	collision := postAs(t, router, createTenantPath, body, user)
	assertStatus(t, collision, http.StatusBadRequest)
	saved, err := store.Signup(ctx, request.ID)
	if err != nil || saved.Status != "approved" || saved.Tenant != "" {
		t.Fatalf("known refusal pinned a claim: %+v %v", saved, err)
	}
	reader.tenants = []gitops.Tenant{}
	defaults := postAs(t, router, createTenantPath, map[string]string{"tenant_name": "budget-team"}, user)
	assertStatus(t, defaults, http.StatusConflict)
	if !strings.Contains(defaults.Body.String(), "workspace_profile=starter") {
		t.Fatalf("missing actionable profile guidance: %s", defaults.Body.String())
	}
	accepted := postAs(t, router, createTenantPath, body, user)
	assertStatus(t, accepted, http.StatusAccepted)
	last := exec.submittedParams[len(exec.submittedParams)-1]
	if last["workspace_profile"] != "starter" || last["quota_memory_req"] != "512Mi" || last["quota_memory_lim"] != "1Gi" || last["quota_cpu_lim"] != "1" {
		t.Fatalf("caller enlarged starter profile: %+v", last)
	}
	if len(exec.submitted) != 3 {
		t.Fatalf("submitted %d, expected pilot, admin and funded customer", len(exec.submitted))
	}
	capacity, err := store.SignupCapacity(ctx)
	if err != nil || capacity.Used != 1 {
		t.Fatalf("capacity %+v %v", capacity, err)
	}
}
