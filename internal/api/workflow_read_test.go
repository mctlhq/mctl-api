package api_test

import (
	"net/http"
	"testing"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/operations"
)

func TestGetWorkflowDeleteTenantSafeUsesArgoWorkflowsNamespace(t *testing.T) {
	logger := audit.NewLogger()
	logger.Log(audit.Entry{
		UserID:       "test-admin",
		Operation:    "delete-tenant-safe",
		Parameters:   map[string]string{"tenant_name": "tests"},
		WorkflowName: "delete-tenant-safe-abc123",
		Status:       "submitted",
	})

	router := mctlapi.NewRouter(mctlapi.Options{
		Registry:  operations.NewRegistry(),
		GitReader: &fakeGitReader{},
		ArgoCD:    &fakeArgoCD{apps: map[string]*argocd.AppStatus{}},
		AuditLog:  logger,
		Executor:  &fakeExecutor{},
	})

	w := getAs(t, router, "/api/v1/workflows/delete-tenant-safe-abc123", adminUser)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if body["namespace"] != "argo-workflows" {
		t.Fatalf("expected namespace argo-workflows, got %v", body["namespace"])
	}
}
