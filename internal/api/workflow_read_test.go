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

// TestListAgentRunsMergesOperatorAndCron pins the cron-visibility fix
// from B6 G1 (~/.claude/plans/mctl-agents-daily-cron-visibility.md):
// the audit log used to be the only source, hiding scheduled cron-
// driven runs and producing a false "agent system idle" reading
// during the 2026-05-07 incident triage.
func TestListAgentRunsMergesOperatorAndCron(t *testing.T) {
	logger := audit.NewLogger()
	// One operator-initiated run, deliberately the OLDER timestamp.
	logger.Log(audit.Entry{
		UserID:       "test-admin",
		Operation:    "mctl-agents-implement",
		WorkflowName: "mctl-agents-implement-old",
		Status:       "submitted",
	})

	exec := &fakeExecutor{
		// Two cron-driven runs, both NEWER than the operator entry.
		// Sorted output should put cron-newest first.
		cronAgentRuns: []map[string]interface{}{
			{
				"workflowName": "mctl-agents-daily-1778047200",
				"operation":    "mctl-agents-daily",
				"status":       "succeeded",
				"user":         "cron",
				"timestamp":    "2099-01-01T06:00:00Z",
				"riskLevel":    "low",
				"source":       "cron",
			},
			{
				"workflowName": "mctl-agents-shepherd-1777999999",
				"operation":    "mctl-agents-shepherd",
				"status":       "succeeded",
				"user":         "cron",
				"timestamp":    "2098-12-31T23:30:00Z",
				"riskLevel":    "low",
				"source":       "cron",
			},
		},
	}

	router := mctlapi.NewRouter(mctlapi.Options{
		Registry:  operations.NewRegistry(),
		GitReader: &fakeGitReader{},
		ArgoCD:    &fakeArgoCD{apps: map[string]*argocd.AppStatus{}},
		AuditLog:  logger,
		Executor:  exec,
	})

	w := getAs(t, router, "/api/v1/agent-runs", adminUser)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	items, ok := body["items"].([]interface{})
	if !ok {
		t.Fatalf("items not an array: %v", body["items"])
	}
	if len(items) != 3 {
		t.Fatalf("expected 3 items (1 operator + 2 cron), got %d", len(items))
	}
	first := items[0].(map[string]interface{})
	if first["source"] != "cron" || first["workflowName"] != "mctl-agents-daily-1778047200" {
		t.Errorf("expected newest cron run first, got source=%v name=%v",
			first["source"], first["workflowName"])
	}
	last := items[2].(map[string]interface{})
	if last["source"] != "operator" || last["workflowName"] != "mctl-agents-implement-old" {
		t.Errorf("expected oldest operator run last, got source=%v name=%v",
			last["source"], last["workflowName"])
	}
}
