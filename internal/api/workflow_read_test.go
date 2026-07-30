package api_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
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

// Regression: cron-driven runs (mctl-agents-issue-poll, -implement, -run,
// -shepherd, ...) are spawned directly by Argo's CronWorkflow controller and
// never enter the audit log, since only operator-initiated REST submissions
// do. GetWorkflow used to 404 all of these outright; it must now fall back
// to a live k8s lookup in the argo-workflows namespace for admins.
func TestGetWorkflowFallsBackToLiveLookupForCronRuns(t *testing.T) {
	router := mctlapi.NewRouter(mctlapi.Options{
		Registry:  operations.NewRegistry(),
		GitReader: &fakeGitReader{},
		ArgoCD:    &fakeArgoCD{apps: map[string]*argocd.AppStatus{}},
		AuditLog:  audit.NewLogger(),
		Executor:  &fakeExecutor{},
	})

	w := getAs(t, router, "/api/v1/workflows/mctl-agents-issue-poll-1785399300", adminUser)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	if body["namespace"] != "argo-workflows" {
		t.Errorf("namespace = %v, want argo-workflows", body["namespace"])
	}
	if _, ok := body["live"]; !ok {
		t.Errorf("expected a live status block, got %v", body)
	}
	if _, ok := body["audit"]; ok {
		t.Errorf("should not fabricate an audit entry, got %v", body["audit"])
	}
}

// A non-admin must not get the fallback: without an audit entry there is no
// team to check access against, so absence must still 404 for anyone who
// isn't an admin (mirrors GetWorkflowLogs's team-less gate).
func TestGetWorkflowFallbackIsAdminOnly(t *testing.T) {
	router := mctlapi.NewRouter(mctlapi.Options{
		Registry:  operations.NewRegistry(),
		GitReader: &fakeGitReader{},
		ArgoCD:    &fakeArgoCD{apps: map[string]*argocd.AppStatus{}},
		AuditLog:  audit.NewLogger(),
		Executor:  &fakeExecutor{},
	})

	tenantUser := &auth.User{ID: "dev", Groups: []string{"labs"}}
	w := getAs(t, router, "/api/v1/workflows/mctl-agents-issue-poll-1785399300", tenantUser)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for non-admin with no audit entry, got %d: %s", w.Code, w.Body.String())
	}
}

// When the fallback k8s lookup also fails (the workflow has aged out, or the
// name is simply wrong), the response must still be a 404 rather than a
// live-status response with a nil body.
func TestGetWorkflowFallbackSurfaces404WhenLiveLookupFails(t *testing.T) {
	group := schema.GroupResource{Group: "argoproj.io", Resource: "workflows"}
	router := mctlapi.NewRouter(mctlapi.Options{
		Registry:  operations.NewRegistry(),
		GitReader: &fakeGitReader{},
		ArgoCD:    &fakeArgoCD{apps: map[string]*argocd.AppStatus{}},
		AuditLog:  audit.NewLogger(),
		Executor:  &fakeExecutor{getWorkflowStatusErr: apierrors.NewNotFound(group, "nope")},
	})

	w := getAs(t, router, "/api/v1/workflows/totally-unknown-workflow", adminUser)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

// Regression for review P3 on #121: a cluster-side failure (RBAC denied, API
// server unreachable, timeout) must not read as "no such workflow" — that
// misleads an admin triaging a live incident into thinking a workflow never
// ran when the real story is "couldn't ask the cluster."
func TestGetWorkflowFallbackSurfaces502OnClusterError(t *testing.T) {
	router := mctlapi.NewRouter(mctlapi.Options{
		Registry:  operations.NewRegistry(),
		GitReader: &fakeGitReader{},
		ArgoCD:    &fakeArgoCD{apps: map[string]*argocd.AppStatus{}},
		AuditLog:  audit.NewLogger(),
		Executor:  &fakeExecutor{getWorkflowStatusErr: errors.New("Get \"https://k8s/apis/argoproj.io/v1alpha1/namespaces/argo-workflows/workflows/x\": context deadline exceeded")},
	})

	w := getAs(t, router, "/api/v1/workflows/some-cron-run", adminUser)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 for a non-NotFound cluster error, got %d: %s", w.Code, w.Body.String())
	}
}

// Regression for the same P3, on the audit-fallback path: when a workflow
// has an audit entry but the live lookup fails with something other than
// NotFound, the degraded 200 response's note must say so rather than
// implying the workflow is simply gone.
func TestGetWorkflowAuditFallbackNoteDistinguishesClusterError(t *testing.T) {
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
		Executor:  &fakeExecutor{getWorkflowStatusErr: errors.New("connection refused")},
	})

	w := getAs(t, router, "/api/v1/workflows/delete-tenant-safe-abc123", adminUser)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (audit fallback), got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	note, _ := body["note"].(string)
	if !strings.Contains(note, "not confirmed missing") {
		t.Errorf("expected note to distinguish a cluster-side error from absence, got: %q", note)
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
