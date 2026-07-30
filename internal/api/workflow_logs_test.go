package api_test

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/argoarchive"
	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// fakeLogArchive stands in for the object store holding archived Argo step
// logs. GetStep is called concurrently by the handler for multi-step
// requests, so its mutable state is mutex-guarded.
type fakeLogArchive struct {
	steps   []argoarchive.StepLog
	bodies  map[string]string
	listErr error
	getErr  error

	mu       sync.Mutex
	lastTail int
	getCalls int
}

func (f *fakeLogArchive) ListSteps(_ context.Context, _ string) ([]argoarchive.StepLog, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.steps, nil
}

func (f *fakeLogArchive) GetStep(_ context.Context, key string, tailLines int) (string, error) {
	f.mu.Lock()
	f.lastTail = tailLines
	f.getCalls++
	f.mu.Unlock()
	if f.getErr != nil {
		return "", f.getErr
	}
	return f.bodies[key], nil
}

// archiveOfFailedPoll mirrors the real 2026-07-30 issue-poll failure: the
// run-poller step is absent because its pod never started.
func archiveOfFailedPoll() *fakeLogArchive {
	return &fakeLogArchive{
		steps: []argoarchive.StepLog{
			{Step: "clone-gitops-733206375", Pod: "wf-1-clone-gitops-733206375", Key: "k1", Size: 333},
			{Step: "notify-telegram-4116628385", Pod: "wf-1-notify-telegram-4116628385", Key: "k2", Size: 36},
		},
		bodies: map[string]string{
			"k1": "✓ gitops cloned",
			"k2": "telegram http=200\nincident http=401",
		},
	}
}

func logsRouter(archive mctlapi.WorkflowLogArchive, logger audit.Log) http.Handler {
	if logger == nil {
		logger = audit.NewLogger()
	}
	return mctlapi.NewRouter(mctlapi.Options{
		Registry:           operations.NewRegistry(),
		GitReader:          &fakeGitReader{},
		ArgoCD:             &fakeArgoCD{apps: map[string]*argocd.AppStatus{}},
		AuditLog:           logger,
		Executor:           &fakeExecutor{},
		WorkflowLogArchive: archive,
	})
}

func TestGetWorkflowLogsListsSteps(t *testing.T) {
	router := logsRouter(archiveOfFailedPoll(), nil)

	w := getAs(t, router, "/api/v1/workflows/wf-1/logs", adminUser)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}

	raw := w.Body.String()
	body := decodeJSON(t, w)
	if body["count"] != float64(2) {
		t.Errorf("count = %v, want 2", body["count"])
	}
	// The absent run-poller step is the whole diagnosis; make sure the
	// listing is returned verbatim rather than being filtered.
	if !strings.Contains(raw, "clone-gitops") || !strings.Contains(raw, "notify-telegram") {
		t.Errorf("listing did not include both steps: %s", raw)
	}
}

func TestGetWorkflowLogsReturnsStepBody(t *testing.T) {
	archive := archiveOfFailedPoll()
	router := logsRouter(archive, nil)

	w := getAs(t, router, "/api/v1/workflows/wf-1/logs?step=notify-telegram&lines=50", adminUser)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}

	if !strings.Contains(w.Body.String(), "incident http=401") {
		t.Errorf("step body missing: %s", w.Body.String())
	}
	if archive.lastTail != 50 {
		t.Errorf("lines param not forwarded: got %d, want 50", archive.lastTail)
	}
}

func TestGetWorkflowLogsRejectsOutOfRangeLines(t *testing.T) {
	archive := archiveOfFailedPoll()
	router := logsRouter(archive, nil)

	getAs(t, router, "/api/v1/workflows/wf-1/logs?step=notify&lines=99999", adminUser)
	if archive.lastTail != 100 {
		t.Errorf("out-of-range lines should fall back to 100, got %d", archive.lastTail)
	}
}

// Regression: multi-step reads used to fetch serially, each bounded only by
// the archive client's own 30s timeout, which could exceed the route's
// request deadline. Confirms a filter matching several steps still returns
// every body (run with -race to catch any shared-state issue in the
// concurrent fetch).
func TestGetWorkflowLogsFetchesMultipleMatchesConcurrently(t *testing.T) {
	archive := &fakeLogArchive{
		steps: []argoarchive.StepLog{
			{Step: "run-poller-1", Pod: "wf-2-run-poller-1", Key: "k1"},
			{Step: "run-poller-2", Pod: "wf-2-run-poller-2", Key: "k2"},
			{Step: "run-poller-3", Pod: "wf-2-run-poller-3", Key: "k3"},
		},
		bodies: map[string]string{
			"k1": "poller one",
			"k2": "poller two",
			"k3": "poller three",
		},
	}
	router := logsRouter(archive, nil)

	w := getAs(t, router, "/api/v1/workflows/wf-2/logs?step=run-poller", adminUser)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}

	raw := w.Body.String()
	for _, want := range []string{"poller one", "poller two", "poller three"} {
		if !strings.Contains(raw, want) {
			t.Errorf("response missing %q: %s", want, raw)
		}
	}
	archive.mu.Lock()
	defer archive.mu.Unlock()
	if archive.getCalls != 3 {
		t.Errorf("expected 3 GetStep calls, got %d", archive.getCalls)
	}
}

func TestGetWorkflowLogsUnmatchedStepListsAvailable(t *testing.T) {
	router := logsRouter(archiveOfFailedPoll(), nil)

	w := getAs(t, router, "/api/v1/workflows/wf-1/logs?step=run-poller", adminUser)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	note, _ := body["note"].(string)
	// Naming what IS archived is what turns "no match" into the finding
	// that the step never ran.
	if !strings.Contains(note, "clone-gitops") || !strings.Contains(note, "notify-telegram") {
		t.Errorf("note should list archived steps, got %q", note)
	}
}

func TestGetWorkflowLogsCronWorkflowIsAdminOnly(t *testing.T) {
	// No audit entry — the state of every cron-driven run.
	router := logsRouter(archiveOfFailedPoll(), nil)

	tenantUser := &auth.User{ID: "dev", Groups: []string{"labs"}}
	w := getAs(t, router, "/api/v1/workflows/mctl-agents-issue-poll-1/logs", tenantUser)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin, got %d: %s", w.Code, w.Body.String())
	}

	w = getAs(t, router, "/api/v1/workflows/mctl-agents-issue-poll-1/logs", adminUser)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for admin, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetWorkflowLogsTeamScoping(t *testing.T) {
	logger := audit.NewLogger()
	logger.Log(audit.Entry{
		UserID:       "someone",
		Operation:    "deploy-service",
		Parameters:   map[string]string{"team_name": "admins"},
		WorkflowName: "deploy-service-xyz",
		Status:       "submitted",
	})
	router := logsRouter(archiveOfFailedPoll(), logger)

	foreign := &auth.User{ID: "dev", Groups: []string{"labs"}}
	if w := getAs(t, router, "/api/v1/workflows/deploy-service-xyz/logs", foreign); w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 across teams, got %d: %s", w.Code, w.Body.String())
	}

	owner := &auth.User{ID: "dev", Groups: []string{"admins"}}
	if w := getAs(t, router, "/api/v1/workflows/deploy-service-xyz/logs", owner); w.Code != http.StatusOK {
		t.Fatalf("owning team should be allowed, got %d: %s", w.Code, w.Body.String())
	}
}

// A workflow whose audit entry carries no team is an AdminOnly
// platform-scoped operation; its logs must not fall open to any
// authenticated user (GetWorkflow's status endpoint tolerates this, the
// log endpoint deliberately does not).
func TestGetWorkflowLogsTeamlessAuditEntryIsAdminOnly(t *testing.T) {
	logger := audit.NewLogger()
	logger.Log(audit.Entry{
		UserID:       "test-admin",
		Operation:    "platform-skill-publish",
		WorkflowName: "platform-skill-publish-abc",
		Status:       "submitted",
	})
	router := logsRouter(archiveOfFailedPoll(), logger)

	someUser := &auth.User{ID: "dev", Groups: []string{"labs"}}
	if w := getAs(t, router, "/api/v1/workflows/platform-skill-publish-abc/logs", someUser); w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for a team-less workflow, got %d: %s", w.Code, w.Body.String())
	}
	if w := getAs(t, router, "/api/v1/workflows/platform-skill-publish-abc/logs", adminUser); w.Code != http.StatusOK {
		t.Fatalf("admin should be allowed, got %d", w.Code)
	}
}

func TestGetWorkflowLogsWithoutArchiveConfigured(t *testing.T) {
	router := logsRouter(nil, nil)

	w := getAs(t, router, "/api/v1/workflows/wf-1/logs", adminUser)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	note, _ := body["note"].(string)
	if !strings.Contains(note, "ARGO_LOGS_R2_ENDPOINT") {
		t.Errorf("note should name the missing configuration, got %q", note)
	}
}

func TestGetWorkflowLogsEmptyArchiveExplainsWhy(t *testing.T) {
	router := logsRouter(&fakeLogArchive{}, nil)

	w := getAs(t, router, "/api/v1/workflows/ancient-wf/logs", adminUser)
	body := decodeJSON(t, w)
	note, _ := body["note"].(string)
	if !strings.Contains(note, "retention") {
		t.Errorf("empty result should explain retention, got %q", note)
	}
}

func TestGetWorkflowLogsSurfacesArchiveError(t *testing.T) {
	router := logsRouter(&fakeLogArchive{listErr: errArchiveDown}, nil)

	w := getAs(t, router, "/api/v1/workflows/wf-1/logs", adminUser)
	body := decodeJSON(t, w)
	note, _ := body["note"].(string)
	// A credentials/endpoint failure must not be mistaken for "no logs".
	if !strings.Contains(note, "archive down") {
		t.Errorf("archive error not surfaced, got %q", note)
	}
}

var errArchiveDown = &archiveError{"archive down"}

type archiveError struct{ msg string }

func (e *archiveError) Error() string { return e.msg }
