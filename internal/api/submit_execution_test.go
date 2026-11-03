package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

const investigatePath = "/api/v1/operations/mctl-agents-investigate/execute"

// recordingExecutor behaves like Executor.Submit as far as naming goes: the
// workflow is called <template>-<request id from the context>.
type recordingExecutor struct {
	fakeExecutor
	err error
}

func (e *recordingExecutor) Submit(ctx context.Context, op operations.Operation, params map[string]string, userID, ns string) (*operations.SubmitResult, error) {
	if _, err := e.fakeExecutor.Submit(ctx, op, params, userID, ns); err != nil {
		return nil, err
	}
	if e.err != nil {
		return nil, e.err
	}
	id, ok := operations.WorkflowRequestIDFrom(ctx)
	if !ok {
		id = "deadbeef"
	}
	return &operations.SubmitResult{WorkflowName: operations.WorkflowNameFor(op, id), Namespace: ns, RequestID: id, Status: "Pending"}, nil
}

type submitEnv struct {
	t      *testing.T
	router http.Handler
	store  *workitems.Store
	exec   *recordingExecutor
	tenant string
}

func newSubmitEnv(t *testing.T, withStore bool) *submitEnv {
	t.Helper()
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed submit test")
	}
	ctx := context.Background()
	store, err := workitems.NewStore(ctx, connStr)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	tenant := fmt.Sprintf("sx-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		if pool, err := pgxpool.New(ctx, connStr); err == nil {
			_, _ = pool.Exec(ctx, `DELETE FROM work_items WHERE tenant LIKE $1`, tenant+"%")
			pool.Close()
		}
		store.Close()
	})
	e := &submitEnv{t: t, store: store, exec: &recordingExecutor{}, tenant: tenant}
	opts := mctlapi.Options{
		Registry: operations.NewRegistry(), GitReader: &fakeGitReader{}, AuditLog: audit.NewLogger(),
		Executor: e.exec, IssueWorkItemTenant: tenant,
	}
	if withStore {
		opts.WorkItems = store
	}
	e.router = mctlapi.NewRouter(opts)
	return e
}

type submitResp struct {
	Workflow    operations.SubmitResult `json:"workflow"`
	WorkItemID  string                  `json:"work_item_id"`
	ExecutionID string                  `json:"execution_id"`
}

func (e *submitEnv) post(in map[string]string) (*submitResp, int, string) {
	e.t.Helper()
	w := postAs(e.t, e.router, investigatePath, in, adminUser)
	var r submitResp
	_ = json.Unmarshal(w.Body.Bytes(), &r)
	return &r, w.Code, w.Body.String()
}

func (e *submitEnv) execs(item string) []workitems.Execution {
	e.t.Helper()
	x, err := e.store.Executions(context.Background(), item)
	if err != nil {
		e.t.Fatal(err)
	}
	return x
}

func (e *submitEnv) lastParams() map[string]string {
	e.t.Helper()
	if len(e.exec.submittedParams) == 0 {
		e.t.Fatal("nothing was submitted")
	}
	return e.exec.submittedParams[len(e.exec.submittedParams)-1]
}

// The legacy shape: no execution_id, no work_item_id. The execution is
// created first, recorded under the workflow's own name, and passed on.
func TestInvestigateSubmit_CreatesExecutionFirst(t *testing.T) {
	e := newSubmitEnv(t, true)
	r, code, body := e.post(map[string]string{"issue_url": "https://github.com/mctlhq/mctl-api/issues/0042"})
	if code != http.StatusAccepted {
		t.Fatalf("status %d: %s", code, body)
	}
	if !strings.HasPrefix(r.ExecutionID, "we_") || !strings.HasPrefix(r.WorkItemID, "wi_") {
		t.Fatalf("response ids = %q %q", r.WorkItemID, r.ExecutionID)
	}
	p := e.lastParams()
	if p["execution_id"] != r.ExecutionID || p["work_item_id"] != r.WorkItemID {
		t.Errorf("submitted params %v do not carry the created ids", p)
	}
	item, err := e.store.Get(context.Background(), r.WorkItemID)
	if err != nil {
		t.Fatal(err)
	}
	if item.Tenant != e.tenant || item.ExternalKey != "https://github.com/mctlhq/mctl-api/issues/42" {
		t.Errorf("item = tenant %q key %q", item.Tenant, item.ExternalKey)
	}
	xs := e.execs(r.WorkItemID)
	if len(xs) != 1 || xs[0].ID != r.ExecutionID || xs[0].Engine != workitems.EngineArgo ||
		xs[0].EngineRef != r.Workflow.WorkflowName || xs[0].Phase != workitems.PhasePending {
		t.Errorf("executions = %+v, want one Pending argo execution named %s", xs, r.Workflow.WorkflowName)
	}
}

// A second trigger for the same issue joins the open item once the first
// execution has ended, instead of opening another item.
func TestInvestigateSubmit_SameIssueSameItemAfterRunEnds(t *testing.T) {
	e := newSubmitEnv(t, true)
	in := map[string]string{"issue_url": "https://github.com/mctlhq/mctl-api/issues/7"}
	first, _, _ := e.post(in)
	// While the first run is open, a second trigger is refused, not duplicated.
	if _, code, body := e.post(in); code != http.StatusConflict || !strings.Contains(body, "execution_active") {
		t.Fatalf("second trigger while open: %d %s", code, body)
	}
	if n := len(e.exec.submitted); n != 1 {
		t.Fatalf("%d workflows submitted, want 1", n)
	}
	_, _, err := e.store.AttachExecution(context.Background(), workitems.ExecutionInput{
		Mutation: workitems.Mutation{Actor: "service:test"}, WorkItemID: first.WorkItemID,
		Engine: workitems.EngineArgo, EngineRef: first.Workflow.WorkflowName, Phase: workitems.PhaseSucceeded,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, code, body := e.post(in)
	if code != http.StatusAccepted || second.WorkItemID != first.WorkItemID || second.ExecutionID == first.ExecutionID {
		t.Fatalf("second run: %d %s (want same item, new execution)", code, body)
	}
}

// A caller that resumes a work item names it; the execution goes on that item.
func TestInvestigateSubmit_AttachesToNamedWorkItem(t *testing.T) {
	e := newSubmitEnv(t, true)
	item, _, err := e.store.Create(context.Background(), workitems.CreateInput{
		Mutation: workitems.Mutation{Actor: "service:test"}, Tenant: e.tenant, Visibility: workitems.VisibilityTenant,
		OriginSurface: "api", Title: "resume me", ExternalKey: "https://github.com/mctlhq/mctl-api/issues/9",
	})
	if err != nil {
		t.Fatal(err)
	}
	r, code, body := e.post(map[string]string{"issue_url": "https://github.com/mctlhq/mctl-api/issues/9", "work_item_id": item.ID})
	if code != http.StatusAccepted || r.WorkItemID != item.ID {
		t.Fatalf("%d %s", code, body)
	}
	if xs := e.execs(item.ID); len(xs) != 1 || xs[0].ID != r.ExecutionID {
		t.Errorf("executions = %+v", xs)
	}
}

// The DevLoop path already names its execution: nothing is created, and the
// ids reach the workflow untouched.
func TestInvestigateSubmit_CallerExecutionPassesThrough(t *testing.T) {
	e := newSubmitEnv(t, true)
	_, code, body := e.post(map[string]string{
		"issue_url": "https://github.com/mctlhq/mctl-api/issues/5", "work_item_id": "wi_given", "execution_id": "we_given",
	})
	if code != http.StatusAccepted {
		t.Fatalf("%d %s", code, body)
	}
	if p := e.lastParams(); p["execution_id"] != "we_given" || p["work_item_id"] != "wi_given" {
		t.Errorf("params = %v", p)
	}
	items, err := e.store.List(context.Background(), workitems.ListFilter{Tenants: []string{e.tenant}})
	if err != nil || len(items) != 0 {
		t.Errorf("items = %v, err %v; the caller's execution must create nothing", items, err)
	}
}

// If the execution cannot be created the run is not submitted at all.
func TestInvestigateSubmit_NoStoreMeansNoSubmit(t *testing.T) {
	e := newSubmitEnv(t, false)
	_, code, body := e.post(map[string]string{"issue_url": "https://github.com/mctlhq/mctl-api/issues/5"})
	if code != http.StatusServiceUnavailable {
		t.Fatalf("%d %s", code, body)
	}
	if len(e.exec.submitted) != 0 {
		t.Fatalf("submitted %v without an execution", e.exec.submitted)
	}
}

func TestInvestigateSubmit_UnknownWorkItemMeansNoSubmit(t *testing.T) {
	e := newSubmitEnv(t, true)
	_, code, body := e.post(map[string]string{"issue_url": "https://github.com/mctlhq/mctl-api/issues/5", "work_item_id": "wi_missing"})
	if code != http.StatusNotFound {
		t.Fatalf("%d %s", code, body)
	}
	if len(e.exec.submitted) != 0 {
		t.Fatalf("submitted %v", e.exec.submitted)
	}
}

// A workflow that fails to start does not leave its execution open: that
// would block the work item's next run.
func TestInvestigateSubmit_FailedSubmitEndsTheExecution(t *testing.T) {
	e := newSubmitEnv(t, true)
	e.exec.err = errors.New("argo is down")
	_, code, body := e.post(map[string]string{"issue_url": "https://github.com/mctlhq/mctl-api/issues/11"})
	if code != http.StatusInternalServerError {
		t.Fatalf("%d %s", code, body)
	}
	items, err := e.store.List(context.Background(), workitems.ListFilter{Tenants: []string{e.tenant}})
	if err != nil || len(items) != 1 {
		t.Fatalf("items = %v, err %v", items, err)
	}
	xs := e.execs(items[0].ID)
	if len(xs) != 1 || xs[0].Phase != workitems.PhaseError {
		t.Fatalf("executions = %+v, want one in phase Error", xs)
	}
	e.exec.err = nil
	if _, code, body := e.post(map[string]string{"issue_url": "https://github.com/mctlhq/mctl-api/issues/11"}); code != http.StatusAccepted {
		t.Errorf("retry after a failed submit: %d %s", code, body)
	}
}

// Other operations are untouched: they need no execution and get none.
func TestExecute_OtherOperationsCreateNoExecution(t *testing.T) {
	e := newSubmitEnv(t, true)
	w := postAs(t, e.router, "/api/v1/operations/mctl-agents-implement/execute",
		map[string]string{"service": "mctl-api"}, adminUser)
	if w.Code != http.StatusAccepted && w.Code != http.StatusBadRequest {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	items, _ := e.store.List(context.Background(), workitems.ListFilter{Tenants: []string{e.tenant}})
	if len(items) != 0 {
		t.Errorf("items = %v", items)
	}
}
