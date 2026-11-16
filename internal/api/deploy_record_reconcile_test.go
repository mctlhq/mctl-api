package api

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/deployplan"
	"github.com/mctlhq/mctl-api/internal/operations"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// reconcileStore keeps the real store's write conditions: status moves once
// out of submitting, a run result once and only on a submitted record.
type reconcileStore struct {
	recs    []*deployplan.Record
	listErr error
	// results are the SetRunResult calls made, id=result.
	results []string
}

func (s *reconcileStore) RecordsToReconcile(_ context.Context, since, afterCreated time.Time, afterID string, limit int) ([]*deployplan.Record, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	var out []*deployplan.Record
	for _, r := range s.recs {
		open := (r.Status == deployplan.RecordSubmitting && r.WorkflowRef != "") || (r.Status == deployplan.RecordSubmitted && r.RunResult == "")
		after := r.CreatedAt.After(afterCreated) || (r.CreatedAt.Equal(afterCreated) && r.ID > afterID)
		if open && r.CreatedAt.After(since) && after && len(out) < limit {
			c := *r
			out = append(out, &c)
		}
	}
	return out, nil
}

func (s *reconcileStore) find(id string) *deployplan.Record {
	for _, r := range s.recs {
		if r.ID == id {
			return r
		}
	}
	return nil
}

func (s *reconcileStore) SetRecordSubmission(_ context.Context, id, status, workflow string) (*deployplan.Record, error) {
	r := s.find(id)
	if r == nil || r.Status != deployplan.RecordSubmitting {
		return nil, errors.New("not awaiting submission")
	}
	if status == deployplan.RecordSubmitted && workflow != r.WorkflowRef {
		return nil, errors.New("workflow differs from its ref")
	}
	r.Status, r.Workflow = status, workflow
	return r, nil
}

func (s *reconcileStore) SetRunResult(_ context.Context, id, result, digest string) (*deployplan.Record, error) {
	s.results = append(s.results, id+"="+result)
	r := s.find(id)
	if r == nil || r.Status != deployplan.RecordSubmitted || r.RunResult != "" {
		return nil, errors.New("not awaiting a run result")
	}
	r.RunResult = result
	if r.ImageDigest == "" {
		r.ImageDigest = digest
	}
	return r, nil
}

type outcomeExec struct {
	byName map[string]*operations.WorkflowOutcome
	err    error
	asked  []string
}

func (e *outcomeExec) GetWorkflowOutcome(_ context.Context, ns, name string) (*operations.WorkflowOutcome, error) {
	e.asked = append(e.asked, ns+"/"+name)
	if e.err != nil {
		return nil, e.err
	}
	if o, ok := e.byName[name]; ok {
		return o, nil
	}
	return nil, apierrors.NewNotFound(schema.GroupResource{Group: "argoproj.io", Resource: "workflows"}, name)
}

var recNow = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)

func newRec(id, status, ref string, age time.Duration) *deployplan.Record {
	r := &deployplan.Record{ID: id, Tenant: "acme", Status: status, WorkflowRef: ref, Health: deployplan.HealthUnknown, CreatedAt: recNow.Add(-age)}
	if status == deployplan.RecordSubmitted {
		r.Workflow = ref
	}
	return r
}

func testReconciler(store *reconcileStore, exec *outcomeExec) *deployRecordReconciler {
	r := newDeployRecordReconciler(store, exec, operations.Operation{Name: "preview-deploy", WorkflowTemplate: "preview-deploy"})
	r.now = func() time.Time { return recNow }
	return r
}

var goodDigest = "sha256:" + strings.Repeat("c", 64)

func TestDeployRecordReconcile(t *testing.T) {
	store := &reconcileStore{recs: []*deployplan.Record{
		newRec("dep_1", deployplan.RecordSubmitting, "wf-1", 2*time.Minute),  // seen running: submitted, no result yet
		newRec("dep_2", deployplan.RecordSubmitting, "wf-2", 2*time.Minute),  // absent, too young: untouched
		newRec("dep_3", deployplan.RecordSubmitting, "wf-3", 20*time.Minute), // absent long enough: submit_failed
		newRec("dep_4", deployplan.RecordSubmitting, "wf-4", 80*time.Hour),   // absent past GC grace: proves nothing
		newRec("dep_5", deployplan.RecordSubmitted, "wf-5", time.Hour),       // succeeded with a digest
		newRec("dep_6", deployplan.RecordSubmitted, "wf-6", time.Hour),       // failed
		newRec("dep_7", deployplan.RecordSubmitted, "wf-7", time.Hour),       // succeeded, malformed digest
		newRec("dep_8", deployplan.RecordSubmitted, "wf-8", time.Hour),       // collected before seen
		newRec("dep_9", deployplan.RecordSubmitting, "wf-9", 2*time.Minute),  // seen finished: submitted and its result in one pass
		newRec("dep_10", deployplan.RecordSubmitted, "wf-10", time.Hour),     // unknown phase
	}}
	exec := &outcomeExec{byName: map[string]*operations.WorkflowOutcome{
		"wf-1":  {Phase: "Running", Outputs: map[string]string{}},
		"wf-5":  {Phase: "Succeeded", Outputs: map[string]string{"image_digest": goodDigest}},
		"wf-6":  {Phase: "Failed", Outputs: map[string]string{"image_digest": goodDigest}},
		"wf-7":  {Phase: "Succeeded", Outputs: map[string]string{"image_digest": "latest"}},
		"wf-9":  {Phase: "Error", Outputs: map[string]string{}},
		"wf-10": {Phase: "", Outputs: map[string]string{}},
	}}
	testReconciler(store, exec).reconcileOnce(context.Background())

	want := map[string][3]string{ // status, run result, digest
		"dep_1":  {"submitted", "", ""},
		"dep_2":  {"submitting", "", ""},
		"dep_3":  {"submit_failed", "", ""},
		"dep_4":  {"submitting", "", ""},
		"dep_5":  {"submitted", "succeeded", goodDigest},
		"dep_6":  {"submitted", "failed", ""},
		"dep_7":  {"submitted", "succeeded", ""},
		"dep_8":  {"submitted", "", ""},
		"dep_9":  {"submitted", "failed", ""},
		"dep_10": {"submitted", "", ""},
	}
	for id, w := range want {
		r := store.find(id)
		if got := [3]string{r.Status, r.RunResult, r.ImageDigest}; got != w {
			t.Errorf("%s = %v, want %v", id, got, w)
		}
		if r.Status == deployplan.RecordSubmitted && r.Workflow != r.WorkflowRef {
			t.Errorf("%s submitted as %q, ref %q", id, r.Workflow, r.WorkflowRef)
		}
	}
	// Only finished runs get a result write; running or unknown ones none.
	if len(store.results) != 4 {
		t.Errorf("run result writes = %v, want one each for dep_5, dep_6, dep_7, dep_9", store.results)
	}
	if exec.asked[0] != "acme/wf-1" {
		t.Errorf("looked up %v: the workflow lives in the tenant's namespace", exec.asked[0])
	}
}

// An Argo that cannot be read changes nothing, however old the record: an
// unreadable workflow is not an absent one.
func TestDeployRecordReconcile_UnreadableArgoChangesNothing(t *testing.T) {
	store := &reconcileStore{recs: []*deployplan.Record{
		newRec("dep_1", deployplan.RecordSubmitting, "wf-1", 20*time.Minute),
		newRec("dep_2", deployplan.RecordSubmitted, "wf-2", time.Hour),
	}}
	exec := &outcomeExec{err: apierrors.NewForbidden(schema.GroupResource{Resource: "workflows"}, "wf", errors.New("rbac"))}
	testReconciler(store, exec).reconcileOnce(context.Background())
	if r := store.find("dep_1"); r.Status != deployplan.RecordSubmitting {
		t.Fatalf("an unreadable Argo failed a submit: %+v", r)
	}
	if r := store.find("dep_2"); r.RunResult != "" {
		t.Fatalf("an unreadable Argo recorded a result: %+v", r)
	}
	store.listErr = errors.New("db down")
	exec.err, exec.asked = nil, nil
	testReconciler(store, exec).reconcileOnce(context.Background())
	if len(exec.asked) != 0 {
		t.Fatalf("looked up workflows without a queue: %v", exec.asked)
	}
}

// Records that cannot be resolved yet (still running) stay at the head of
// the queue; paging must still reach the finished ones behind them.
func TestDeployRecordReconcile_Pages(t *testing.T) {
	store := &reconcileStore{}
	exec := &outcomeExec{byName: map[string]*operations.WorkflowOutcome{}}
	for i := 0; i < 7; i++ {
		id := "dep_" + string(rune('a'+i))
		store.recs = append(store.recs, newRec(id, deployplan.RecordSubmitted, "wf-"+id, time.Hour))
		phase := "Succeeded"
		if i < 4 {
			phase = "Running"
		}
		exec.byName["wf-"+id] = &operations.WorkflowOutcome{Phase: phase, Outputs: map[string]string{}}
	}
	r := testReconciler(store, exec)
	r.batch, r.maxPerPass = 3, 9
	r.reconcileOnce(context.Background())
	for _, rec := range store.recs[4:] {
		if rec.RunResult != deployplan.RunSucceeded {
			t.Fatalf("%s not reached behind running records", rec.ID)
		}
	}
}
