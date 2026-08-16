package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/operations"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type fakeStatusGetter struct {
	// phase keyed by workflow name; a missing key means NotFound.
	phase map[string]string
	// err, when set, is returned for every lookup instead.
	err error
	// calls records the (namespace, name) pairs asked for.
	calls []string
	// deadlineSeen records whether the caller passed a bounded context.
	deadlineSeen bool
}

func (f *fakeStatusGetter) GetWorkflowStatus(ctx context.Context, namespace, name string) (map[string]interface{}, error) {
	if _, ok := ctx.Deadline(); ok {
		f.deadlineSeen = true
	}
	f.calls = append(f.calls, namespace+"/"+name)
	if f.err != nil {
		return nil, f.err
	}
	p, ok := f.phase[name]
	if !ok {
		return nil, apierrors.NewNotFound(schema.GroupResource{Group: "argoproj.io", Resource: "workflows"}, name)
	}
	return map[string]interface{}{
		"metadata": map[string]interface{}{"name": name, "namespace": namespace},
		"status":   map[string]interface{}{"phase": p},
	}, nil
}

// submit records a deploy-service audit row aged by the given duration.
func submit(t *testing.T, log audit.Log, workflow, tenant string, age time.Duration) {
	t.Helper()
	log.Log(audit.Entry{
		Operation:    "deploy-service",
		WorkflowName: workflow,
		Parameters:   map[string]string{"team_name": tenant},
		Status:       "submitted",
		Timestamp:    time.Now().UTC().Add(-age),
	})
}

func newTestReconciler(log audit.Log, getter workflowStatusGetter) *auditReconciler {
	r := newAuditReconciler(log, getter, operations.NewRegistry())
	return r
}

func TestReconcileClosesTerminalPhases(t *testing.T) {
	for _, tc := range []struct {
		phase string
		want  string
	}{
		{"Succeeded", "succeeded"},
		{"Failed", "failed"},
		{"Error", "error"},
	} {
		t.Run(tc.phase, func(t *testing.T) {
			log := audit.NewLogger()
			submit(t, log, "wf-1", "labs", time.Minute)
			getter := &fakeStatusGetter{phase: map[string]string{"wf-1": tc.phase}}

			newTestReconciler(log, getter).reconcileOnce(context.Background())

			if got := log.GetByWorkflow("wf-1"); got.Status != tc.want {
				t.Errorf("status = %q, want %q", got.Status, tc.want)
			}
			if !getter.deadlineSeen {
				t.Error("workflow lookup ran on an unbounded context; one slow read would stall the pass")
			}
		})
	}
}

// deploy-service runs in the tenant namespace — that is the whole reason the
// reconciler exists, since the completion webhook never fires there.
func TestReconcileUsesTenantNamespace(t *testing.T) {
	log := audit.NewLogger()
	submit(t, log, "wf-ns", "labs", time.Minute)
	getter := &fakeStatusGetter{phase: map[string]string{"wf-ns": "Succeeded"}}

	newTestReconciler(log, getter).reconcileOnce(context.Background())

	if len(getter.calls) != 1 || getter.calls[0] != "labs/wf-ns" {
		t.Errorf("lookups = %v, want [labs/wf-ns]", getter.calls)
	}
}

func TestReconcileLeavesRunningAlone(t *testing.T) {
	log := audit.NewLogger()
	submit(t, log, "wf-running", "labs", time.Minute)
	getter := &fakeStatusGetter{phase: map[string]string{"wf-running": "Running"}}

	newTestReconciler(log, getter).reconcileOnce(context.Background())

	if got := log.GetByWorkflow("wf-running"); got.Status != "submitted" {
		t.Errorf("status = %q, want it left at \"submitted\"", got.Status)
	}
}

// Inside the grace period a missing workflow means "not created yet", not
// "gone". Closing it here would mark a live submission expired.
func TestReconcileNotFoundWithinGraceIsLeftAlone(t *testing.T) {
	log := audit.NewLogger()
	submit(t, log, "wf-young", "labs", time.Minute)
	getter := &fakeStatusGetter{phase: map[string]string{}}

	newTestReconciler(log, getter).reconcileOnce(context.Background())

	if got := log.GetByWorkflow("wf-young"); got.Status != "submitted" {
		t.Errorf("status = %q, want it left at \"submitted\"", got.Status)
	}
}

func TestReconcileNotFoundPastGraceExpires(t *testing.T) {
	log := audit.NewLogger()
	submit(t, log, "wf-old", "labs", 96*time.Hour)
	getter := &fakeStatusGetter{phase: map[string]string{}}

	newTestReconciler(log, getter).reconcileOnce(context.Background())

	got := log.GetByWorkflow("wf-old")
	if got.Status != "expired" {
		t.Errorf("status = %q, want %q", got.Status, "expired")
	}
	if got.Message == "" {
		t.Error("expired rows must say why")
	}
}

// A transport error is not evidence about the workflow. Leave the row for the
// next pass rather than guessing.
func TestReconcileTransportErrorLeavesRowOpen(t *testing.T) {
	log := audit.NewLogger()
	submit(t, log, "wf-err", "labs", 96*time.Hour)
	getter := &fakeStatusGetter{err: errors.New("connection refused")}

	newTestReconciler(log, getter).reconcileOnce(context.Background())

	if got := log.GetByWorkflow("wf-err"); got.Status != "submitted" {
		t.Errorf("status = %q, want it left at \"submitted\"", got.Status)
	}
}

// Without the operation the workflow's namespace cannot be derived, so there is
// nothing to look up.
func TestReconcileSkipsUnknownOperation(t *testing.T) {
	log := audit.NewLogger()
	log.Log(audit.Entry{
		Operation:    "operation-that-was-removed",
		WorkflowName: "wf-gone-op",
		Parameters:   map[string]string{"team_name": "labs"},
		Status:       "submitted",
	})
	getter := &fakeStatusGetter{phase: map[string]string{"wf-gone-op": "Succeeded"}}

	newTestReconciler(log, getter).reconcileOnce(context.Background())

	if len(getter.calls) != 0 {
		t.Errorf("looked up %v for an unknown operation", getter.calls)
	}
	if got := log.GetByWorkflow("wf-gone-op"); got.Status != "submitted" {
		t.Errorf("status = %q, want it untouched", got.Status)
	}
}

// A tenant-namespaced operation with no tenant recorded has no namespace to
// query.
func TestReconcileSkipsWhenNamespaceUnknown(t *testing.T) {
	log := audit.NewLogger()
	log.Log(audit.Entry{
		Operation:    "deploy-service",
		WorkflowName: "wf-no-team",
		Status:       "submitted",
	})
	getter := &fakeStatusGetter{phase: map[string]string{"wf-no-team": "Succeeded"}}

	newTestReconciler(log, getter).reconcileOnce(context.Background())

	if len(getter.calls) != 0 {
		t.Errorf("looked up %v with no tenant recorded", getter.calls)
	}
}

// Oldest-first: the queue drains from the old end, because an old submitted row
// is the one most likely to be genuinely stuck. With batch=1 the pass pages
// through all three, in age order.
func TestReconcileDrainsOldestFirst(t *testing.T) {
	log := audit.NewLogger()
	submit(t, log, "wf-oldest", "labs", 48*time.Hour)
	submit(t, log, "wf-middle", "labs", 24*time.Hour)
	submit(t, log, "wf-newest", "labs", time.Minute)

	getter := &fakeStatusGetter{phase: map[string]string{
		"wf-oldest": "Succeeded", "wf-middle": "Succeeded", "wf-newest": "Succeeded",
	}}
	r := newTestReconciler(log, getter)
	r.batch = 1

	r.reconcileOnce(context.Background())

	want := []string{"labs/wf-oldest", "labs/wf-middle", "labs/wf-newest"}
	if len(getter.calls) != len(want) {
		t.Fatalf("lookups = %v, want %v", getter.calls, want)
	}
	for i := range want {
		if getter.calls[i] != want[i] {
			t.Fatalf("lookups = %v, want %v (oldest first)", getter.calls, want)
		}
	}
}

// Rows outside the lookback are past any hope of resolution; rescanning them
// every pass forever is the failure mode lookback exists to prevent.
func TestReconcileIgnoresRowsOutsideLookback(t *testing.T) {
	log := audit.NewLogger()
	submit(t, log, "wf-ancient", "labs", 30*24*time.Hour)
	getter := &fakeStatusGetter{phase: map[string]string{}}

	newTestReconciler(log, getter).reconcileOnce(context.Background())

	if len(getter.calls) != 0 {
		t.Errorf("looked up %v outside the lookback window", getter.calls)
	}
}

func TestReconcileIgnoresAlreadyTerminalRows(t *testing.T) {
	log := audit.NewLogger()
	log.Log(audit.Entry{
		Operation:    "deploy-service",
		WorkflowName: "wf-done",
		Parameters:   map[string]string{"team_name": "labs"},
		Status:       "succeeded",
	})
	getter := &fakeStatusGetter{phase: map[string]string{"wf-done": "Failed"}}

	newTestReconciler(log, getter).reconcileOnce(context.Background())

	if len(getter.calls) != 0 {
		t.Errorf("looked up %v for an already-terminal row", getter.calls)
	}
	if got := log.GetByWorkflow("wf-done"); got.Status != "succeeded" {
		t.Errorf("status = %q, want it to stay %q", got.Status, "succeeded")
	}
}

// Head-of-line blocking: rows that cannot be resolved yet stay among the oldest
// forever. Without paging past them, a batch-sized clump of stuck rows would
// occupy every pass and no newer completed workflow would ever be closed.
func TestReconcilePagesPastUnresolvableRows(t *testing.T) {
	log := audit.NewLogger()
	// Two old rows that never resolve: still Running in Argo.
	submit(t, log, "wf-stuck-1", "labs", 48*time.Hour)
	submit(t, log, "wf-stuck-2", "labs", 47*time.Hour)
	// One newer row that is finished and should be closed this pass.
	submit(t, log, "wf-finished", "labs", time.Minute)

	getter := &fakeStatusGetter{phase: map[string]string{
		"wf-stuck-1":  "Running",
		"wf-stuck-2":  "Running",
		"wf-finished": "Succeeded",
	}}
	r := newTestReconciler(log, getter)
	r.batch = 2 // both stuck rows fill the first page exactly

	r.reconcileOnce(context.Background())

	if got := log.GetByWorkflow("wf-finished"); got.Status != "succeeded" {
		t.Errorf("newer finished row = %q, want %q — the pass never got past the stuck rows",
			got.Status, "succeeded")
	}
	for _, w := range []string{"wf-stuck-1", "wf-stuck-2"} {
		if got := log.GetByWorkflow(w); got.Status != "submitted" {
			t.Errorf("%s = %q, want it left at \"submitted\"", w, got.Status)
		}
	}
}

// maxPerPass has to bound the paging, or a large backlog turns one tick into an
// unbounded walk.
func TestReconcileRespectsMaxPerPass(t *testing.T) {
	log := audit.NewLogger()
	phases := map[string]string{}
	for i := 0; i < 10; i++ {
		name := "wf-" + string(rune('a'+i))
		submit(t, log, name, "labs", time.Duration(100-i)*time.Hour/10)
		phases[name] = "Running"
	}
	getter := &fakeStatusGetter{phase: phases}
	r := newTestReconciler(log, getter)
	r.batch = 2
	r.maxPerPass = 4

	r.reconcileOnce(context.Background())

	if len(getter.calls) != 4 {
		t.Errorf("examined %d rows, want maxPerPass=4", len(getter.calls))
	}
}
