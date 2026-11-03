package api

import (
	"context"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/mctlhq/mctl-api/internal/workitems"
)

type ctxKey struct{}

// lookupRecorder is a WorkflowExecutor whose lookup reports the workflow
// absent and records the value it saw on its context.
type lookupRecorder struct {
	WorkflowExecutor
	saw any
}

func (l *lookupRecorder) GetWorkflowStatus(ctx context.Context, _, name string) (map[string]interface{}, error) {
	l.saw = ctx.Value(ctxKey{})
	return nil, apierrors.NewNotFound(schema.GroupResource{Group: "argoproj.io", Resource: "workflows"}, name)
}

// The cleanup after a failed submit runs on the request's values (trace span,
// log attributes) but outlives its cancellation.
func TestSubmitExecutionEnded_KeepsRequestValuesAndSurvivesCancel(t *testing.T) {
	env := newWorkItemsEnv(t)
	ctx := context.Background()
	m := workitems.Mutation{Actor: "service:test"}
	item, _, err := env.h.opts.WorkItems.Create(ctx, workitems.CreateInput{
		Mutation: m, Tenant: env.tenant, Visibility: workitems.VisibilityTenant, OriginSurface: "api", Title: "t",
	})
	if err != nil {
		t.Fatal(err)
	}
	exec, _, err := env.h.opts.WorkItems.AttachExecution(ctx, workitems.ExecutionInput{
		Mutation: m, WorkItemID: item.ID, Engine: workitems.EngineArgo, EngineRef: "wf-ctx", Phase: workitems.PhasePending,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := &lookupRecorder{}
	env.h.opts.Executor = rec

	reqCtx, cancel := context.WithCancel(context.WithValue(ctx, ctxKey{}, "span-1"))
	cancel() // the request is already gone
	se := &submitExecution{h: env.h, item: item.ID, exec: exec.ID, ref: "wf-ctx", mut: m, namespace: "ns", reqCtx: reqCtx}
	if note := se.ended(nil, context.DeadlineExceeded); note != "" {
		t.Fatalf("note = %q, want the execution ended cleanly", note)
	}
	if rec.saw != "span-1" {
		t.Errorf("lookup context lost the request's values: %v", rec.saw)
	}
	xs, err := env.h.opts.WorkItems.Executions(ctx, item.ID)
	if err != nil || len(xs) != 1 || xs[0].Phase != workitems.PhaseError {
		t.Errorf("executions = %+v, err %v; want one in Error", xs, err)
	}
}
