package operations

import (
	"context"
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

// Executor.Submit is the choke point every caller shares: it refuses an
// investigate run without an execution_id before it touches the cluster.
func TestSubmit_InvestigateWithoutExecutionIsRefused(t *testing.T) {
	t.Setenv(SubmitCreatesExecutionEnv, "on")
	op, ok := NewRegistry().Get(InvestigateOperation)
	if !ok {
		t.Fatal("investigate operation missing")
	}
	e := &Executor{}
	for _, params := range []map[string]string{
		{"issue_url": "https://github.com/mctlhq/mctl-api/issues/1"},
		{"issue_url": "https://github.com/mctlhq/mctl-api/issues/1", "execution_id": "  "},
	} {
		_, err := e.Submit(context.Background(), op, params, "u", "platform")
		if !errors.Is(err, ErrExecutionRequired) {
			t.Errorf("Submit(%v) err = %v, want ErrExecutionRequired", params, err)
		}
	}
	// With an execution it gets past the check (and stops at the missing client).
	_, err := e.Submit(context.Background(), op, map[string]string{
		"issue_url": "https://github.com/mctlhq/mctl-api/issues/1", "execution_id": "we_x",
	}, "u", "platform")
	if err == nil || errors.Is(err, ErrExecutionRequired) {
		t.Errorf("err = %v, want a failure other than ErrExecutionRequired", err)
	}
}

func TestWorkflowRequestIDFrom_AcceptsOnlyGeneratedShape(t *testing.T) {
	ctx := WithWorkflowRequestID(context.Background(), NewWorkflowRequestID())
	if _, ok := WorkflowRequestIDFrom(ctx); !ok {
		t.Error("a generated id was refused")
	}
	for _, bad := range []string{"", "x", "ABCDEF12", "abc/defg", "0123456789"} {
		if _, ok := WorkflowRequestIDFrom(WithWorkflowRequestID(context.Background(), bad)); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

// The workflow is named after the request id the caller recorded its
// execution under, and the execution_id reaches the workflow's arguments.
func TestSubmit_NamesWorkflowAfterPresetRequestID(t *testing.T) {
	t.Setenv(SubmitCreatesExecutionEnv, "on")
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{workflowGVR: "WorkflowList"})
	e := &Executor{dynamicClient: dyn}
	op, _ := NewRegistry().Get(InvestigateOperation)
	ctx := WithWorkflowRequestID(context.Background(), "0a1b2c3d")
	res, err := e.Submit(ctx, op, map[string]string{
		"issue_url": "https://github.com/mctlhq/mctl-api/issues/1", "execution_id": "we_x",
	}, "u", "platform")
	if err != nil {
		t.Fatal(err)
	}
	if want := "mctl-agents-investigate-0a1b2c3d"; res.WorkflowName != want || res.RequestID != "0a1b2c3d" {
		t.Errorf("workflow %q request %q, want %q", res.WorkflowName, res.RequestID, want)
	}
	wf, err := dyn.Resource(workflowGVR).Namespace(res.Namespace).Get(ctx, res.WorkflowName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	params, _, _ := unstructured.NestedSlice(wf.Object, "spec", "arguments", "parameters")
	found := false
	for _, p := range params {
		if m, _ := p.(map[string]any); m["name"] == "execution_id" && m["value"] == "we_x" {
			found = true
		}
	}
	if !found {
		t.Errorf("execution_id not in workflow arguments: %v", params)
	}
}

// Switch off (default): the backstop does not exist, id-less submits are as before.
func TestSubmit_SwitchOffDoesNotRefuse(t *testing.T) {
	op, _ := NewRegistry().Get(InvestigateOperation)
	for _, v := range []string{"", "off"} {
		t.Setenv(SubmitCreatesExecutionEnv, v)
		_, err := (&Executor{}).Submit(context.Background(), op,
			map[string]string{"issue_url": "https://github.com/mctlhq/mctl-api/issues/1"}, "u", "platform")
		if err == nil || errors.Is(err, ErrExecutionRequired) {
			t.Errorf("value %q: err = %v, want the missing-client failure, not a refusal", v, err)
		}
	}
}

func TestSubmitCreatesExecution_ParsesStrictly(t *testing.T) {
	for v, want := range map[string]bool{"": false, "off": false, "OFF": false, "on": true, " On ": true} {
		t.Setenv(SubmitCreatesExecutionEnv, v)
		if got, err := SubmitCreatesExecution(); err != nil || got != want {
			t.Errorf("%q = %v, %v; want %v", v, got, err, want)
		}
	}
	t.Setenv(SubmitCreatesExecutionEnv, "true")
	if _, err := SubmitCreatesExecution(); err == nil {
		t.Error("true accepted")
	}
}
