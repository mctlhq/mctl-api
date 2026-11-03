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
	k8stesting "k8s.io/client-go/testing"
)

// Executor.Submit is the choke point every caller shares: it refuses an
// investigate run without an execution_id before it touches the cluster.
func TestSubmit_InvestigateWithoutExecutionIsRefused(t *testing.T) {
	op, ok := NewRegistry().Get(InvestigateOperation)
	if !ok {
		t.Fatal("investigate operation missing")
	}
	e := &Executor{submitCreatesExecution: true}
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
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{workflowGVR: "WorkflowList"})
	e := &Executor{dynamicClient: dyn, submitCreatesExecution: true}
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
	_, err := (&Executor{}).Submit(context.Background(), op,
		map[string]string{"issue_url": "https://github.com/mctlhq/mctl-api/issues/1"}, "u", "platform")
	if err == nil || errors.Is(err, ErrExecutionRequired) {
		t.Errorf("err = %v, want the missing-client failure, not a refusal", err)
	}
}

func TestParseSubmitCreatesExecution(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{{"", false}, {"off", false}, {"OFF", false}, {"on", true}, {" On ", true}} {
		if got, err := ParseSubmitCreatesExecution(tc.in); err != nil || got != tc.want {
			t.Errorf("%q = %v, %v; want %v", tc.in, got, err, tc.want)
		}
	}
	for _, bad := range []string{"true", "1", "yes", "enabled"} {
		if _, err := ParseSubmitCreatesExecution(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// Failures raised before the Workflow create call are marked so the caller
// may end the execution; a create failure is not (it may have been accepted).
func TestSubmit_NotCreatedMarking(t *testing.T) {
	op, _ := NewRegistry().Get(InvestigateOperation)
	params := map[string]string{"issue_url": "https://github.com/mctlhq/mctl-api/issues/1", "execution_id": "we_x"}
	_, err := (&Executor{submitCreatesExecution: true}).Submit(context.Background(), op, params, "u", "platform")
	if !IsNotCreated(err) {
		t.Errorf("no client: %v not marked", err)
	}
	_, err = (&Executor{submitCreatesExecution: true}).Submit(context.Background(), op, map[string]string{"issue_url": params["issue_url"]}, "u", "platform")
	if !IsNotCreated(err) || !errors.Is(err, ErrExecutionRequired) {
		t.Errorf("backstop refusal %v not marked or not ErrExecutionRequired", err)
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{workflowGVR: "WorkflowList"})
	dyn.PrependReactor("create", "workflows", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("timeout")
	})
	_, err = (&Executor{dynamicClient: dyn}).Submit(context.Background(), op, params, "u", "platform")
	if err == nil || IsNotCreated(err) {
		t.Errorf("create failure %v must not be marked", err)
	}
}
