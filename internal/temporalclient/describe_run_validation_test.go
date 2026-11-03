package temporalclient

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	commonpb "go.temporal.io/api/common/v1"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/api/serviceerror"
	workflowpb "go.temporal.io/api/workflow/v1"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/mocks"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// DescribeDevLoopRun: a run id is passed through (including ""), the status
// and start time are mapped, ErrRunNotFound is returned ONLY for NotFound.
func TestDescribeDevLoopRun_Validation(t *testing.T) {
	started := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	for _, runID := range []string{"", "run-1"} {
		m := new(mocks.Client)
		m.On("DescribeWorkflowExecution", mock.Anything, "wf", runID).Return(&workflowservice.DescribeWorkflowExecutionResponse{
			WorkflowExecutionInfo: &workflowpb.WorkflowExecutionInfo{
				Execution: &commonpb.WorkflowExecution{WorkflowId: "wf", RunId: "run-1"},
				Status:    enumspb.WORKFLOW_EXECUTION_STATUS_CONTINUED_AS_NEW,
				StartTime: timestamppb.New(started),
			}}, nil)
		d, err := (&Client{temporal: m}).DescribeDevLoopRun(context.Background(), "wf", runID)
		if err != nil || d.Status != "ContinuedAsNew" || d.RunID != "run-1" || !d.StartTime.Equal(started) {
			t.Fatalf("run %q = %+v %v", runID, d, err)
		}
		m.AssertExpectations(t)
	}

	nf := new(mocks.Client)
	nf.On("DescribeWorkflowExecution", mock.Anything, "wf", "gone").Return(nil, serviceerror.NewNotFound("no such run"))
	if _, err := (&Client{temporal: nf}).DescribeDevLoopRun(context.Background(), "wf", "gone"); !errors.Is(err, ErrRunNotFound) {
		t.Fatalf("not found = %v", err)
	}
	for name, cause := range map[string]error{
		"unavailable": serviceerror.NewUnavailable("down"),
		"deadline":    context.DeadlineExceeded,
		"namespace":   serviceerror.NewNamespaceNotFound("ns"),
		"perm denied": serviceerror.NewPermissionDenied("no", ""),
		"plain":       errors.New("boom"),
	} {
		m := new(mocks.Client)
		m.On("DescribeWorkflowExecution", mock.Anything, "wf", "r").Return(nil, cause)
		d, err := (&Client{temporal: m}).DescribeDevLoopRun(context.Background(), "wf", "r")
		if err == nil || errors.Is(err, ErrRunNotFound) || d != nil {
			t.Errorf("%s: %+v %v must be a plain error, never ErrRunNotFound", name, d, err)
		}
	}
}
