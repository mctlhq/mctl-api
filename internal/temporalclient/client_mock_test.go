// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package temporalclient

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/api/serviceerror"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/mocks"
)

// fakeWorkflowRun is a minimal client.WorkflowRun — the SDK ships no
// exported concrete type for tests to construct directly.
type fakeWorkflowRun struct {
	id, runID string
}

func (f *fakeWorkflowRun) GetID() string                          { return f.id }
func (f *fakeWorkflowRun) GetRunID() string                       { return f.runID }
func (f *fakeWorkflowRun) Get(context.Context, interface{}) error { return nil }
func (f *fakeWorkflowRun) GetWithOptions(context.Context, interface{}, client.WorkflowRunGetOptions) error {
	return nil
}

func TestStartDevLoopWorkflow_UsesComputedIDAndTaskQueue(t *testing.T) {
	mockClient := new(mocks.Client)
	mockClient.On("ExecuteWorkflow", mock.Anything, mock.MatchedBy(func(opts client.StartWorkflowOptions) bool {
		return opts.ID == "dev-loop-mctlhq-mctl-telegram-296" && opts.TaskQueue == TaskQueue
	}), DevLoopWorkflowType, mock.MatchedBy(func(arg issueRef) bool {
		return arg.IssueURL == "https://github.com/mctlhq/mctl-telegram/issues/296"
	})).Return(&fakeWorkflowRun{id: "dev-loop-mctlhq-mctl-telegram-296", runID: "run-1"}, nil)

	c := &Client{temporal: mockClient}
	workflowID, runID, err := c.StartDevLoopWorkflow(context.Background(), "https://github.com/mctlhq/mctl-telegram/issues/296")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if workflowID != "dev-loop-mctlhq-mctl-telegram-296" || runID != "run-1" {
		t.Fatalf("got workflowID=%q runID=%q", workflowID, runID)
	}
	mockClient.AssertExpectations(t)
}

func TestStartDevLoopWorkflow_RejectsMalformedIssueURLWithoutCallingTemporal(t *testing.T) {
	mockClient := new(mocks.Client) // no .On(...) set up — a call would fail the test
	c := &Client{temporal: mockClient}

	_, _, err := c.StartDevLoopWorkflow(context.Background(), "not-a-github-issue-url")
	if err == nil {
		t.Fatal("expected an error for a malformed issue URL")
	}
	if !errors.Is(err, ErrInvalidIssueURL) {
		t.Fatalf("expected ErrInvalidIssueURL so handlers can map it to 400, got %v", err)
	}
	mockClient.AssertNotCalled(t, "ExecuteWorkflow", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestStartDevLoopWorkflow_TrueNoOpOnMatchingWorkflowID(t *testing.T) {
	// REJECT_DUPLICATE + USE_EXISTING is what makes a repeated start against
	// the same issue a real no-op (return the existing run) instead of the
	// SDK default (fresh run once the prior one closed, error if still
	// running) — see the docstring on StartDevLoopWorkflow.
	mockClient := new(mocks.Client)
	mockClient.On("ExecuteWorkflow", mock.Anything, mock.MatchedBy(func(opts client.StartWorkflowOptions) bool {
		return opts.WorkflowIDReusePolicy == enumspb.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE &&
			opts.WorkflowIDConflictPolicy == enumspb.WORKFLOW_ID_CONFLICT_POLICY_USE_EXISTING
	}), DevLoopWorkflowType, mock.Anything).
		Return(&fakeWorkflowRun{id: "dev-loop-mctlhq-mctl-telegram-296", runID: "run-1"}, nil)

	c := &Client{temporal: mockClient}
	if _, _, err := c.StartDevLoopWorkflow(context.Background(), "https://github.com/mctlhq/mctl-telegram/issues/296"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mockClient.AssertExpectations(t)
}

func TestStartDevLoopWorkflow_TemporalRPCFailureIsNotErrInvalidIssueURL(t *testing.T) {
	// Handlers use errors.Is(err, ErrInvalidIssueURL) to pick 400 vs 502 —
	// an RPC failure on a perfectly valid URL must NOT match that sentinel.
	mockClient := new(mocks.Client)
	mockClient.On("ExecuteWorkflow", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil, serviceerror.NewUnavailable("temporal frontend unreachable"))

	c := &Client{temporal: mockClient}
	_, _, err := c.StartDevLoopWorkflow(context.Background(), "https://github.com/mctlhq/mctl-telegram/issues/296")
	if err == nil {
		t.Fatal("expected an error")
	}
	if errors.Is(err, ErrInvalidIssueURL) {
		t.Fatal("a Temporal RPC failure must not be mistaken for ErrInvalidIssueURL")
	}
}

func TestSignalApprove_SignalsCorrectWorkflowAndSignalName(t *testing.T) {
	mockClient := new(mocks.Client)
	mockClient.On("SignalWorkflow", mock.Anything, "dev-loop-mctlhq-mctl-telegram-296", "", ApproveSignalName, nil).
		Return(nil)

	c := &Client{temporal: mockClient}
	if err := c.SignalApprove(context.Background(), "dev-loop-mctlhq-mctl-telegram-296"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mockClient.AssertExpectations(t)
}

func TestSignalApprove_UnknownWorkflowIsDetectableViaIsNotFound(t *testing.T) {
	mockClient := new(mocks.Client)
	mockClient.On("SignalWorkflow", mock.Anything, "dev-loop-mctlhq-mctl-telegram-999", "", ApproveSignalName, nil).
		Return(serviceerror.NewNotFound("workflow not found"))

	c := &Client{temporal: mockClient}
	err := c.SignalApprove(context.Background(), "dev-loop-mctlhq-mctl-telegram-999")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !IsNotFound(err) {
		t.Fatalf("expected IsNotFound(err) to be true so handlers can map it to 404, got %v", err)
	}
}

func TestSignalApprove_OtherFailuresAreNotIsNotFound(t *testing.T) {
	mockClient := new(mocks.Client)
	mockClient.On("SignalWorkflow", mock.Anything, "dev-loop-mctlhq-mctl-telegram-1", "", ApproveSignalName, nil).
		Return(serviceerror.NewUnavailable("temporal frontend unreachable"))

	c := &Client{temporal: mockClient}
	err := c.SignalApprove(context.Background(), "dev-loop-mctlhq-mctl-telegram-1")
	if IsNotFound(err) {
		t.Fatal("an Unavailable error must not be mistaken for NotFound")
	}
}
