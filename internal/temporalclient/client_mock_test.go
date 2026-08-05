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
	"testing"

	"github.com/stretchr/testify/mock"
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
	mockClient.AssertNotCalled(t, "ExecuteWorkflow", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
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
