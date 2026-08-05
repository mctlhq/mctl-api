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

// Package temporalclient wires mctl-api into the dev-workflow control
// plane's Temporal deployment (plan phase 4) — a thin client to start and
// signal DevLoopWorkflow, whose definition and worker live in mctl-agents
// (orchestrator/temporal/). Temporal's default data converter is
// cross-language JSON, so nothing here needs to import Python types; it
// just has to encode/name things exactly the way the Python side expects.
package temporalclient

import (
	"context"
	"fmt"
	"regexp"

	"go.temporal.io/sdk/client"
)

const (
	// TaskQueue must match orchestrator/temporal/worker.py's TASK_QUEUE.
	TaskQueue = "mctl-dev-loop"
	// DevLoopWorkflowType is the workflow type name Temporal registers
	// orchestrator/temporal/workflows/dev_loop.py's DevLoopWorkflow under —
	// the class name, since that module's @workflow.defn does not override
	// it with an explicit name.
	DevLoopWorkflowType = "DevLoopWorkflow"
	// ApproveSignalName matches DevLoopWorkflow's @workflow.signal method
	// name (also un-overridden, so it's the method name "approve").
	ApproveSignalName = "approve"
)

var issueURLPattern = regexp.MustCompile(`^https://github\.com/mctlhq/([A-Za-z0-9_.-]+)/issues/([0-9]+)$`)

// Client wraps the Temporal SDK client with just the operations mctl-api
// needs: start a DevLoopWorkflow, signal its approval.
type Client struct {
	temporal client.Client
}

// New connects to the Temporal frontend. Mirrors the other optional-store
// init pattern in cmd/api/main.go (agentregistry.NewStore etc.) — callers
// are expected to log and continue with a nil *Client on error rather than
// fail startup, since the dev-loop trigger path is opt-in (use_temporal).
func New(hostPort, namespace string) (*Client, error) {
	c, err := client.Dial(client.Options{HostPort: hostPort, Namespace: namespace})
	if err != nil {
		return nil, fmt.Errorf("temporalclient: dial %s (namespace %s): %w", hostPort, namespace, err)
	}
	return &Client{temporal: c}, nil
}

func (c *Client) Close() {
	c.temporal.Close()
}

// issueRef mirrors orchestrator/temporal/workflows/dev_loop.py's IssueRef
// dataclass exactly — field name and JSON shape both matter, since the
// Python worker decodes this payload by field name.
type issueRef struct {
	IssueURL string `json:"issue_url"`
}

// WorkflowIDForIssueURL mirrors orchestrator/temporal/cli.py's
// _workflow_id_for: "dev-loop-{owner}-{repo}-{issue}", the format
// DevLoopWorkflow's own dedup relies on regardless of which side (this Go
// client or the Python CLI) started the run. Returns an error for anything
// that isn't a well-formed mctlhq GitHub issue URL — same validation the
// Python CLI applies before ever calling Temporal.
func WorkflowIDForIssueURL(issueURL string) (string, error) {
	m := issueURLPattern.FindStringSubmatch(issueURL)
	if m == nil {
		return "", fmt.Errorf("temporalclient: %q is not a well-formed mctlhq GitHub issue URL", issueURL)
	}
	repo, issueNumber := m[1], m[2]
	return fmt.Sprintf("dev-loop-mctlhq-%s-%s", repo, issueNumber), nil
}

// StartDevLoopWorkflow starts (or, on a matching workflow ID, no-ops
// against the already-running/completed) a DevLoopWorkflow run for one
// issue. Returns the workflow ID and run ID.
func (c *Client) StartDevLoopWorkflow(ctx context.Context, issueURL string) (workflowID, runID string, err error) {
	workflowID, err = WorkflowIDForIssueURL(issueURL)
	if err != nil {
		return "", "", err
	}
	run, err := c.temporal.ExecuteWorkflow(ctx, client.StartWorkflowOptions{
		ID:        workflowID,
		TaskQueue: TaskQueue,
	}, DevLoopWorkflowType, issueRef{IssueURL: issueURL})
	if err != nil {
		return "", "", fmt.Errorf("temporalclient: start workflow: %w", err)
	}
	return run.GetID(), run.GetRunID(), nil
}

// SignalApprove signals an already-running DevLoopWorkflow's approve
// handler — the durable "human flips it to accepted" step the plan
// describes, expressed as a Temporal signal instead of a gitops
// .status.yaml edit.
func (c *Client) SignalApprove(ctx context.Context, workflowID string) error {
	if err := c.temporal.SignalWorkflow(ctx, workflowID, "", ApproveSignalName, nil); err != nil {
		return fmt.Errorf("temporalclient: signal approve on %s: %w", workflowID, err)
	}
	return nil
}
