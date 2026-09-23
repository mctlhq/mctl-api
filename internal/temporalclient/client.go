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
	"errors"
	"fmt"
	"regexp"
	"strings"

	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/api/serviceerror"
	"go.temporal.io/sdk/client"
)

// ErrInvalidIssueURL marks a caller-input validation failure (malformed
// issue_url), as opposed to a Temporal RPC/connectivity failure — callers
// use errors.Is against this to pick an HTTP status: 400 for this, 502/503
// for everything else StartDevLoopWorkflow can return.
var ErrInvalidIssueURL = errors.New("temporalclient: not a well-formed mctlhq GitHub issue URL")

// ErrNoDevLoopForProposalRef marks a well-formed proposal_ref whose slug
// carries no `issue-<N>-` prefix — incident-*, and everything from before the
// Temporal migration. Those proposals NEVER had a DevLoopWorkflow, so this is
// an ANSWER: a caller comparing mechanisms may record "no live DevLoop" on it.
var ErrNoDevLoopForProposalRef = errors.New("temporalclient: proposal ref names no DevLoopWorkflow")

// ErrMalformedProposalRef marks a proposal_ref this code could not read at all
// — no service part, an empty service, an empty slug.
//
// Separate from the sentinel above, and the separation is the point: both
// mean "no workflow id", but only one of them means "no workflow". Reporting
// an unreadable ref as "nobody is driving this entity" is the fold this whole
// contract exists to undo, and it fails in the unsafe direction.
var ErrMalformedProposalRef = errors.New("temporalclient: malformed proposal ref")

const (
	// TaskQueue must match orchestrator/temporal/worker.py's TASK_QUEUE.
	TaskQueue = "mctl-dev-loop"
	// DevLoopWorkflowType is the workflow type name Temporal registers
	// orchestrator/temporal/workflows/dev_loop.py's DevLoopWorkflow under —
	// the class name, since that module's @workflow.defn does not override
	// it with an explicit name.
	DevLoopWorkflowType = "DevLoopWorkflow" //nolint:gosec // a Temporal workflow type name, not a credential
	// ApproveSignalName matches DevLoopWorkflow's @workflow.signal method
	// name (also un-overridden, so it's the method name "approve").
	ApproveSignalName = "approve"
)

var issueURLPattern = regexp.MustCompile(`^https://github\.com/mctlhq/([A-Za-z0-9_.-]+)/issues/([0-9]+)$`)

// proposalSlugPattern mirrors run_shepherd.py's `re.match(r"issue-(\d+)-", slug)`
// — a PREFIX match, trailing hyphen included, so `issue-42-add-a-thing` matches
// and `issue-42` alone does not.
var proposalSlugPattern = regexp.MustCompile(`^issue-([0-9]+)-`)

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
		return "", fmt.Errorf("%w: %q", ErrInvalidIssueURL, issueURL)
	}
	repo, issueNumber := m[1], m[2]
	return fmt.Sprintf("dev-loop-mctlhq-%s-%s", repo, issueNumber), nil
}

// WorkflowIDForProposalRef derives a DevLoopWorkflow id from the
// `proposal_ref` a lifecycle ownership record carries.
//
// DevLoopWorkflow writes `proposal_ref = f"{service}/{slug}"` on every acquire
// (orchestrator/temporal/workflows/dev_loop.py), which is the whole reason the
// legacy answer needs no extra input: the workflow id is reconstructible from
// the stored record alone, with no GitHub call and no second index.
//
// The owner is hardcoded `mctlhq` for the same reason run_shepherd.py hardcodes
// it: a proposal ref carries no repo owner, every proposal lives under this org
// today, and a wrong owner would only produce a NotFound — which this caller
// already reads as "no live DevLoop".
//
// The two failure sentinels are NOT interchangeable and callers must tell them
// apart: ErrNoDevLoopForProposalRef is an answer ("this proposal never had
// one"), ErrMalformedProposalRef is an absence ("this ref could not be read").
func WorkflowIDForProposalRef(proposalRef string) (string, error) {
	service, slug, ok := strings.Cut(proposalRef, "/")
	if !ok || service == "" || slug == "" {
		return "", fmt.Errorf("%w: %q", ErrMalformedProposalRef, proposalRef)
	}
	m := proposalSlugPattern.FindStringSubmatch(slug)
	if m == nil {
		return "", fmt.Errorf("%w: %q", ErrNoDevLoopForProposalRef, proposalRef)
	}
	return fmt.Sprintf("dev-loop-mctlhq-%s-%s", service, m[1]), nil
}

// StartDevLoopWorkflow starts a DevLoopWorkflow run for one issue, or on a
// matching workflow ID, truly no-ops: WorkflowIDReusePolicy REJECT_DUPLICATE
// plus WorkflowIDConflictPolicy USE_EXISTING mean a closed prior run is not
// restarted and a running prior run is not errored on — both return that
// same run's ID/run ID instead. (The Temporal default policies would
// otherwise start a fresh run once the prior one closes, or error while one
// is still running — mirror any change here in orchestrator/temporal/cli.py's
// _connect/start, which uses the SDK default today.) Returns the workflow ID
// and run ID.
func (c *Client) StartDevLoopWorkflow(ctx context.Context, issueURL string) (workflowID, runID string, err error) {
	workflowID, err = WorkflowIDForIssueURL(issueURL)
	if err != nil {
		return "", "", err
	}
	run, err := c.temporal.ExecuteWorkflow(ctx, client.StartWorkflowOptions{
		ID:                       workflowID,
		TaskQueue:                TaskQueue,
		WorkflowIDReusePolicy:    enumspb.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE,
		WorkflowIDConflictPolicy: enumspb.WORKFLOW_ID_CONFLICT_POLICY_USE_EXISTING,
	}, DevLoopWorkflowType, issueRef{IssueURL: issueURL})
	if err != nil {
		return "", "", fmt.Errorf("temporalclient: start workflow: %w", err)
	}
	return run.GetID(), run.GetRunID(), nil
}

// SignalApprove signals an already-running DevLoopWorkflow's approve
// handler — the durable "human flips it to accepted" step the plan
// describes, expressed as a Temporal signal instead of a gitops
// .status.yaml edit. payload carries approver provenance
// ({"approver": ..., "reason": ...}); nil/empty sends a bare signal,
// which the workflow's defensive approve() parser also accepts.
func (c *Client) SignalApprove(ctx context.Context, workflowID string, payload map[string]string) error {
	var arg interface{}
	if len(payload) > 0 {
		arg = payload
	}
	if err := c.temporal.SignalWorkflow(ctx, workflowID, "", ApproveSignalName, arg); err != nil {
		return fmt.Errorf("temporalclient: signal approve on %s: %w", workflowID, err)
	}
	return nil
}

// DescribeDevLoop returns the execution status of the DevLoopWorkflow with
// the given workflow ID — the liveness read the shepherd sweeper uses to
// skip proposals a live DevLoop already drives (mctl-agents#213). The
// status string is Temporal's WORKFLOW_EXECUTION_STATUS_* short name, e.g.
// "Running", "Completed", "Failed", "TimedOut", "Terminated".
func (c *Client) DescribeDevLoop(ctx context.Context, workflowID string) (string, error) {
	resp, err := c.temporal.DescribeWorkflowExecution(ctx, workflowID, "")
	if err != nil {
		return "", fmt.Errorf("temporalclient: describe %s: %w", workflowID, err)
	}
	switch resp.GetWorkflowExecutionInfo().GetStatus() {
	case enumspb.WORKFLOW_EXECUTION_STATUS_RUNNING:
		return "Running", nil
	case enumspb.WORKFLOW_EXECUTION_STATUS_COMPLETED:
		return "Completed", nil
	case enumspb.WORKFLOW_EXECUTION_STATUS_FAILED:
		return "Failed", nil
	case enumspb.WORKFLOW_EXECUTION_STATUS_CANCELED:
		return "Canceled", nil
	case enumspb.WORKFLOW_EXECUTION_STATUS_TERMINATED:
		return "Terminated", nil
	case enumspb.WORKFLOW_EXECUTION_STATUS_CONTINUED_AS_NEW:
		return "ContinuedAsNew", nil
	case enumspb.WORKFLOW_EXECUTION_STATUS_TIMED_OUT:
		return "TimedOut", nil
	default:
		return "Unknown", nil
	}
}

// ShepherdInLoopQueryName is DevLoopWorkflow's query handler reporting
// whether THIS execution runs its own in-loop shepherd ticks. It answers
// false on an execution that started before mctl-agents shipped the
// `shepherd-in-loop` patch: such a run is Running but will never tick, so
// the shepherd cron must keep sweeping its proposal (mctl-agents#213).
const ShepherdInLoopQueryName = "shepherd_in_loop"

// QueryShepherdInLoop asks the workflow itself rather than inferring from
// its status. A worker too old to define the handler fails the query; the
// caller treats any failure as false, which degrades to "the cron keeps
// shepherding this proposal" — the pre-#213 behaviour.
func (c *Client) QueryShepherdInLoop(ctx context.Context, workflowID string) (bool, error) {
	value, err := c.temporal.QueryWorkflow(ctx, workflowID, "", ShepherdInLoopQueryName)
	if err != nil {
		return false, fmt.Errorf("temporalclient: query %s on %s: %w", ShepherdInLoopQueryName, workflowID, err)
	}
	var inLoop bool
	if err := value.Get(&inLoop); err != nil {
		return false, fmt.Errorf("temporalclient: decode %s on %s: %w", ShepherdInLoopQueryName, workflowID, err)
	}
	return inLoop, nil
}

// HumanInputStateQueryName is DevLoopWorkflow's query handler for the
// durable clarification gate (mctl-agents#333, ADR 013). It never returns
// the question, reason or answer -- only ids, hashes, timestamps and
// counters -- and is served on closed executions too.
const HumanInputStateQueryName = "human_input_state"

// DevLoop human-input states (dev_loop.py). RUNNING also covers "never
// waited" and "answered and resumed"; RequestID tells them apart.
const (
	HumanInputRunning         = "RUNNING"
	HumanInputWaitingForInput = "WAITING_FOR_INPUT"
	HumanInputTimedOut        = "INPUT_TIMED_OUT"
)

// HumanInputState is the workflow's own view of its clarification gate,
// decoded from the HumanInputState dataclass. It is the ONLY source of
// truth for whether a request is still waiting: mctl-api keeps no copy of
// that state machine.
type HumanInputState struct {
	State             string `json:"state"`
	RequestID         string `json:"request_id"`
	RequestHash       string `json:"request_hash"`
	QuestionHash      string `json:"question_hash"`
	ExpiresAt         string `json:"expires_at"`
	Round             int    `json:"round"`
	ResumeCount       int    `json:"resume_count"`
	RejectedCount     int    `json:"rejected_count"`
	EffectiveDeadline string `json:"effective_deadline"`
}

// QueryHumanInputState asks the workflow for its clarification state.
// runID may be empty (the latest run of workflowID).
func (c *Client) QueryHumanInputState(ctx context.Context, workflowID, runID string) (*HumanInputState, error) {
	value, err := c.temporal.QueryWorkflow(ctx, workflowID, runID, HumanInputStateQueryName)
	if err != nil {
		return nil, fmt.Errorf("temporalclient: query %s on %s: %w", HumanInputStateQueryName, workflowID, err)
	}
	var st HumanInputState
	if err := value.Get(&st); err != nil {
		return nil, fmt.Errorf("temporalclient: decode %s on %s: %w", HumanInputStateQueryName, workflowID, err)
	}
	return &st, nil
}

// IsNotFound reports whether err is (or wraps) Temporal's NotFound service
// error — the case SignalApprove hits when workflowID doesn't correspond to
// any workflow (never started, or already past retention). Callers use this
// to map that specific case to HTTP 404 instead of a generic 502.
func IsNotFound(err error) bool {
	var notFound *serviceerror.NotFound
	return errors.As(err, &notFound)
}
