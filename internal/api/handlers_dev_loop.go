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

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/temporalclient"
)

// shepherdQueryTimeout bounds the best-effort shepherd_in_loop query so a
// worker outage degrades to "false" quickly instead of holding the HTTP
// request open until the API-wide 30s timeout.
const shepherdQueryTimeout = 3 * time.Second

// devLoopDescribeTimeout bounds each pre-start describe call startDevLoop
// makes, mirroring roadmapWaveCallTimeout (handlers_roadmap_wave.go) so a
// hung Temporal frontend fails fast instead of eating the request's full
// API-wide timeout.
const devLoopDescribeTimeout = 10 * time.Second

// devLoopOutcome* is the shared vocabulary both the single-issue start route
// and the roadmap wave route report; waveOutcome* in handlers_roadmap_wave.go
// are aliases of these so the two routes cannot drift on what
// "already_running" means.
const (
	devLoopOutcomeStarted        = "started"
	devLoopOutcomeAlreadyRunning = "already_running"
	devLoopOutcomeAlreadyExists  = "already_exists"
	devLoopOutcomeFailed         = "failed"
)

// devLoopStartResult is startDevLoop's answer: what happened, and everything
// a caller needs to report it (the pre-existing execution's status/run id, or
// the new run's id, or why nothing could be decided/started).
type devLoopStartResult struct {
	Outcome string
	Status  string // Temporal status of the pre-existing execution, when one exists
	RunID   string
	Err     error
}

// startDevLoop implements the describe -> classify -> start decision shared
// by StartDevLoopWorkflow (the single-issue route) and ExecuteRoadmapWave
// (the wave route), so the two cannot report "already_running" or
// "already_exists" differently for the same execution (issue #287:
// StartDevLoopWorkflow used to report "started" even when
// WorkflowIDReusePolicy/WorkflowIDConflictPolicy silently absorbed the call
// into an existing run).
//
// It is deliberately composed of two separately-callable halves,
// classifyDevLoop and startDevLoopAfterNotFound: ExecuteRoadmapWave bounds
// each one with its own fresh per-item Temporal-call timeout (so one item's
// slow describe cannot eat its own start's budget, or another item's), while
// this function bounds the describe half with devLoopDescribeTimeout and
// otherwise lets the caller's context govern the start.
//
// TOCTOU: two callers racing can both observe NotFound between the describe
// and the start; the second start is then absorbed by StartDevLoopWorkflow's
// WorkflowIDConflictPolicy USE_EXISTING and reported as "started" even though
// nothing new actually began. This is strictly narrower than the bug this
// function fixes (which reported every no-op as a start regardless of
// timing) and is not closable without dropping USE_EXISTING, which would be a
// cross-repo behaviour change to orchestrator/temporal/cli.py's start policy
// — out of scope here (see mctl-api#404).
func startDevLoop(ctx context.Context, c DevLoopClient, issueURL, workflowID string) devLoopStartResult {
	dctx, cancel := context.WithTimeout(ctx, devLoopDescribeTimeout)
	result := classifyDevLoop(dctx, c, workflowID)
	cancel()
	if result.Outcome != "" {
		return result
	}
	// Empty Outcome is classifyDevLoop's signal for "not found; start it".
	return startDevLoopAfterNotFound(ctx, c, issueURL, workflowID)
}

// classifyDevLoop describes workflowID and decides whether a start should
// follow. A zero-value devLoopStartResult (empty Outcome, nil Err) means
// "not found: proceed to start" — every other case is terminal and callers
// must not start on top of it.
//
// It calls DescribeDevLoopExecution — not the plainer DescribeDevLoop — so a
// single Temporal describe RPC supplies both the status used to classify the
// execution and the run id reported alongside it. A second describe call
// purely to fetch the run id would be a redundant Temporal round trip:
// DescribeDevLoopExecution already returns both fields from the one call.
//
//   - describe succeeds and status == devLoopStatusRunning -> already_running, existing
//     run id, do NOT start.
//   - describe succeeds with any other status (a closed execution) ->
//     already_exists, existing run id, do NOT start (REJECT_DUPLICATE would
//     not restart it anyway).
//   - describe fails with temporalclient.IsNotFound -> the zero value: proceed.
//   - describe fails with any other error -> failed, WITHOUT starting: an
//     unreadable execution is never started blind.
func classifyDevLoop(ctx context.Context, c DevLoopClient, workflowID string) devLoopStartResult {
	exec, err := c.DescribeDevLoopExecution(ctx, workflowID)
	switch {
	case err != nil && !temporalclient.IsNotFound(err):
		// Cannot tell whether it exists: do not start blind.
		return devLoopStartResult{Outcome: devLoopOutcomeFailed, Err: fmt.Errorf("could not read the existing DevLoop: %w", err)}
	case err == nil && exec.Status == devLoopStatusRunning:
		return devLoopStartResult{Outcome: devLoopOutcomeAlreadyRunning, Status: exec.Status, RunID: exec.RunID}
	case err == nil:
		// A closed DevLoop is not restarted (REJECT_DUPLICATE); report it.
		return devLoopStartResult{Outcome: devLoopOutcomeAlreadyExists, Status: exec.Status, RunID: exec.RunID}
	default:
		return devLoopStartResult{}
	}
}

// startDevLoopAfterNotFound performs the actual start once classifyDevLoop
// has determined no execution exists yet, including the "started workflow X,
// planned Y" guard against trusting a start that reports a different id than
// expected.
func startDevLoopAfterNotFound(ctx context.Context, c DevLoopClient, issueURL, workflowID string) devLoopStartResult {
	wf, runID, err := c.StartDevLoopWorkflow(ctx, issueURL)
	switch {
	case err != nil:
		return devLoopStartResult{Outcome: devLoopOutcomeFailed, Err: err}
	case wf != workflowID:
		return devLoopStartResult{Outcome: devLoopOutcomeFailed, Err: fmt.Errorf("started workflow %s, planned %s", wf, workflowID)}
	default:
		return devLoopStartResult{Outcome: devLoopOutcomeStarted, RunID: runID}
	}
}

// requireTemporalAdmin mirrors requireAgentRegistryAdmin: configured,
// authenticated, admin. The dev-loop trigger path is a separate optional
// dependency from the agent registry store (a deployment can have one
// without the other), so it gets its own nil check.
func (h *Handlers) requireTemporalAdmin(w http.ResponseWriter, r *http.Request) (*auth.User, bool) {
	if h.opts.TemporalClient == nil {
		writeError(w, http.StatusServiceUnavailable, "dev-loop Temporal client not configured")
		return nil, false
	}
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}
	if !user.IsAdmin() {
		writeError(w, http.StatusForbidden, "dev-loop workflow control is admin-only")
		return nil, false
	}
	return user, true
}

type startDevLoopRequest struct {
	IssueURL string `json:"issue_url"`
}

// StartDevLoopWorkflow handles POST /api/v1/agents/dev-loop/start — the
// use_temporal path for mctl_trigger_issue (plan phase 4). Starts
// DevLoopWorkflow (orchestrator/temporal/workflows/dev_loop.py) on the
// shared Temporal deployment instead of submitting the investigate CWFT
// directly; the workflow itself pins a registry-resolved version and
// submits that same CWFT as its first activity.
//
// StartDevLoopWorkflow's own idempotency policies (REJECT_DUPLICATE +
// USE_EXISTING) mean a call against an id that already has a running or
// closed execution truly no-ops. Reporting every such call as "started"
// would be a lie (issue #287, portfolio#7): this handler describes before it
// starts, via the shared startDevLoop, and reports the real outcome.
func (h *Handlers) StartDevLoopWorkflow(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireTemporalAdmin(w, r)
	if !ok {
		return
	}

	var body startDevLoopRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.IssueURL == "" {
		writeError(w, http.StatusBadRequest, "missing required field: issue_url")
		return
	}

	workflowID, err := temporalclient.WorkflowIDForIssueURL(body.IssueURL)
	if err != nil {
		// Caller input (a malformed issue_url) — real 400, not audited, same
		// as before this change.
		writeError(w, http.StatusBadRequest, "invalid issue_url: "+err.Error())
		return
	}

	auditParams := map[string]string{"issue_url": body.IssueURL}

	result := startDevLoop(r.Context(), h.opts.TemporalClient, body.IssueURL, workflowID)
	auditParams["outcome"] = result.Outcome

	switch result.Outcome {
	case devLoopOutcomeStarted:
		h.logAudit(r, audit.Entry{
			UserID:       user.ID,
			Operation:    "dev-loop-start",
			Parameters:   auditParams,
			WorkflowName: workflowID,
			Status:       "succeeded",
			RiskLevel:    string(operations.RiskMedium),
		})
		writeJSON(w, http.StatusAccepted, map[string]interface{}{
			"workflow_id": workflowID,
			"run_id":      result.RunID,
			"started":     true,
			"outcome":     result.Outcome,
			"message":     "DevLoopWorkflow started. Approve the implement step with POST /api/v1/agents/dev-loop/{workflow_id}/approve once the proposal is reviewed.",
		})
	case devLoopOutcomeAlreadyRunning:
		h.logAudit(r, audit.Entry{
			UserID:       user.ID,
			Operation:    "dev-loop-start",
			Parameters:   auditParams,
			WorkflowName: workflowID,
			Status:       "succeeded",
			RiskLevel:    string(operations.RiskMedium),
			Message:      "not started: already_running (run " + result.RunID + ")",
		})
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"workflow_id": workflowID,
			"run_id":      result.RunID,
			"started":     false,
			"outcome":     result.Outcome,
			"status":      result.Status,
			"message":     "A DevLoopWorkflow is already running for this issue; nothing new was started. Check its progress with GET /api/v1/agents/dev-loop/{workflow_id}.",
		})
	case devLoopOutcomeAlreadyExists:
		h.logAudit(r, audit.Entry{
			UserID:       user.ID,
			Operation:    "dev-loop-start",
			Parameters:   auditParams,
			WorkflowName: workflowID,
			Status:       "succeeded",
			RiskLevel:    string(operations.RiskMedium),
			Message:      "not started: already_exists (run " + result.RunID + ", status " + result.Status + ")",
		})
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"workflow_id": workflowID,
			"run_id":      result.RunID,
			"started":     false,
			"outcome":     result.Outcome,
			"status":      result.Status,
			"message":     "A DevLoopWorkflow already ran for this issue and is not restarted; nothing new was started.",
		})
	default: // devLoopOutcomeFailed
		h.logAudit(r, audit.Entry{
			UserID:     user.ID,
			Operation:  "dev-loop-start",
			Parameters: auditParams,
			Status:     "failed",
			RiskLevel:  string(operations.RiskMedium),
			Message:    "failed to start dev-loop workflow: " + result.Err.Error(),
		})
		writeError(w, http.StatusBadGateway, "failed to start dev-loop workflow: "+result.Err.Error())
	}
}

type approveDevLoopRequest struct {
	// Approver is accepted only so an explicit value can be REJECTED rather
	// than silently ignored. The approver is taken from the caller's verified
	// identity; see ApproveDevLoopWorkflow. Dropping the field instead would
	// let a caller that still sends one believe it was honoured.
	Approver string `json:"approver"`
	Reason   string `json:"reason"`
}

// ApproveDevLoopWorkflow handles POST /api/v1/agents/dev-loop/{workflow_id}/approve
// — the durable "human flips it to accepted" step, expressed as a Temporal
// signal instead of a gitops .status.yaml edit. The optional JSON body
// {reason?} rides on the signal.
//
// This is the one place in the pipeline where a human actually performs the
// act of approving: an authenticated HTTP call. So the approver is taken from
// the caller's verified identity and nowhere else. It used to merely DEFAULT
// to that identity, which made `approved_by` in the gitops proposal a
// self-asserted string — any authenticated admin could record the approval
// under a colleague's name, and nothing downstream could tell the difference
// (gitops#986).
//
// A request that still carries an `approver` is rejected rather than having
// the field quietly ignored: a caller that believes it is setting the
// approver must be told it is not.
func (h *Handlers) ApproveDevLoopWorkflow(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireTemporalAdmin(w, r)
	if !ok {
		return
	}

	workflowID := chi.URLParam(r, "workflow_id")
	if workflowID == "" {
		writeError(w, http.StatusBadRequest, "missing workflow_id path parameter")
		return
	}

	// Refuse a body naming who acted before decoding it (mctl-api#376 slice
	// B3): additive only, so the approver-equals-caller tolerance, the admin
	// check and the EOF-tolerant decode just below are unchanged -- those
	// belong to Slice C.
	if !refuseIdentityFields(w, r, maxExecutionRequestBodyBytes) {
		return
	}

	var body approveDevLoopRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.Approver != "" && body.Approver != user.ID {
		writeError(w, http.StatusBadRequest,
			"approver is not an input: it is taken from the authenticated caller. Remove the field from the request body.")
		return
	}
	// Deliberately not stamping an "approver_verified" flag onto the signal
	// yet: nothing downstream reads one, and a field no consumer checks is
	// documentation pretending to be enforcement. The remaining half of
	// gitops#986 — having the implement step enforce
	// control.requires_human_approval — is where that carrier belongs, added
	// together with the code that reads it.
	approver := user.ID
	payload := map[string]string{"approver": approver}
	if body.Reason != "" {
		payload["reason"] = body.Reason
	}

	auditParams := map[string]string{"approver": approver}
	if body.Reason != "" {
		auditParams["reason"] = body.Reason
	}

	if err := h.opts.TemporalClient.SignalApprove(r.Context(), workflowID, payload); err != nil {
		if temporalclient.IsNotFound(err) {
			h.logAudit(r, audit.Entry{
				UserID:       user.ID,
				Operation:    "dev-loop-approve",
				Parameters:   auditParams,
				WorkflowName: workflowID,
				Status:       "failed",
				RiskLevel:    string(operations.RiskMedium),
				Message:      "workflow not found",
			})
			writeError(w, http.StatusNotFound, "workflow not found: "+workflowID)
			return
		}
		h.logAudit(r, audit.Entry{
			UserID:       user.ID,
			Operation:    "dev-loop-approve",
			Parameters:   auditParams,
			WorkflowName: workflowID,
			Status:       "failed",
			RiskLevel:    string(operations.RiskMedium),
			Message:      "signal failed: " + err.Error(),
		})
		writeError(w, http.StatusBadGateway, "failed to signal approval: "+err.Error())
		return
	}

	h.logAudit(r, audit.Entry{
		UserID:       user.ID,
		Operation:    "dev-loop-approve",
		Parameters:   auditParams,
		WorkflowName: workflowID,
		Status:       "succeeded",
		RiskLevel:    string(operations.RiskMedium),
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"workflow_id": workflowID,
		"signalled":   "approve",
	})
}

type abandonDevLoopRequest struct {
	Reason string `json:"reason"`
}

// devLoopOutcomeSignalled and devLoopOutcomeAlreadyFinished are the two
// answers AbandonDevLoopWorkflow gives on success.
const (
	devLoopOutcomeSignalled       = "signalled"
	devLoopOutcomeAlreadyFinished = "already_finished"
)

// AbandonDevLoopWorkflow handles POST /api/v1/agents/dev-loop/{workflow_id}/abandon
// (mctl-api#392) — the MCP-reachable form of mctl-agents#420's
// `python -m orchestrator.temporal.cli abandon`. It sends the workflow's
// `abandon` signal rather than Temporal `terminate`, because terminate skips
// `_watch_pr`'s `finally`, where the lifecycle-ownership row is released.
//
// The body is {"reason": "<required>"}. Who ended the loop is the
// authenticated caller, recorded on the signal and in the audit log the same
// way ApproveDevLoopWorkflow records the approver, and never read from the
// body: unknown fields are rejected, so `abandoned_by` cannot be supplied.
//
// The execution is described first, so the answer is always an observation:
//   - no execution under this id: 404;
//   - an execution that already finished: 200 with its final status and
//     outcome already_finished, nothing signalled, so a retry is harmless;
//   - a running execution: signalled, 200 with outcome signalled. The
//     workflow ends at its next observation point, so the status reported is
//     still Running; mctl_get_dev_loop shows the terminal status after.
//
// Any Temporal error is a 502, never a success. The signal is pinned to the
// run the describe observed, so a run that closed in between -- even one
// already replaced by a new run under the same workflow id -- answers
// NotFound rather than abandoning a loop nobody looked at. That NotFound is
// answered from a second describe rather than assumed either way; a new
// run found there is reported as a 409, not abandoned.
func (h *Handlers) AbandonDevLoopWorkflow(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireTemporalAdmin(w, r)
	if !ok {
		return
	}

	workflowID := chi.URLParam(r, "workflow_id")
	if workflowID == "" {
		writeError(w, http.StatusBadRequest, "missing workflow_id path parameter")
		return
	}
	if !refuseIdentityFields(w, r, maxExecutionRequestBodyBytes) {
		return
	}

	var body abandonDevLoopRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest,
			"invalid JSON: "+err.Error()+" (the body is {\"reason\": ...}; who abandoned the loop is taken from the authenticated caller)")
		return
	}
	reason := strings.TrimSpace(body.Reason)
	if reason == "" {
		writeError(w, http.StatusBadRequest, "missing required field: reason")
		return
	}

	auditParams := map[string]string{"abandoned_by": user.ID, "reason": reason}
	fail := func(code int, message, clientMessage string) {
		h.logAudit(r, audit.Entry{
			UserID:       user.ID,
			Operation:    "dev-loop-abandon",
			Parameters:   auditParams,
			WorkflowName: workflowID,
			Status:       "failed",
			RiskLevel:    string(operations.RiskMedium),
			Message:      message,
		})
		writeError(w, code, clientMessage)
	}
	finished := func(exec *temporalclient.DevLoopExecution) {
		h.logAudit(r, audit.Entry{
			UserID:       user.ID,
			Operation:    "dev-loop-abandon",
			Parameters:   auditParams,
			WorkflowName: workflowID,
			Status:       "succeeded",
			RiskLevel:    string(operations.RiskMedium),
			Message:      "not signalled: already finished (run " + exec.RunID + ", status " + exec.Status + ")",
		})
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"workflow_id": workflowID,
			"run_id":      exec.RunID,
			"status":      exec.Status,
			"outcome":     devLoopOutcomeAlreadyFinished,
			"message":     "The DevLoopWorkflow already finished; nothing was signalled.",
		})
	}
	// describe answers with the execution, or writes the error response
	// itself and returns nil. notFoundAudit is the audit message for a
	// NotFound: on the second look the execution was observed moments ago,
	// so "workflow not found" would misreport what happened.
	describe := func(notFoundAudit string) *temporalclient.DevLoopExecution {
		dctx, cancel := context.WithTimeout(r.Context(), devLoopDescribeTimeout)
		defer cancel()
		exec, err := h.opts.TemporalClient.DescribeDevLoopExecution(dctx, workflowID)
		switch {
		case temporalclient.IsNotFound(err):
			fail(http.StatusNotFound, notFoundAudit, "workflow not found: "+workflowID)
			return nil
		case err != nil:
			fail(http.StatusBadGateway, "describe failed: "+err.Error(), "failed to describe workflow: "+err.Error())
			return nil
		case exec.Status == devLoopStatusUnknown:
			// Neither running nor finished as far as anyone can tell: not a
			// state to signal into, and not one to report as finished.
			fail(http.StatusBadGateway, "describe returned an unknown status",
				"workflow "+workflowID+" has an execution status this server could not determine")
			return nil
		}
		return exec
	}

	exec := describe("workflow not found")
	if exec == nil {
		return
	}
	if exec.Status != devLoopStatusRunning {
		finished(exec)
		return
	}

	payload := map[string]string{"reason": reason, "abandoned_by": user.ID}
	if err := h.opts.TemporalClient.SignalAbandon(r.Context(), workflowID, exec.RunID, payload); err != nil {
		if !temporalclient.IsNotFound(err) {
			fail(http.StatusBadGateway, "signal failed: "+err.Error(), "failed to signal abandon: "+err.Error())
			return
		}
		// Temporal answers NotFound for the described run once it has
		// completed, whether or not a new run has started since. Look again
		// instead of guessing.
		after := describe("execution vanished between describe and signal")
		if after == nil {
			return
		}
		if after.Status == devLoopStatusRunning {
			if after.RunID != exec.RunID {
				// The described run ended and a new one took the id. It was
				// not the run anyone looked at, so it is not abandoned here.
				fail(http.StatusConflict, "described run "+exec.RunID+" ended; new run "+after.RunID+" not signalled",
					"run "+exec.RunID+" ended before the signal and a new run "+after.RunID+
						" is running under the same workflow id; it was not abandoned. Re-issue the request to abandon it.")
				return
			}
			fail(http.StatusBadGateway, "signal answered not found for a running execution",
				"failed to signal abandon: "+err.Error())
			return
		}
		finished(after)
		return
	}

	h.logAudit(r, audit.Entry{
		UserID:       user.ID,
		Operation:    "dev-loop-abandon",
		Parameters:   auditParams,
		WorkflowName: workflowID,
		Status:       "succeeded",
		RiskLevel:    string(operations.RiskMedium),
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"workflow_id": workflowID,
		"run_id":      exec.RunID,
		"status":      exec.Status,
		"outcome":     devLoopOutcomeSignalled,
		"signalled":   "abandon",
		"message":     "Abandon signalled. The DevLoopWorkflow ends at its next observation point; check GET /api/v1/agents/dev-loop/{workflow_id} for the terminal status.",
	})
}

// GetDevLoopWorkflow handles GET /api/v1/agents/dev-loop/{workflow_id} —
// a liveness read: the shepherd cron's sweeper skips proposals whose
// DevLoopWorkflow is still Running (it drives its own review loop, see
// mctl-agents#213), and this is the only Temporal surface the sweeper —
// which deliberately holds no Temporal client — can reach.
func (h *Handlers) GetDevLoopWorkflow(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireTemporalAdmin(w, r); !ok {
		return
	}

	workflowID := chi.URLParam(r, "workflow_id")
	if workflowID == "" {
		writeError(w, http.StatusBadRequest, "missing workflow_id path parameter")
		return
	}
	status, err := h.opts.TemporalClient.DescribeDevLoop(r.Context(), workflowID)
	if err != nil {
		if temporalclient.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "workflow not found: "+workflowID)
			return
		}
		writeError(w, http.StatusBadGateway, "failed to describe workflow: "+err.Error())
		return
	}
	// Only a Running execution can be shepherding anything, and a query
	// against a finished one would fail anyway. A query failure is not an
	// error for the caller: an old worker without the handler, or a
	// transient blip, both mean "assume it does not tick", which leaves the
	// shepherd cron responsible — the pre-#213 behaviour.
	// The query gets its own short deadline, not the request's: Temporal
	// blocks a QueryWorkflow until a worker on that task queue answers, so
	// during a worker outage the request context's only bound is the 30s
	// API timeout — the caller would be timing out (or already gone) before
	// the false fallback reached it, exactly when the cron most needs to
	// take over.
	//
	// `shepherd_in_loop_known` carries whether that false is an ANSWER or a
	// fallback. The two are the same value on the wire and mean opposite
	// things: a live execution declining to shepherd is a fact, while a failed
	// query is an absence. A caller deciding whether to sweep may treat them
	// alike -- that is the fail-open above -- but a caller COMPARING this
	// answer against the ownership store may not, because folding "could not
	// ask" into "nobody is driving it" manufactures exactly the divergence
	// class that licenses two machines to drive one pull request.
	shepherdInLoop := false
	// Known unless a query was put and failed. A finished execution is NOT an
	// unknown: false there is derived from the status -- a Completed workflow
	// definitively is not ticking a shepherd -- and reporting it as unknown
	// would make a consumer that follows this field report UNKNOWN for every
	// finished DevLoopWorkflow, which is the same absent/negative collapse
	// this field exists to remove.
	//
	// `status != "Unknown"` rather than an unconditional true: DescribeDevLoop
	// returns "Unknown" from its own default arm for an execution status it
	// could not determine, so a read that determined nothing would otherwise
	// answer known=true about a false it derived from nothing. The old
	// `status == devLoopStatusRunning` covered that case by accident; this covers it on
	// purpose.
	shepherdInLoopKnown := status != "Unknown"
	if status == devLoopStatusRunning {
		qctx, cancel := context.WithTimeout(r.Context(), shepherdQueryTimeout)
		inLoop, qerr := h.opts.TemporalClient.QueryShepherdInLoop(qctx, workflowID)
		cancel()
		if qerr != nil {
			slog.Debug("dev-loop shepherd_in_loop query failed; reporting false",
				"workflow_id", workflowID, "error", qerr)
			shepherdInLoopKnown = false
		}
		shepherdInLoop = inLoop
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"workflow_id": workflowID,
		"status":      status,
		// Unchanged in value and meaning for every existing caller: the
		// shepherd's own probe reads `is True` and nothing else.
		"shepherd_in_loop":       shepherdInLoop,
		"shepherd_in_loop_known": shepherdInLoopKnown,
	})
}
