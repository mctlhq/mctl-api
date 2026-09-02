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
	"io"
	"log/slog"
	"net/http"
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

	auditParams := map[string]string{"issue_url": body.IssueURL}

	workflowID, runID, err := h.opts.TemporalClient.StartDevLoopWorkflow(r.Context(), body.IssueURL)
	if err != nil {
		// ErrInvalidIssueURL is caller input (a malformed issue_url) — real
		// 400. Everything else is a Temporal RPC/connectivity failure the
		// caller sent a perfectly valid request for and can't fix by
		// retrying with different input, so it gets 502 instead of being
		// indistinguishable from a bad request.
		if errors.Is(err, temporalclient.ErrInvalidIssueURL) {
			writeError(w, http.StatusBadRequest, "invalid issue_url: "+err.Error())
			return
		}
		h.logAudit(r, audit.Entry{
			UserID:     user.ID,
			Operation:  "dev-loop-start",
			Parameters: auditParams,
			Status:     "failed",
			RiskLevel:  string(operations.RiskMedium),
			Message:    "failed to start dev-loop workflow: " + err.Error(),
		})
		writeError(w, http.StatusBadGateway, "failed to start dev-loop workflow: "+err.Error())
		return
	}
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
		"run_id":      runID,
		"message":     "DevLoopWorkflow started. Approve the implement step with POST /api/v1/agents/dev-loop/{workflow_id}/approve once the proposal is reviewed.",
	})
}

type approveDevLoopRequest struct {
	Approver string `json:"approver"`
	Reason   string `json:"reason"`
}

// ApproveDevLoopWorkflow handles POST /api/v1/agents/dev-loop/{workflow_id}/approve
// — the durable "human flips it to accepted" step, expressed as a Temporal
// signal instead of a gitops .status.yaml edit. The optional JSON body
// {approver?, reason?} rides on the signal; approver defaults to the
// authenticated caller so the gitops approval block records who flipped it
// (same provenance rule as the mctl-agents-approve operation).
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

	var body approveDevLoopRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.Approver == "" {
		body.Approver = user.ID
	}
	payload := map[string]string{"approver": body.Approver}
	if body.Reason != "" {
		payload["reason"] = body.Reason
	}

	auditParams := map[string]string{"approver": body.Approver}
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
	shepherdInLoop := false
	if status == "Running" {
		qctx, cancel := context.WithTimeout(r.Context(), shepherdQueryTimeout)
		inLoop, qerr := h.opts.TemporalClient.QueryShepherdInLoop(qctx, workflowID)
		cancel()
		if qerr != nil {
			slog.Debug("dev-loop shepherd_in_loop query failed; reporting false",
				"workflow_id", workflowID, "error", qerr)
		}
		shepherdInLoop = inLoop
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"workflow_id":      workflowID,
		"status":           status,
		"shepherd_in_loop": shepherdInLoop,
	})
}
