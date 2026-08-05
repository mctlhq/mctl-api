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
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-api/internal/auth"
)

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
	if _, ok := h.requireTemporalAdmin(w, r); !ok {
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

	workflowID, runID, err := h.opts.TemporalClient.StartDevLoopWorkflow(r.Context(), body.IssueURL)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to start dev-loop workflow: "+err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"workflow_id": workflowID,
		"run_id":      runID,
		"message":     "DevLoopWorkflow started. Approve the implement step with POST /api/v1/agents/dev-loop/{workflow_id}/approve once the proposal is reviewed.",
	})
}

// ApproveDevLoopWorkflow handles POST /api/v1/agents/dev-loop/{workflow_id}/approve
// — the durable "human flips it to accepted" step, expressed as a Temporal
// signal instead of a gitops .status.yaml edit.
func (h *Handlers) ApproveDevLoopWorkflow(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireTemporalAdmin(w, r); !ok {
		return
	}

	workflowID := chi.URLParam(r, "workflow_id")
	if err := h.opts.TemporalClient.SignalApprove(r.Context(), workflowID); err != nil {
		writeError(w, http.StatusBadRequest, "failed to signal approval: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"workflow_id": workflowID,
		"signalled":   "approve",
	})
}
