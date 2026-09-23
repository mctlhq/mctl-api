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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/roadmap"
	"github.com/mctlhq/mctl-api/internal/temporalclient"
)

// Governed wave start (mctl-api#334). A plan is selected from the verified
// RoadmapPublication; executing it reloads the latest verified publication
// and starts DevLoops only if that is the very publication the plan was made
// from and it is fresh enough. mctl-api evaluates nothing, reads nothing
// from GitHub and dispatches no publisher: anything that does not match
// fails closed, and never as a subset.

// waveNow is the clock freshness is judged by; tests pin it.
var waveNow = time.Now

// DefaultRoadmapWaveMaxAge is how old the latest publication's observation
// may be when a wave executes, unless ROADMAP_WAVE_MAX_AGE says otherwise.
const DefaultRoadmapWaveMaxAge = 30 * time.Minute

const (
	roadmapCodePlanStale        = "plan_stale"
	roadmapCodeTooOld           = "publication_too_old"
	roadmapCodeInvalidSelection = "invalid_selection"
	roadmapCodeWaveDisabled     = "wave_execution_disabled"

	roadmapWaveMaxBody = 64 << 10

	// roadmapWaveStartTimeout bounds one wave's DevLoop starts once begun.
	roadmapWaveStartTimeout = 2 * time.Minute
)

// Per-item execution outcomes.
const (
	waveOutcomeStarted        = "started"
	waveOutcomeAlreadyRunning = "already_running"
	waveOutcomeAlreadyExists  = "already_exists"
	waveOutcomeFailed         = "failed"
)

// waveMaxAge is the configured freshness bound. A negative value means the
// configuration was invalid: execution is then refused rather than run
// against an unintended bound.
func (h *Handlers) waveMaxAge() time.Duration {
	if h.opts.RoadmapWaveMaxAge == 0 {
		return DefaultRoadmapWaveMaxAge
	}
	return h.opts.RoadmapWaveMaxAge
}

type wavePlanRequest struct {
	Epic         string   `json:"epic"`
	RequiredOnly *bool    `json:"required_only"`
	Items        []string `json:"items"`
}

type waveExecuteRequest struct {
	Epic          string   `json:"epic"`
	RequiredOnly  *bool    `json:"required_only"`
	Items         []string `json:"items"`
	PlanHash      string   `json:"plan_hash"`
	StateRevision string   `json:"state_revision"`
}

// decodeWaveBody reads one strict JSON object.
func decodeWaveBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, roadmapWaveMaxBody))
	if err != nil {
		writeErrorCode(w, http.StatusBadRequest, roadmapCodeInvalid, "could not read the body", nil)
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeErrorCode(w, http.StatusBadRequest, roadmapCodeInvalid, "invalid JSON body: "+err.Error(), nil)
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeErrorCode(w, http.StatusBadRequest, roadmapCodeInvalid, "invalid JSON body: trailing data", nil)
		return false
	}
	return true
}

// waveFreshness reports whether the publication is fresh enough to execute
// from, and how old it is. A publication without a capture time (a
// synthetic observation) is never fresh.
func waveFreshness(prov roadmap.Provenance, maxAge time.Duration) (fresh bool, reason string) {
	if prov.AgeSeconds == nil {
		return false, "the publication carries no observation time"
	}
	if maxAge <= 0 {
		return false, "ROADMAP_WAVE_MAX_AGE is invalid"
	}
	if *prov.AgeSeconds < 0 {
		// Captured "in the future": the clocks disagree, so the age is
		// unknown. Fail closed rather than read it as fresh.
		return false, "the publication's observation time is ahead of this server's clock"
	}
	if time.Duration(*prov.AgeSeconds)*time.Second > maxAge {
		return false, "the publication's observation is " + strconv.FormatInt(*prov.AgeSeconds, 10) +
			"s old; the maximum is " + strconv.FormatInt(int64(maxAge/time.Second), 10) + "s"
	}
	return true, ""
}

// wavePlanErrorCode is the typed code writeWavePlanError answers err with.
func wavePlanErrorCode(err error) string {
	var sel *roadmap.SelectionError
	switch {
	case errors.As(err, &sel):
		return roadmapCodeInvalidSelection
	case errors.Is(err, roadmap.ErrEpicNotFound):
		return roadmapCodeEpicNotFound
	case errors.Is(err, roadmap.ErrUnavailable):
		return roadmapCodeUnavailable
	}
	return "internal_error"
}

// writeWavePlanError answers err with the code wavePlanErrorCode names, so
// the audited reason and the HTTP answer cannot diverge.
func writeWavePlanError(w http.ResponseWriter, err error) {
	switch wavePlanErrorCode(err) {
	case roadmapCodeInvalidSelection:
		var sel *roadmap.SelectionError
		errors.As(err, &sel)
		writeErrorCode(w, http.StatusConflict, roadmapCodeInvalidSelection, err.Error(),
			map[string]any{"refused": sel.Refused})
	case roadmapCodeEpicNotFound:
		writeErrorCode(w, http.StatusNotFound, roadmapCodeEpicNotFound, err.Error(), nil)
	case roadmapCodeUnavailable:
		slog.Warn("roadmap wave: publication unusable", "error", err)
		writeErrorCode(w, http.StatusServiceUnavailable, roadmapCodeUnavailable,
			"no verified roadmap publication: readiness is unknown, not empty", nil)
	default:
		writeError(w, http.StatusInternalServerError, "roadmap wave planning failed")
	}
}

// PlanRoadmapWave handles POST /api/v1/roadmap/waves/plan: the dry run. It
// starts nothing and needs no Temporal client.
func (h *Handlers) PlanRoadmapWave(w http.ResponseWriter, r *http.Request) {
	if auth.UserFromContext(r.Context()) == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var body wavePlanRequest
	if !decodeWaveBody(w, r, &body) {
		return
	}
	req, ok := waveRequest(w, body.Epic, body.RequiredOnly, body.Items)
	if !ok {
		return
	}
	pub, ok := h.roadmapPublication(w)
	if !ok {
		return
	}
	plan, err := pub.PlanWave(req, temporalclient.WorkflowIDForIssueURL, waveNow())
	if err != nil {
		writeWavePlanError(w, err)
		return
	}
	maxAge := h.waveMaxAge()
	fresh, why := waveFreshness(plan.Provenance, maxAge)
	resp := map[string]any{
		"plan":            plan,
		"max_age_seconds": max(int64(maxAge/time.Second), 0),
		"executable":      fresh && len(plan.Selected) > 0,
	}
	switch {
	case maxAge < 0:
		// The same terminal answer execute gives: no publication fixes it.
		resp["not_executable_reason"] = roadmapCodeWaveDisabled + ": ROADMAP_WAVE_MAX_AGE is invalid"
	case !fresh:
		resp["not_executable_reason"] = roadmapCodeTooOld + ": " + why
	case len(plan.Selected) == 0:
		resp["not_executable_reason"] = roadmapCodeInvalidSelection + ": nothing to start"
	}
	writeJSON(w, http.StatusOK, resp)
}

func waveRequest(w http.ResponseWriter, epic string, requiredOnly *bool, items []string) (roadmap.WaveRequest, bool) {
	epic = strings.TrimSpace(epic)
	if epic == "" {
		writeErrorCode(w, http.StatusBadRequest, roadmapCodeInvalid, "epic is required: a name or a root issue such as mctlhq/.github#57", nil)
		return roadmap.WaveRequest{}, false
	}
	req := roadmap.WaveRequest{Epic: epic, RequiredOnly: true, Items: items}
	if requiredOnly != nil {
		req.RequiredOnly = *requiredOnly
	}
	for _, id := range items {
		if strings.TrimSpace(id) == "" || id != strings.TrimSpace(id) {
			writeErrorCode(w, http.StatusBadRequest, roadmapCodeInvalid, "items must be exact work-item ids", nil)
			return roadmap.WaveRequest{}, false
		}
	}
	return req, true
}

// ExecuteRoadmapWave handles POST /api/v1/roadmap/waves/execute. The body
// names the plan (its hash, its state_revision and its exact selected ids);
// the plan is re-derived from the latest verified publication and must come
// out identical. Admin-only, like POST /api/v1/agents/dev-loop/start, whose
// idempotent start it uses per item. It never approves a proposal.
func (h *Handlers) ExecuteRoadmapWave(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireTemporalAdmin(w, r)
	if !ok {
		return
	}
	var body waveExecuteRequest
	// Every refusal from here on is audited, including a malformed body.
	auditRefusal := func(code, msg string) {
		h.logAudit(r, audit.Entry{
			UserID: user.ID, Operation: "roadmap-wave-execute", Status: "failed",
			RiskLevel: string(operations.RiskMedium),
			Parameters: map[string]string{
				"epic": body.Epic, "plan_hash": body.PlanHash, "state_revision": body.StateRevision,
				"items": strings.Join(body.Items, ","), "reason": code,
			},
			Message: msg,
		})
	}
	refuse := func(status int, code, msg string, details map[string]any) {
		auditRefusal(code, msg)
		writeErrorCode(w, status, code, msg, details)
	}
	if !decodeWaveBody(w, r, &body) {
		auditRefusal(roadmapCodeInvalid, "malformed request body")
		return
	}
	if body.PlanHash == "" || body.StateRevision == "" || len(body.Items) == 0 {
		refuse(http.StatusBadRequest, roadmapCodeInvalid,
			"plan_hash, state_revision and the plan's exact items are required: plan first with POST /api/v1/roadmap/waves/plan", nil)
		return
	}
	req, ok := waveRequest(w, body.Epic, body.RequiredOnly, body.Items)
	if !ok {
		auditRefusal(roadmapCodeInvalid, "invalid epic or items")
		return
	}
	if h.waveMaxAge() < 0 {
		refuse(http.StatusServiceUnavailable, roadmapCodeWaveDisabled, "ROADMAP_WAVE_MAX_AGE is invalid; wave execution is off", nil)
		return
	}

	// 1. The latest verified publication.
	pub, err := h.opts.Roadmap.Current()
	if err != nil {
		slog.Warn("roadmap wave: publication unavailable", "error", err)
		refuse(http.StatusServiceUnavailable, roadmapCodeUnavailable,
			"no verified roadmap publication: readiness is unknown, not empty", nil)
		return
	}
	prov := pub.Provenance(waveNow())
	// 2. The very publication the plan was made from.
	if prov.StateRevision != body.StateRevision {
		refuse(http.StatusConflict, roadmapCodePlanStale,
			"the roadmap publication changed since the plan was made; plan again",
			map[string]any{"plan_state_revision": body.StateRevision, "current_state_revision": prov.StateRevision})
		return
	}
	// 3. Fresh enough.
	if fresh, why := waveFreshness(prov, h.waveMaxAge()); !fresh {
		refuse(http.StatusConflict, roadmapCodeTooOld, why, map[string]any{"age_seconds": prov.AgeSeconds})
		return
	}
	// 4. Exactly the planned selection and provenance.
	plan, err := pub.PlanWave(req, temporalclient.WorkflowIDForIssueURL, waveNow())
	if err != nil {
		// Every refused execution is audited, whatever the planning error.
		auditRefusal(wavePlanErrorCode(err), err.Error())
		writeWavePlanError(w, err)
		return
	}
	if plan.PlanHash != body.PlanHash {
		refuse(http.StatusConflict, roadmapCodeInvalidSelection,
			"the request does not match the plan it names: epic, required_only, items and state_revision must be the plan's own", nil)
		return
	}

	// 5. Start each item through the idempotent DevLoop start.
	type outcome struct {
		roadmap.WaveItem
		Outcome string `json:"outcome"`
		Status  string `json:"status,omitempty"`
		RunID   string `json:"run_id,omitempty"`
		Error   string `json:"error,omitempty"`
	}
	// A client that disconnects mid-wave must not abort it part-way: the
	// loop finishes what it began, bounded by its own timeout.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), roadmapWaveStartTimeout)
	defer cancel()
	outcomes := make([]outcome, 0, len(plan.Selected))
	for _, it := range plan.Selected {
		o := outcome{WaveItem: it}
		status, err := h.opts.TemporalClient.DescribeDevLoop(ctx, it.WorkflowID)
		switch {
		case err != nil && !temporalclient.IsNotFound(err):
			// Cannot tell whether it exists: do not start blind.
			o.Outcome, o.Error = waveOutcomeFailed, "could not read the DevLoop: "+err.Error()
		case err == nil && status == "Running":
			o.Outcome, o.Status = waveOutcomeAlreadyRunning, status
		case err == nil:
			// A closed DevLoop is not restarted (REJECT_DUPLICATE); report it.
			o.Outcome, o.Status = waveOutcomeAlreadyExists, status
		default:
			wf, runID, err := h.opts.TemporalClient.StartDevLoopWorkflow(ctx, it.IssueURL)
			switch {
			case err != nil:
				o.Outcome, o.Error = waveOutcomeFailed, err.Error()
			case wf != it.WorkflowID:
				o.Outcome, o.Error = waveOutcomeFailed, "started workflow "+wf+", planned "+it.WorkflowID
			default:
				o.Outcome, o.RunID = waveOutcomeStarted, runID
			}
		}
		outcomes = append(outcomes, o)
	}

	ids := make([]string, 0, len(outcomes))
	refs := make([]string, 0, len(outcomes))
	wfs := make([]string, 0, len(outcomes))
	results := make([]string, 0, len(outcomes))
	status := "succeeded"
	for i := range outcomes {
		o := &outcomes[i]
		ids = append(ids, o.ID)
		refs = append(refs, o.Issue.String())
		wfs = append(wfs, o.WorkflowID)
		results = append(results, o.ID+"="+o.Outcome)
		if o.Outcome == waveOutcomeFailed {
			status = "failed"
		}
	}
	captured := ""
	if at := prov.Observation.CapturedAt; at != nil {
		captured = at.UTC().Format(time.RFC3339)
	}
	params := map[string]string{
		"operation_id":            plan.OperationID,
		"plan_hash":               plan.PlanHash,
		"epic":                    plan.Epic.Name,
		"manifest_path":           plan.Epic.Manifest.Path,
		"manifest_sha256":         plan.Epic.Manifest.SHA256,
		"manifest_revision":       prov.Source.Revision,
		"state_revision":          prov.StateRevision,
		"evaluator_revision":      prov.EvaluatorRevision,
		"observation_captured_at": captured,
		"required_only":           strconv.FormatBool(plan.RequiredOnly),
		"items":                   strings.Join(ids, ","),
		"issue_refs":              strings.Join(refs, ","),
		"workflow_ids":            strings.Join(wfs, ","),
		"outcomes":                strings.Join(results, ","),
	}
	if plan.Epic.Issue != nil {
		params["root_issue"] = plan.Epic.Issue.String()
	}
	h.logAudit(r, audit.Entry{
		UserID: user.ID, Operation: "roadmap-wave-execute", Status: status,
		RiskLevel: string(operations.RiskMedium), Parameters: params,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"operation_id": plan.OperationID,
		"plan_hash":    plan.PlanHash,
		"epic":         plan.Epic,
		"provenance":   prov,
		"outcomes":     outcomes,
		"message":      "Starting a wave never approves a proposal: each DevLoop still waits for its human approval.",
	})
}
