package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/ghactions"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Release window removal (sync-window write path; mctl-gitops
// docs/plans/sync-window-write-path.md, section 6).
//
//	POST /api/v1/release/window-removals
//	     {"project":"apps","applications":["labs-x"],"schedule":"0 22 * * 5","duration":"48h"}
//	POST /api/v1/release/window-removals/{approval_id}/execute
//
// The mirror of the release window routes, for lifting ONE deny window. It is
// a separate kind (release.window.removal) with its own policy, hash and
// decide wording, and these handlers refuse an addition's row as the addition's
// handlers refuse this kind's. The window is named exactly as Argo CD and the
// AppProject template hold it: the same canonical form an addition is made in
// (applications sorted and unique).
//
// POST opens the pending request. The server reads the mctl-gitops main commit
// itself and reads the AppProject's configured windows (spec.syncWindows) from
// Argo CD; unless exactly one of them is this window, with this Application list,
// the request is refused before the owner is asked. That is a pre-check, not the
// authority: Argo CD may lag main, and the workflow
// (release-window-removal-pr.yml) requires the exact window to be held exactly
// once by the project on main and refuses otherwise. No Application is read, so
// a window naming a deleted Application can still be lifted; a project that
// cannot be read is unavailable, never "present" and never "absent".
//
// The execute call is the add one's: one claim, one dispatch (of
// release-window-removal-pr.yml), one settle, and a dispatch GitHub did not
// accept hands the decision back. The owner's MFA approval is the only review;
// the workflow queues the removal pull request itself.

const (
	releaseWindowRemovalWorkflow = "release-window-removal-pr.yml"
	codeReleaseWindowNotAssigned = "release_window_not_assigned"
)

// checkWindowConfigured asks Argo CD for the project's configured windows and
// requires exactly one of them to be win: the same match the workflow makes on
// main (kind deny, schedule, duration, the Applications in the same order, and
// no other restriction).
func (h *Handlers) checkWindowConfigured(win workitems.ReleaseWindow) (code string, status int, msg string) {
	unavailable := func() (string, int, string) {
		return codeReleaseWindowUnavailable, http.StatusServiceUnavailable, "the project's sync windows could not be read right now"
	}
	reader, ok := h.opts.ArgoCD.(ArgoSyncWindowsReader)
	if h.opts.ArgoCD == nil || !ok {
		return unavailable()
	}
	configured, err := reader.GetProjectSyncWindows(win.Project)
	if err != nil || configured == nil {
		slog.Warn("release window removal: project windows", "project", win.Project, "error", err)
		return unavailable()
	}
	matches := 0
	for i := range configured.Windows {
		if isWindowToRemove(&configured.Windows[i], win) {
			matches++
		}
	}
	if matches != 1 {
		return codeReleaseWindowNotAssigned, http.StatusUnprocessableEntity,
			fmt.Sprintf("project %s holds %d deny windows with exactly these applications, this schedule and this duration and no other setting "+
				"(namespaces, clusters, time zone, description, manualSync, andOperator); exactly one is required",
				win.Project, matches)
	}
	return "", 0, ""
}

// isWindowToRemove reports whether a configured window is the one win names. A
// window carrying anything a release window cannot express is a different one.
func isWindowToRemove(c *argocd.SyncWindow, win workitems.ReleaseWindow) bool {
	return c.Kind == "deny" && c.Schedule == win.Schedule && c.Duration == win.Duration &&
		slices.Equal(c.Applications, win.Applications) &&
		len(c.Namespaces) == 0 && len(c.Clusters) == 0 &&
		c.TimeZone == "" && c.Description == "" && !c.ManualSync && !c.AndOperator
}

// RequestReleaseWindowRemoval answers POST /api/v1/release/window-removals.
func (h *Handlers) RequestReleaseWindowRemoval(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	o := h.opts.ReleaseWindows
	params := map[string]string{}
	refuse := func(status int, code, msg string) {
		h.releaseWindowAudit(r, user, "release.window.removal.request", "denied", code+": "+msg, params)
		writeErrorCode(w, status, code, msg, nil)
	}
	if !user.IsAdmin() || user.IsCI() {
		refuse(http.StatusForbidden, codeReleaseWindowForbidden, "only an admin may request the removal of a release window")
		return
	}
	var body struct {
		Project      string   `json:"project"`
		Applications []string `json:"applications"`
		Schedule     string   `json:"schedule"`
		Duration     string   `json:"duration"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, releaseWindowMaxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil || dec.More() {
		refuse(http.StatusBadRequest, codeReleaseWindowInvalid,
			"the body must be {\"project\": ..., \"applications\": [...], \"schedule\": ..., \"duration\": ...}")
		return
	}
	params["project"], params["schedule"], params["duration"] = truncate256(body.Project), truncate256(body.Schedule), truncate256(body.Duration)
	apps := slices.Clone(body.Applications)
	slices.Sort(apps)
	win := workitems.ReleaseWindow{Project: body.Project, Applications: apps, Schedule: body.Schedule, Duration: body.Duration}
	// Shape first, with a placeholder base the server replaces below: a
	// malformed request must not cost a GitHub or Argo call.
	win.BaseSHA = "0000000000000000000000000000000000000000"
	if err := win.Validate(); err != nil {
		refuse(http.StatusBadRequest, codeReleaseWindowInvalid, err.Error())
		return
	}
	base, err := o.Head.Head(r.Context())
	if err != nil {
		slog.Warn("release window removal: base commit unavailable", "error", err)
		refuse(http.StatusServiceUnavailable, codeReleaseWindowUnavailable, "the mctl-gitops main commit could not be read right now")
		return
	}
	win.BaseSHA = base
	if code, status, msg := h.checkWindowConfigured(win); code != "" {
		refuse(status, code, msg)
		return
	}
	intent, err := workitems.ReleaseWindowRemovalIntent(win)
	if err != nil {
		refuse(http.StatusBadRequest, codeReleaseWindowInvalid, err.Error())
		return
	}
	key, _ := workitems.ReleaseWindowRemovalIdempotencyKey(win)
	id, _ := win.ReleaseWindowRemovalID()
	hash, _ := win.RemovalSHA256()
	params["window_id"], params["removal_sha256"], params["base_sha"] = id, hash, base

	actor, subject := actorAndSubject(user)
	in := workitems.ActionApprovalInput{
		ActionIntent:           intent,
		RequestedBy:            principalOf(user),
		RequestedByPrincipalID: user.PrincipalID(),
		ViaPrincipalID:         user.ViaPrincipalID(),
		ActorKind:              actor.Kind,
		ActorName:              actor.Name,
		AgentRunID:             user.AgentRunID(),
		IdempotencyKey:         key,
		ExpiresAt:              h.deployPlanNow().Add(o.ttl()),
		RiskLevel:              string(operations.RiskHigh),
		IntentSource:           "release-window-removal:" + win.Project + "/" + id,
	}
	if subject != nil {
		in.SubjectPrincipalID, in.SubjectKind = subject.PrincipalID, subject.Kind
	}
	pol := h.approvalPolicies()[workitems.ReleaseWindowRemovalPolicyRuleID]
	in.SideEffect, in.PolicyDecision = pol.SideEffect, pol.Decision
	in.PolicyReasons = append([]string(nil), pol.Reasons...)
	approval, created, err := h.opts.WorkItems.CreateReleaseWindowRemovalApproval(r.Context(), win, in)
	if err != nil {
		if code := actionApprovalRefusalCode(err); code != "" {
			h.releaseWindowAudit(r, user, "release.window.removal.request", "denied", code, params)
		} else {
			slog.Error("release window removal: create", "window_id", id, "error", err)
			h.releaseWindowAudit(r, user, "release.window.removal.request", "error", "create_failed", params)
		}
		writeActionApprovalError(w, err)
		return
	}
	params["approval_id"] = approval.ID
	if created {
		h.auditActionApproval(r, user, "action_approval.create", approval, operations.RiskHigh, nil)
		h.releaseWindowAudit(r, user, "release.window.removal.request", "succeeded", "succeeded", params)
	} else {
		h.releaseWindowAudit(r, user, "release.window.removal.request", "succeeded", "replayed", params)
	}
	out := map[string]any{
		"schema_version": workitems.ActionApprovalSchemaVersion,
		"removal": map[string]any{
			"approval": approval, "window": win, "window_id": id, "removal_sha256": hash,
		},
		"decided_by": "the owner, signed in fresh with a second factor on the release window approval page; a bearer token cannot decide it",
	}
	if h.releaseWindowApproval != nil {
		out["decide_url"] = h.releaseWindowApproval.removalDecideURL(approval.ID)
	} else {
		out["decide_unavailable"] = "the release window approval page is not enabled on this server, so this request cannot be decided"
	}
	writeJSON(w, createdStatus(created), out)
}

// ExecuteReleaseWindowRemoval answers
// POST /api/v1/release/window-removals/{approval_id}/execute.
func (h *Handlers) ExecuteReleaseWindowRemoval(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	o := h.opts.ReleaseWindows
	id := chi.URLParam(r, "approval_id")
	params := map[string]string{"approval_id": truncate256(id)}
	refuse := func(status int, code, msg string) {
		h.releaseWindowAudit(r, user, "release.window.removal.execute", "denied", code+": "+msg, params)
		writeErrorCode(w, status, code, msg, nil)
	}
	if !user.IsAdmin() || user.IsCI() {
		refuse(http.StatusForbidden, codeReleaseWindowForbidden, "only an admin may execute the removal of a release window")
		return
	}
	if !basketApprovalRefRe.MatchString(id) {
		refuse(http.StatusBadRequest, codeReleaseWindowInvalid, "the approval id is malformed")
		return
	}
	caller := principalOf(user)
	a, err := h.opts.WorkItems.ActionApproval(r.Context(), id)
	switch {
	case errors.Is(err, workitems.ErrApprovalNotFound):
		refuse(http.StatusNotFound, codeReleaseWindowForbidden, "no such release window removal approval")
		return
	case err != nil:
		slog.Error("release window removal: read approval", "approval", id, "error", err)
		refuse(http.StatusServiceUnavailable, codeReleaseWindowStore, "the approval could not be read right now")
		return
	// Not yours, and not a removal (an addition included), read like "no such approval".
	case a.ActionKind != workitems.ActionKindReleaseWindowRemoval || a.RequestedBy != caller:
		refuse(http.StatusNotFound, codeReleaseWindowForbidden, "no such release window removal approval")
		return
	}
	win, err := workitems.ReleaseWindowRemovalOf(a)
	if err != nil {
		slog.Error("release window removal: inconsistent record", "approval", id, "error", err)
		refuse(http.StatusInternalServerError, codeReleaseWindowInconsistent, "a release window removal record does not reproduce its digests")
		return
	}
	windowID, _ := win.ReleaseWindowRemovalID()
	hash, _ := win.RemovalSHA256()
	params["window_id"], params["removal_sha256"], params["base_sha"], params["project"] = windowID, hash, win.BaseSHA, win.Project

	if a.State == workitems.ApprovalPending {
		msg := "the owner has not decided this removal yet"
		if h.releaseWindowApproval != nil {
			msg += "; the decide page is " + h.releaseWindowApproval.removalDecideURL(a.ID)
		}
		refuse(http.StatusConflict, codeReleaseWindowNotDecided, msg)
		return
	}
	if a.State == workitems.ApprovalApproved || a.State == workitems.ApprovalInFlight {
		// The state says approved; the evidence must reproduce the row too.
		if ev, err := workitems.ReleaseWindowRemovalDecisionOf(a); err != nil || ev == nil {
			slog.Error("release window removal: decision does not reproduce its record", "approval", id, "error", err)
			refuse(http.StatusInternalServerError, codeReleaseWindowInconsistent, "the decision on this release window removal does not reproduce its record")
			return
		}
	}

	// What can be refused without side effects is refused before the claim.
	// No Argo CD check here: an Argo CD that cannot be read must not stop an
	// approved removal, and the workflow checks the window on main.
	if h.opts.WorkflowDispatcher == nil {
		refuse(http.StatusServiceUnavailable, codeReleaseWindowNoDispatch, "GitHub workflow dispatch is not configured on this server")
		return
	}

	claim, err := h.opts.WorkItems.ClaimReleaseWindowRemovalApproval(r.Context(), id, caller, a.IntentHash, workitems.ReleaseWindowReclaimAfter)
	if err != nil {
		if code := actionApprovalRefusalCode(err); code != "" {
			h.releaseWindowAudit(r, user, "release.window.removal.execute", "denied", code, params)
		} else {
			slog.Error("release window removal: claim", "approval", id, "error", err)
			h.releaseWindowAudit(r, user, "release.window.removal.execute", "error", "claim_failed", params)
		}
		writeActionApprovalError(w, err)
		return
	}

	owner, repo, fullRepo := o.dispatchRepo()
	inputs := map[string]string{
		"window_id":     windowID,
		"project":       win.Project,
		"applications":  strings.Join(win.Applications, ","),
		"schedule":      win.Schedule,
		"duration":      win.Duration,
		"base_sha":      win.BaseSHA,
		"window_sha256": hash,
	}
	dispatchErr := h.opts.WorkflowDispatcher.Dispatch(r.Context(), owner, repo, releaseWindowRemovalWorkflow, releaseWindowDispatchRef, inputs)
	if err := dispatchErr; err != nil {
		settleCtx, cancelSettle := o.settleContext(r.Context())
		defer cancelSettle()
		// Not accepted: hand the decision back so a retry needs no new one.
		if _, serr := h.opts.WorkItems.SettleReleaseWindowRemovalApproval(settleCtx, claim, false); serr != nil {
			slog.Error("release window removal: could not return the claim after a failed dispatch", "approval", id, "error", serr)
		}
		status := http.StatusBadGateway
		if errors.Is(err, ghactions.ErrNotConfigured) || errors.Is(err, ghactions.ErrCredentialUnavailable) {
			status = http.StatusServiceUnavailable
		}
		slog.Error("release window removal: dispatch failed", "approval", id, "window_id", windowID, "error", err)
		h.releaseWindowAudit(r, user, "release.window.removal.execute", "failed", codeReleaseWindowDispatch, params)
		writeErrorCode(w, status, codeReleaseWindowDispatch,
			"the workflow could not be dispatched; the approval is intact and the call can be repeated", nil)
		return
	}

	settleCtx, cancelSettle := o.settleContext(r.Context())
	defer cancelSettle()
	done, serr := h.opts.WorkItems.SettleReleaseWindowRemovalApproval(settleCtx, claim, true)
	resp := map[string]any{
		"schema_version":    workitems.ActionApprovalSchemaVersion,
		"status":            "dispatched",
		"window_id":         windowID,
		"removal_sha256":    hash,
		"branch":            "release-window-removal/" + windowID,
		"workflow":          fullRepo + "/.github/workflows/" + releaseWindowRemovalWorkflow + "@refs/heads/" + releaseWindowDispatchRef,
		"workflow_runs_url": "https://github.com/" + fullRepo + "/actions/workflows/" + releaseWindowRemovalWorkflow,
		"dispatch_inputs":   inputs,
		"next": "The workflow opens the pull request " + "release-window-removal/" + windowID + " as mctl-gitops-pr, " +
			"which deletes the window, and queues it for merge; the owner's approval is the only review and no person merges it. " +
			"The window is gone once the pull request has merged and Argo CD has synced it. A failing check leaves the pull request open and the window in place. " +
			"This call merged and synced nothing itself, and no run id is returned: GitHub does not give one for a dispatch.",
	}
	switch {
	case serr == nil:
		resp["approval"] = done
	case errors.Is(serr, workitems.ErrApprovalExecuted):
		resp["approval"] = claim
	default:
		slog.Error("release window removal: dispatched but the claim could not be settled", "approval", id, "error", serr)
		resp["approval"] = claim
		resp["warning"] = "the dispatch was accepted but its record could not be completed; do not request a new approval, look at the runs"
	}
	params["workflow"], params["ref"] = fullRepo+"/"+releaseWindowRemovalWorkflow, releaseWindowDispatchRef
	h.releaseWindowAudit(r, user, "release.window.removal.execute", "succeeded", "dispatched", params)
	h.auditActionApproval(r, user, "action_approval.execute", claim, operations.RiskHigh, map[string]string{"surface": "release-window-removal-execute"})
	writeJSON(w, http.StatusOK, resp)
}
