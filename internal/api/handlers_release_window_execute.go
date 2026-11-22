package api

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/ghactions"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Release window execution, slice S3 (sync-window write path).
//
//	POST /api/v1/release/windows/{approval_id}/execute
//
// Spends ONE approved release.window by ONE dispatch of release-window-pr.yml
// in mctl-gitops. The workflow opens the pull request release-window/<id> as
// mctl-gitops-pr; it does not merge it, and nothing here syncs anything. A
// person reviews that pull request and merges it like any gitops change, and
// only the merge adds the window.
//
// Only the requester may execute (an admin acting directly, not CI), and the
// execution is addressed by the approval id, not by the window's fields: a
// request repeated with the same fields after main moved would be another
// request (its base_sha is part of the idempotency key), so the approved one
// must be named.
//
// Order, so that a refusal never burns the owner's decision:
//  1. caller, approval and decision are checked (the decision's evidence must
//     reproduce the row, not just the state say "approved");
//  2. everything that can be refused without side effects is refused: no
//     dispatcher, an Argo CD that cannot confirm the Applications still exist;
//  3. one compare-and-set claims the approval (approved -> in_flight);
//  4. the dispatch;
//  5. the claim is settled: executed when GitHub accepted the dispatch, back to
//     approved when it did not, so a retry needs no second human decision.
//
// A retry after an outcome nobody saw (a timeout after GitHub accepted the
// dispatch) is safe: the workflow refuses a window whose branch or open pull
// request already exists. A claim never settled (the process died) is claimable
// again after workitems.ReleaseWindowReclaimAfter.

const (
	releaseWindowWorkflow    = "release-window-pr.yml"
	releaseWindowDispatchRef = "main"

	codeReleaseWindowNotDecided = "release_window_not_decided"
	codeReleaseWindowDispatch   = "release_window_dispatch_failed"
	codeReleaseWindowNoDispatch = "release_window_dispatch_unavailable"
)

// releaseWindowDispatchRepo is the owner and name of the repository the
// workflow runs in: the repository the base commit was read from, so the
// approval and the dispatch name the same one.
func (o *ReleaseWindowOptions) dispatchRepo() (owner, name, full string) {
	full = o.Repository
	if full == "" {
		full = "mctlhq/mctl-gitops"
	}
	owner, name, _ = strings.Cut(full, "/")
	return owner, name, full
}

// ExecuteReleaseWindow answers POST /api/v1/release/windows/{approval_id}/execute.
func (h *Handlers) ExecuteReleaseWindow(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	o := h.opts.ReleaseWindows
	id := chi.URLParam(r, "approval_id")
	params := map[string]string{"approval_id": truncate256(id)}
	refuse := func(status int, code, msg string) {
		h.releaseWindowAudit(r, user, "release.window.execute", "denied", code+": "+msg, params)
		writeErrorCode(w, status, code, msg, nil)
	}
	if !user.IsAdmin() || user.IsCI() {
		refuse(http.StatusForbidden, codeReleaseWindowForbidden, "only an admin may execute a release window")
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
		refuse(http.StatusNotFound, codeReleaseWindowForbidden, "no such release window approval")
		return
	case err != nil:
		slog.Error("release window: read approval", "approval", id, "error", err)
		refuse(http.StatusServiceUnavailable, codeReleaseWindowStore, "the approval could not be read right now")
		return
	// Not yours, and not a window, read like "no such approval".
	case a.ActionKind != workitems.ActionKindReleaseWindow || a.RequestedBy != caller:
		refuse(http.StatusNotFound, codeReleaseWindowForbidden, "no such release window approval")
		return
	}
	win, err := workitems.ReleaseWindowOf(a)
	if err != nil {
		slog.Error("release window: inconsistent record", "approval", id, "error", err)
		refuse(http.StatusInternalServerError, codeReleaseWindowInconsistent, "a release window record does not reproduce its digests")
		return
	}
	windowID, _ := win.ReleaseWindowID()
	hash, _ := win.WindowSHA256()
	params["window_id"], params["window_sha256"], params["base_sha"], params["project"] = windowID, hash, win.BaseSHA, win.Project

	// Only an approved (or a stale in-flight) request is spent. A pending one
	// has not been decided yet: say where, instead of a bare refusal.
	if a.State == workitems.ApprovalPending {
		msg := "the owner has not decided this window yet"
		if h.releaseWindowApproval != nil {
			msg += "; the decide page is " + h.releaseWindowApproval.decideURL(a.ID)
		}
		refuse(http.StatusConflict, codeReleaseWindowNotDecided, msg)
		return
	}
	if a.State == workitems.ApprovalApproved || a.State == workitems.ApprovalInFlight {
		// The state says approved; the evidence must reproduce the row too.
		if ev, err := workitems.ReleaseWindowDecisionOf(a); err != nil || ev == nil {
			slog.Error("release window: decision does not reproduce its record", "approval", id, "error", err)
			refuse(http.StatusInternalServerError, codeReleaseWindowInconsistent, "the decision on this release window does not reproduce its record")
			return
		}
	}

	// What can be refused without side effects is refused before the claim.
	if h.opts.WorkflowDispatcher == nil {
		refuse(http.StatusServiceUnavailable, codeReleaseWindowNoDispatch, "GitHub workflow dispatch is not configured on this server")
		return
	}
	if code, status, msg := h.checkWindowApplications(win.Project, win.Applications); code != "" {
		refuse(status, code, msg)
		return
	}

	claim, err := h.opts.WorkItems.ClaimReleaseWindowApproval(r.Context(), id, caller, a.IntentHash, workitems.ReleaseWindowReclaimAfter)
	if err != nil {
		if code := actionApprovalRefusalCode(err); code != "" {
			h.releaseWindowAudit(r, user, "release.window.execute", "denied", code, params)
		} else {
			slog.Error("release window: claim", "approval", id, "error", err)
			h.releaseWindowAudit(r, user, "release.window.execute", "error", "claim_failed", params)
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
	if err := h.opts.WorkflowDispatcher.Dispatch(r.Context(), owner, repo, releaseWindowWorkflow, releaseWindowDispatchRef, inputs); err != nil {
		// Not accepted: hand the decision back so a retry needs no new one.
		if _, serr := h.opts.WorkItems.SettleReleaseWindowApproval(r.Context(), claim, false); serr != nil {
			slog.Error("release window: could not return the claim after a failed dispatch", "approval", id, "error", serr)
		}
		// A dispatch that never reached GitHub is "unavailable"; only a real
		// refusal from GitHub is a bad gateway.
		status := http.StatusBadGateway
		if errors.Is(err, ghactions.ErrNotConfigured) || errors.Is(err, ghactions.ErrCredentialUnavailable) {
			status = http.StatusServiceUnavailable
		}
		slog.Error("release window: dispatch failed", "approval", id, "window_id", windowID, "error", err)
		h.releaseWindowAudit(r, user, "release.window.execute", "failed", codeReleaseWindowDispatch, params)
		writeErrorCode(w, status, codeReleaseWindowDispatch,
			"the workflow could not be dispatched; the approval is intact and the call can be repeated", nil)
		return
	}

	done, serr := h.opts.WorkItems.SettleReleaseWindowApproval(r.Context(), claim, true)
	resp := map[string]any{
		"schema_version":    workitems.ActionApprovalSchemaVersion,
		"status":            "dispatched",
		"window_id":         windowID,
		"window_sha256":     hash,
		"branch":            "release-window/" + windowID,
		"workflow":          fullRepo + "/.github/workflows/" + releaseWindowWorkflow + "@refs/heads/" + releaseWindowDispatchRef,
		"workflow_runs_url": "https://github.com/" + fullRepo + "/actions/workflows/" + releaseWindowWorkflow,
		"dispatch_inputs":   inputs,
		"next": "The workflow opens the pull request " + "release-window/" + windowID + " as mctl-gitops-pr. " +
			"Review and merge it like any gitops pull request; only its merge adds the window. " +
			"This call merged and synced nothing, and no run id is returned: GitHub does not give one for a dispatch.",
	}
	switch {
	case serr == nil:
		resp["approval"] = done
	case errors.Is(serr, workitems.ErrApprovalExecuted):
		// A newer claim already recorded it.
		resp["approval"] = claim
	default:
		// The dispatch was accepted; the record could not say so. A repeat is
		// safe (the workflow refuses a second pull request for this id) and the
		// claim is claimable again after the reclaim bound.
		slog.Error("release window: dispatched but the claim could not be settled", "approval", id, "error", serr)
		resp["approval"] = claim
		resp["warning"] = "the dispatch was accepted but its record could not be completed; do not request a new approval, look at the runs"
	}
	params["workflow"], params["ref"] = fullRepo+"/"+releaseWindowWorkflow, releaseWindowDispatchRef
	h.releaseWindowAudit(r, user, "release.window.execute", "succeeded", "dispatched", params)
	h.auditActionApproval(r, user, "action_approval.execute", claim, operations.RiskHigh, map[string]string{"surface": "release-window-execute"})
	writeJSON(w, http.StatusOK, resp)
}
