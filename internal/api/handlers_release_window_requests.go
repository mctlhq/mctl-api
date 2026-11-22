package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Release windows, slice S1 (sync-window write path, proposal issue-2828 8.2).
//
//	POST /api/v1/release/windows
//	     {"project":"apps","applications":["labs-x"],"schedule":"0 22 * * 5","duration":"48h"}
//	GET  /api/v1/release/windows?project=apps&window_id=w-0123456789ab
//
// POST opens the pending release.window request for one deny window. The
// server reads the mctl-gitops main commit itself (base_sha) and checks that
// every named Application exists in the project, then binds the request to the
// window and its hash; nothing in the intent comes from the body but the four
// window fields. The request grants nothing: nothing in this slice can decide
// or spend it, so every request created now stays pending. Deciding is S2 (a
// fresh, MFA-backed sign-in page), the pull request is S3.
//
// This is a pre-check, not the authority: the workflow (release-window-pr.yml)
// renders the window against the live inventory, including the bootstrap
// recovery chain this layer does not know, and refuses what it must.
//
// Dark by default: the routes exist only when ReleaseWindows is configured
// (RELEASE_WINDOWS_ENABLED=true in cmd/api).

const (
	codeReleaseWindowInvalid      = "release_window_invalid_input"
	codeReleaseWindowForbidden    = "release_window_forbidden"
	codeReleaseWindowUnknownApp   = "release_window_unknown_application"
	codeReleaseWindowUnavailable  = "release_window_unavailable"
	codeReleaseWindowStore        = "release_window_store_unavailable"
	codeReleaseWindowInconsistent = "release_window_record_inconsistent"

	releaseWindowMaxBody    = 8192
	defaultReleaseWindowTTL = 72 * time.Hour
)

// ReleaseWindowHeadReader reads the mctl-gitops main commit a window approval
// is given on. *gitopshead.Resolver implements it.
type ReleaseWindowHeadReader interface {
	Head(ctx context.Context) (string, error)
}

// ReleaseWindowOptions configures the release window routes.
type ReleaseWindowOptions struct {
	Head ReleaseWindowHeadReader
	// Repository is the owner/name the base commit belongs to; the approval
	// page links the commit to it. Empty shows the commit as plain text.
	Repository string
	// TTL is how long a request stays decidable; zero means 72 hours.
	TTL time.Duration
}

func (o *ReleaseWindowOptions) enabled() bool { return o != nil && o.Head != nil }

func (o *ReleaseWindowOptions) ttl() time.Duration {
	if o.TTL > 0 {
		return o.TTL
	}
	return defaultReleaseWindowTTL
}

type releaseWindowView struct {
	Approval     *workitems.ActionApprovalRequest `json:"approval"`
	Window       workitems.ReleaseWindow          `json:"window"`
	WindowID     string                           `json:"window_id"`
	WindowSHA256 string                           `json:"window_sha256"`
}

func (h *Handlers) releaseWindowAudit(r *http.Request, user *auth.User, op, status, msg string, params map[string]string) {
	h.logAudit(r, audit.Entry{
		UserID: user.ID, Operation: op, Parameters: params, Status: status,
		RiskLevel: string(operations.RiskHigh), Message: msg,
	})
}

func releaseWindowViewOf(a *workitems.ActionApprovalRequest) (releaseWindowView, error) {
	w, err := workitems.ReleaseWindowOf(a)
	if err != nil {
		return releaseWindowView{}, err
	}
	id, err := w.ReleaseWindowID()
	if err != nil {
		return releaseWindowView{}, err
	}
	hash, err := w.WindowSHA256()
	if err != nil {
		return releaseWindowView{}, err
	}
	return releaseWindowView{Approval: a, Window: w, WindowID: id, WindowSHA256: hash}, nil
}

// checkWindowApplications asks Argo CD whether each Application exists under
// the project. Argo answers 404 both for an unknown Application and for one in
// another project, which is the refusal wanted either way. An Argo that cannot
// be read, or a client without the reader, is "unavailable", never "exists".
func (h *Handlers) checkWindowApplications(project string, apps []string) (code string, status int, msg string) {
	reader, ok := h.opts.ArgoCD.(ArgoSyncWindowsReader)
	if h.opts.ArgoCD == nil || !ok {
		return codeReleaseWindowUnavailable, http.StatusServiceUnavailable, "the Application inventory could not be read right now"
	}
	for _, app := range apps {
		_, err := reader.GetAppSyncWindows(project, app)
		switch {
		case err == nil:
		case errors.Is(err, argocd.ErrNotFound):
			return codeReleaseWindowUnknownApp, http.StatusUnprocessableEntity,
				"application " + app + " does not exist in project " + project
		default:
			slog.Warn("release window: application check", "project", project, "application", app, "error", err)
			return codeReleaseWindowUnavailable, http.StatusServiceUnavailable, "the Application inventory could not be read right now"
		}
	}
	return "", 0, ""
}

// RequestReleaseWindow answers POST /api/v1/release/windows.
func (h *Handlers) RequestReleaseWindow(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	o := h.opts.ReleaseWindows
	params := map[string]string{}
	refuse := func(status int, code, msg string) {
		h.releaseWindowAudit(r, user, "release.window.request", "denied", code+": "+msg, params)
		writeErrorCode(w, status, code, msg, nil)
	}
	// Requesting grants nothing, but only an admin may put a window in front
	// of the owner.
	if !user.IsAdmin() || user.IsCI() {
		refuse(http.StatusForbidden, codeReleaseWindowForbidden, "only an admin may request a release window")
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
		slog.Warn("release window: base commit unavailable", "error", err)
		refuse(http.StatusServiceUnavailable, codeReleaseWindowUnavailable, "the mctl-gitops main commit could not be read right now")
		return
	}
	win.BaseSHA = base
	if code, status, msg := h.checkWindowApplications(win.Project, win.Applications); code != "" {
		refuse(status, code, msg)
		return
	}
	intent, err := workitems.ReleaseWindowIntent(win)
	if err != nil {
		refuse(http.StatusBadRequest, codeReleaseWindowInvalid, err.Error())
		return
	}
	key, _ := workitems.ReleaseWindowIdempotencyKey(win)
	id, _ := win.ReleaseWindowID()
	hash, _ := win.WindowSHA256()
	params["window_id"], params["window_sha256"], params["base_sha"] = id, hash, base

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
		IntentSource:           "release-window:" + win.Project + "/" + id,
	}
	if subject != nil {
		in.SubjectPrincipalID, in.SubjectKind = subject.PrincipalID, subject.Kind
	}
	pol := h.approvalPolicies()[workitems.ReleaseWindowPolicyRuleID]
	in.SideEffect, in.PolicyDecision = pol.SideEffect, pol.Decision
	in.PolicyReasons = append([]string(nil), pol.Reasons...)
	approval, created, err := h.opts.WorkItems.CreateReleaseWindowApproval(r.Context(), win, in)
	if err != nil {
		if code := actionApprovalRefusalCode(err); code != "" {
			h.releaseWindowAudit(r, user, "release.window.request", "denied", code, params)
		} else {
			slog.Error("release window: create", "window_id", id, "error", err)
			h.releaseWindowAudit(r, user, "release.window.request", "error", "create_failed", params)
		}
		writeActionApprovalError(w, err)
		return
	}
	params["approval_id"] = approval.ID
	if created {
		h.auditActionApproval(r, user, "action_approval.create", approval, operations.RiskHigh, nil)
		h.releaseWindowAudit(r, user, "release.window.request", "succeeded", "succeeded", params)
	} else {
		h.releaseWindowAudit(r, user, "release.window.request", "succeeded", "replayed", params)
	}
	out := map[string]any{
		"schema_version": workitems.ActionApprovalSchemaVersion,
		"window":         releaseWindowView{Approval: approval, Window: win, WindowID: id, WindowSHA256: hash},
		"decided_by":     "the owner, signed in fresh with a second factor on the release window approval page; a bearer token cannot decide it",
	}
	if h.releaseWindowApproval != nil {
		out["decide_url"] = h.releaseWindowApproval.decideURL(approval.ID)
	} else {
		out["decide_unavailable"] = "the release window approval page is not enabled on this server, so this request cannot be decided"
	}
	writeJSON(w, createdStatus(created), out)
}

// ListReleaseWindows answers GET /api/v1/release/windows.
func (h *Handlers) ListReleaseWindows(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	q := r.URL.Query()
	project, windowID := q.Get("project"), q.Get("window_id")
	params := map[string]string{"project": truncate256(project), "window_id": truncate256(windowID)}
	if !user.IsAdmin() || user.IsCI() {
		h.releaseWindowAudit(r, user, "release.window.list", "denied", "not an admin", params)
		writeErrorCode(w, http.StatusForbidden, codeReleaseWindowForbidden, "release windows are readable by admins only", nil)
		return
	}
	rows, err := h.opts.WorkItems.ReleaseWindowApprovals(r.Context(), project, windowID, 0)
	switch {
	case errors.Is(err, workitems.ErrInvalid):
		h.releaseWindowAudit(r, user, "release.window.list", "denied", codeReleaseWindowInvalid, params)
		writeErrorCode(w, http.StatusBadRequest, codeReleaseWindowInvalid, err.Error(), nil)
		return
	case err != nil:
		slog.Error("release window: list", "window_id", windowID, "error", err)
		h.releaseWindowAudit(r, user, "release.window.list", "error", codeReleaseWindowStore, params)
		writeErrorCode(w, http.StatusServiceUnavailable, codeReleaseWindowStore, "release windows could not be read", nil)
		return
	}
	out := make([]releaseWindowView, 0, len(rows))
	for i := range rows {
		v, err := releaseWindowViewOf(&rows[i])
		if err != nil {
			slog.Error("release window: inconsistent record", "id", rows[i].ID, "error", err)
			params["approval_id"] = rows[i].ID
			h.releaseWindowAudit(r, user, "release.window.list", "error", codeReleaseWindowInconsistent, params)
			writeErrorCode(w, http.StatusInternalServerError, codeReleaseWindowInconsistent,
				"a release window record does not reproduce its digests", map[string]any{"approval_id": rows[i].ID})
			return
		}
		out = append(out, v)
	}
	h.releaseWindowAudit(r, user, "release.window.list", "succeeded", "succeeded", params)
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": workitems.ActionApprovalSchemaVersion,
		"project":        project,
		"window_id":      windowID,
		"windows":        out,
	})
}
