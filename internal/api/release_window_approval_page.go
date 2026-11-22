package api

import (
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"golang.org/x/oauth2"

	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Release window approval page (sync-window write path, S2). The only place a
// release.window request is decided.
//
// POST /api/v1/release/windows answers a link to
// /release/window-approvals/{aar_id}. The page asks the person to sign in to
// ZITADEL in this browser, fresh (prompt=login, max_age=0, PKCE S256, a
// nonce), through the release approval page's ZITADEL client, and holds the
// sign-in to exactly what the release page holds it to: a resolved human admin
// acting directly AND one of the configured deciders (owner only), an ID token
// issued to this client (aud and azp), an amr naming a required second factor,
// and a fresh auth_time.
//
// The mechanics are the release approval page's (release_approval_page.go) and
// they share its configuration (client, deciders, required amr), with three
// differences that keep the two pages apart:
//   - its own callback path, so the ZITADEL client needs a second redirect URI
//     (<SELF_URL>/release/window-approvals/callback). The grant page is not
//     touched;
//   - its own cookie and its own flow-store kinds, so a start or decide entry
//     made on one page can never be taken by the other;
//   - a window row is accepted only as a self-consistent release.window
//     (ReleaseWindowOf) and decided only by DecideReleaseWindowApproval, which
//     refuses a release.grant row, as the grant path refuses this one.
//
// What the person is shown is what they approve: the project, the exact
// Applications, the window and its hash, the base commit, and a preview from
// Argo CD of each Application now. The preview is information, not the check:
// release-window-pr.yml renders the window against the live inventory
// (including the bootstrap recovery chain this page does not know) and refuses
// what it must. An Argo CD that cannot be read refuses the page; it is never
// shown as "fine".
//
// Approving changes nothing by itself: it records the decision. The pull
// request is opened by a second call of mctl_propose_release_window (S3).
//
// Dark by default: mounted only when the release approval page options are
// complete and the release window routes are enabled.

const (
	releaseWindowPageCookie      = "__Host-mctl_release_window_approval"
	releaseWindowPagePrefix      = "/release/window-approvals/"
	releaseWindowStartPath       = "/release/window-approvals/start"
	releaseWindowCallbackPath    = "/release/window-approvals/callback"
	releaseWindowConfirmPath     = "/release/window-approvals/confirm"
	releaseWindowPageAuditOp     = "release-window-approval-page"
	releaseWindowNotFoundMessage = "There is no release window approval with this reference waiting for you."

	releaseWindowKindStart  = "release-window-approval-start"
	releaseWindowKindDecide = "release-window-approval-decide"
)

// windowDecider is the release decider's machinery with the window page's own
// callback, cookie and flow kinds.
type windowDecider struct {
	*releaseDecider
}

func newWindowDecider(opts *ReleaseApprovalPageOptions) *windowDecider {
	return &windowDecider{newReleaseDecider(opts)}
}

func (d *windowDecider) oauthConfig(p *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID: d.opts.ClientID, ClientSecret: d.opts.ClientSecret, Endpoint: p.Endpoint(),
		RedirectURL: d.opts.BaseURL + releaseWindowCallbackPath, Scopes: []string{oidc.ScopeOpenID, "profile"},
	}
}

func (d *windowDecider) decideURL(approvalRef string) string {
	return d.opts.BaseURL + releaseWindowPagePrefix + approvalRef
}

func windowBrowser(r *http.Request) string {
	ck, err := r.Cookie(releaseWindowPageCookie)
	if err != nil {
		return ""
	}
	return ck.Value
}

func setWindowCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: releaseWindowPageCookie, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
}

var releaseWindowPage = shellPage("release-window-approval", `{{if .SignIn}}<form class="actions" method="post" action="{{.SignIn.Action}}">
<input type="hidden" name="approval_ref" value="{{.SignIn.ApprovalRef}}">
<button type="submit">Sign in to review this window</button></form>{{end}}
{{if .Decide}}<form class="actions" method="post" action="{{.Decide.Action}}">
<input type="hidden" name="challenge" value="{{.Decide.Challenge}}">
<input type="hidden" name="csrf" value="{{.Decide.CSRF}}">
<button type="submit" name="decision" value="approve">Approve this window</button>
<button type="submit" name="decision" value="reject" class="secondary">Reject</button></form>{{end}}`)

// renderPage works on a nil receiver, for the "not enabled" page.
func (d *windowDecider) renderPage(w http.ResponseWriter, status int, title string, lines []string, p releasePageData) {
	formAction := "'self'"
	if d != nil {
		if u, err := url.Parse(d.opts.Issuer); err == nil && u.Scheme == "https" && u.Host != "" {
			formAction += " https://" + u.Host
		}
	}
	renderShellPage(w, status, "default-src 'none'; style-src 'unsafe-inline'; form-action "+formAction+"; frame-ancestors 'none'; base-uri 'none'",
		releaseWindowPage, shellData{Title: title, Lines: lines, Links: p.Links, Wide: true, Page: p})
}

func (d *windowDecider) failed(w http.ResponseWriter, status int, msg string) {
	d.renderPage(w, status, "Cannot decide this release window", []string{msg, "Open the approval link again to start over."}, releasePageData{})
}

func (d *windowDecider) storeDown(w http.ResponseWriter, err error) {
	slog.Warn("release window approval: flow store unavailable", "error", err)
	d.failed(w, http.StatusServiceUnavailable, "The approval page cannot reach its store right now; nothing was decided. Try again in a few minutes.")
}

func (h *Handlers) releaseWindowPageDecider(w http.ResponseWriter) (*windowDecider, bool) {
	d := h.releaseWindowApproval
	if d == nil || !d.opts.enabled() || h.opts.WorkItems == nil || !h.opts.ReleaseWindows.enabled() {
		var none *windowDecider
		none.failed(w, http.StatusServiceUnavailable, "The release window approval page is not enabled on this server.")
		return nil, false
	}
	return d, true
}

type releaseWindowStartEntry = releaseStartEntry

type releaseWindowDecideEntry = releaseDecideEntry

// handleReleaseWindowApprovalPage: GET /release/window-approvals/{approval_ref}.
// Reads and changes nothing.
func (h *Handlers) handleReleaseWindowApprovalPage(w http.ResponseWriter, r *http.Request) {
	d, ok := h.releaseWindowPageDecider(w)
	if !ok {
		return
	}
	ref := chi.URLParam(r, "approval_ref")
	if !basketApprovalRefRe.MatchString(ref) {
		d.failed(w, http.StatusBadRequest, "This approval link is malformed.")
		return
	}
	d.renderPage(w, http.StatusOK, "Review a release window", []string{
		"Approval: " + ref,
		"Sign in to ZITADEL as yourself, with your second factor, to see the window and approve or reject it. Only the release owner can see or decide it.",
		"Approving records your decision that this one deny window may be added to one Argo CD project by a pull request. It changes nothing by itself.",
	}, releasePageData{SignIn: &struct{ Action, ApprovalRef string }{Action: releaseWindowStartPath, ApprovalRef: ref}})
}

// handleReleaseWindowApprovalStart: POST /release/window-approvals/start.
func (h *Handlers) handleReleaseWindowApprovalStart(w http.ResponseWriter, r *http.Request) {
	d, ok := h.releaseWindowPageDecider(w)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		d.failed(w, http.StatusBadRequest, "The request could not be read.")
		return
	}
	ref := r.PostForm.Get("approval_ref")
	if !basketApprovalRefRe.MatchString(ref) {
		d.failed(w, http.StatusBadRequest, "This approval link is malformed.")
		return
	}
	prov, err := d.oidcProvider(r.Context())
	if err != nil {
		slog.Warn("release window approval: ZITADEL discovery failed", "issuer", d.opts.Issuer, "error", err)
		d.failed(w, http.StatusBadGateway, "ZITADEL is not reachable right now.")
		return
	}
	browser, err1 := randomLinkToken()
	state, err2 := randomLinkToken()
	nonce, err3 := randomLinkToken()
	if err := errors.Join(err1, err2, err3); err != nil {
		d.failed(w, http.StatusInternalServerError, "Internal error.")
		return
	}
	entry := releaseWindowStartEntry{ApprovalRef: ref, StartedAt: d.now(), Nonce: nonce, Verifier: oauth2.GenerateVerifier()}
	if err := d.put(r.Context(), releaseWindowKindStart, basketStartKey(state, browser), entry, releaseChallengeTTL); err != nil {
		d.storeDown(w, err)
		return
	}
	setWindowCookie(w, browser, int(releaseChallengeTTL.Seconds()))
	authURL := d.oauthConfig(prov).AuthCodeURL(state, oauth2.S256ChallengeOption(entry.Verifier), oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("prompt", "login"), oauth2.SetAuthURLParam("max_age", "0"))
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

// windowAppPreview is what Argo CD says about one Application now.
type windowAppPreview struct {
	Name      string
	CanSync   bool
	ActiveNow int
}

// windowShown is a release window as the decider is shown it.
type windowShown struct {
	approval *workitems.ActionApprovalRequest
	window   workitems.ReleaseWindow
	windowID string
	preview  []windowAppPreview
	repo     string
}

func (s *windowShown) decidable(now time.Time) bool {
	return s.approval.State == workitems.ApprovalPending && now.Before(s.approval.ExpiresAt)
}

// binding is what the decider is shown and what confirm must still find: the
// request, its args digest and the window hash. A preview is not part of it.
func (s *windowShown) binding() decisionBinding {
	return decisionBinding{ApprovalRef: s.approval.ID, ContextDigest: s.approval.ArgsDigest, ContentDigest: s.approval.ArtifactHash}
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func (s *windowShown) lines(display string) []string {
	a, w := s.approval, s.window
	requester := a.RequestedBy
	if a.ActorKind != "" {
		requester += " (" + a.ActorKind
		if a.ActorName != "" {
			requester += " " + a.ActorName
		}
		requester += ")"
	}
	out := []string{
		"Signed in as " + display + ".",
		"Project: " + w.Project,
		"Applications (" + strconv.Itoa(len(w.Applications)) + "): " + strings.Join(w.Applications, ", "),
		"Window: deny, cron \"" + w.Schedule + "\" (UTC), duration " + w.Duration,
		"Window id: " + s.windowID,
		"Window hash: " + s.approval.ArtifactHash,
		"Base commit: " + w.BaseSHA,
	}
	if len(s.preview) > 0 {
		out = append(out, "Preview from Argo CD now (information only; the workflow checks the window again and refuses what it must):")
		for _, p := range s.preview {
			out = append(out, "  "+p.Name+": exists, can sync now "+yesNo(p.CanSync)+", active windows "+strconv.Itoa(p.ActiveNow))
		}
	}
	return append(out,
		"Requested by: "+requester,
		"Approval: "+a.ID+" ("+basketStateWord(a.State)+"), expires "+a.ExpiresAt.UTC().Format(time.RFC3339),
	)
}

func (s *windowShown) links() []shellLink {
	if !linkRepoRe.MatchString(s.repo) || !linkSHARe.MatchString(s.window.BaseSHA) {
		return nil
	}
	return []shellLink{{Text: s.window.BaseSHA, URL: "https://github.com/" + s.repo + "/commit/" + s.window.BaseSHA}}
}

// windowPreview asks Argo CD about each Application. Argo answers 404 for an
// Application that is unknown or in another project; an Argo that cannot be
// read, a forbidden read or a client without the reader is "unavailable".
func (h *Handlers) windowPreview(project string, apps []string) ([]windowAppPreview, *releasePageRefusal) {
	reader, ok := h.opts.ArgoCD.(ArgoSyncWindowsReader)
	if h.opts.ArgoCD == nil || !ok {
		return nil, &releasePageRefusal{status: http.StatusServiceUnavailable,
			msg:   "The Application inventory cannot be read right now; nothing was decided. Try again later.",
			audit: "argo reader missing"}
	}
	out := make([]windowAppPreview, 0, len(apps))
	for _, app := range apps {
		aw, err := reader.GetAppSyncWindows(project, app)
		switch {
		case err == nil && aw != nil:
			out = append(out, windowAppPreview{Name: app, CanSync: aw.CanSync, ActiveNow: len(aw.ActiveWindows)})
		case errors.Is(err, argocd.ErrNotFound):
			return nil, &releasePageRefusal{status: http.StatusConflict,
				msg:   "Application " + app + " no longer exists in project " + project + "; nothing can be decided. Ask for a new approval.",
				audit: "application gone"}
		default:
			slog.Warn("release window approval: application unreadable", "project", project, "application", app, "error", err)
			return nil, &releasePageRefusal{status: http.StatusServiceUnavailable,
				msg:   "The Application inventory cannot be read right now; nothing was decided. Try again later.",
				audit: "argo unreadable"}
		}
	}
	return out, nil
}

func releaseWindowNotFound(reason string) *releasePageRefusal {
	return &releasePageRefusal{status: http.StatusNotFound, msg: releaseWindowNotFoundMessage, audit: reason}
}

// readReleaseWindowApproval reads ref as a decider and reads the Applications
// again from Argo CD. Every "not yours" reads like "no such approval".
func (h *Handlers) readReleaseWindowApproval(r *http.Request, d *windowDecider, user *auth.User, ref string) (*windowShown, *releasePageRefusal) {
	if !d.isDecider(user) {
		return nil, releaseWindowNotFound("not a release window decider")
	}
	a, err := h.opts.WorkItems.ActionApproval(r.Context(), ref)
	switch {
	case errors.Is(err, workitems.ErrApprovalNotFound):
		return nil, releaseWindowNotFound("no such approval")
	case err != nil:
		return nil, &releasePageRefusal{status: http.StatusServiceUnavailable, msg: "The approval cannot be read right now; try again later.", audit: "approval read failed"}
	case a.ActionKind != workitems.ActionKindReleaseWindow:
		return nil, releaseWindowNotFound("not a release window approval")
	}
	win, err := workitems.ReleaseWindowOf(a)
	if err != nil {
		return nil, &releasePageRefusal{status: http.StatusConflict, msg: "This approval record is inconsistent; nothing can be decided on it.", audit: "inconsistent record"}
	}
	id, _ := win.ReleaseWindowID()
	shown := &windowShown{approval: a, window: win, windowID: id, repo: h.opts.ReleaseWindows.Repository}
	if !shown.decidable(d.now()) {
		return shown, nil
	}
	preview, refusal := h.windowPreview(win.Project, win.Applications)
	if refusal != nil {
		return nil, refusal
	}
	shown.preview = preview
	return shown, nil
}

// handleReleaseWindowApprovalCallback: GET /release/window-approvals/callback.
func (h *Handlers) handleReleaseWindowApprovalCallback(w http.ResponseWriter, r *http.Request) {
	d, ok := h.releaseWindowPageDecider(w)
	if !ok {
		return
	}
	q := r.URL.Query()
	state, browser := q.Get("state"), windowBrowser(r)
	if state == "" || browser == "" {
		d.failed(w, http.StatusBadRequest, releaseUnknownSignIn)
		return
	}
	var c releaseWindowStartEntry
	found, err := d.take(r.Context(), releaseWindowKindStart, basketStartKey(state, browser), &c)
	if err != nil {
		d.storeDown(w, err)
		return
	}
	if !found || d.remaining(c.StartedAt) <= 0 {
		d.failed(w, http.StatusBadRequest, releaseUnknownSignIn)
		return
	}
	if q.Get("error") != "" {
		d.failed(w, http.StatusBadRequest, "ZITADEL refused the sign-in.")
		return
	}
	code := q.Get("code")
	if code == "" {
		d.failed(w, http.StatusBadRequest, "ZITADEL returned no code.")
		return
	}
	prov, err := d.oidcProvider(r.Context())
	if err != nil {
		d.failed(w, http.StatusBadGateway, "ZITADEL is not reachable right now.")
		return
	}
	tok, err := d.oauthConfig(prov).Exchange(r.Context(), code, oauth2.VerifierOption(c.Verifier))
	if err != nil {
		slog.Warn("release window approval: ZITADEL code exchange failed", "error", err)
		d.failed(w, http.StatusBadGateway, "Could not complete the ZITADEL sign-in.")
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := prov.Verifier(&oidc.Config{ClientID: d.opts.ClientID}).Verify(r.Context(), raw)
	if err != nil {
		slog.Warn("release window approval: ZITADEL ID token refused", "error", err)
		d.failed(w, http.StatusBadRequest, "The ZITADEL ID token was not valid.")
		return
	}
	var claims releaseClaims
	if err := idt.Claims(&claims); err != nil || subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(c.Nonce)) != 1 {
		d.failed(w, http.StatusBadRequest, "The ZITADEL sign-in does not belong to this approval.")
		return
	}
	if claims.AuthTime == 0 || time.Unix(claims.AuthTime, 0).Before(c.StartedAt.Add(-time.Minute)) {
		d.failed(w, http.StatusBadRequest, "ZITADEL did not report a fresh sign-in for this approval.")
		return
	}
	if !issuedToClient(claims.Aud, claims.AZP, d.opts.ClientID) {
		d.failed(w, http.StatusBadRequest, "The ZITADEL ID token was not issued to the release approval page.")
		return
	}
	display := claims.PreferredUsername
	if display == "" {
		display = idt.Subject
	}
	stored := basketIdentity{Provider: d.opts.ProviderName, Issuer: idt.Issuer, Subject: idt.Subject, Display: display}
	id := stored.identity()
	user, err := auth.UserForSignIn(r.Context(), id, d.opts.Principals, d.opts.Authz)
	if err != nil {
		h.auditReleaseWindowPage(r, nil, id, c.ApprovalRef, "denied", "sign-in refused")
		d.failed(w, http.StatusNotFound, releaseWindowNotFoundMessage)
		return
	}
	if !d.isDecider(user) {
		h.auditReleaseWindowPage(r, user, id, c.ApprovalRef, "denied", "not a release window decider")
		d.failed(w, http.StatusNotFound, releaseWindowNotFoundMessage)
		return
	}
	amr := workitems.NormalizeAMR(claims.AMR)
	if !slices.ContainsFunc(d.opts.RequiredAMR, func(m string) bool { return slices.Contains(amr, m) }) {
		got := strings.Join(amr, ", ")
		if got == "" {
			got = "none"
		}
		h.auditReleaseWindowPage(r, user, id, c.ApprovalRef, "denied", "amr without a required method: "+got)
		d.failed(w, http.StatusForbidden, "This sign-in did not report a second factor. ZITADEL reported amr: "+got+
			"; required: one of "+strings.Join(d.opts.RequiredAMR, ", ")+".")
		return
	}
	shown, refusal := h.readReleaseWindowApproval(r, d, user, c.ApprovalRef)
	if refusal != nil {
		h.auditReleaseWindowPage(r, user, id, c.ApprovalRef, "denied", refusal.audit)
		d.failed(w, refusal.status, refusal.msg)
		return
	}
	if !shown.decidable(d.now()) {
		title := "This release window approval is " + basketStateWord(shown.approval.State)
		if shown.approval.State == workitems.ApprovalPending {
			title = "This release window approval has expired"
		}
		d.renderPage(w, http.StatusOK, title, append(shown.lines(display), "There is nothing to decide here."), releasePageData{Links: shown.links()})
		return
	}
	evidence := workitems.ReleaseEvidence{Schema: workitems.ReleaseEvidenceSchema, ArgsDigest: shown.approval.ArgsDigest,
		Issuer: idt.Issuer, Subject: idt.Subject, ClientID: d.opts.ClientID, AuthTime: claims.AuthTime, AMR: amr}
	if err := evidence.Validate(); err != nil {
		h.auditReleaseWindowPage(r, user, id, c.ApprovalRef, "denied", "evidence incomplete")
		d.failed(w, http.StatusBadRequest, "The ZITADEL sign-in is missing what a release window decision records.")
		return
	}
	left := d.remaining(c.StartedAt)
	challenge, err1 := randomLinkToken()
	csrf, err2 := randomLinkToken()
	if err := errors.Join(err1, err2); err != nil {
		d.failed(w, http.StatusInternalServerError, "Internal error.")
		return
	}
	if left <= 0 {
		d.failed(w, http.StatusBadRequest, "This approval page expired while ZITADEL was being verified.")
		return
	}
	entry := releaseWindowDecideEntry{ApprovalRef: c.ApprovalRef, StartedAt: c.StartedAt, Identity: stored, Evidence: evidence, Shown: shown.binding()}
	if err := d.put(r.Context(), releaseWindowKindDecide, basketDecideKey(challenge, csrf, browser), entry, left); err != nil {
		d.storeDown(w, err)
		return
	}
	d.renderPage(w, http.StatusOK, "Approve or reject this release window", append(shown.lines(display),
		"Approving records your decision. It changes nothing by itself: nothing is added to Git and nothing is synced until the pull request is opened and merged."),
		releasePageData{Links: shown.links(), Decide: &struct{ Action, Challenge, CSRF string }{Action: releaseWindowConfirmPath, Challenge: challenge, CSRF: csrf}})
}

// handleReleaseWindowApprovalConfirm: POST /release/window-approvals/confirm.
func (h *Handlers) handleReleaseWindowApprovalConfirm(w http.ResponseWriter, r *http.Request) {
	d, ok := h.releaseWindowPageDecider(w)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		d.failed(w, http.StatusBadRequest, "The request could not be read.")
		return
	}
	decision := r.PostForm.Get("decision")
	if decision != "approve" && decision != "reject" {
		d.failed(w, http.StatusBadRequest, "Choose Approve or Reject.")
		return
	}
	challenge, csrf, browser := r.PostForm.Get("challenge"), r.PostForm.Get("csrf"), windowBrowser(r)
	if challenge == "" || csrf == "" || browser == "" {
		d.failed(w, http.StatusBadRequest, releaseUnknownConfirm)
		return
	}
	var c releaseWindowDecideEntry
	found, err := d.take(r.Context(), releaseWindowKindDecide, basketDecideKey(challenge, csrf, browser), &c)
	if err != nil {
		d.storeDown(w, err)
		return
	}
	if !found || d.remaining(c.StartedAt) <= 0 {
		d.failed(w, http.StatusBadRequest, releaseUnknownConfirm)
		return
	}
	setWindowCookie(w, "", -1)
	id := c.Identity.identity()
	user, err := auth.UserForSignIn(r.Context(), id, d.opts.Principals, d.opts.Authz)
	if err != nil {
		h.auditReleaseWindowPage(r, nil, id, c.ApprovalRef, "denied", "sign-in refused")
		d.failed(w, http.StatusNotFound, releaseWindowNotFoundMessage)
		return
	}
	shown, refusal := h.readReleaseWindowApproval(r, d, user, c.ApprovalRef)
	if refusal != nil {
		h.auditReleaseWindowPage(r, user, id, c.ApprovalRef, "denied", refusal.audit)
		d.failed(w, refusal.status, refusal.msg)
		return
	}
	if shown.binding() != c.Shown {
		h.auditReleaseWindowPage(r, user, id, c.ApprovalRef, "denied", "approval changed since it was shown")
		d.failed(w, http.StatusConflict, "The window or its approval changed after you were shown it; nothing was decided.")
		return
	}
	if !shown.decidable(d.now()) {
		h.auditReleaseWindowPage(r, user, id, c.ApprovalRef, "denied", "not decidable")
		d.failed(w, http.StatusConflict, "This approval is already "+basketStateWord(shown.approval.State)+" or has expired; nothing was decided.")
		return
	}
	if decision == "approve" {
		if status, err := h.approvalPolicies().Admit(shown.approval.PolicyRuleID, shown.approval.PolicyVersion, h.opts.RequireRegisteredPolicy); err != nil {
			h.auditReleaseWindowPage(r, user, id, c.ApprovalRef, "denied", "policy "+status)
			d.failed(w, http.StatusConflict, "The release window policy this approval was asked under is not current; nothing was decided. Ask for a new approval.")
			return
		}
	}
	decided, err := h.opts.WorkItems.DecideReleaseWindowApproval(r.Context(), workitems.ReleaseWindowDecisionInput{
		ID: c.ApprovalRef, DecidedBy: principalOf(user), DecidedByPrincipalID: user.PrincipalID(),
		Approve: decision == "approve", Evidence: c.Evidence,
	})
	if err != nil {
		code := actionApprovalRefusalCode(err)
		if code == "" {
			slog.Error("release window approval: decide failed", "approval", c.ApprovalRef, "error", err)
			code = "decide_failed"
		}
		h.auditReleaseWindowPage(r, user, id, c.ApprovalRef, "failed", decision+": "+code)
		d.failed(w, http.StatusConflict, "The "+decision+" was refused ("+code+"); nothing was decided.")
		return
	}
	h.auditActionApproval(r, user, "action_approval.decision", decided, operations.RiskHigh,
		map[string]string{"surface": releaseWindowPageAuditOp, "amr": strings.Join(c.Evidence.AMR, ",")})
	h.auditReleaseWindowPage(r, user, id, c.ApprovalRef, "succeeded", decision)
	title, outcome := "Release window approved", "Your approval of exactly this window is recorded. It changes nothing by itself: no pull request exists yet. An admin opens it with a second call of mctl_propose_release_window; that pull request is reviewed and merged like any other, and only its merge adds the window. This page opened nothing."
	if decision == "reject" {
		title, outcome = "Release window rejected", "Your rejection of exactly this window is recorded. No pull request will be opened for it; a new window needs a new request and a new approval."
	}
	shown.approval = decided
	d.renderPage(w, http.StatusOK, title, append(shown.lines(id.Display), outcome), releasePageData{Links: shown.links()})
}

// auditReleaseWindowPage records what the page itself decided. Ids only.
func (h *Handlers) auditReleaseWindowPage(r *http.Request, user *auth.User, id auth.Identity, approvalRef, status, msg string) {
	actor := id.Provider + ":" + id.Subject
	if user != nil {
		actor = user.ID
	}
	h.logAudit(r, audit.Entry{
		UserID:     actor,
		Operation:  releaseWindowPageAuditOp,
		Parameters: map[string]string{"approval_ref": approvalRef, "provider": id.Provider, "subject": id.Subject},
		Status:     status,
		RiskLevel:  string(operations.RiskHigh),
		Message:    msg,
	})
}
