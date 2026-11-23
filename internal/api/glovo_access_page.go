// Copyright 2026 MCTL Authors
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
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"golang.org/x/oauth2"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovoconsent"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Glovo access decision page (mctl-glovo#82, stage B, design 5.4 and D1). The
// only place a Glovo access request is approved or rejected, and the only
// place approved access is revoked: no bearer, token or service route
// decides. It is the release approval page's machinery (release_approval_page.go)
// with its own paths, cookie and flow kinds, configured by the same
// ReleaseApprovalPageOptions (client, deciders, required amr), the way the
// release window page is:
//
//   - fresh ZITADEL sign-in (prompt=login, max_age=0, PKCE S256, nonce);
//   - the person must be a resolved human admin acting directly AND one of the
//     configured deciders;
//   - the ID token must be issued to the page's client and its amr must name a
//     required method (default mfa);
//   - the decision form carries a one-time challenge and CSRF token bound to the
//     browser cookie, held in the shared flow store (several replicas), spent
//     with an atomic Take;
//   - the access row is read again on confirm and must still be what the page
//     showed, so a request withdrawn and reopened in between is not decided
//     on a stale view.
//
// The page shows the principal id only: no email, no display name, no host.
// The decision and its reason go to the access store, which appends an
// event; the page also writes one audit row per attempt. Nothing is
// decided without the reason (mandatory, design 5.4).
//
// Dark by default: mounted only when the release approval page options are
// complete and the access store is wired. The ZITADEL client's redirect URIs
// must include BaseURL + glovoAccessCallbackPath.

const (
	glovoAccessPageCookie      = "__Host-mctl_glovo_access_decision"
	glovoAccessPagePrefix      = "/glovo/access-approvals/"
	glovoAccessStartPath       = "/glovo/access-approvals/start"
	glovoAccessCallbackPath    = "/glovo/access-approvals/callback"
	glovoAccessConfirmPath     = "/glovo/access-approvals/confirm"
	glovoAccessPageAuditOp     = "glovo-access-approval-page"
	glovoAccessNotFoundMessage = "There is no Glovo access request with this reference waiting for you."

	glovoAccessKindStart  = "glovo-access-approval-start"
	glovoAccessKindDecide = "glovo-access-approval-decide"

	glovoAccessDecisionApprove = "approve"
	glovoAccessDecisionReject  = "reject"
	glovoAccessDecisionRevoke  = "revoke"
)

// glovoAccessDecider is the release decider's machinery with the access
// page's own callback, cookie and flow kinds.
type glovoAccessDecider struct {
	*releaseDecider
}

func newGlovoAccessDecider(opts *ReleaseApprovalPageOptions) *glovoAccessDecider {
	return &glovoAccessDecider{newReleaseDecider(opts)}
}

type glovoAccessStartEntry struct {
	Principal string    `json:"principal"`
	StartedAt time.Time `json:"started_at"`
	Nonce     string    `json:"nonce"`
	Verifier  string    `json:"verifier"`
}

// glovoAccessBinding is what the decider was shown. Times are RFC 3339 text so
// the comparison is exact and survives the flow store's JSON.
type glovoAccessBinding struct {
	Principal   string `json:"principal"`
	Status      string `json:"status"`
	RequestedAt string `json:"requested_at"`
	DecidedAt   string `json:"decided_at"`
}

type glovoAccessDecideEntry struct {
	Principal string             `json:"principal"`
	StartedAt time.Time          `json:"started_at"`
	Identity  basketIdentity     `json:"identity"`
	AMR       []string           `json:"amr"`
	Shown     glovoAccessBinding `json:"shown"`
}

func (d *glovoAccessDecider) oauthConfig(p *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID: d.opts.ClientID, ClientSecret: d.opts.ClientSecret, Endpoint: p.Endpoint(),
		RedirectURL: d.opts.BaseURL + glovoAccessCallbackPath, Scopes: []string{oidc.ScopeOpenID, "profile"},
	}
}

func (d *glovoAccessDecider) decideURL(principal string) string {
	return d.opts.BaseURL + glovoAccessPagePrefix + principal
}

func glovoAccessBrowser(r *http.Request) string {
	ck, err := r.Cookie(glovoAccessPageCookie)
	if err != nil {
		return ""
	}
	return ck.Value
}

func setGlovoAccessCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: glovoAccessPageCookie, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
}

var glovoAccessPage = shellPage("glovo-access-approval", `{{if .SignIn}}<form class="actions" method="post" action="{{.SignIn.Action}}">
<input type="hidden" name="principal" value="{{.SignIn.Principal}}">
<button type="submit">Sign in to review this request</button></form>{{end}}
{{if .Decide}}<form class="actions" method="post" action="{{.Decide.Action}}">
<input type="hidden" name="challenge" value="{{.Decide.Challenge}}">
<input type="hidden" name="csrf" value="{{.Decide.CSRF}}">
<label for="reason">Reason (required, recorded with your decision)</label>
<input type="text" id="reason" name="reason" required maxlength="500" autocomplete="off">
{{if .Decide.Pending}}<button type="submit" name="decision" value="approve">Approve access</button>
<button type="submit" name="decision" value="reject" class="secondary">Reject</button>{{end}}
{{if .Decide.Approved}}<button type="submit" name="decision" value="revoke">Revoke access</button>{{end}}</form>{{end}}`)

type glovoAccessPageData struct {
	SignIn *struct{ Action, Principal string }
	Decide *struct {
		Action, Challenge, CSRF string
		Pending, Approved       bool
	}
}

// renderPage works on a nil receiver, for the "not enabled" page.
func (d *glovoAccessDecider) renderPage(w http.ResponseWriter, status int, title string, lines []string, p glovoAccessPageData) {
	formAction := "'self'"
	if d != nil {
		if u, err := url.Parse(d.opts.Issuer); err == nil && u.Scheme == "https" && u.Host != "" {
			formAction += " https://" + u.Host
		}
	}
	renderShellPage(w, status, "default-src 'none'; style-src 'unsafe-inline'; form-action "+formAction+"; frame-ancestors 'none'; base-uri 'none'",
		glovoAccessPage, shellData{Title: title, Lines: lines, Page: p})
}

func (d *glovoAccessDecider) failed(w http.ResponseWriter, status int, msg string) {
	d.renderPage(w, status, "Cannot decide this access request", []string{msg, "Open the decision link again to start over."}, glovoAccessPageData{})
}

func (d *glovoAccessDecider) storeDown(w http.ResponseWriter, err error) {
	slog.Warn("glovo access approval: flow store unavailable", "error", err)
	d.failed(w, http.StatusServiceUnavailable, "The decision page cannot reach its store right now; nothing was decided. Try again in a few minutes.")
}

func (h *Handlers) glovoAccessPageDecider(w http.ResponseWriter) (*glovoAccessDecider, bool) {
	d := h.glovoAccessApproval
	if d == nil || !d.opts.enabled() || !h.opts.GlovoConsent.accessMounted() {
		var none *glovoAccessDecider
		none.failed(w, http.StatusServiceUnavailable, "The Glovo access decision page is not enabled on this server.")
		return nil, false
	}
	return d, true
}

// glovoAccessShown is an access row as the decider is shown it.
type glovoAccessShown struct {
	access glovoconsent.Access
}

func (s *glovoAccessShown) pendingNow(now time.Time) bool {
	return s.access.Status == glovoconsent.AccessPending && !s.access.ExpiresAt.IsZero() && !now.After(s.access.ExpiresAt)
}

func (s *glovoAccessShown) approved() bool { return s.access.Status == glovoconsent.AccessApproved }

func (s *glovoAccessShown) decidable(now time.Time) bool { return s.pendingNow(now) || s.approved() }

func glovoAccessTime(t *time.Time) string {
	if t == nil || t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func (s *glovoAccessShown) binding() glovoAccessBinding {
	a := s.access
	b := glovoAccessBinding{Principal: a.PrincipalID, Status: string(a.Status), DecidedAt: glovoAccessTime(a.DecidedAt)}
	if !a.RequestedAt.IsZero() {
		b.RequestedAt = a.RequestedAt.UTC().Format(time.RFC3339Nano)
	}
	return b
}

func (s *glovoAccessShown) lines(now time.Time) []string {
	a := s.access
	state := string(a.Status)
	if a.Status == glovoconsent.AccessPending && !s.pendingNow(now) {
		state = "pending, but expired"
	}
	out := []string{"Principal: " + a.PrincipalID, "Status: " + state}
	if !a.RequestedAt.IsZero() {
		out = append(out, "Requested: "+a.RequestedAt.UTC().Format(time.RFC3339))
	}
	if a.Status == glovoconsent.AccessPending && !a.ExpiresAt.IsZero() {
		out = append(out, "Expires: "+a.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if a.DecidedAt != nil && a.DecidedBy != "" {
		out = append(out, "Last decision: "+a.DecidedAt.UTC().Format(time.RFC3339)+" by "+a.DecidedBy)
	}
	return out
}

type glovoAccessRefusal struct {
	status int
	msg    string
	audit  string
}

// readGlovoAccess reads principal as a decider. Every "not yours" reads like
// "no such request"; a failed or inconsistent read is a 503, never an empty
// or "none" answer.
func (h *Handlers) readGlovoAccess(r *http.Request, d *glovoAccessDecider, user *auth.User, principal string) (*glovoAccessShown, *glovoAccessRefusal) {
	if !d.isDecider(user) {
		return nil, &glovoAccessRefusal{status: http.StatusNotFound, msg: glovoAccessNotFoundMessage, audit: "not a decider"}
	}
	a, err := h.opts.GlovoConsent.Access.GetAccess(r.Context(), principal)
	if err != nil || !validAccessOf(a, principal) {
		slog.Warn("glovo access approval: access row unreadable", "error", err)
		return nil, &glovoAccessRefusal{status: http.StatusServiceUnavailable,
			msg: "The access request cannot be read right now; nothing was decided. Try again later.", audit: "access read failed"}
	}
	if a.Status == glovoconsent.AccessNone {
		return nil, &glovoAccessRefusal{status: http.StatusNotFound, msg: glovoAccessNotFoundMessage, audit: "no such request"}
	}
	return &glovoAccessShown{access: a}, nil
}

// handleGlovoAccessPage: GET /glovo/access-approvals/{principal_id}. Reads and
// changes nothing.
func (h *Handlers) handleGlovoAccessPage(w http.ResponseWriter, r *http.Request) {
	d, ok := h.glovoAccessPageDecider(w)
	if !ok {
		return
	}
	pid := chi.URLParam(r, "principal_id")
	if !auth.ValidPrincipalID(pid) {
		d.failed(w, http.StatusBadRequest, "This decision link is malformed.")
		return
	}
	d.renderPage(w, http.StatusOK, "Review a Glovo access request", []string{
		"Request: " + pid,
		"Sign in to ZITADEL as yourself, with your second factor, to see the request and approve, reject or revoke it. Only an access decider can see or decide it.",
	}, glovoAccessPageData{SignIn: &struct{ Action, Principal string }{Action: glovoAccessStartPath, Principal: pid}})
}

// handleGlovoAccessStart: POST /glovo/access-approvals/start.
func (h *Handlers) handleGlovoAccessStart(w http.ResponseWriter, r *http.Request) {
	d, ok := h.glovoAccessPageDecider(w)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		d.failed(w, http.StatusBadRequest, "The request could not be read.")
		return
	}
	pid := r.PostForm.Get("principal")
	if !auth.ValidPrincipalID(pid) {
		d.failed(w, http.StatusBadRequest, "This decision link is malformed.")
		return
	}
	prov, err := d.oidcProvider(r.Context())
	if err != nil {
		slog.Warn("glovo access approval: ZITADEL discovery failed", "issuer", d.opts.Issuer, "error", err)
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
	entry := glovoAccessStartEntry{Principal: pid, StartedAt: d.now(), Nonce: nonce, Verifier: oauth2.GenerateVerifier()}
	if err := d.put(r.Context(), glovoAccessKindStart, basketStartKey(state, browser), entry, releaseChallengeTTL); err != nil {
		d.storeDown(w, err)
		return
	}
	setGlovoAccessCookie(w, browser, int(releaseChallengeTTL.Seconds()))
	authURL := d.oauthConfig(prov).AuthCodeURL(state, oauth2.S256ChallengeOption(entry.Verifier), oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("prompt", "login"), oauth2.SetAuthURLParam("max_age", "0"))
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

// handleGlovoAccessCallback: GET /glovo/access-approvals/callback.
func (h *Handlers) handleGlovoAccessCallback(w http.ResponseWriter, r *http.Request) {
	d, ok := h.glovoAccessPageDecider(w)
	if !ok {
		return
	}
	q := r.URL.Query()
	state, browser := q.Get("state"), glovoAccessBrowser(r)
	if state == "" || browser == "" {
		d.failed(w, http.StatusBadRequest, releaseUnknownSignIn)
		return
	}
	var c glovoAccessStartEntry
	found, err := d.take(r.Context(), glovoAccessKindStart, basketStartKey(state, browser), &c)
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
		slog.Warn("glovo access approval: ZITADEL code exchange failed", "error", err)
		d.failed(w, http.StatusBadGateway, "Could not complete the ZITADEL sign-in.")
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := prov.Verifier(&oidc.Config{ClientID: d.opts.ClientID}).Verify(r.Context(), raw)
	if err != nil {
		slog.Warn("glovo access approval: ZITADEL ID token refused", "error", err)
		d.failed(w, http.StatusBadRequest, "The ZITADEL ID token was not valid.")
		return
	}
	var claims releaseClaims
	if err := idt.Claims(&claims); err != nil || subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(c.Nonce)) != 1 {
		d.failed(w, http.StatusBadRequest, "The ZITADEL sign-in does not belong to this request.")
		return
	}
	if claims.AuthTime == 0 || time.Unix(claims.AuthTime, 0).Before(c.StartedAt.Add(-time.Minute)) {
		d.failed(w, http.StatusBadRequest, "ZITADEL did not report a fresh sign-in for this request.")
		return
	}
	if !issuedToClient(claims.Aud, claims.AZP, d.opts.ClientID) {
		d.failed(w, http.StatusBadRequest, "The ZITADEL ID token was not issued to this decision page.")
		return
	}
	// The display name can be an email address: it is neither shown nor stored.
	stored := basketIdentity{Provider: d.opts.ProviderName, Issuer: idt.Issuer, Subject: idt.Subject}
	id := stored.identity()
	user, err := auth.UserForSignIn(r.Context(), id, d.opts.Principals, d.opts.Authz)
	if err != nil {
		h.auditGlovoAccessPage(r, nil, id, c.Principal, "denied", "sign-in refused")
		d.failed(w, http.StatusNotFound, glovoAccessNotFoundMessage)
		return
	}
	if !d.isDecider(user) {
		h.auditGlovoAccessPage(r, user, id, c.Principal, "denied", "not a decider")
		d.failed(w, http.StatusNotFound, glovoAccessNotFoundMessage)
		return
	}
	amr := workitems.NormalizeAMR(claims.AMR)
	if !slices.ContainsFunc(d.opts.RequiredAMR, func(m string) bool { return slices.Contains(amr, m) }) {
		got := strings.Join(amr, ", ")
		if got == "" {
			got = "none"
		}
		h.auditGlovoAccessPage(r, user, id, c.Principal, "denied", "amr without a required method: "+got)
		d.failed(w, http.StatusForbidden, "This sign-in did not report a second factor. ZITADEL reported amr: "+got+
			"; required: one of "+strings.Join(d.opts.RequiredAMR, ", ")+".")
		return
	}
	shown, refusal := h.readGlovoAccess(r, d, user, c.Principal)
	if refusal != nil {
		h.auditGlovoAccessPage(r, user, id, c.Principal, "denied", refusal.audit)
		d.failed(w, refusal.status, refusal.msg)
		return
	}
	now := d.now()
	if !shown.decidable(now) {
		d.renderPage(w, http.StatusOK, "This access request is "+string(shown.access.Status), append(shown.lines(now), "There is nothing to decide here."), glovoAccessPageData{})
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
		d.failed(w, http.StatusBadRequest, "This decision page expired while ZITADEL was being verified.")
		return
	}
	entry := glovoAccessDecideEntry{Principal: c.Principal, StartedAt: c.StartedAt, Identity: stored, AMR: amr, Shown: shown.binding()}
	if err := d.put(r.Context(), glovoAccessKindDecide, basketDecideKey(challenge, csrf, browser), entry, left); err != nil {
		d.storeDown(w, err)
		return
	}
	title, note := "Approve or reject this access request", "Approving gives this principal access to the hosted Glovo connector, subject to its link consent and the capacity."
	if shown.approved() {
		title, note = "Revoke this access", "Revoking ends the principal's Glovo access at the next check and frees its slot."
	}
	data := glovoAccessPageData{Decide: &struct {
		Action, Challenge, CSRF string
		Pending, Approved       bool
	}{Action: glovoAccessConfirmPath, Challenge: challenge, CSRF: csrf, Pending: shown.pendingNow(now), Approved: shown.approved()}}
	d.renderPage(w, http.StatusOK, title, append(shown.lines(now), note), data)
}

// cleanGlovoAccessReason trims the decider's reason and refuses an empty,
// over-long or control-character one.
func cleanGlovoAccessReason(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" || utf8.RuneCountInString(s) > 500 || !utf8.ValidString(s) {
		return "", false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	return s, true
}

// decideGlovoAccess maps a decision to the store call. The decision is
// already checked against the shown status.
func (h *Handlers) decideGlovoAccess(ctx context.Context, decision, pid, actor, reason string) (glovoconsent.Access, error) {
	store := h.opts.GlovoConsent.Access
	switch decision {
	case glovoAccessDecisionApprove:
		return store.ApproveAccess(ctx, pid, actor, reason, h.opts.GlovoConsent.Capacity)
	case glovoAccessDecisionReject:
		return store.RejectAccess(ctx, pid, actor, reason)
	default:
		return store.RevokeAccess(ctx, pid, actor, reason)
	}
}

// handleGlovoAccessConfirm: POST /glovo/access-approvals/confirm.
func (h *Handlers) handleGlovoAccessConfirm(w http.ResponseWriter, r *http.Request) {
	d, ok := h.glovoAccessPageDecider(w)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		d.failed(w, http.StatusBadRequest, "The request could not be read.")
		return
	}
	decision := r.PostForm.Get("decision")
	if decision != glovoAccessDecisionApprove && decision != glovoAccessDecisionReject && decision != glovoAccessDecisionRevoke {
		d.failed(w, http.StatusBadRequest, "Choose Approve, Reject or Revoke.")
		return
	}
	reason, reasonOK := cleanGlovoAccessReason(r.PostForm.Get("reason"))
	challenge, csrf, browser := r.PostForm.Get("challenge"), r.PostForm.Get("csrf"), glovoAccessBrowser(r)
	if challenge == "" || csrf == "" || browser == "" {
		d.failed(w, http.StatusBadRequest, releaseUnknownConfirm)
		return
	}
	// A missing reason is refused BEFORE the challenge is spent, so the
	// decider can fill it in and submit the same form again.
	if !reasonOK {
		d.failed(w, http.StatusBadRequest, "A reason is required (at most 500 characters, no control characters); nothing was decided. Go back and submit the form again.")
		return
	}
	var c glovoAccessDecideEntry
	found, err := d.take(r.Context(), glovoAccessKindDecide, basketDecideKey(challenge, csrf, browser), &c)
	if err != nil {
		d.storeDown(w, err)
		return
	}
	if !found || d.remaining(c.StartedAt) <= 0 {
		d.failed(w, http.StatusBadRequest, releaseUnknownConfirm)
		return
	}
	setGlovoAccessCookie(w, "", -1)
	id := c.Identity.identity()
	user, err := auth.UserForSignIn(r.Context(), id, d.opts.Principals, d.opts.Authz)
	if err != nil {
		h.auditGlovoAccessPage(r, nil, id, c.Principal, "denied", "sign-in refused")
		d.failed(w, http.StatusNotFound, glovoAccessNotFoundMessage)
		return
	}
	shown, refusal := h.readGlovoAccess(r, d, user, c.Principal)
	if refusal != nil {
		h.auditGlovoAccessPage(r, user, id, c.Principal, "denied", refusal.audit)
		d.failed(w, refusal.status, refusal.msg)
		return
	}
	if shown.binding() != c.Shown {
		h.auditGlovoAccessPage(r, user, id, c.Principal, "denied", "request changed since it was shown")
		d.failed(w, http.StatusConflict, "The request changed after you were shown it; nothing was decided.")
		return
	}
	now := d.now()
	allowed := (decision == glovoAccessDecisionRevoke && shown.approved()) ||
		(decision != glovoAccessDecisionRevoke && shown.pendingNow(now))
	if !allowed {
		h.auditGlovoAccessPage(r, user, id, c.Principal, "denied", "not decidable: "+decision)
		d.failed(w, http.StatusConflict, "This request is "+string(shown.access.Status)+" or has expired; "+decision+" does not apply and nothing was decided.")
		return
	}
	actor := user.PrincipalID()
	_, err = h.decideGlovoAccess(r.Context(), decision, c.Principal, actor, reason)
	switch {
	case errors.Is(err, glovoconsent.ErrAccessNotPending), errors.Is(err, glovoconsent.ErrAccessNotApproved):
		glovoConsentEvents.WithLabelValues("access_decide", "already_decided").Inc()
		h.auditGlovoAccessPage(r, user, id, c.Principal, "denied", decision+": already decided")
		d.failed(w, http.StatusConflict, "Someone decided this request first, or it expired; nothing more was decided.")
		return
	case errors.Is(err, glovoconsent.ErrCapacityReached):
		glovoConsentEvents.WithLabelValues("access_decide", "capacity_reached").Inc()
		h.auditGlovoAccessPage(r, user, id, c.Principal, "refused", decision+": capacity reached")
		d.failed(w, http.StatusConflict, "Every slot is taken; the request stays pending and nothing was decided.")
		return
	case err != nil:
		slog.Error("glovo access approval: decide failed", "decision", decision, "error", err)
		glovoConsentEvents.WithLabelValues("access_decide", "store_error").Inc()
		h.auditGlovoAccessPage(r, user, id, c.Principal, "failed", decision+": store error")
		d.failed(w, http.StatusServiceUnavailable, "The decision could not be recorded right now; nothing was decided. Try again later.")
		return
	}
	glovoConsentEvents.WithLabelValues("access_decide", decision).Inc()
	h.auditGlovoAccessPage(r, user, id, c.Principal, "succeeded", decision)
	titles := map[string]string{
		glovoAccessDecisionApprove: "Access approved",
		glovoAccessDecisionReject:  "Access rejected",
		glovoAccessDecisionRevoke:  "Access revoked",
	}
	outcomes := map[string]string{
		glovoAccessDecisionApprove: "Your approval is recorded. The principal's Glovo access now depends on its link consent and the capacity.",
		glovoAccessDecisionReject:  "Your rejection is recorded. The principal can open a new request.",
		glovoAccessDecisionRevoke:  "Your revocation is recorded. The principal's Glovo access ends at the next check.",
	}
	d.renderPage(w, http.StatusOK, titles[decision], []string{"Principal: " + c.Principal, outcomes[decision]}, glovoAccessPageData{})
}

// auditGlovoAccessPage records what the page itself decided. Ids only.
func (h *Handlers) auditGlovoAccessPage(r *http.Request, user *auth.User, id auth.Identity, principal, status, msg string) {
	actor := id.Provider + ":" + id.Subject
	if user != nil {
		// The principal id, never user.ID, which can be a login name.
		if actor = user.PrincipalID(); actor == "" {
			actor = id.Provider + ":" + id.Subject
		}
	}
	h.logAudit(r, audit.Entry{
		UserID:     actor,
		Operation:  glovoAccessPageAuditOp,
		Parameters: map[string]string{"principal": principal, "provider": id.Provider, "subject": id.Subject},
		Status:     status,
		RiskLevel:  string(operations.RiskHigh),
		Message:    msg,
	})
}
