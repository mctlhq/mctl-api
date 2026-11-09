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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"golang.org/x/oauth2"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// DevLoop decide page (mctl-api#964). A DevLoop notification carries a link
// to /devloop/decide/{workflow_id} with the binding the person is shown
// (approval_ref, context_digest, content_digest). The link carries no
// secret and grants nothing: the page asks the person to sign in to ZITADEL
// in this browser, fresh (prompt=login, max_age=0), and only a human admin
// so proven may approve or reject. The approve and the reject go through
// the same handlers as the API routes, as that person, so every gate of
// mctl-api#571 and #869 (human admin, binding, decision context, audit)
// still decides. Neither the notifying bot nor the page attests anything.
//
// State is this process's memory, like identity linking: mctl-api runs one
// replica, and a restart only means "open the link again".

// DevLoopDecideOptions configures the decide page. All fields are needed;
// with any missing the page answers 503.
type DevLoopDecideOptions struct {
	// ProviderName and Issuer are those of the federation entry the
	// signed-in identity is resolved as (MCTL_OIDC_PROVIDERS), so the
	// person is the same principal their ZITADEL bearer would be.
	ProviderName string
	Issuer       string
	// ClientID and ClientSecret are the decide page's own ZITADEL web
	// client. Only its ID token is read, never an access token.
	ClientID     string
	ClientSecret string
	// BaseURL is mctl-api's public URL; the callback hangs off it.
	BaseURL string
	// Principals and Authz are the middleware's: the person is resolved
	// and authorized exactly as a bearer of theirs would be.
	Principals auth.PrincipalResolver
	Authz      *auth.PrincipalAuthz

	// clock replaces time.Now in tests.
	clock func() time.Time
}

func (o *DevLoopDecideOptions) enabled() bool {
	return o != nil && o.ProviderName != "" && o.Issuer != "" && o.ClientID != "" &&
		o.ClientSecret != "" && o.BaseURL != "" && o.Principals != nil && o.Authz != nil
}

const (
	decideCookieName    = "__Host-mctl_devloop_decide"
	decidePathPrefix    = "/devloop/decide/"
	decideStartPath     = "/devloop/decide/start"
	decideCallbackPath  = "/devloop/decide/callback"
	decideConfirmPath   = "/devloop/decide/confirm"
	decideChallengeTTL  = 10 * time.Minute
	decideMaxChallenges = 1000
	decideMaxPerIP      = 3
	decideReasonApprove = "approved on the DevLoop decide page"
	decideReasonReject  = "rejected on the DevLoop decide page"
	decideAuditOp       = "dev-loop-decide-page"
)

// decideWorkflowRe is a DevLoop workflow id, as the start handler forms it.
var decideWorkflowRe = regexp.MustCompile(`^dev-loop-[A-Za-z0-9_.-]{1,200}$`)

type decidePhase int

const (
	decideStarted decidePhase = iota
	decideSignedIn
	decideUsed
)

type decideChallenge struct {
	id          string
	browserHash [32]byte
	expiresAt   time.Time
	startedAt   time.Time
	phase       decidePhase
	clientIP    string

	workflowID string
	bind       decisionBinding

	state    string
	nonce    string
	verifier string

	identity auth.Identity
	csrfHash [32]byte
}

type devLoopDecider struct {
	opts *DevLoopDecideOptions

	mu      sync.Mutex
	byID    map[string]*decideChallenge
	byState map[string]*decideChallenge

	lazyOIDCProvider
	now func() time.Time
}

func newDevLoopDecider(opts *DevLoopDecideOptions) *devLoopDecider {
	now := time.Now
	if opts.clock != nil {
		now = opts.clock
	}
	return &devLoopDecider{
		opts:             opts,
		lazyOIDCProvider: lazyOIDCProvider{issuer: opts.Issuer},
		byID:             map[string]*decideChallenge{},
		byState:          map[string]*decideChallenge{},
		now:              now,
	}
}

func (d *devLoopDecider) sweepLocked(now time.Time) {
	for id, c := range d.byID {
		if now.After(c.expiresAt) {
			d.dropLocked(id, c)
		}
	}
	for k, c := range d.byState {
		if d.byID[c.id] != c || now.After(c.expiresAt) {
			delete(d.byState, k)
		}
	}
}

func (d *devLoopDecider) liveLocked(c *decideChallenge, phase decidePhase, now time.Time) bool {
	return d.byID[c.id] == c && c.phase == phase && !now.After(c.expiresAt)
}

func (d *devLoopDecider) dropLocked(id string, c *decideChallenge) {
	delete(d.byID, id)
	delete(d.byState, c.state)
}

func (d *devLoopDecider) abandon(c *decideChallenge) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.byID[c.id] == c {
		d.dropLocked(c.id, c)
	}
}

// capSourceLocked makes room for one more challenge from ip by dropping its
// oldest one still waiting for ZITADEL, and reports false when ip's
// challenges are all signed in.
func (d *devLoopDecider) capSourceLocked(ip string) bool {
	for {
		mine := 0
		var oldest *decideChallenge
		for _, c := range d.byID {
			if c.clientIP != ip {
				continue
			}
			mine++
			if c.phase == decideStarted && (oldest == nil || c.startedAt.Before(oldest.startedAt)) {
				oldest = c
			}
		}
		if mine < decideMaxPerIP {
			return true
		}
		if oldest == nil {
			return false
		}
		d.dropLocked(oldest.id, oldest)
	}
}

func (d *devLoopDecider) oauthConfig(p *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     d.opts.ClientID,
		ClientSecret: d.opts.ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  d.opts.BaseURL + decideCallbackPath,
		Scopes:       []string{oidc.ScopeOpenID, "profile"},
	}
}

func decideBrowserMatches(r *http.Request, c *decideChallenge) bool {
	ck, err := r.Cookie(decideCookieName)
	if err != nil || ck.Value == "" {
		return false
	}
	sum := sha256.Sum256([]byte(ck.Value))
	return subtle.ConstantTimeCompare(sum[:], c.browserHash[:]) == 1
}

func setDecideCookie(w http.ResponseWriter, value string, maxAge int) {
	// SameSite=Lax: sent on the top-level redirect back from ZITADEL and on
	// the same-site confirm POST, never on a cross-site POST.
	http.SetCookie(w, &http.Cookie{
		Name: decideCookieName, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
}

// decideBindingFrom reads and checks the workflow id and the binding a
// link or a form names. False when any of them is absent or malformed.
func decideBindingFrom(workflowID string, v url.Values) (decisionBinding, bool) {
	b := decisionBinding{ApprovalRef: v.Get("grant"), ContextDigest: v.Get("cd"), ContentDigest: v.Get("xd")}
	return b, decideWorkflowRe.MatchString(workflowID) && len(b.missingFields()) == 0
}

var decidePage = shellPage("devloop-decide", `{{if .SignIn}}<form class="actions" method="post" action="{{.SignIn.Action}}">
<input type="hidden" name="workflow_id" value="{{.SignIn.WorkflowID}}">
<input type="hidden" name="grant" value="{{.SignIn.Grant}}">
<input type="hidden" name="cd" value="{{.SignIn.CD}}">
<input type="hidden" name="xd" value="{{.SignIn.XD}}">
<button type="submit">Sign in to ZITADEL to decide</button></form>{{end}}
{{if .Decide}}<form class="actions" method="post" action="{{.Decide.Action}}">
<input type="hidden" name="challenge" value="{{.Decide.Challenge}}">
<input type="hidden" name="csrf" value="{{.Decide.CSRF}}">
<button type="submit" name="decision" value="approve">Approve</button>
<button type="submit" name="decision" value="reject" class="secondary">Reject</button></form>{{end}}`)

type decidePageData struct {
	SignIn *struct{ Action, WorkflowID, Grant, CD, XD string }
	Decide *struct{ Action, Challenge, CSRF string }
}

func (d *devLoopDecider) renderPage(w http.ResponseWriter, status int, title string, lines []string, p decidePageData) {
	// form-action names the issuer too: the sign-in POST answers with a
	// redirect to ZITADEL, and form-action governs that redirect.
	formAction := "'self'"
	if d != nil {
		if u, err := url.Parse(d.opts.Issuer); err == nil && u.Scheme == "https" && u.Host != "" {
			formAction += " https://" + u.Host
		}
	}
	renderShellPage(w, status, "default-src 'none'; style-src 'unsafe-inline'; form-action "+formAction+"; frame-ancestors 'none'",
		decidePage, shellData{Title: title, Lines: lines, Page: p})
}

func (d *devLoopDecider) failed(w http.ResponseWriter, status int, msg string) {
	d.renderPage(w, status, "Could not decide", []string{msg, "Open the link from the notification again to start over."}, decidePageData{})
}

func (h *Handlers) decider(w http.ResponseWriter) (*devLoopDecider, bool) {
	d := h.devLoopDecide
	if d == nil || !d.opts.enabled() {
		var none *devLoopDecider
		none.failed(w, http.StatusServiceUnavailable, "The DevLoop decide page is not configured on this server.")
		return nil, false
	}
	return d, true
}

// handleDevLoopDecidePage: GET /devloop/decide/{workflow_id}. It shows what
// the link names and changes nothing: the sign-in starts on a POST, so a
// link preview or a prefetch creates no state.
func (h *Handlers) handleDevLoopDecidePage(w http.ResponseWriter, r *http.Request) {
	d, ok := h.decider(w)
	if !ok {
		return
	}
	workflowID := chi.URLParam(r, "workflow_id")
	b, ok := decideBindingFrom(workflowID, r.URL.Query())
	if !ok {
		d.failed(w, http.StatusBadRequest, "This decide link is incomplete or malformed.")
		return
	}
	d.renderPage(w, http.StatusOK, "Decide a DevLoop proposal", []string{
		"DevLoop: " + workflowID,
		"Approval: " + b.ApprovalRef,
		"Sign in to ZITADEL as yourself to see the proposal's decision context and approve or reject it. Only a platform admin can decide.",
		"On the ZITADEL page, enter your ZITADEL login name, not your e-mail address or your GitHub login.",
	}, decidePageData{SignIn: &struct{ Action, WorkflowID, Grant, CD, XD string }{
		Action: decideStartPath, WorkflowID: workflowID, Grant: b.ApprovalRef, CD: b.ContextDigest, XD: b.ContentDigest,
	}})
}

// handleDevLoopDecideStart: POST /devloop/decide/start.
func (h *Handlers) handleDevLoopDecideStart(w http.ResponseWriter, r *http.Request) {
	d, ok := h.decider(w)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		d.failed(w, http.StatusBadRequest, "The request could not be read.")
		return
	}
	workflowID := r.PostForm.Get("workflow_id")
	b, ok := decideBindingFrom(workflowID, r.PostForm)
	if !ok {
		d.failed(w, http.StatusBadRequest, "This decide link is incomplete or malformed.")
		return
	}
	prov, err := d.oidcProvider(r.Context())
	if err != nil {
		slog.Warn("devloop decide: ZITADEL discovery failed", "issuer", d.opts.Issuer, "error", err)
		d.failed(w, http.StatusBadGateway, "ZITADEL is not reachable right now.")
		return
	}
	browser, err1 := randomLinkToken()
	id, err2 := randomLinkToken()
	state, err3 := randomLinkToken()
	nonce, err4 := randomLinkToken()
	if err := errors.Join(err1, err2, err3, err4); err != nil {
		d.failed(w, http.StatusInternalServerError, "Internal error.")
		return
	}
	now := d.now()
	ip, _ := keyByTrustedIP(r)
	c := &decideChallenge{
		id: id, browserHash: sha256.Sum256([]byte(browser)), expiresAt: now.Add(decideChallengeTTL),
		startedAt: now, clientIP: ip, workflowID: workflowID, bind: b,
		state: state, nonce: nonce, verifier: oauth2.GenerateVerifier(),
	}
	d.mu.Lock()
	d.sweepLocked(now)
	if !d.capSourceLocked(ip) {
		d.mu.Unlock()
		d.failed(w, http.StatusTooManyRequests, "Too many decisions in progress from your network; finish one or try again in a few minutes.")
		return
	}
	if len(d.byID) >= decideMaxChallenges {
		d.mu.Unlock()
		d.failed(w, http.StatusServiceUnavailable, "Too many decisions in progress; try again in a few minutes.")
		return
	}
	d.byID[c.id] = c
	d.byState[c.state] = c
	d.mu.Unlock()

	setDecideCookie(w, browser, int(decideChallengeTTL.Seconds()))
	// prompt=login: the person signs in now, in this browser, not through
	// an older ZITADEL session. max_age=0 makes auth_time a REQUIRED claim
	// (OIDC Core 3.1.2.1), which the callback checks.
	authURL := d.oauthConfig(prov).AuthCodeURL(state, oauth2.S256ChallengeOption(c.verifier), oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("prompt", "login"), oauth2.SetAuthURLParam("max_age", "0"))
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

// signedInAdmin resolves the identity a sign-in proved, as the middleware
// would resolve a bearer of it, and requires a human admin acting directly.
func (d *devLoopDecider) signedInAdmin(ctx context.Context, id auth.Identity) (*auth.User, error) {
	u, err := auth.UserForSignIn(ctx, id, d.opts.Principals, d.opts.Authz)
	if err != nil {
		return nil, err
	}
	if !isHumanAdmin(u) {
		return u, errDecideNotAdmin
	}
	return u, nil
}

var errDecideNotAdmin = errors.New("not a platform admin")

// handleDevLoopDecideCallback: GET /devloop/decide/callback.
func (h *Handlers) handleDevLoopDecideCallback(w http.ResponseWriter, r *http.Request) {
	d, ok := h.decider(w)
	if !ok {
		return
	}
	q := r.URL.Query()
	d.mu.Lock()
	now := d.now()
	d.sweepLocked(now)
	c, ok := d.byState[q.Get("state")]
	valid := ok && d.liveLocked(c, decideStarted, now) && decideBrowserMatches(r, c)
	if valid {
		delete(d.byState, c.state)
	}
	d.mu.Unlock()
	if !valid {
		d.failed(w, http.StatusBadRequest, "This sign-in is unknown, expired, started in another browser, or replaced by a newer decision started in this browser.")
		return
	}
	advanced := false
	defer func() {
		if !advanced {
			d.abandon(c)
		}
	}()
	if e := q.Get("error"); e != "" {
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
	tok, err := d.oauthConfig(prov).Exchange(r.Context(), code, oauth2.VerifierOption(c.verifier))
	if err != nil {
		slog.Warn("devloop decide: ZITADEL code exchange failed", "error", err)
		d.failed(w, http.StatusBadGateway, "Could not complete the ZITADEL sign-in.")
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := prov.Verifier(&oidc.Config{ClientID: d.opts.ClientID}).Verify(r.Context(), raw)
	if err != nil {
		slog.Warn("devloop decide: ZITADEL ID token refused", "error", err)
		d.failed(w, http.StatusBadRequest, "The ZITADEL ID token was not valid.")
		return
	}
	var claims struct {
		Nonce             string `json:"nonce"`
		AuthTime          int64  `json:"auth_time"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idt.Claims(&claims); err != nil || subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(c.nonce)) != 1 {
		d.failed(w, http.StatusBadRequest, "The ZITADEL sign-in does not belong to this decision.")
		return
	}
	if claims.AuthTime == 0 || time.Unix(claims.AuthTime, 0).Before(c.startedAt.Add(-time.Minute)) {
		d.failed(w, http.StatusBadRequest, "ZITADEL did not report a fresh sign-in for this decision.")
		return
	}
	display := claims.PreferredUsername
	if display == "" {
		display = idt.Subject
	}
	id := auth.Identity{Provider: d.opts.ProviderName, Issuer: idt.Issuer, Subject: idt.Subject, Display: display, Kind: auth.KindHuman}
	user, err := d.signedInAdmin(r.Context(), id)
	if err != nil {
		h.auditDecidePage(r, user, id, c, "denied", err.Error())
		d.failed(w, http.StatusForbidden, "You signed in as "+display+", who may not decide a DevLoop: only a platform admin can.")
		return
	}

	// What the person is about to decide, read as them: the grant the link
	// names must still be this DevLoop's newest, with the same context and
	// content, or the page offers no decision at all.
	status, body := h.callAs(r, user, http.MethodGet, "workflow_id", c.workflowID, nil, h.GetDevLoopApproval)
	if status != http.StatusOK {
		d.failed(w, status, "The DevLoop's approval could not be read: "+errorText(body)+".")
		return
	}
	var got struct {
		Approval struct {
			ID    string `json:"id"`
			State string `json:"state"`
		} `json:"approval"`
		Context struct {
			Target       string    `json:"target"`
			RiskLevel    string    `json:"risk_level"`
			SideEffect   string    `json:"side_effect"`
			ArtifactHash string    `json:"artifact_hash"`
			ExpiresAt    time.Time `json:"expires_at"`
			Digest       string    `json:"context_digest"`
		} `json:"decision_context"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		d.failed(w, http.StatusBadGateway, "The DevLoop's approval could not be read.")
		return
	}
	if got.Approval.ID != c.bind.ApprovalRef || got.Context.Digest != c.bind.ContextDigest || got.Context.ArtifactHash != c.bind.ContentDigest {
		h.auditDecidePage(r, user, id, c, "denied", "binding no longer matches the newest grant")
		d.failed(w, http.StatusConflict, "This proposal changed since the notification was sent: open the newest notification for this DevLoop.")
		return
	}
	if got.Approval.State != workitems.ApprovalPending {
		d.failed(w, http.StatusConflict, "This approval is already "+got.Approval.State+"; there is nothing left to decide.")
		return
	}
	csrf, err := randomLinkToken()
	if err != nil {
		d.failed(w, http.StatusInternalServerError, "Internal error.")
		return
	}
	d.mu.Lock()
	live := d.liveLocked(c, decideStarted, d.now())
	if live {
		c.identity, c.csrfHash, c.phase = id, sha256.Sum256([]byte(csrf)), decideSignedIn
		advanced = true
	}
	d.mu.Unlock()
	if !live {
		d.failed(w, http.StatusBadRequest, "This decision expired while ZITADEL was being verified.")
		return
	}
	d.renderPage(w, http.StatusOK, "Approve or reject", []string{
		"Signed in as " + display + ".",
		"DevLoop: " + c.workflowID,
		"Approval: " + got.Approval.ID + " (" + got.Approval.State + ")",
		"Target: " + got.Context.Target,
		"Risk: " + got.Context.RiskLevel + ", side effect: " + got.Context.SideEffect,
		"Expires: " + got.Context.ExpiresAt.UTC().Format(time.RFC3339),
		"Approving lets this DevLoop implement its proposal. Rejecting denies the approval; the DevLoop does not proceed.",
	}, decidePageData{Decide: &struct{ Action, Challenge, CSRF string }{Action: decideConfirmPath, Challenge: c.id, CSRF: csrf}})
}

// handleDevLoopDecideConfirm: POST /devloop/decide/confirm.
func (h *Handlers) handleDevLoopDecideConfirm(w http.ResponseWriter, r *http.Request) {
	d, ok := h.decider(w)
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
	sum := sha256.Sum256([]byte(r.PostForm.Get("csrf")))
	d.mu.Lock()
	now := d.now()
	d.sweepLocked(now)
	c, ok := d.byID[r.PostForm.Get("challenge")]
	valid := ok && d.liveLocked(c, decideSignedIn, now) && decideBrowserMatches(r, c) &&
		subtle.ConstantTimeCompare(sum[:], c.csrfHash[:]) == 1
	if valid {
		// Used once, whatever happens next.
		c.phase = decideUsed
		d.dropLocked(c.id, c)
	}
	d.mu.Unlock()
	setDecideCookie(w, "", -1)
	if !valid {
		d.failed(w, http.StatusBadRequest, "This decision is unknown, expired, already used, started in another browser, or replaced by a newer decision started in this browser.")
		return
	}
	// Resolved again: an admin removed, or a principal disabled, since the
	// sign-in no longer decides.
	user, err := d.signedInAdmin(r.Context(), c.identity)
	if err != nil {
		h.auditDecidePage(r, user, c.identity, c, "denied", err.Error())
		d.failed(w, http.StatusForbidden, "You may no longer decide a DevLoop.")
		return
	}
	var status int
	var body []byte
	if decision == "approve" {
		status, body = h.callAs(r, user, http.MethodPost, "workflow_id", c.workflowID,
			map[string]any{"binding": c.bind, "reason": decideReasonApprove}, h.ApproveDevLoopWorkflow)
	} else {
		status, body = h.callAs(r, user, http.MethodPost, "id", c.bind.ApprovalRef,
			map[string]any{"decision": workitems.DecisionDeny, "reason": decideReasonReject}, h.DecideActionApproval)
	}
	if status != http.StatusOK {
		h.auditDecidePage(r, user, c.identity, c, "failed", decision+": "+errorText(body))
		d.failed(w, status, "The "+decision+" was refused: "+errorText(body)+".")
		return
	}
	h.auditDecidePage(r, user, c.identity, c, "succeeded", decision)
	title, line := "Approved", "The DevLoop will implement its proposal."
	if decision == "reject" {
		title, line = "Rejected", "The approval is denied; the DevLoop does not proceed."
	}
	d.renderPage(w, http.StatusOK, title, []string{"DevLoop: " + c.workflowID, "Approval: " + c.bind.ApprovalRef, line}, decidePageData{})
}

// callAs runs handler in-process as user, with one chi URL parameter and an
// optional JSON body, and returns its status and body. It is the same
// handler the API route serves, so every gate in it decides. Only the
// context (with the user) and RemoteAddr carry over, never the original
// headers: none of the handlers called here reads one, and one that starts
// to must get it passed explicitly.
func (h *Handlers) callAs(r *http.Request, user *auth.User, method, param, value string, body any, handler http.HandlerFunc) (int, []byte) {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return http.StatusInternalServerError, nil
		}
	}
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(param, value)
	ctx := context.WithValue(auth.WithUser(r.Context(), user), chi.RouteCtxKey, rctx)
	req, err := http.NewRequestWithContext(ctx, method, "/", &buf)
	if err != nil {
		return http.StatusInternalServerError, nil
	}
	req.RemoteAddr = r.RemoteAddr
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec.Code, rec.Body.Bytes()
}

// errorText is the message of an API error body, or a generic one.
func errorText(body []byte) string {
	var e struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	if json.Unmarshal(body, &e) != nil || e.Error == "" {
		return "unexpected response"
	}
	if e.Code != "" {
		return e.Code + ": " + e.Error
	}
	return e.Error
}

// auditDecidePage records what the page itself decided: a refused sign-in,
// a binding that moved, and the outcome of a decision. The approve and the
// deny write their own entries too, as the handlers they are.
func (h *Handlers) auditDecidePage(r *http.Request, user *auth.User, id auth.Identity, c *decideChallenge, status, msg string) {
	actor := id.Display
	if user != nil {
		actor = user.ID
	}
	h.logAudit(r, audit.Entry{
		UserID:       actor,
		Operation:    decideAuditOp,
		WorkflowName: c.workflowID,
		Parameters:   map[string]string{"approval_ref": c.bind.ApprovalRef, "provider": id.Provider, "subject": id.Subject},
		Status:       status,
		RiskLevel:    string(operations.RiskMedium),
		Message:      msg,
	})
}
