package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"golang.org/x/oauth2"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/auth/flowstore"
	"github.com/mctlhq/mctl-api/internal/deployplan"
	"github.com/mctlhq/mctl-api/internal/governance"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Deploy approval page (mctl-api#1026, slice 2). The only place a deploy.apply
// grant is decided.
//
// POST /api/v1/deploy/plans/{id}/approval answers a link to
// /deploy/approvals/{aar_id}; the agent shows it to a person. The link
// carries no secret and grants nothing. The page asks the person to sign in
// to ZITADEL in this browser, fresh (prompt=login, max_age=0, PKCE S256, a
// nonce), resolves them exactly as a bearer of theirs would be resolved
// (auth.UserForSignIn), checks that they are a live owner of the plan's
// tenant, shows them the plan, and on their click decides the grant through
// workitems.DecideDeployApproval, bound to what was shown.
//
// Why a page and not a route: an MCP session carries its person's own
// principal, so no bearer check can tell an agent from the owner it works
// for. A fresh interactive sign-in can: the agent cannot perform it. That is
// also why the owner may approve a plan their own agent asked for (owner
// decision 2026-11-14, mctl-api#1026).
//
// The mechanics are the Glovo basket page's (glovo_basket_approval_page.go),
// itself the DevLoop decide page's: no session, no long-lived cookie, no
// token in the browser, no script. A __Host- cookie lives for one decision
// and binds the ZITADEL round trip and the confirm POST to this browser; the
// confirm also carries a one-time CSRF token. Challenges live in the shared
// OAuth flow store, consumed with its atomic Take, so the steps may reach
// different replicas and none can be replayed. A store that cannot be read
// refuses the step; it is never read as "no such challenge".
//
// Dark by default: the routes are mounted only when DeployApprovalPage is
// complete, which cmd/api does only with DEPLOY_APPROVAL_UI_ENABLED=true and
// every dependency present.

// DeployApprovalPageOptions configures the page. All fields are needed; with
// any missing the routes are not mounted.
type DeployApprovalPageOptions struct {
	// ProviderName and Issuer are the federation entry the signed-in
	// identity is resolved as (MCTL_OIDC_PROVIDERS), so the person is the
	// same principal their bearer would be.
	ProviderName string
	Issuer       string
	// ClientID and ClientSecret are a ZITADEL web client whose redirect URIs
	// include BaseURL + /deploy/approvals/callback. Only its ID token is
	// read, never an access token.
	ClientID     string
	ClientSecret string
	// BaseURL is mctl-api's public URL.
	BaseURL    string
	Principals auth.PrincipalResolver
	Authz      *auth.PrincipalAuthz
	// Flow is the OAuth server's shared flow store.
	Flow flowstore.Store

	// clock replaces time.Now in tests.
	clock func() time.Time
}

func (o *DeployApprovalPageOptions) enabled() bool {
	return o != nil && o.ProviderName != "" && o.Issuer != "" && o.ClientID != "" && o.ClientSecret != "" &&
		o.BaseURL != "" && o.Principals != nil && o.Authz != nil && o.Flow != nil
}

const (
	deployPageCookie      = "__Host-mctl_deploy_approval"
	deployPagePrefix      = "/deploy/approvals/"
	deployStartPath       = "/deploy/approvals/start"
	deployCallbackPath    = "/deploy/approvals/callback"
	deployConfirmPath     = "/deploy/approvals/confirm"
	deployChallengeTTL    = 10 * time.Minute
	deployReasonApprove   = "approved on the deploy approval page"
	deployReasonReject    = "rejected on the deploy approval page"
	deployPageAuditOp     = "deploy-approval-page"
	deployNotFoundMessage = "There is no deploy approval with this reference waiting for you."
	deployUnknownSignIn   = "This sign-in is unknown, expired, already used, started in another browser, or replaced by a newer one started in this browser."
	deployUnknownConfirm  = "This approval page is unknown, expired, already used, or was opened in another browser."

	// Kinds of flow store entry, distinct from every other page's.
	deployKindStart  = "deploy-approval-start"
	deployKindDecide = "deploy-approval-decide"
)

type deployStartEntry struct {
	ApprovalRef string    `json:"approval_ref"`
	StartedAt   time.Time `json:"started_at"`
	Nonce       string    `json:"nonce"`
	Verifier    string    `json:"verifier"`
}

type deployDecideEntry struct {
	ApprovalRef string         `json:"approval_ref"`
	StartedAt   time.Time      `json:"started_at"`
	Identity    basketIdentity `json:"identity"`
	// Shown is the binding of what the person was shown at sign-in; the
	// decision is bound to it and to nothing read later.
	Shown decisionBinding `json:"shown"`
}

type deployDecider struct {
	opts *DeployApprovalPageOptions
	lazyOIDCProvider
	now func() time.Time
}

func newDeployDecider(opts *DeployApprovalPageOptions) *deployDecider {
	now := time.Now
	if opts.clock != nil {
		now = opts.clock
	}
	return &deployDecider{opts: opts, lazyOIDCProvider: lazyOIDCProvider{issuer: opts.Issuer}, now: now}
}

func (d *deployDecider) put(ctx context.Context, kind, key string, v any, ttl time.Duration) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return d.opts.Flow.Put(ctx, kind, key, b, ttl)
}

// take consumes the entry under (kind, key) into v. found is false only when
// the store answered that no live entry exists.
func (d *deployDecider) take(ctx context.Context, kind, key string, v any) (bool, error) {
	b, found, err := d.opts.Flow.Take(ctx, kind, key)
	if err != nil || !found {
		return false, err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return false, fmt.Errorf("deploy approval: %s entry unreadable: %w", kind, err)
	}
	return true, nil
}

func (d *deployDecider) remaining(startedAt time.Time) time.Duration {
	return startedAt.Add(deployChallengeTTL).Sub(d.now())
}

func (d *deployDecider) oauthConfig(p *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID: d.opts.ClientID, ClientSecret: d.opts.ClientSecret, Endpoint: p.Endpoint(),
		RedirectURL: d.opts.BaseURL + deployCallbackPath, Scopes: []string{oidc.ScopeOpenID, "profile"},
	}
}

// decideURL is the page link for an approval.
func (d *deployDecider) decideURL(approvalRef string) string {
	return d.opts.BaseURL + deployPagePrefix + approvalRef
}

func deployBrowser(r *http.Request) string {
	ck, err := r.Cookie(deployPageCookie)
	if err != nil {
		return ""
	}
	return ck.Value
}

func setDeployCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: deployPageCookie, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
}

// deployPage draws the plan's diff. html/template escapes every value; there
// is no script on the page.
var deployPage = shellPage("deploy-approval", `{{with .Diff}}<pre style="white-space:pre-wrap;overflow-wrap:anywhere;font-size:.8125rem;margin:.5rem 0 1rem">{{.}}</pre>{{end}}
{{if .SignIn}}<form class="actions" method="post" action="{{.SignIn.Action}}">
<input type="hidden" name="approval_ref" value="{{.SignIn.ApprovalRef}}">
<button type="submit">Sign in to review this deploy</button></form>{{end}}
{{if .Decide}}<form class="actions" method="post" action="{{.Decide.Action}}">
<input type="hidden" name="challenge" value="{{.Decide.Challenge}}">
<input type="hidden" name="csrf" value="{{.Decide.CSRF}}">
<button type="submit" name="decision" value="approve">Approve this deploy</button>
<button type="submit" name="decision" value="reject" class="secondary">Reject</button></form>{{end}}`)

type deployPageData struct {
	Diff   string
	SignIn *struct{ Action, ApprovalRef string }
	Decide *struct{ Action, Challenge, CSRF string }
}

func (d *deployDecider) renderPage(w http.ResponseWriter, status int, title string, lines []string, p deployPageData) {
	// form-action names the issuer too: the sign-in POST answers with a
	// redirect to ZITADEL, and form-action governs that redirect.
	formAction := "'self'"
	if d != nil {
		if u, err := url.Parse(d.opts.Issuer); err == nil && u.Scheme == "https" && u.Host != "" {
			formAction += " https://" + u.Host
		}
	}
	renderShellPage(w, status, "default-src 'none'; style-src 'unsafe-inline'; form-action "+formAction+"; frame-ancestors 'none'; base-uri 'none'",
		deployPage, shellData{Title: title, Lines: lines, Page: p})
}

func (d *deployDecider) failed(w http.ResponseWriter, status int, msg string) {
	d.renderPage(w, status, "Cannot decide this deploy", []string{msg, "Open the approval link again to start over."}, deployPageData{})
}

func (d *deployDecider) storeDown(w http.ResponseWriter, err error) {
	slog.Warn("deploy approval: flow store unavailable", "error", err)
	d.failed(w, http.StatusServiceUnavailable, "The approval page cannot reach its store right now; nothing was decided. Try again in a few minutes.")
}

// deployPageDecider is the mounted page, or a 503 answered.
func (h *Handlers) deployPageDecider(w http.ResponseWriter) (*deployDecider, bool) {
	d := h.deployApproval
	if d == nil || !d.opts.enabled() || h.opts.WorkItems == nil || h.opts.DeployPlans == nil {
		var none *deployDecider
		none.failed(w, http.StatusServiceUnavailable, "The deploy approval page is not enabled on this server.")
		return nil, false
	}
	return d, true
}

// handleDeployApprovalPage: GET /deploy/approvals/{approval_ref}. It reads
// nothing and changes nothing: the sign-in starts on a POST, so a link
// preview or a prefetch creates no state, and the link alone tells nobody
// whether the approval exists.
func (h *Handlers) handleDeployApprovalPage(w http.ResponseWriter, r *http.Request) {
	d, ok := h.deployPageDecider(w)
	if !ok {
		return
	}
	ref := chi.URLParam(r, "approval_ref")
	if !basketApprovalRefRe.MatchString(ref) {
		d.failed(w, http.StatusBadRequest, "This approval link is malformed.")
		return
	}
	d.renderPage(w, http.StatusOK, "Review a deploy", []string{
		"Approval: " + ref,
		"Sign in to ZITADEL as yourself to see the deploy plan and approve or reject it. Only an owner of the plan's team can see or decide it.",
		"Approving lets the requester apply exactly this plan, once.",
	}, deployPageData{SignIn: &struct{ Action, ApprovalRef string }{Action: deployStartPath, ApprovalRef: ref}})
}

// handleDeployApprovalStart: POST /deploy/approvals/start.
func (h *Handlers) handleDeployApprovalStart(w http.ResponseWriter, r *http.Request) {
	d, ok := h.deployPageDecider(w)
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
		slog.Warn("deploy approval: ZITADEL discovery failed", "issuer", d.opts.Issuer, "error", err)
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
	entry := deployStartEntry{ApprovalRef: ref, StartedAt: d.now(), Nonce: nonce, Verifier: oauth2.GenerateVerifier()}
	if err := d.put(r.Context(), deployKindStart, basketStartKey(state, browser), entry, deployChallengeTTL); err != nil {
		d.storeDown(w, err)
		return
	}
	setDeployCookie(w, browser, int(deployChallengeTTL.Seconds()))
	// prompt=login: the person signs in now, in this browser. max_age=0
	// makes auth_time a REQUIRED claim (OIDC Core 3.1.2.1), checked below.
	authURL := d.oauthConfig(prov).AuthCodeURL(state, oauth2.S256ChallengeOption(entry.Verifier), oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("prompt", "login"), oauth2.SetAuthURLParam("max_age", "0"))
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

// deployShown is a deploy grant and its plan as an owner is shown them,
// after every check of the page.
type deployShown struct {
	approval *workitems.ActionApprovalRequest
	plan     *deployplan.Plan
	context  governance.DecisionContext
	// unapplicable is why the plan cannot be applied as planned, nil if it
	// can.
	unapplicable *planRefusal
}

func (s *deployShown) decidable(now time.Time) bool {
	return s.approval.State == workitems.ApprovalPending && now.Before(s.approval.ExpiresAt) &&
		s.unapplicable == nil && s.context.ContextComplete
}

func (s *deployShown) binding() decisionBinding {
	return decisionBinding{ApprovalRef: s.approval.ID, ContextDigest: s.context.ContextDigest, ContentDigest: s.plan.Digest}
}

func (s *deployShown) lines(display string) []string {
	a, p := s.approval, s.plan
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
		"Team: " + p.Tenant + ", service: " + p.Service + ", environment: " + p.Environment,
		"Source revision: " + p.Revision,
		"Preview: https://" + p.Host,
		"Requested by: " + requester,
		"Plan: " + p.ID,
		"Plan digest: " + p.Digest,
		"GitOps commit: " + p.GitopsBaseSHA,
		"Approval: " + a.ID + " (" + basketStateWord(a.State) + "), expires " + a.ExpiresAt.UTC().Format(time.RFC3339),
		"Context digest: " + s.context.ContextDigest,
	}
	if s.unapplicable != nil {
		out = append(out, "This plan cannot be applied: "+s.unapplicable.msg+".")
	}
	return out
}

// deployPageRefusal is a page answer instead of a plan.
type deployPageRefusal struct {
	status int
	msg    string
	audit  string // the reason recorded, never shown
}

func deployNotFound(reason string) *deployPageRefusal {
	return &deployPageRefusal{status: http.StatusNotFound, msg: deployNotFoundMessage, audit: reason}
}

// readDeployApproval reads approval ref and its plan as user, and checks that
// user is a live owner of the plan's tenant. Every "not yours" reads like "no
// such approval": an unknown id, another kind, a plan that is gone or names
// another target, and anyone who is not an owner of the tenant, an admin
// included.
func (h *Handlers) readDeployApproval(r *http.Request, d *deployDecider, user *auth.User, ref string) (*deployShown, *deployPageRefusal) {
	if !isGlovoOwnerCandidate(user) {
		// A resolved human principal acting directly, nothing relayed or
		// delegated: the same test as the Glovo owner decision.
		return nil, deployNotFound("not a human principal")
	}
	a, err := h.opts.WorkItems.ActionApproval(r.Context(), ref)
	switch {
	case errors.Is(err, workitems.ErrApprovalNotFound):
		return nil, deployNotFound("no such approval")
	case err != nil:
		return nil, &deployPageRefusal{status: http.StatusServiceUnavailable, msg: "The approval cannot be read right now; try again later.", audit: "approval read failed"}
	case a.ActionKind != workitems.ActionKindDeployApply:
		return nil, deployNotFound("not a deploy approval")
	}
	p, err := h.opts.DeployPlans.Get(r.Context(), a.ExecutionID)
	switch {
	case errors.Is(err, deployplan.ErrNotFound):
		return nil, deployNotFound("no plan")
	case err != nil:
		return nil, &deployPageRefusal{status: http.StatusServiceUnavailable, msg: "The plan cannot be read right now; try again later.", audit: "plan read failed"}
	case a.Target != p.Tenant+"/"+p.Service:
		return nil, deployNotFound("plan names another target")
	}
	switch err := h.deployOwnerCheck(p.Tenant, user.PrincipalID()); {
	case errors.Is(err, governance.ErrAuthorityUnavailable):
		return nil, &deployPageRefusal{status: http.StatusServiceUnavailable, msg: "Your ownership of the team cannot be checked right now; try again later.", audit: "owner check unavailable: " + err.Error()}
	case err != nil:
		return nil, deployNotFound("not an owner: " + err.Error())
	}
	// From here the caller is an owner: a refusal may say what is wrong.
	if workitems.IntentHash(deployApplyIntent(p)) != a.IntentHash {
		return nil, &deployPageRefusal{status: http.StatusConflict, msg: "The plan does not match what this approval is bound to; ask for a new approval.", audit: "intent mismatch"}
	}
	_, unapplicable := planApplicableCheck(p, h.deployPlanNow())
	return &deployShown{approval: a, plan: p, context: h.decisionContext(a), unapplicable: unapplicable}, nil
}

// handleDeployApprovalCallback: GET /deploy/approvals/callback.
func (h *Handlers) handleDeployApprovalCallback(w http.ResponseWriter, r *http.Request) {
	d, ok := h.deployPageDecider(w)
	if !ok {
		return
	}
	q := r.URL.Query()
	state, browser := q.Get("state"), deployBrowser(r)
	if state == "" || browser == "" {
		d.failed(w, http.StatusBadRequest, deployUnknownSignIn)
		return
	}
	// Consumed now, on whichever replica the callback reached.
	var c deployStartEntry
	found, err := d.take(r.Context(), deployKindStart, basketStartKey(state, browser), &c)
	if err != nil {
		d.storeDown(w, err)
		return
	}
	if !found || d.remaining(c.StartedAt) <= 0 {
		d.failed(w, http.StatusBadRequest, deployUnknownSignIn)
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
		slog.Warn("deploy approval: ZITADEL code exchange failed", "error", err)
		d.failed(w, http.StatusBadGateway, "Could not complete the ZITADEL sign-in.")
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := prov.Verifier(&oidc.Config{ClientID: d.opts.ClientID}).Verify(r.Context(), raw)
	if err != nil {
		slog.Warn("deploy approval: ZITADEL ID token refused", "error", err)
		d.failed(w, http.StatusBadRequest, "The ZITADEL ID token was not valid.")
		return
	}
	var claims struct {
		Nonce             string `json:"nonce"`
		AuthTime          int64  `json:"auth_time"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idt.Claims(&claims); err != nil || subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(c.Nonce)) != 1 {
		d.failed(w, http.StatusBadRequest, "The ZITADEL sign-in does not belong to this approval.")
		return
	}
	if claims.AuthTime == 0 || time.Unix(claims.AuthTime, 0).Before(c.StartedAt.Add(-time.Minute)) {
		d.failed(w, http.StatusBadRequest, "ZITADEL did not report a fresh sign-in for this approval.")
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
		h.auditDeployPage(r, nil, id, c.ApprovalRef, "denied", "sign-in refused")
		d.failed(w, http.StatusNotFound, deployNotFoundMessage)
		return
	}
	shown, ref := h.readDeployApproval(r, d, user, c.ApprovalRef)
	if ref != nil {
		h.auditDeployPage(r, user, id, c.ApprovalRef, "denied", ref.audit)
		d.failed(w, ref.status, ref.msg)
		return
	}
	page := deployPageData{Diff: shown.plan.Diff}
	if !shown.decidable(d.now()) {
		title, status := "This deploy approval is "+basketStateWord(shown.approval.State), http.StatusOK
		switch {
		case shown.unapplicable != nil:
			title, status = "This plan cannot be applied", http.StatusConflict
		case !shown.context.ContextComplete:
			title, status = "This approval is incomplete", http.StatusConflict
		case shown.approval.State == workitems.ApprovalPending:
			title = "This deploy approval has expired"
		}
		d.renderPage(w, status, title, append(shown.lines(display), "There is nothing to decide here."), page)
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
	entry := deployDecideEntry{ApprovalRef: c.ApprovalRef, StartedAt: c.StartedAt, Identity: stored, Shown: shown.binding()}
	if err := d.put(r.Context(), deployKindDecide, basketDecideKey(challenge, csrf, browser), entry, left); err != nil {
		d.storeDown(w, err)
		return
	}
	page.Decide = &struct{ Action, Challenge, CSRF string }{Action: deployConfirmPath, Challenge: challenge, CSRF: csrf}
	d.renderPage(w, http.StatusOK, "Approve or reject this deploy", append(shown.lines(display),
		"Approving lets the requester apply exactly this plan, once, to the preview above. It deploys nothing by itself."), page)
}

// handleDeployApprovalConfirm: POST /deploy/approvals/confirm.
func (h *Handlers) handleDeployApprovalConfirm(w http.ResponseWriter, r *http.Request) {
	d, ok := h.deployPageDecider(w)
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
	challenge, csrf, browser := r.PostForm.Get("challenge"), r.PostForm.Get("csrf"), deployBrowser(r)
	if challenge == "" || csrf == "" || browser == "" {
		d.failed(w, http.StatusBadRequest, deployUnknownConfirm)
		return
	}
	// Used once, whatever happens next, across every replica.
	var c deployDecideEntry
	found, err := d.take(r.Context(), deployKindDecide, basketDecideKey(challenge, csrf, browser), &c)
	if err != nil {
		d.storeDown(w, err)
		return
	}
	if !found || d.remaining(c.StartedAt) <= 0 {
		d.failed(w, http.StatusBadRequest, deployUnknownConfirm)
		return
	}
	setDeployCookie(w, "", -1)
	id := c.Identity.identity()
	// Resolved and read again: a principal disabled, an ownership lost or a
	// plan or approval changed since the sign-in decides now.
	user, err := auth.UserForSignIn(r.Context(), id, d.opts.Principals, d.opts.Authz)
	if err != nil {
		h.auditDeployPage(r, nil, id, c.ApprovalRef, "denied", "sign-in refused")
		d.failed(w, http.StatusNotFound, deployNotFoundMessage)
		return
	}
	shown, ref := h.readDeployApproval(r, d, user, c.ApprovalRef)
	if ref != nil {
		h.auditDeployPage(r, user, id, c.ApprovalRef, "denied", ref.audit)
		d.failed(w, ref.status, ref.msg)
		return
	}
	if shown.binding() != c.Shown {
		h.auditDeployPage(r, user, id, c.ApprovalRef, "denied", "approval changed since it was shown")
		d.failed(w, http.StatusConflict, "The plan or its approval changed after you were shown it; nothing was decided.")
		return
	}
	if !shown.decidable(d.now()) {
		h.auditDeployPage(r, user, id, c.ApprovalRef, "denied", "not decidable")
		d.failed(w, http.StatusConflict, "This approval is already "+basketStateWord(shown.approval.State)+", has expired, or its plan can no longer be applied; nothing was decided.")
		return
	}
	in := workitems.ActionDecisionInput{
		ID: c.ApprovalRef, DecidedBy: principalOf(user), DecidedByPrincipalID: user.PrincipalID(),
		Decision: workitems.DecisionDeny, Reason: deployReasonReject,
	}
	if decision == "approve" {
		if status, err := h.approvalPolicies().Admit(shown.approval.PolicyRuleID, shown.approval.PolicyVersion, h.opts.RequireRegisteredPolicy); err != nil {
			h.auditDeployPage(r, user, id, c.ApprovalRef, "denied", "policy "+status)
			d.failed(w, http.StatusConflict, "The deploy policy this approval was asked under is not current; nothing was decided. Ask for a new approval.")
			return
		}
		in.Decision, in.Reason = workitems.DecisionApprove, deployReasonApprove
		in.ContextDigest = c.Shown.ContextDigest
		in.AuthzMode = string(h.opts.TenantAuthzMode)
		in.FreshFor = h.maxDecisionAge()
	}
	decided, err := h.opts.WorkItems.DecideDeployApproval(r.Context(), in)
	if err != nil {
		code := actionApprovalRefusalCode(err)
		if code == "" {
			slog.Error("deploy approval: decide failed", "approval", c.ApprovalRef, "error", err)
			code = "decide_failed"
		}
		h.auditDeployPage(r, user, id, c.ApprovalRef, "failed", decision+": "+code)
		d.failed(w, http.StatusConflict, "The "+decision+" was refused ("+code+"); nothing was decided.")
		return
	}
	h.auditActionApproval(r, user, "action_approval.decision", decided, operations.RiskMedium,
		map[string]string{"surface": deployPageAuditOp})
	h.auditDeployPage(r, user, id, c.ApprovalRef, "succeeded", decision)
	title := "Deploy approved"
	if decision == "reject" {
		title = "Deploy rejected"
	}
	shown.approval = decided
	d.renderPage(w, http.StatusOK, title, append(shown.lines(id.Display),
		"The assistant that asked can now apply this plan once. Nothing was deployed yet."), deployPageData{Diff: shown.plan.Diff})
}

// auditDeployPage records what the page itself decided. Ids only.
func (h *Handlers) auditDeployPage(r *http.Request, user *auth.User, id auth.Identity, approvalRef, status, msg string) {
	actor := id.Provider + ":" + id.Subject
	if user != nil {
		actor = user.ID
	}
	h.logAudit(r, audit.Entry{
		UserID:     actor,
		Operation:  deployPageAuditOp,
		Parameters: map[string]string{"approval_ref": approvalRef, "provider": id.Provider, "subject": id.Subject},
		Status:     status,
		RiskLevel:  string(operations.RiskMedium),
		Message:    msg,
	})
}
