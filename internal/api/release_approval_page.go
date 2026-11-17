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
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"golang.org/x/oauth2"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/auth/flowstore"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/releaseartifact"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Release approval page (mctl-api#1022, slice S2). The only place a
// release.grant request is decided.
//
// POST /api/v1/release/grants answers a link to /release/approvals/{aar_id}.
// The page asks the person to sign in to ZITADEL in this browser, fresh
// (prompt=login, max_age=0, PKCE S256, a nonce), through a ZITADEL client of
// its own, and then holds the sign-in to more than the deploy page does:
//
//   - the person must be a resolved human admin acting directly AND one of
//     the configured deciders (RELEASE_APPROVAL_DECIDERS, principal ids, owner
//     decision 2026-11-16: the owner only);
//   - the ID token must be issued to this page's client: aud contains the
//     client id and azp names it (OIDC Core 3.1.3.7). azp is required as
//     soon as aud has more than one entry, which is ZITADEL's normal shape:
//     it adds the project id and the project's other client ids to aud
//     (mctl-api#1022, first real sign-in 2026-11-17). So no token minted for
//     an MCP client or any other application is accepted, whatever its aud;
//   - its amr must name one of the required methods (default "mfa"). A
//     refusal lists the amr the token did carry, so the first real sign-in
//     shows what ZITADEL reports;
//   - the tag and the image are read again from GitHub and GHCR, and must
//     still be the commit and digest the request binds.
//
// What the sign-in proved is stored with the decision as its evidence
// (workitems.ReleaseEvidence) and is what the release gate reads.
//
// The mechanics are the deploy approval page's (deploy_approval_page.go): no
// session, no token in the browser, no script, a __Host- cookie for one
// decision, a one-time CSRF token, and challenges in the shared flow store
// consumed with its atomic Take. A store that cannot be read refuses the
// step.
//
// Dark by default: mounted only when ReleaseApproval is complete and the
// release grant routes are enabled.

// ReleaseApprovalPageOptions configures the page. All fields but clock are
// needed; with any missing the routes are not mounted.
type ReleaseApprovalPageOptions struct {
	// ProviderName and Issuer are the federation entry the signed-in
	// identity is resolved as (MCTL_OIDC_PROVIDERS).
	ProviderName string
	Issuer       string
	// ClientID and ClientSecret are a ZITADEL web client used by this page
	// only, whose redirect URIs include BaseURL + /release/approvals/callback.
	ClientID     string
	ClientSecret string
	BaseURL      string
	Principals   auth.PrincipalResolver
	Authz        *auth.PrincipalAuthz
	Flow         flowstore.Store
	// Deciders are the principal ids that may decide a release grant.
	Deciders []string
	// RequiredAMR: the ID token's amr must contain at least one of these.
	RequiredAMR []string

	clock func() time.Time
}

func (o *ReleaseApprovalPageOptions) enabled() bool {
	return o != nil && o.ProviderName != "" && o.Issuer != "" && o.ClientID != "" && o.ClientSecret != "" &&
		o.BaseURL != "" && o.Principals != nil && o.Authz != nil && o.Flow != nil &&
		len(o.Deciders) > 0 && len(o.RequiredAMR) > 0
}

const (
	releasePageCookie      = "__Host-mctl_release_approval"
	releasePagePrefix      = "/release/approvals/"
	releaseStartPath       = "/release/approvals/start"
	releaseCallbackPath    = "/release/approvals/callback"
	releaseConfirmPath     = "/release/approvals/confirm"
	releaseChallengeTTL    = 10 * time.Minute
	releasePageAuditOp     = "release-approval-page"
	releaseNotFoundMessage = "There is no release approval with this reference waiting for you."
	releaseUnknownSignIn   = "This sign-in is unknown, expired, already used, started in another browser, or replaced by a newer one started in this browser."
	releaseUnknownConfirm  = "This approval page is unknown, expired, already used, or was opened in another browser."

	releaseKindStart  = "release-approval-start"
	releaseKindDecide = "release-approval-decide"
)

type releaseStartEntry struct {
	ApprovalRef string    `json:"approval_ref"`
	StartedAt   time.Time `json:"started_at"`
	Nonce       string    `json:"nonce"`
	Verifier    string    `json:"verifier"`
}

type releaseDecideEntry struct {
	ApprovalRef string                    `json:"approval_ref"`
	StartedAt   time.Time                 `json:"started_at"`
	Identity    basketIdentity            `json:"identity"`
	Evidence    workitems.ReleaseEvidence `json:"evidence"`
	Shown       decisionBinding           `json:"shown"`
}

type releaseDecider struct {
	opts *ReleaseApprovalPageOptions
	lazyOIDCProvider
	now func() time.Time
}

func newReleaseDecider(opts *ReleaseApprovalPageOptions) *releaseDecider {
	now := time.Now
	if opts.clock != nil {
		now = opts.clock
	}
	return &releaseDecider{opts: opts, lazyOIDCProvider: lazyOIDCProvider{issuer: opts.Issuer}, now: now}
}

func (d *releaseDecider) put(ctx context.Context, kind, key string, v any, ttl time.Duration) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return d.opts.Flow.Put(ctx, kind, key, b, ttl)
}

func (d *releaseDecider) take(ctx context.Context, kind, key string, v any) (bool, error) {
	b, found, err := d.opts.Flow.Take(ctx, kind, key)
	if err != nil || !found {
		return false, err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return false, fmt.Errorf("release approval: %s entry unreadable: %w", kind, err)
	}
	return true, nil
}

func (d *releaseDecider) remaining(startedAt time.Time) time.Duration {
	return startedAt.Add(releaseChallengeTTL).Sub(d.now())
}

func (d *releaseDecider) oauthConfig(p *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID: d.opts.ClientID, ClientSecret: d.opts.ClientSecret, Endpoint: p.Endpoint(),
		RedirectURL: d.opts.BaseURL + releaseCallbackPath, Scopes: []string{oidc.ScopeOpenID, "profile"},
	}
}

func (d *releaseDecider) decideURL(approvalRef string) string {
	return d.opts.BaseURL + releasePagePrefix + approvalRef
}

// isDecider: a resolved human admin acting directly, named in Deciders.
func (d *releaseDecider) isDecider(u *auth.User) bool {
	return isGlovoOwnerCandidate(u) && u.IsAdmin() && slices.Contains(d.opts.Deciders, u.PrincipalID())
}

func releaseBrowser(r *http.Request) string {
	ck, err := r.Cookie(releasePageCookie)
	if err != nil {
		return ""
	}
	return ck.Value
}

func setReleaseCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: releasePageCookie, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
}

var releasePage = shellPage("release-approval", `{{if .SignIn}}<form class="actions" method="post" action="{{.SignIn.Action}}">
<input type="hidden" name="approval_ref" value="{{.SignIn.ApprovalRef}}">
<button type="submit">Sign in to review this release</button></form>{{end}}
{{if .Decide}}<form class="actions" method="post" action="{{.Decide.Action}}">
<input type="hidden" name="challenge" value="{{.Decide.Challenge}}">
<input type="hidden" name="csrf" value="{{.Decide.CSRF}}">
<button type="submit" name="decision" value="approve">Approve this release</button>
<button type="submit" name="decision" value="reject" class="secondary">Reject</button></form>{{end}}`)

type releasePageData struct {
	SignIn *struct{ Action, ApprovalRef string }
	Decide *struct{ Action, Challenge, CSRF string }
}

func (d *releaseDecider) renderPage(w http.ResponseWriter, status int, title string, lines []string, p releasePageData) {
	formAction := "'self'"
	if d != nil {
		if u, err := url.Parse(d.opts.Issuer); err == nil && u.Scheme == "https" && u.Host != "" {
			formAction += " https://" + u.Host
		}
	}
	renderShellPage(w, status, "default-src 'none'; style-src 'unsafe-inline'; form-action "+formAction+"; frame-ancestors 'none'; base-uri 'none'",
		releasePage, shellData{Title: title, Lines: lines, Page: p})
}

func (d *releaseDecider) failed(w http.ResponseWriter, status int, msg string) {
	d.renderPage(w, status, "Cannot decide this release", []string{msg, "Open the approval link again to start over."}, releasePageData{})
}

func (d *releaseDecider) storeDown(w http.ResponseWriter, err error) {
	slog.Warn("release approval: flow store unavailable", "error", err)
	d.failed(w, http.StatusServiceUnavailable, "The approval page cannot reach its store right now; nothing was decided. Try again in a few minutes.")
}

func (h *Handlers) releasePageDecider(w http.ResponseWriter) (*releaseDecider, bool) {
	d := h.releaseApproval
	if d == nil || !d.opts.enabled() || h.opts.WorkItems == nil || !h.opts.ReleaseGrants.enabled() {
		var none *releaseDecider
		none.failed(w, http.StatusServiceUnavailable, "The release approval page is not enabled on this server.")
		return nil, false
	}
	return d, true
}

// handleReleaseApprovalPage: GET /release/approvals/{approval_ref}. Reads and
// changes nothing.
func (h *Handlers) handleReleaseApprovalPage(w http.ResponseWriter, r *http.Request) {
	d, ok := h.releasePageDecider(w)
	if !ok {
		return
	}
	ref := chi.URLParam(r, "approval_ref")
	if !basketApprovalRefRe.MatchString(ref) {
		d.failed(w, http.StatusBadRequest, "This approval link is malformed.")
		return
	}
	d.renderPage(w, http.StatusOK, "Review a release", []string{
		"Approval: " + ref,
		"Sign in to ZITADEL as yourself, with your second factor, to see the release and approve or reject it. Only the release owner can see or decide it.",
		"Approving lets exactly this image of this version reach production.",
	}, releasePageData{SignIn: &struct{ Action, ApprovalRef string }{Action: releaseStartPath, ApprovalRef: ref}})
}

// handleReleaseApprovalStart: POST /release/approvals/start.
func (h *Handlers) handleReleaseApprovalStart(w http.ResponseWriter, r *http.Request) {
	d, ok := h.releasePageDecider(w)
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
		slog.Warn("release approval: ZITADEL discovery failed", "issuer", d.opts.Issuer, "error", err)
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
	entry := releaseStartEntry{ApprovalRef: ref, StartedAt: d.now(), Nonce: nonce, Verifier: oauth2.GenerateVerifier()}
	if err := d.put(r.Context(), releaseKindStart, basketStartKey(state, browser), entry, releaseChallengeTTL); err != nil {
		d.storeDown(w, err)
		return
	}
	setReleaseCookie(w, browser, int(releaseChallengeTTL.Seconds()))
	authURL := d.oauthConfig(prov).AuthCodeURL(state, oauth2.S256ChallengeOption(entry.Verifier), oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("prompt", "login"), oauth2.SetAuthURLParam("max_age", "0"))
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

// releaseShown is a release grant as the decider is shown it.
type releaseShown struct {
	approval *workitems.ActionApprovalRequest
	artifact workitems.ReleaseArtifact
}

func (s *releaseShown) decidable(now time.Time) bool {
	return s.approval.State == workitems.ApprovalPending && now.Before(s.approval.ExpiresAt)
}

func (s *releaseShown) binding() decisionBinding {
	return decisionBinding{ApprovalRef: s.approval.ID, ContextDigest: s.approval.ArgsDigest, ContentDigest: s.artifact.ImageDigest}
}

func (s *releaseShown) lines(display string) []string {
	a, art := s.approval, s.artifact
	requester := a.RequestedBy
	if a.ActorKind != "" {
		requester += " (" + a.ActorKind
		if a.ActorName != "" {
			requester += " " + a.ActorName
		}
		requester += ")"
	}
	return []string{
		"Signed in as " + display + ".",
		"Repository: " + art.Repository + ", version: " + art.Version,
		"Tag commit: " + art.TagCommit,
		"Image digest: " + art.ImageDigest,
		"Requested by: " + requester,
		"Approval: " + a.ID + " (" + basketStateWord(a.State) + "), expires " + a.ExpiresAt.UTC().Format(time.RFC3339),
	}
}

type releasePageRefusal struct {
	status int
	msg    string
	audit  string
}

func releaseNotFound(reason string) *releasePageRefusal {
	return &releasePageRefusal{status: http.StatusNotFound, msg: releaseNotFoundMessage, audit: reason}
}

// readReleaseApproval reads ref as a decider and reads the release again from
// GitHub and GHCR. Every "not yours" reads like "no such approval".
func (h *Handlers) readReleaseApproval(r *http.Request, d *releaseDecider, user *auth.User, ref string) (*releaseShown, *releasePageRefusal) {
	if !d.isDecider(user) {
		return nil, releaseNotFound("not a release decider")
	}
	a, err := h.opts.WorkItems.ActionApproval(r.Context(), ref)
	switch {
	case errors.Is(err, workitems.ErrApprovalNotFound):
		return nil, releaseNotFound("no such approval")
	case err != nil:
		return nil, &releasePageRefusal{status: http.StatusServiceUnavailable, msg: "The approval cannot be read right now; try again later.", audit: "approval read failed"}
	case a.ActionKind != workitems.ActionKindReleaseGrant:
		return nil, releaseNotFound("not a release approval")
	}
	art, err := workitems.ReleaseArtifactOf(a)
	if err != nil {
		return nil, &releasePageRefusal{status: http.StatusConflict, msg: "This approval record is inconsistent; nothing can be decided on it.", audit: "inconsistent record"}
	}
	shown := &releaseShown{approval: a, artifact: art}
	if !shown.decidable(d.now()) {
		return shown, nil
	}
	now, err := h.opts.ReleaseGrants.Resolver.Resolve(r.Context(), art.Repository, art.Version)
	switch {
	case err == nil && now == art:
		return shown, nil
	case err == nil, errors.Is(err, releaseartifact.ErrMismatch), errors.Is(err, releaseartifact.ErrNotFound):
		if err != nil {
			slog.Warn("release approval: release changed", "approval", a.ID, "error", err)
		}
		return nil, &releasePageRefusal{status: http.StatusConflict,
			msg: "The tag or the image of this release is no longer what the approval binds; nothing can be decided. Ask for a new approval.", audit: "release changed"}
	default:
		slog.Warn("release approval: release unreadable", "approval", a.ID, "error", err)
		return nil, &releasePageRefusal{status: http.StatusServiceUnavailable,
			msg: "The release cannot be read from GitHub and the registry right now; nothing was decided. Try again later.", audit: "release unreadable"}
	}
}

// releaseClaims are the ID token claims the page reads.
type releaseClaims struct {
	Nonce             string          `json:"nonce"`
	AuthTime          int64           `json:"auth_time"`
	PreferredUsername string          `json:"preferred_username"`
	AZP               string          `json:"azp"`
	AMR               []string        `json:"amr"`
	Aud               json.RawMessage `json:"aud"`
}

// issuedToClient reports whether an ID token with this aud and azp was
// issued to clientID, per OIDC Core 3.1.3.7: aud (a string or an array) must
// contain clientID; with more than one audience azp must be present; and a
// present azp must be clientID. A malformed or empty aud is refused.
func issuedToClient(raw json.RawMessage, azp, clientID string) bool {
	if clientID == "" {
		return false
	}
	var auds []string
	var one string
	if json.Unmarshal(raw, &one) == nil {
		auds = []string{one}
	} else if json.Unmarshal(raw, &auds) != nil {
		return false
	}
	found := false
	for _, a := range auds {
		if a == clientID {
			found = true
		}
	}
	if !found {
		return false
	}
	if len(auds) > 1 && azp == "" {
		return false
	}
	return azp == "" || azp == clientID
}

// handleReleaseApprovalCallback: GET /release/approvals/callback.
func (h *Handlers) handleReleaseApprovalCallback(w http.ResponseWriter, r *http.Request) {
	d, ok := h.releasePageDecider(w)
	if !ok {
		return
	}
	q := r.URL.Query()
	state, browser := q.Get("state"), releaseBrowser(r)
	if state == "" || browser == "" {
		d.failed(w, http.StatusBadRequest, releaseUnknownSignIn)
		return
	}
	var c releaseStartEntry
	found, err := d.take(r.Context(), releaseKindStart, basketStartKey(state, browser), &c)
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
		slog.Warn("release approval: ZITADEL code exchange failed", "error", err)
		d.failed(w, http.StatusBadGateway, "Could not complete the ZITADEL sign-in.")
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := prov.Verifier(&oidc.Config{ClientID: d.opts.ClientID}).Verify(r.Context(), raw)
	if err != nil {
		slog.Warn("release approval: ZITADEL ID token refused", "error", err)
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
		h.auditReleasePage(r, nil, id, c.ApprovalRef, "denied", "sign-in refused")
		d.failed(w, http.StatusNotFound, releaseNotFoundMessage)
		return
	}
	if !d.isDecider(user) {
		h.auditReleasePage(r, user, id, c.ApprovalRef, "denied", "not a release decider")
		d.failed(w, http.StatusNotFound, releaseNotFoundMessage)
		return
	}
	amr := workitems.NormalizeAMR(claims.AMR)
	if !slices.ContainsFunc(d.opts.RequiredAMR, func(m string) bool { return slices.Contains(amr, m) }) {
		got := strings.Join(amr, ", ")
		if got == "" {
			got = "none"
		}
		h.auditReleasePage(r, user, id, c.ApprovalRef, "denied", "amr without a required method: "+got)
		d.failed(w, http.StatusForbidden, "This sign-in did not report a second factor. ZITADEL reported amr: "+got+
			"; required: one of "+strings.Join(d.opts.RequiredAMR, ", ")+".")
		return
	}
	shown, refusal := h.readReleaseApproval(r, d, user, c.ApprovalRef)
	if refusal != nil {
		h.auditReleasePage(r, user, id, c.ApprovalRef, "denied", refusal.audit)
		d.failed(w, refusal.status, refusal.msg)
		return
	}
	if !shown.decidable(d.now()) {
		title := "This release approval is " + basketStateWord(shown.approval.State)
		if shown.approval.State == workitems.ApprovalPending {
			title = "This release approval has expired"
		}
		d.renderPage(w, http.StatusOK, title, append(shown.lines(display), "There is nothing to decide here."), releasePageData{})
		return
	}
	evidence := workitems.ReleaseEvidence{Schema: workitems.ReleaseEvidenceSchema, ArgsDigest: shown.approval.ArgsDigest,
		Issuer: idt.Issuer, Subject: idt.Subject, ClientID: d.opts.ClientID, AuthTime: claims.AuthTime, AMR: amr}
	if err := evidence.Validate(); err != nil {
		h.auditReleasePage(r, user, id, c.ApprovalRef, "denied", "evidence incomplete")
		d.failed(w, http.StatusBadRequest, "The ZITADEL sign-in is missing what a release decision records.")
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
	entry := releaseDecideEntry{ApprovalRef: c.ApprovalRef, StartedAt: c.StartedAt, Identity: stored, Evidence: evidence, Shown: shown.binding()}
	if err := d.put(r.Context(), releaseKindDecide, basketDecideKey(challenge, csrf, browser), entry, left); err != nil {
		d.storeDown(w, err)
		return
	}
	d.renderPage(w, http.StatusOK, "Approve or reject this release", append(shown.lines(display),
		"Approving lets exactly this image of this version reach production. It deploys nothing by itself."),
		releasePageData{Decide: &struct{ Action, Challenge, CSRF string }{Action: releaseConfirmPath, Challenge: challenge, CSRF: csrf}})
}

// handleReleaseApprovalConfirm: POST /release/approvals/confirm.
func (h *Handlers) handleReleaseApprovalConfirm(w http.ResponseWriter, r *http.Request) {
	d, ok := h.releasePageDecider(w)
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
	challenge, csrf, browser := r.PostForm.Get("challenge"), r.PostForm.Get("csrf"), releaseBrowser(r)
	if challenge == "" || csrf == "" || browser == "" {
		d.failed(w, http.StatusBadRequest, releaseUnknownConfirm)
		return
	}
	var c releaseDecideEntry
	found, err := d.take(r.Context(), releaseKindDecide, basketDecideKey(challenge, csrf, browser), &c)
	if err != nil {
		d.storeDown(w, err)
		return
	}
	if !found || d.remaining(c.StartedAt) <= 0 {
		d.failed(w, http.StatusBadRequest, releaseUnknownConfirm)
		return
	}
	setReleaseCookie(w, "", -1)
	id := c.Identity.identity()
	user, err := auth.UserForSignIn(r.Context(), id, d.opts.Principals, d.opts.Authz)
	if err != nil {
		h.auditReleasePage(r, nil, id, c.ApprovalRef, "denied", "sign-in refused")
		d.failed(w, http.StatusNotFound, releaseNotFoundMessage)
		return
	}
	shown, refusal := h.readReleaseApproval(r, d, user, c.ApprovalRef)
	if refusal != nil {
		h.auditReleasePage(r, user, id, c.ApprovalRef, "denied", refusal.audit)
		d.failed(w, refusal.status, refusal.msg)
		return
	}
	if shown.binding() != c.Shown {
		h.auditReleasePage(r, user, id, c.ApprovalRef, "denied", "approval changed since it was shown")
		d.failed(w, http.StatusConflict, "The release or its approval changed after you were shown it; nothing was decided.")
		return
	}
	if !shown.decidable(d.now()) {
		h.auditReleasePage(r, user, id, c.ApprovalRef, "denied", "not decidable")
		d.failed(w, http.StatusConflict, "This approval is already "+basketStateWord(shown.approval.State)+" or has expired; nothing was decided.")
		return
	}
	if decision == "approve" {
		if status, err := h.approvalPolicies().Admit(shown.approval.PolicyRuleID, shown.approval.PolicyVersion, h.opts.RequireRegisteredPolicy); err != nil {
			h.auditReleasePage(r, user, id, c.ApprovalRef, "denied", "policy "+status)
			d.failed(w, http.StatusConflict, "The release policy this approval was asked under is not current; nothing was decided. Ask for a new approval.")
			return
		}
	}
	decided, err := h.opts.WorkItems.DecideReleaseApproval(r.Context(), workitems.ReleaseDecisionInput{
		ID: c.ApprovalRef, DecidedBy: principalOf(user), DecidedByPrincipalID: user.PrincipalID(),
		Approve: decision == "approve", Evidence: c.Evidence,
	})
	if err != nil {
		code := actionApprovalRefusalCode(err)
		if code == "" {
			slog.Error("release approval: decide failed", "approval", c.ApprovalRef, "error", err)
			code = "decide_failed"
		}
		h.auditReleasePage(r, user, id, c.ApprovalRef, "failed", decision+": "+code)
		d.failed(w, http.StatusConflict, "The "+decision+" was refused ("+code+"); nothing was decided.")
		return
	}
	h.auditActionApproval(r, user, "action_approval.decision", decided, operations.RiskHigh,
		map[string]string{"surface": releasePageAuditOp, "amr": strings.Join(c.Evidence.AMR, ",")})
	h.auditReleasePage(r, user, id, c.ApprovalRef, "succeeded", decision)
	title, outcome := "Release approved", "The release gate may now let exactly this image reach production. Nothing was deployed yet."
	if decision == "reject" {
		title, outcome = "Release rejected", "This image of this version will not be let through. Nothing was deployed."
	}
	shown.approval = decided
	d.renderPage(w, http.StatusOK, title, append(shown.lines(id.Display), outcome), releasePageData{})
}

// auditReleasePage records what the page itself decided. Ids only.
func (h *Handlers) auditReleasePage(r *http.Request, user *auth.User, id auth.Identity, approvalRef, status, msg string) {
	actor := id.Provider + ":" + id.Subject
	if user != nil {
		actor = user.ID
	}
	h.logAudit(r, audit.Entry{
		UserID:     actor,
		Operation:  releasePageAuditOp,
		Parameters: map[string]string{"approval_ref": approvalRef, "provider": id.Provider, "subject": id.Subject},
		Status:     status,
		RiskLevel:  string(operations.RiskHigh),
		Message:    msg,
	})
}
