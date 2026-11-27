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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/httprate"
	"golang.org/x/oauth2"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/auth/flowstore"
	"github.com/mctlhq/mctl-api/internal/glovoconsent"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/principals"
)

// Glovo access page for the person asking (mctl-glovo#82, self-service). The
// bearer routes /api/v1/glovo/link-consent and /api/v1/glovo/access-request
// need a token and curl; this page is the same four operations for a new
// Google customer in a browser:
//
//   - GET  /glovo/access           static: what happens, and a sign-in button;
//   - POST /glovo/access/start     fresh ZITADEL sign-in through the customers
//     organization's Google IdP (prompt=login, max_age=0, PKCE S256, nonce);
//   - GET  /glovo/access/callback  verifies the sign-in and shows the person's
//     own consent and access state with the actions valid for it;
//   - POST /glovo/access/confirm   one action: record consent, request access,
//     withdraw the request, withdraw consent.
//
// Who may use it. Only a customers-organization identity whose token carries
// the identity hook's Google proof (auth.ReadCustomerProofWith). Staff, a
// user of another organization, a GitHub-proven customer, an unproven or
// refused one and a token naming no organization all get one answer that
// does not say which check failed. No second factor is asked: the page acts
// on the person's own records only, and the owner still approves on the
// decision page (glovo_access_page.go) with one.
//
// Whose records. The principal is resolved from the verified sign-in and
// nothing else: no route, form field or query parameter names a principal.
// It is resolved again on every action, so a principal disabled inside the
// flow stops there.
//
// How long. There is no session. The sign-in yields a one-time challenge and
// CSRF token bound to the browser cookie, held in the shared flow store and
// spent with its atomic Take. An action renders the new state with a freshly
// issued challenge, so the person can do the next one without signing in
// again, but only until the flow's absolute lifetime (releaseChallengeTTL,
// counted from the start of the sign-in) runs out: an action never extends
// it.
//
// What is recorded. The page calls the store methods of the bearer routes
// and writes their metric labels and audit operations, with the principal id
// as the audit actor and the store actor. The display name, login and email
// of the person are never read into a page, a flow entry, a log line or an
// audit row; the page shows a masked principal id only. No body it renders
// holds an email-shaped string, which the edge in front of it would rewrite.
//
// Dark by default: mounted only when GlovoAccessSelf is complete, mctl-api
// runs in principal mode and the access store is wired. Unmounted, every
// path is the router's 404. The ZITADEL client's redirect URIs must include
// BaseURL + glovoAccessSelfCallbackPath, and the identity hook must issue
// the mctl:* claims to it.

// GlovoAccessSelfPageOptions configures the page. Every field but clock is
// needed; with any missing the routes are not mounted.
type GlovoAccessSelfPageOptions struct {
	// ProviderName and Issuer are the federation entry of the customers'
	// ZITADEL (MCTL_OIDC_PROVIDERS), the one the OAuth upstream signs
	// customers in through.
	ProviderName string
	Issuer       string
	// ClientID and ClientSecret are a ZITADEL web client used by this page
	// only.
	ClientID     string
	ClientSecret string
	BaseURL      string
	Principals   auth.PrincipalResolver
	Flow         flowstore.Store
	// CustomersOrgID and CustomersGoogleIdPID are the ZITADEL organization of
	// self-service customers and its Google IdP: the sign-in is started
	// there, and only a Google proof of that organization is accepted.
	CustomersOrgID       string
	CustomersGoogleIdPID string

	clock func() time.Time
}

func (o *GlovoAccessSelfPageOptions) enabled() bool {
	return o != nil && o.ProviderName != "" && o.Issuer != "" && o.ClientID != "" && o.ClientSecret != "" &&
		o.BaseURL != "" && o.Principals != nil && o.Flow != nil && o.CustomersOrgID != "" && o.CustomersGoogleIdPID != ""
}

const (
	glovoAccessSelfCookie       = "__Host-mctl_glovo_access_self"
	glovoAccessSelfPath         = "/glovo/access"
	glovoAccessSelfStartPath    = "/glovo/access/start"
	glovoAccessSelfCallbackPath = "/glovo/access/callback"
	glovoAccessSelfConfirmPath  = "/glovo/access/confirm"

	glovoAccessSelfKindStart = "glovo-access-self-start"
	glovoAccessSelfKindAct   = "glovo-access-self-act"

	// glovoAccessSelfSurface marks the page's audit rows apart from the
	// bearer routes', which write the same operations.
	glovoAccessSelfSurface = "glovo-access-self-page"

	// glovoAccessSelfLinkURL is where the consent text and the linking steps
	// are published.
	glovoAccessSelfLinkURL = "https://glovo.mctl.ai/link"
	// glovoAccessSelfGoogleOrigin is added to form-action: the sign-in form's
	// redirect chain goes through ZITADEL straight on to Google without a
	// page in between, and a browser that applies form-action to redirects
	// would stop it there.
	glovoAccessSelfGoogleOrigin = "https://accounts.google.com"

	// glovoAccessSelfRequestsPerHour bounds how many access requests one
	// principal can open through the page. Each new request queues an owner
	// card.
	glovoAccessSelfRequestsPerHour = 3

	// glovoAccessSelfStartsPerMinute bounds POST /glovo/access/start per
	// client address. Every start writes one flow-store row without
	// authentication. The count is per process, so with N replicas the
	// ceiling is N x this value. The group limit of 60 per minute still
	// applies in front of it.
	glovoAccessSelfStartsPerMinute = 10

	glovoAccessSelfActionConsent         = "consent"
	glovoAccessSelfActionRequest         = "request"
	glovoAccessSelfActionWithdrawRequest = "withdraw_request"
	glovoAccessSelfActionWithdrawConsent = "withdraw_consent"

	gcCodeConsentRequired = "glovo_consent_required"

	glovoAccessSelfNeedsGoogle  = "This page needs a Google sign-in with the Google account you connect your assistant with. This sign-in cannot be used here; nothing was changed."
	glovoAccessSelfUnknownFlow  = "This sign-in is unknown, expired, already used, or was started in another browser."
	glovoAccessSelfUnknownForm  = "This page is unknown, expired, already used, or was opened in another browser. Nothing was changed."
	glovoAccessSelfSignInAgain  = "This page has expired. Sign in again to do more."
	glovoAccessSelfNotValidHere = "That action does not apply to your current state; nothing was changed."
)

type glovoAccessSelf struct {
	opts *GlovoAccessSelfPageOptions
	lazyOIDCProvider
	now func() time.Time
	// requests is the per-principal limiter on opening a request. It lives
	// in this process, like the other per-principal limiters here.
	requests *httprate.RateLimiter
}

func newGlovoAccessSelf(opts *GlovoAccessSelfPageOptions) *glovoAccessSelf {
	now := time.Now
	if opts.clock != nil {
		now = opts.clock
	}
	return &glovoAccessSelf{opts: opts, lazyOIDCProvider: lazyOIDCProvider{issuer: opts.Issuer}, now: now,
		requests: httprate.NewRateLimiter(glovoAccessSelfRequestsPerHour, time.Hour)}
}

type glovoAccessSelfStartEntry struct {
	StartedAt time.Time `json:"started_at"`
	Nonce     string    `json:"nonce"`
	Verifier  string    `json:"verifier"`
}

// glovoAccessSelfActEntry is what the sign-in proved, kept for the actions
// of one flow: ids only.
type glovoAccessSelfActEntry struct {
	StartedAt time.Time `json:"started_at"`
	Issuer    string    `json:"issuer"`
	Subject   string    `json:"subject"`
	GoogleSub string    `json:"google_sub"`
	Principal string    `json:"principal"`
}

func (c glovoAccessSelfActEntry) identity(provider string) auth.Identity {
	// No display: the token's name can be an email address.
	return auth.Identity{Provider: provider, Issuer: c.Issuer, Subject: c.Subject, Kind: auth.KindHuman,
		Customer: &auth.CustomerProof{Provider: auth.ProviderGoogle, GoogleSub: c.GoogleSub}}
}

func (p *glovoAccessSelf) put(ctx context.Context, kind, key string, v any, ttl time.Duration) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return p.opts.Flow.Put(ctx, kind, key, b, ttl)
}

func (p *glovoAccessSelf) take(ctx context.Context, kind, key string, v any) (bool, error) {
	b, found, err := p.opts.Flow.Take(ctx, kind, key)
	if err != nil || !found {
		return false, err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return false, fmt.Errorf("glovo access page: %s entry unreadable: %w", kind, err)
	}
	return true, nil
}

func (p *glovoAccessSelf) remaining(startedAt time.Time) time.Duration {
	return startedAt.Add(releaseChallengeTTL).Sub(p.now())
}

func (p *glovoAccessSelf) oauthConfig(prov *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID: p.opts.ClientID, ClientSecret: p.opts.ClientSecret, Endpoint: prov.Endpoint(),
		RedirectURL: p.opts.BaseURL + glovoAccessSelfCallbackPath,
		// The resource-owner scope makes the ID token name the user's
		// organization, without which a customer cannot be told from anyone.
		Scopes: []string{oidc.ScopeOpenID, "profile", auth.ScopeResourceOwner},
	}
}

func glovoAccessSelfBrowser(r *http.Request) string {
	ck, err := r.Cookie(glovoAccessSelfCookie)
	if err != nil {
		return ""
	}
	return ck.Value
}

func setGlovoAccessSelfCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: glovoAccessSelfCookie, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
}

var glovoAccessSelfTemplate = shellPage("glovo-access-self", `{{if .SignIn}}<form class="actions" method="post" action="{{.SignIn}}">
<button type="submit">Sign in with Google</button></form>{{end}}
{{if .Act}}<form class="actions" method="post" action="{{.Act.Action}}">
<input type="hidden" name="challenge" value="{{.Act.Challenge}}">
<input type="hidden" name="csrf" value="{{.Act.CSRF}}">
{{range .Act.Buttons}}<button type="submit" name="action" value="{{.Value}}"{{if .Secondary}} class="secondary"{{end}}>{{.Text}}</button>
{{end}}</form>{{end}}`)

type glovoAccessSelfButton struct {
	Value, Text string
	Secondary   bool
}

type glovoAccessSelfPageData struct {
	// SignIn is the start path when the page offers the sign-in button.
	SignIn string
	Act    *struct {
		Action, Challenge, CSRF string
		Buttons                 []glovoAccessSelfButton
	}
}

func (p *glovoAccessSelf) renderPage(w http.ResponseWriter, status int, title string, lines []string, links []shellLink, d glovoAccessSelfPageData) {
	formAction := "'self'"
	if u, err := url.Parse(p.opts.Issuer); err == nil && u.Scheme == "https" && u.Host != "" {
		formAction += " https://" + u.Host
	}
	formAction += " " + glovoAccessSelfGoogleOrigin
	renderShellPage(w, status, "default-src 'none'; style-src 'unsafe-inline'; form-action "+formAction+"; frame-ancestors 'none'; base-uri 'none'",
		glovoAccessSelfTemplate, shellData{Title: title, Lines: lines, Links: links, Page: d})
}

// failed ends a flow: the message, and the way back to the first page.
// startLimit is the dedicated per-client-address limit on the start route. It
// runs before the handler, so a refused request writes nothing.
func (p *glovoAccessSelf) startLimit() func(http.Handler) http.Handler {
	return httprate.Limit(glovoAccessSelfStartsPerMinute, time.Minute,
		httprate.WithKeyFuncs(keyByTrustedIP),
		httprate.WithResponseHeaders(httprate.ResponseHeaders{RetryAfter: "Retry-After"}),
		httprate.WithLimitHandler(func(w http.ResponseWriter, _ *http.Request) {
			p.failed(w, http.StatusTooManyRequests, "Too many sign-in attempts from your network. Wait a minute and try again; nothing was changed.")
		}))
}

func (p *glovoAccessSelf) failed(w http.ResponseWriter, status int, msg string) {
	start := p.opts.BaseURL + glovoAccessSelfPath
	p.renderPage(w, status, "Glovo access", []string{msg, "To start over, open " + start},
		[]shellLink{{Text: start, URL: start}}, glovoAccessSelfPageData{})
}

func (p *glovoAccessSelf) storeDown(w http.ResponseWriter, err error) {
	slog.Warn("glovo access page: flow store unavailable", "error", err)
	p.failed(w, http.StatusServiceUnavailable, "This page cannot reach its store right now; nothing was changed. Try again in a few minutes.")
}

// glovoAccessSelfPage answers 404 unless the page is fully configured: the
// routes are not mounted then either, this keeps a handler safe on its own.
func (h *Handlers) glovoAccessSelfPage(w http.ResponseWriter, r *http.Request) (*glovoAccessSelf, bool) {
	p := h.glovoAccessSelf
	if p == nil || !p.opts.enabled() || !h.opts.GlovoConsent.accessMounted() || h.opts.TenantAuthzMode != TenantAuthzPrincipal {
		http.NotFound(w, r)
		return nil, false
	}
	return p, true
}

// handleGlovoAccessSelfPage: GET /glovo/access. Static: it reads nothing,
// changes nothing and sets no cookie.
func (h *Handlers) handleGlovoAccessSelfPage(w http.ResponseWriter, r *http.Request) {
	p, ok := h.glovoAccessSelfPage(w, r)
	if !ok {
		return
	}
	p.renderPage(w, http.StatusOK, "Get access to the Glovo connector", []string{
		"1. Sign in with Google. Use the same Google account you connect your assistant with.",
		"2. Record your consent to link a Glovo account (consent version " + glovoconsent.Version + ").",
		"3. Request access.",
		"4. Wait for the approval, then link your Glovo account.",
		"The consent text and the linking steps are at " + glovoAccessSelfLinkURL,
	}, []shellLink{{Text: glovoAccessSelfLinkURL, URL: glovoAccessSelfLinkURL}},
		glovoAccessSelfPageData{SignIn: glovoAccessSelfStartPath})
}

// handleGlovoAccessSelfStart: POST /glovo/access/start.
func (h *Handlers) handleGlovoAccessSelfStart(w http.ResponseWriter, r *http.Request) {
	p, ok := h.glovoAccessSelfPage(w, r)
	if !ok {
		return
	}
	prov, err := p.oidcProvider(r.Context())
	if err != nil {
		slog.Warn("glovo access page: ZITADEL discovery failed", "issuer", p.opts.Issuer, "error", err)
		p.failed(w, http.StatusBadGateway, "The sign-in service is not reachable right now.")
		return
	}
	browser, err1 := randomLinkToken()
	state, err2 := randomLinkToken()
	nonce, err3 := randomLinkToken()
	if err := errors.Join(err1, err2, err3); err != nil {
		p.failed(w, http.StatusInternalServerError, "Internal error.")
		return
	}
	entry := glovoAccessSelfStartEntry{StartedAt: p.now(), Nonce: nonce, Verifier: oauth2.GenerateVerifier()}
	if err := p.put(r.Context(), glovoAccessSelfKindStart, basketStartKey(state, browser), entry, releaseChallengeTTL); err != nil {
		p.storeDown(w, err)
		return
	}
	setGlovoAccessSelfCookie(w, browser, int(releaseChallengeTTL.Seconds()))
	cfg := p.oauthConfig(prov)
	// Only the authorize request names the organization and the IdP: ZITADEL
	// then skips its own login page and goes to Google.
	cfg.Scopes = append(cfg.Scopes, auth.ScopeOrgIDPrefix+p.opts.CustomersOrgID, auth.ScopeIdPIDPrefix+p.opts.CustomersGoogleIdPID)
	authURL := cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(entry.Verifier), oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("prompt", "login"), oauth2.SetAuthURLParam("max_age", "0"))
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

// glovoAccessSelfClaims are the ID token claims the page reads by name. The
// preferred_username is deliberately not among them.
type glovoAccessSelfClaims struct {
	Nonce    string          `json:"nonce"`
	AuthTime int64           `json:"auth_time"`
	AZP      string          `json:"azp"`
	Aud      json.RawMessage `json:"aud"`
}

// glovoAccessSelfGoogleProof reads the verified token's customer proof and
// accepts a Google proof of the customers organization only. reason says
// what was wrong, for the log and the metric; the person is told nothing of
// it.
func (p *glovoAccessSelf) googleProof(idt *oidc.IDToken) (proof *auth.CustomerProof, reason string) {
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return nil, "claims_unreadable"
	}
	proof, err := auth.ReadCustomerProofWith(claims, p.opts.CustomersOrgID, true)
	switch {
	case errors.Is(err, auth.ErrResourceOwnerUnknown):
		return nil, "no_organization"
	case errors.Is(err, auth.ErrCustomerUnproven):
		return nil, "unproven"
	case err != nil:
		return nil, "proof_unreadable"
	case proof == nil:
		return nil, "not_customers_org"
	case proof.Provider != auth.ProviderGoogle || !auth.ValidGoogleSubject(proof.GoogleSub):
		return nil, "not_google"
	}
	return proof, ""
}

type glovoAccessSelfRefusal struct {
	status  int
	msg     string
	outcome string
}

// resolve turns the proven identity into its principal. Every refusal fails
// closed: a conflict, a disabled or refused principal and a failed lookup
// all end the flow, and only the first three say so.
func (p *glovoAccessSelf) resolve(ctx context.Context, id auth.Identity) (string, *glovoAccessSelfRefusal) {
	pid, err := p.opts.Principals.ResolvePrincipal(ctx, id)
	if err == nil && !auth.ValidPrincipalID(pid) {
		err = errors.New("the resolver answered without a principal id")
	}
	switch {
	case err == nil:
		return pid, nil
	case errors.Is(err, principals.ErrCustomerConflict):
		slog.Warn("glovo access page: customer identity conflicts with another principal", "zitadel_subject", id.Subject, "error", err)
		return "", &glovoAccessSelfRefusal{status: http.StatusConflict, outcome: "conflict",
			msg: "Your Google account is already tied to a different MCTL account, so this page does not guess which one you are. Nothing was changed. Contact MCTL support."}
	case errors.Is(err, auth.ErrPrincipalDisabled), errors.Is(err, auth.ErrIdentityRefused):
		slog.Warn("glovo access page: sign-in refused for its principal", "zitadel_subject", id.Subject, "error", err)
		return "", &glovoAccessSelfRefusal{status: http.StatusForbidden, outcome: "disabled",
			msg: "This account is disabled on MCTL. Nothing was changed. Contact MCTL support if you think that is a mistake."}
	default:
		slog.Warn("glovo access page: principal not resolved", "zitadel_subject", id.Subject, "error", err)
		return "", &glovoAccessSelfRefusal{status: http.StatusServiceUnavailable, outcome: "unavailable",
			msg: "MCTL cannot look up your account right now; nothing was changed. Try again later."}
	}
}

// glovoAccessSelfState is the person's own consent and access, as read.
type glovoAccessSelfState struct {
	consent bool
	access  glovoAccessView
}

func (s glovoAccessSelfState) pendingNow(now time.Time) bool {
	return s.access.Status == string(glovoconsent.AccessPending) && s.access.ExpiresAt != nil && !now.After(*s.access.ExpiresAt)
}

func (s glovoAccessSelfState) approved() bool {
	return s.access.Status == string(glovoconsent.AccessApproved)
}

// allows reports whether action applies to the state: the page offers
// exactly these, and a confirm is held to them again.
func (s glovoAccessSelfState) allows(action string, now time.Time) bool {
	switch action {
	case glovoAccessSelfActionConsent:
		return !s.consent
	case glovoAccessSelfActionWithdrawConsent:
		return s.consent
	case glovoAccessSelfActionRequest:
		// A request needs the consent first: the owner is asked to approve
		// someone who has already agreed to the text.
		return s.consent && !s.pendingNow(now) && !s.approved()
	case glovoAccessSelfActionWithdrawRequest:
		return s.pendingNow(now)
	}
	return false
}

// readGlovoAccessSelfState reads both records of pid. Only the stores'
// documented absence is "none"; a failed or inconsistent read is an error.
func (h *Handlers) readGlovoAccessSelfState(ctx context.Context, pid string) (glovoAccessSelfState, error) {
	g := h.opts.GlovoConsent
	var st glovoAccessSelfState
	rec, err := g.Store.Active(ctx, pid)
	switch {
	case errors.Is(err, glovoconsent.ErrNoConsent):
	case err != nil:
		return st, fmt.Errorf("consent read: %w", err)
	case !activeConsentOf(rec, pid):
		return st, errors.New("consent read: the store answered with a record that is not an active consent of this principal")
	default:
		st.consent = true
	}
	a, err := g.Access.GetAccess(ctx, pid)
	if err != nil {
		return st, fmt.Errorf("access read: %w", err)
	}
	if !validAccessOf(a, pid) {
		return st, errors.New("access read: the store answered with a row that is not a state of this principal")
	}
	st.access = accessView(a)
	return st, nil
}

func (s glovoAccessSelfState) lines(pid string, now time.Time) []string {
	consent := "not recorded"
	if s.consent {
		consent = "recorded"
	}
	access := s.access.Status
	switch {
	case s.pendingNow(now):
		access = "pending, waiting for approval until " + s.access.ExpiresAt.UTC().Format(time.RFC3339)
	case s.access.Status == string(glovoconsent.AccessPending):
		access = "expired without a decision"
	case s.access.Status == string(glovoconsent.AccessNone):
		access = "not requested"
	}
	out := []string{
		"Signed in with Google as account " + maskedPrincipalID(pid) + ".",
		"Consent (version " + glovoconsent.Version + "): " + consent,
		"Access: " + access,
	}
	switch {
	case s.approved() && s.consent:
		out = append(out, "You have access. Link your Glovo account at "+glovoAccessSelfLinkURL)
	case s.approved():
		out = append(out, "Your access is approved, but linking also needs your consent.")
	case s.pendingNow(now):
		out = append(out, "Your request is waiting for the owner's decision. Come back later to see it.")
	case s.consent:
		out = append(out, "Request access to continue.")
	default:
		out = append(out, "Read the consent text at "+glovoAccessSelfLinkURL+" and record your consent to continue.")
	}
	return out
}

func (s glovoAccessSelfState) buttons(now time.Time) []glovoAccessSelfButton {
	all := []glovoAccessSelfButton{
		{Value: glovoAccessSelfActionConsent, Text: "Record my consent"},
		{Value: glovoAccessSelfActionRequest, Text: "Request access"},
		{Value: glovoAccessSelfActionWithdrawRequest, Text: "Withdraw my request", Secondary: true},
		{Value: glovoAccessSelfActionWithdrawConsent, Text: "Withdraw my consent", Secondary: true},
	}
	var out []glovoAccessSelfButton
	for _, b := range all {
		if s.allows(b.Value, now) {
			out = append(out, b)
		}
	}
	return out
}

// renderState draws the state and, while the flow still has time left, a
// freshly issued one-time form for the next action. The new challenge lives
// only for what is left of the flow that started at startedAt.
func (p *glovoAccessSelf) renderState(w http.ResponseWriter, r *http.Request, status int, notice string, st glovoAccessSelfState, c glovoAccessSelfActEntry, browser string) {
	now := p.now()
	lines := st.lines(c.Principal, now)
	if notice != "" {
		lines = append([]string{notice}, lines...)
	}
	links := []shellLink{{Text: glovoAccessSelfLinkURL, URL: glovoAccessSelfLinkURL}}
	title := "Your Glovo access"
	buttons := st.buttons(now)
	left := p.remaining(c.StartedAt)
	if left <= 0 || len(buttons) == 0 {
		if left <= 0 {
			lines = append(lines, glovoAccessSelfSignInAgain)
		}
		p.renderPage(w, status, title, lines, links, glovoAccessSelfPageData{})
		return
	}
	challenge, err1 := randomLinkToken()
	csrf, err2 := randomLinkToken()
	if err := errors.Join(err1, err2); err != nil {
		p.failed(w, http.StatusInternalServerError, "Internal error.")
		return
	}
	if err := p.put(r.Context(), glovoAccessSelfKindAct, basketDecideKey(challenge, csrf, browser), c, left); err != nil {
		p.storeDown(w, err)
		return
	}
	p.renderPage(w, status, title, lines, links, glovoAccessSelfPageData{Act: &struct {
		Action, Challenge, CSRF string
		Buttons                 []glovoAccessSelfButton
	}{Action: glovoAccessSelfConfirmPath, Challenge: challenge, CSRF: csrf, Buttons: buttons}})
}

// handleGlovoAccessSelfCallback: GET /glovo/access/callback.
func (h *Handlers) handleGlovoAccessSelfCallback(w http.ResponseWriter, r *http.Request) {
	p, ok := h.glovoAccessSelfPage(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	state, browser := q.Get("state"), glovoAccessSelfBrowser(r)
	if state == "" || browser == "" {
		p.failed(w, http.StatusBadRequest, glovoAccessSelfUnknownFlow)
		return
	}
	var c glovoAccessSelfStartEntry
	found, err := p.take(r.Context(), glovoAccessSelfKindStart, basketStartKey(state, browser), &c)
	if err != nil {
		p.storeDown(w, err)
		return
	}
	if !found || p.remaining(c.StartedAt) <= 0 {
		p.failed(w, http.StatusBadRequest, glovoAccessSelfUnknownFlow)
		return
	}
	if q.Get("error") != "" {
		p.failed(w, http.StatusBadRequest, "The sign-in was not completed.")
		return
	}
	code := q.Get("code")
	if code == "" {
		p.failed(w, http.StatusBadRequest, "The sign-in returned no code.")
		return
	}
	prov, err := p.oidcProvider(r.Context())
	if err != nil {
		slog.Warn("glovo access page: ZITADEL discovery failed", "issuer", p.opts.Issuer, "error", err)
		p.failed(w, http.StatusBadGateway, "The sign-in service is not reachable right now.")
		return
	}
	tok, err := p.oauthConfig(prov).Exchange(r.Context(), code, oauth2.VerifierOption(c.Verifier))
	if err != nil {
		slog.Warn("glovo access page: ZITADEL code exchange failed", "error", err)
		p.failed(w, http.StatusBadGateway, "Could not complete the sign-in.")
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := prov.Verifier(&oidc.Config{ClientID: p.opts.ClientID}).Verify(r.Context(), raw)
	if err != nil {
		slog.Warn("glovo access page: ZITADEL ID token refused", "error", err)
		p.failed(w, http.StatusBadRequest, "The sign-in token was not valid.")
		return
	}
	var claims glovoAccessSelfClaims
	if err := idt.Claims(&claims); err != nil || subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(c.Nonce)) != 1 {
		p.failed(w, http.StatusBadRequest, "The sign-in does not belong to this page.")
		return
	}
	if claims.AuthTime <= 0 || time.Unix(claims.AuthTime, 0).Before(c.StartedAt.Add(-time.Minute)) {
		p.failed(w, http.StatusBadRequest, "The sign-in service did not report a fresh sign-in for this page.")
		return
	}
	if !issuedToClient(claims.Aud, claims.AZP, p.opts.ClientID) {
		p.failed(w, http.StatusBadRequest, "The sign-in token was not issued to this page.")
		return
	}
	proof, reason := p.googleProof(idt)
	if proof == nil {
		// One answer for every reason: which check failed is not the
		// visitor's to learn.
		slog.Warn("glovo access page: sign-in refused", "reason", reason, "zitadel_subject", idt.Subject)
		glovoConsentEvents.WithLabelValues("access_self_signin", "not_google").Inc()
		p.failed(w, http.StatusForbidden, glovoAccessSelfNeedsGoogle)
		return
	}
	entry := glovoAccessSelfActEntry{StartedAt: c.StartedAt, Issuer: idt.Issuer, Subject: idt.Subject, GoogleSub: proof.GoogleSub}
	pid, refusal := p.resolve(r.Context(), entry.identity(p.opts.ProviderName))
	if refusal != nil {
		glovoConsentEvents.WithLabelValues("access_self_signin", refusal.outcome).Inc()
		p.failed(w, refusal.status, refusal.msg)
		return
	}
	entry.Principal = pid
	st, err := h.readGlovoAccessSelfState(r.Context(), pid)
	if err != nil {
		slog.Warn("glovo access page: state unreadable", "principal", maskedPrincipalID(pid), "error", err)
		glovoConsentEvents.WithLabelValues("access_self_signin", "store_error").Inc()
		p.failed(w, http.StatusServiceUnavailable, "Your consent and access cannot be read right now; nothing was changed. Try again later.")
		return
	}
	glovoConsentEvents.WithLabelValues("access_self_signin", "ok").Inc()
	p.renderState(w, r, http.StatusOK, "", st, entry, browser)
}

// glovoAccessSelfResult is what one action came to. fatal ends the flow with
// the notice alone; otherwise the state is drawn again under it.
type glovoAccessSelfResult struct {
	status int
	notice string
	fatal  bool
}

// handleGlovoAccessSelfConfirm: POST /glovo/access/confirm.
func (h *Handlers) handleGlovoAccessSelfConfirm(w http.ResponseWriter, r *http.Request) {
	p, ok := h.glovoAccessSelfPage(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		p.failed(w, http.StatusBadRequest, "The request could not be read.")
		return
	}
	action := r.PostForm.Get("action")
	switch action {
	case glovoAccessSelfActionConsent, glovoAccessSelfActionRequest, glovoAccessSelfActionWithdrawRequest, glovoAccessSelfActionWithdrawConsent:
	default:
		p.failed(w, http.StatusBadRequest, "Choose one of the actions on the page.")
		return
	}
	challenge, csrf, browser := r.PostForm.Get("challenge"), r.PostForm.Get("csrf"), glovoAccessSelfBrowser(r)
	if challenge == "" || csrf == "" || browser == "" {
		p.failed(w, http.StatusBadRequest, glovoAccessSelfUnknownForm)
		return
	}
	var c glovoAccessSelfActEntry
	found, err := p.take(r.Context(), glovoAccessSelfKindAct, basketDecideKey(challenge, csrf, browser), &c)
	if err != nil {
		p.storeDown(w, err)
		return
	}
	if !found || p.remaining(c.StartedAt) <= 0 {
		p.failed(w, http.StatusBadRequest, glovoAccessSelfUnknownForm)
		return
	}
	// The principal comes from the flow entry the sign-in wrote, never from
	// the request, and is resolved again: a principal disabled or re-keyed
	// since the sign-in acts on nothing.
	pid, refusal := p.resolve(r.Context(), c.identity(p.opts.ProviderName))
	if refusal != nil {
		glovoConsentEvents.WithLabelValues("access_self_action", refusal.outcome).Inc()
		p.failed(w, refusal.status, refusal.msg)
		return
	}
	if pid != c.Principal {
		slog.Error("glovo access page: the sign-in now resolves to another principal", "was", maskedPrincipalID(c.Principal), "now", maskedPrincipalID(pid))
		glovoConsentEvents.WithLabelValues("access_self_action", "principal_changed").Inc()
		p.failed(w, http.StatusConflict, "Your account changed since you signed in; nothing was changed.")
		return
	}
	st, err := h.readGlovoAccessSelfState(r.Context(), pid)
	if err != nil {
		slog.Warn("glovo access page: state unreadable", "principal", maskedPrincipalID(pid), "error", err)
		glovoConsentEvents.WithLabelValues("access_self_action", "store_error").Inc()
		p.failed(w, http.StatusServiceUnavailable, "Your consent and access cannot be read right now; nothing was changed. Try again later.")
		return
	}
	res := h.actGlovoAccessSelf(w, r, p, pid, action, st)
	if res.fatal {
		p.failed(w, res.status, res.notice)
		return
	}
	st, err = h.readGlovoAccessSelfState(r.Context(), pid)
	if err != nil {
		slog.Warn("glovo access page: state unreadable after an action", "principal", maskedPrincipalID(pid), "error", err)
		glovoConsentEvents.WithLabelValues("access_self_action", "store_error").Inc()
		p.failed(w, http.StatusServiceUnavailable, "Your current state cannot be read right now, so this page does not show one. Open the page again later to see it.")
		return
	}
	p.renderState(w, r, res.status, res.notice, st, c, browser)
}

// actGlovoAccessSelf does one action for pid, with the bearer routes' store
// calls, metric labels and audit operations.
func (h *Handlers) actGlovoAccessSelf(w http.ResponseWriter, r *http.Request, p *glovoAccessSelf, pid, action string, st glovoAccessSelfState) glovoAccessSelfResult {
	g := h.opts.GlovoConsent
	ctx := r.Context()
	storeFailed := glovoAccessSelfResult{status: http.StatusServiceUnavailable, fatal: true,
		notice: "That could not be recorded right now. Open the page again later to see your current state."}
	if !st.allows(action, p.now()) {
		glovoConsentEvents.WithLabelValues("access_self_action", "not_valid").Inc()
		notice := glovoAccessSelfNotValidHere
		if action == glovoAccessSelfActionRequest && !st.consent {
			const op = "glovo.access_request.open"
			glovoConsentEvents.WithLabelValues("access_request", "consent_required").Inc()
			h.auditGlovoAccessSelf(r, pid, op, "refused", nil, gcCodeConsentRequired)
			notice = "Record your consent first; no request was opened."
		}
		return glovoAccessSelfResult{status: http.StatusConflict, notice: notice}
	}
	switch action {
	case glovoAccessSelfActionConsent:
		const op = "glovo.link_consent.record"
		rec, created, err := g.Store.Record(ctx, pid, pid, g.Capacity)
		switch {
		case errors.Is(err, glovoconsent.ErrCapacityReached):
			glovoConsentEvents.WithLabelValues("human_record", "capacity_reached").Inc()
			h.auditGlovoAccessSelf(r, pid, op, "refused", nil, gcCodeCapacityReached)
			return glovoAccessSelfResult{status: http.StatusConflict,
				notice: "Glovo account linking is full right now; your consent was not recorded. You can try again later."}
		case err != nil:
			slog.Error("glovo access page: consent not recorded", "principal", maskedPrincipalID(pid), "error", err)
			glovoConsentEvents.WithLabelValues("human_record", "store_error").Inc()
			h.auditGlovoAccessSelf(r, pid, op, "failed", nil, gcCodeUnavailable)
			return storeFailed
		case !activeConsentOf(rec, pid):
			glovoConsentEvents.WithLabelValues("human_record", "store_inconsistent").Inc()
			h.auditGlovoAccessSelf(r, pid, op, "failed", nil, gcCodeUnavailable)
			return storeFailed
		}
		outcome := "unchanged"
		if created {
			outcome = "recorded"
		}
		glovoConsentEvents.WithLabelValues("human_record", outcome).Inc()
		h.auditGlovoAccessSelf(r, pid, op, outcome, &rec, "")
		return glovoAccessSelfResult{status: http.StatusOK, notice: "Your consent is recorded."}

	case glovoAccessSelfActionWithdrawConsent:
		const op = "glovo.link_consent.revoke"
		rec, err := g.Store.Revoke(ctx, pid, pid)
		switch {
		case errors.Is(err, glovoconsent.ErrNoConsent):
			glovoConsentEvents.WithLabelValues("human_revoke", "none").Inc()
			return glovoAccessSelfResult{status: http.StatusOK, notice: "You had no consent to withdraw."}
		case err != nil:
			slog.Error("glovo access page: consent not withdrawn", "principal", maskedPrincipalID(pid), "error", err)
			glovoConsentEvents.WithLabelValues("human_revoke", "store_error").Inc()
			h.auditGlovoAccessSelf(r, pid, op, "failed", nil, gcCodeUnavailable)
			return storeFailed
		}
		glovoConsentEvents.WithLabelValues("human_revoke", "revoked").Inc()
		h.auditGlovoAccessSelf(r, pid, op, "revoked", &rec, "")
		return glovoAccessSelfResult{status: http.StatusOK, notice: "Your consent is withdrawn."}

	case glovoAccessSelfActionRequest:
		const op = "glovo.access_request.open"
		if p.requests.OnLimit(w, r, "glovo-access-self-request:"+pid) {
			glovoConsentEvents.WithLabelValues("access_request", "rate_limited").Inc()
			h.auditGlovoAccessSelf(r, pid, op, "refused", nil, gcCodeRateLimited)
			return glovoAccessSelfResult{status: http.StatusTooManyRequests,
				notice: "You opened several requests in the last hour; no new request was opened. Try again later."}
		}
		a, created, err := g.Access.RequestAccess(ctx, pid)
		switch {
		case errors.Is(err, glovoconsent.ErrAccessApproved):
			glovoConsentEvents.WithLabelValues("access_request", "already_approved").Inc()
			h.auditGlovoAccessSelf(r, pid, op, "refused", nil, gcCodeAccessApproved)
			return glovoAccessSelfResult{status: http.StatusConflict, notice: "Your access is already approved; no request was opened."}
		case err != nil || !validAccessOf(a, pid) || a.Status != glovoconsent.AccessPending:
			slog.Error("glovo access page: request not opened", "principal", maskedPrincipalID(pid), "error", err)
			glovoConsentEvents.WithLabelValues("access_request", "store_error").Inc()
			h.auditGlovoAccessSelf(r, pid, op, "failed", nil, gcCodeUnavailable)
			return storeFailed
		}
		outcome := "unchanged"
		if created {
			outcome = "opened"
		}
		glovoConsentEvents.WithLabelValues("access_request", outcome).Inc()
		h.auditGlovoAccessSelf(r, pid, op, outcome, nil, "")
		return glovoAccessSelfResult{status: http.StatusOK, notice: "Your request is open. The owner has been asked to decide."}

	default: // glovoAccessSelfActionWithdrawRequest
		const op = "glovo.access_request.withdraw"
		outcome := "withdrawn"
		_, err := g.Access.RejectAccess(ctx, pid, pid, glovoAccessWithdrawReason)
		switch {
		case err == nil:
		case errors.Is(err, glovoconsent.ErrAccessNotPending):
			outcome = "unchanged"
		default:
			slog.Error("glovo access page: request not withdrawn", "principal", maskedPrincipalID(pid), "error", err)
			glovoConsentEvents.WithLabelValues("access_withdraw", "store_error").Inc()
			h.auditGlovoAccessSelf(r, pid, op, "failed", nil, gcCodeUnavailable)
			return storeFailed
		}
		if a, err := g.Access.GetAccess(ctx, pid); err != nil || !validAccessOf(a, pid) {
			glovoConsentEvents.WithLabelValues("access_withdraw", "store_error").Inc()
			h.auditGlovoAccessSelf(r, pid, op, "failed", nil, gcCodeUnavailable)
			return storeFailed
		}
		glovoConsentEvents.WithLabelValues("access_withdraw", outcome).Inc()
		h.auditGlovoAccessSelf(r, pid, op, outcome, nil, "")
		notice := "Your request is withdrawn."
		if outcome == "unchanged" {
			notice = "Your request was no longer pending; nothing was withdrawn."
		}
		return glovoAccessSelfResult{status: http.StatusOK, notice: notice}
	}
}

// auditGlovoAccessSelf writes the audit row of the bearer route's operation
// op, with the principal id as the actor: the page has no user whose ID
// could be a login name. Consent operations carry the consent version and
// id, access operations the principal only, as on the bearer routes.
func (h *Handlers) auditGlovoAccessSelf(r *http.Request, pid, op, status string, rec *glovoconsent.Record, refusal string) {
	params := map[string]string{"principal": pid, "surface": glovoAccessSelfSurface}
	if op == "glovo.link_consent.record" || op == "glovo.link_consent.revoke" {
		params["consent_version"] = glovoconsent.Version
		if rec != nil {
			params["consent_id"] = rec.ID
			params["consent_version"] = rec.Version
		}
	}
	h.logAudit(r, audit.Entry{
		UserID:      pid,
		PrincipalID: pid,
		Operation:   op,
		Parameters:  params,
		Status:      status,
		RiskLevel:   string(operations.RiskMedium),
		RefusalCode: refusal,
	})
}
