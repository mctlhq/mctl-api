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
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/oauth2"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/principals"
)

// Where /oauth/authorize sends a person to sign in (mctl-api#467). GitHub is
// the original upstream. ZITADEL signs the person in as the GitHub login of
// the principal their ZITADEL identity is linked to (#435), so the code,
// the tokens and the groups behind them are exactly what a GitHub sign-in of
// the same person yields. Nothing is linked here, and outside principal
// mode nothing is provisioned either. In principal mode (mctl-api#377) an
// identity with no single GitHub login signs in as its own principal,
// which the resolver provisions on first sight.

// OAuthUpstreamMode is OAUTH_UPSTREAM.
type OAuthUpstreamMode string

const (
	// OAuthUpstreamGitHub is the default and the behaviour before #467.
	OAuthUpstreamGitHub OAuthUpstreamMode = "github"
	// OAuthUpstreamZitadel sends every sign-in to ZITADEL.
	OAuthUpstreamZitadel OAuthUpstreamMode = "zitadel"
	// OAuthUpstreamBoth shows a chooser: ZITADEL first, GitHub as legacy.
	OAuthUpstreamBoth OAuthUpstreamMode = "both"
)

// ParseOAuthUpstreamMode reads OAUTH_UPSTREAM. Empty is github; anything
// else unknown is an error, so a typo refuses boot instead of picking a mode.
func ParseOAuthUpstreamMode(s string) (OAuthUpstreamMode, error) {
	switch m := OAuthUpstreamMode(s); m {
	case "":
		return OAuthUpstreamGitHub, nil
	case OAuthUpstreamGitHub, OAuthUpstreamZitadel, OAuthUpstreamBoth:
		return m, nil
	default:
		return "", fmt.Errorf("OAUTH_UPSTREAM must be github, zitadel or both, not %q", s)
	}
}

func (m OAuthUpstreamMode) allows(upstream string) bool {
	switch m {
	case "", OAuthUpstreamGitHub:
		return upstream == auth.UpstreamGitHub
	case OAuthUpstreamZitadel:
		return upstream == auth.UpstreamZitadel
	case OAuthUpstreamBoth:
		return upstream == auth.UpstreamGitHub || upstream == auth.UpstreamZitadel
	}
	return false
}

// LinkedPrincipalStore is the principal store as the ZITADEL upstream reads
// it (principals.Store.LinkedGitHub). With ErrNoGitHubIdentity,
// ErrGitHubLoginUnknown and ErrAmbiguousGitHubIdentity it also returns the
// principal; one returned without it is treated as a failed read.
type LinkedPrincipalStore interface {
	LinkedGitHub(ctx context.Context, id auth.Identity) (*principals.Principal, *principals.ExternalIdentity, error)
}

// OAuthZitadelOptions configures the ZITADEL upstream: its own confidential
// client (not the link client) and the MCTL_OIDC_PROVIDERS entry whose
// identities the link flow writes.
type OAuthZitadelOptions struct {
	ProviderName string
	Issuer       string
	ClientID     string
	ClientSecret string
	// Store resolves a ZITADEL identity to its linked principal. Nil when
	// mctl-api has no principal store: every ZITADEL sign-in then answers
	// 503, because who is linked cannot be observed.
	Store LinkedPrincipalStore
	// CustomersOrgID is the ZITADEL organization of self-service customer
	// accounts (the provider entry's customers_org_id). When set, a
	// customer signs in as the principal of the GitHub id the identity hook
	// proved, never through the link store; empty keeps the link store as
	// the only path.
	CustomersOrgID string
	// CustomersGitHubIdPID is the ZITADEL id of the customers
	// organization's GitHub IdP (ZITADEL_HOOK_GITHUB_IDP_ID). With it and
	// CustomersOrgID both set, /oauth/authorize offers customers their own
	// "Sign in with GitHub" (mctl-web#158), which asks ZITADEL for that
	// organization and IdP so the customer lands on GitHub rather than on
	// the instance login page, which has no GitHub button. Empty offers
	// no customer entry and leaves the sign-in as it was.
	CustomersGitHubIdPID string
}

const (
	oauthZitadelCallbackPath = "/oauth/zitadel/callback"
	oauthUpstreamParam       = "upstream"
	// oauthUpstreamCustomer is the chooser's customer entry: the ZITADEL
	// upstream, started in the customers organization at its GitHub IdP.
	oauthUpstreamCustomer = "customer"
	// oauthUpstreamZitadelCustomer is the upstream label of a ZITADEL
	// sign-in that resolved to a customer.
	oauthUpstreamZitadelCustomer = "zitadel_customer"
)

var oauthUpstreamSignins = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "oauth_upstream_signins_total",
	Help: "Completed /oauth/authorize sign-ins by upstream identity provider and result (mctl-api#467).",
}, []string{"upstream", "result"})

func init() { prometheus.MustRegister(oauthUpstreamSignins) }

type oauthZitadel struct {
	opts *OAuthZitadelOptions
	lazyOIDCProvider
}

// lazyOIDCProvider runs OIDC discovery for issuer once it first succeeds; a
// failure is retried on the next call, so the identity provider being down
// never delays mctl-api's start. The ZITADEL sign-in, the identity link and
// the portal's customer resolution each hold one.
type lazyOIDCProvider struct {
	issuer string

	// discoMu is named apart from its holders' own mutexes: it guards the
	// discovery call, a network round trip, and nothing else.
	discoMu  sync.Mutex
	provider *oidc.Provider
}

func (l *lazyOIDCProvider) oidcProvider(ctx context.Context) (*oidc.Provider, error) {
	l.discoMu.Lock()
	defer l.discoMu.Unlock()
	if l.provider != nil {
		return l.provider, nil
	}
	p, err := oidc.NewProvider(ctx, l.issuer)
	if err != nil {
		return nil, err
	}
	l.provider = p
	return p, nil
}

// offersCustomers reports whether the customer entry may be offered: both
// ids configured, or nothing is offered (fail closed).
func (z *oauthZitadel) offersCustomers() bool {
	return z != nil && z.opts.CustomersOrgID != "" && z.opts.CustomersGitHubIdPID != ""
}

func (z *oauthZitadel) oauthConfig(p *oidc.Provider, baseURL string) *oauth2.Config {
	scopes := []string{oidc.ScopeOpenID, "profile"}
	if z.opts.CustomersOrgID != "" {
		// The ID token must name the user's organization, or a customer
		// could not be told from anyone else. Asked only when customers
		// are configured, so the sign-in is unchanged until then.
		scopes = append(scopes, auth.ScopeResourceOwner)
	}
	return &oauth2.Config{
		ClientID:     z.opts.ClientID,
		ClientSecret: z.opts.ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  baseURL + oauthZitadelCallbackPath,
		Scopes:       scopes,
	}
}

var oauthPage = shellPage("oauth", `{{if or .Primary .More}}<div class="actions">
{{if .Primary}}<a href="{{.Primary.Href}}">{{.Primary.Text}}</a>{{end}}
{{range .More}}<a class="secondary" href="{{.Href}}">{{.Text}}</a>{{end}}
</div>{{end}}
{{if .Secondary}}<p class="legacy"><a href="{{.Secondary.Href}}">{{.Secondary.Text}}</a></p>{{end}}`)

type oauthPageLink struct{ Href, Text string }

type oauthPageData struct {
	Title   string
	Lines   []string
	Primary *oauthPageLink
	// More are further choices, drawn as secondary buttons below Primary.
	More      []oauthPageLink
	Secondary *oauthPageLink
}

func renderOAuthPage(w http.ResponseWriter, status int, d oauthPageData) {
	renderShellPage(w, status, "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'", oauthPage,
		shellData{Title: d.Title, Lines: d.Lines, Page: d})
}

// pickOAuthUpstream decides where an already validated authorization goes.
// A request that has not chosen yet gets the chooser page and ok=false when
// there is a choice to make: under "both", and under "zitadel" once the
// customer entry is offered. The choice comes back as the same request plus
// upstream=. customer reports the customer entry, which is the ZITADEL
// upstream started in the customers organization at its GitHub IdP.
//
// The customer choice only shapes the request to ZITADEL. Whether the
// person signs in as a customer is decided in the callback from the
// verified ID token's organization, so choosing it grants nothing; it is
// still refused where it is not offered, rather than quietly becoming a
// staff sign-in.
func (h *Handlers) pickOAuthUpstream(w http.ResponseWriter, r *http.Request) (upstream string, customer, ok bool) {
	mode := h.opts.OAuthUpstream
	customers := mode.allows(auth.UpstreamZitadel) && h.oauthZitadel.offersCustomers()
	chosen := r.URL.Query().Get(oauthUpstreamParam)
	if chosen == oauthUpstreamCustomer {
		if !customers {
			// Answered directly, not through oauthError like the other
			// refusals in handleOAuthAuthorize: this choice is only ever
			// made by a person on the chooser page, so the browser is
			// where it must be explained, and the client would get only
			// an opaque error for an option it never offered.
			renderOAuthPage(w, http.StatusBadRequest, oauthPageData{Title: "Sign-in option not available", Lines: []string{
				"GitHub sign-in for customers is not available on this server. Start the connection again from your client.",
			}})
			return "", false, false
		}
		return auth.UpstreamZitadel, true, true
	}
	switch mode {
	case OAuthUpstreamZitadel:
		if !customers || chosen == auth.UpstreamZitadel {
			return auth.UpstreamZitadel, false, true
		}
	case OAuthUpstreamBoth:
		if mode.allows(chosen) {
			return chosen, false, true
		}
	default:
		return auth.UpstreamGitHub, false, true
	}
	choose := func(u string) string {
		q := r.URL.Query()
		q.Set(oauthUpstreamParam, u)
		return "/oauth/authorize?" + q.Encode()
	}
	staff := &oauthPageLink{Href: choose(auth.UpstreamZitadel), Text: "Sign in with MCTL (ZITADEL)"}
	d := oauthPageData{
		Title:   "Sign in to MCTL",
		Lines:   []string{"Sign in with your MCTL account at auth.mctl.ai. GitHub sign-in still works while it is being retired."},
		Primary: staff,
	}
	if customers {
		d.Lines = []string{
			"Customers: sign in with your GitHub account.",
			"MCTL staff and partner accounts: use Sign in with MCTL account.",
		}
		d.Primary = &oauthPageLink{Href: choose(oauthUpstreamCustomer), Text: "Sign in with GitHub"}
		// Not "staff": partner organizations sign in here too, and the
		// GitHub entry would make them a stray customers account that
		// conflicts with their existing principal.
		d.More = []oauthPageLink{{Href: staff.Href, Text: "Sign in with MCTL account"}}
	}
	if mode == OAuthUpstreamBoth {
		if customers {
			d.Lines = append(d.Lines, "Staff GitHub sign-in still works while it is being retired.")
		}
		d.Secondary = &oauthPageLink{Href: choose(auth.UpstreamGitHub), Text: "Sign in with GitHub (legacy, being retired)"}
	}
	renderOAuthPage(w, http.StatusOK, d)
	return "", false, false
}

// startZitadelAuthorize sends a validated authorization to ZITADEL.
// customer starts it in the customers organization at its GitHub IdP.
func (h *Handlers) startZitadelAuthorize(w http.ResponseWriter, r *http.Request, clientID, redirectURI, clientState, codeChallenge string, customer bool) {
	o, z := h.opts.OAuthServer, h.oauthZitadel
	if z == nil {
		http.Error(w, "ZITADEL sign-in is not configured", http.StatusServiceUnavailable)
		return
	}
	if customer && !z.offersCustomers() {
		// pickOAuthUpstream already refuses this; a scope naming an empty
		// organization or IdP must never be sent.
		http.Error(w, "customer sign-in is not configured", http.StatusServiceUnavailable)
		return
	}
	prov, err := z.oidcProvider(r.Context())
	if err != nil {
		slog.Warn("oauth: ZITADEL discovery failed", "issuer", z.opts.Issuer, "error", err)
		http.Error(w, "ZITADEL is not reachable right now", http.StatusBadGateway)
		return
	}
	state, err1 := auth.GenerateState()
	nonce, err2 := auth.GenerateState()
	if err := errors.Join(err1, err2); err != nil {
		slog.Error("failed to generate state", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	verifier := oauth2.GenerateVerifier()
	if err := o.StorePendingOIDCAuth(r.Context(), state, auth.PendingOIDCAuth{
		Upstream: auth.UpstreamZitadel, ClientID: clientID, RedirectURI: redirectURI,
		CodeChallenge: codeChallenge, ClientState: clientState, Nonce: nonce, Verifier: verifier,
	}); err != nil {
		oauthError(w, redirectURI, clientState, "server_error", "the authorization could not be started; try again")
		return
	}
	// No prompt=login: an existing ZITADEL session is the single sign-on
	// this upstream is for. Freshness matters to linking, not to sign-in.
	cfg := z.oauthConfig(prov, o.BaseURL)
	if customer {
		// The same two scopes mctl.ai sends (mctl-web cloudflare-worker/
		// zitadel.js): ZITADEL skips its login page and goes to GitHub.
		// Only the authorize request carries them; the staff entry and
		// the code exchange are unchanged.
		cfg.Scopes = append(cfg.Scopes,
			auth.ScopeOrgIDPrefix+z.opts.CustomersOrgID, auth.ScopeIdPIDPrefix+z.opts.CustomersGitHubIdPID)
	}
	authURL := cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce))
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleOAuthZitadelCallback: GET /oauth/zitadel/callback. It verifies the
// ZITADEL sign-in, resolves it to the linked principal's GitHub login, and
// completes the authorization exactly as the GitHub callback does.
func (h *Handlers) handleOAuthZitadelCallback(w http.ResponseWriter, r *http.Request) {
	o, z := h.opts.OAuthServer, h.oauthZitadel
	if o == nil || z == nil {
		http.Error(w, "ZITADEL sign-in is not configured", http.StatusNotFound)
		return
	}
	q := r.URL.Query()
	// Consumed before anything else, so a replayed or failed callback can
	// never be retried with the same state.
	pending, ok, err := o.LoadPendingAuth(r.Context(), q.Get("state"))
	if err != nil {
		// The pending entry holds the redirect URI, so there is nowhere
		// to send an OAuth error: answer here, and count it.
		oauthUpstreamSignins.WithLabelValues(auth.UpstreamZitadel, "flow_store_unavailable").Inc()
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok || pending.Upstream != auth.UpstreamZitadel || !h.opts.OAuthUpstream.allows(auth.UpstreamZitadel) {
		http.Error(w, "invalid or expired state", http.StatusBadRequest)
		return
	}
	result, label := "error", auth.UpstreamZitadel
	defer func() { oauthUpstreamSignins.WithLabelValues(label, result).Inc() }()

	if e := q.Get("error"); e != "" {
		slog.Warn("ZITADEL OAuth returned error", "error", e, "description", q.Get("error_description"))
		result = "upstream_error"
		oauthError(w, pending.RedirectURI, pending.ClientState, "access_denied", "the ZITADEL sign-in was not completed")
		return
	}
	code := q.Get("code")
	if code == "" {
		result = "bad_request"
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}
	prov, err := z.oidcProvider(r.Context())
	if err != nil {
		slog.Warn("oauth: ZITADEL discovery failed", "issuer", z.opts.Issuer, "error", err)
		result = "upstream_unreachable"
		http.Error(w, "ZITADEL is not reachable right now", http.StatusBadGateway)
		return
	}
	tok, err := z.oauthConfig(prov, o.BaseURL).Exchange(r.Context(), code, oauth2.VerifierOption(pending.Verifier))
	if err != nil {
		slog.Warn("oauth: ZITADEL code exchange failed", "error", err)
		result = "exchange_failed"
		http.Error(w, "failed to exchange ZITADEL code", http.StatusBadGateway)
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := prov.Verifier(&oidc.Config{ClientID: z.opts.ClientID}).Verify(r.Context(), raw)
	if err != nil {
		slog.Warn("oauth: ZITADEL ID token refused", "error", err)
		result = "invalid_token"
		http.Error(w, "the ZITADEL ID token was not valid", http.StatusBadGateway)
		return
	}
	var claims struct {
		Nonce             string `json:"nonce"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idt.Claims(&claims); err != nil || subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(pending.Nonce)) != 1 {
		result = "invalid_token"
		http.Error(w, "the ZITADEL sign-in does not belong to this authorization", http.StatusBadRequest)
		return
	}
	display := claims.PreferredUsername
	if display == "" {
		display = idt.Subject
	}
	id := auth.Identity{Provider: z.opts.ProviderName, Issuer: idt.Issuer, Subject: idt.Subject, Display: display, Kind: auth.KindHuman}

	// issue ends the sign-in: it mints the mctl authorization code for
	// login and principalID and redirects to the client. Groups come from
	// the login outside principal mode only; a customer has no login and
	// so no groups.
	issue := func(login, principalID string) {
		var groups []string
		if h.opts.TenantAuthzMode != TenantAuthzPrincipal && login != "" {
			groups = o.ResolveGroups(login)
		}
		mctlCode, err := o.IssueCode(r.Context(), login, principalID, pending.ClientID, pending.RedirectURI, pending.CodeChallenge, groups)
		if err != nil {
			slog.Error("failed to issue auth code", "error", err)
			result = "internal_error"
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		target, err := url.Parse(pending.RedirectURI)
		if err != nil {
			result = "internal_error"
			http.Error(w, "invalid redirect_uri", http.StatusInternalServerError)
			return
		}
		cq := target.Query()
		cq.Set("code", mctlCode)
		if pending.ClientState != "" {
			cq.Set("state", pending.ClientState)
		}
		target.RawQuery = cq.Encode()
		result = "issued"
		slog.Info("oauth: ZITADEL sign-in", "principal_id", principalID, "login", login, "zitadel_subject", idt.Subject)
		http.Redirect(w, r, target.String(), http.StatusFound)
	}

	if z.opts.CustomersOrgID != "" {
		// Counted apart from the moment the verified token names the
		// customers organization, before its proof is judged, so a
		// customer refused as unproven (a hook or claim-client
		// misconfiguration) shows under the customer label too. The
		// chooser's choice is not stored; this is where a customer is
		// told from anyone else. A token naming no organization cannot be
		// placed and stays under zitadel.
		var owner map[string]any
		if idt.Claims(&owner) == nil && owner[auth.ClaimResourceOwnerID] == z.opts.CustomersOrgID {
			label = oauthUpstreamZitadelCustomer
		}
		customer, stopped := readSigninCustomer(w, idt, z.opts.CustomersOrgID)
		if stopped != "" {
			result = stopped
			return
		}
		if customer != nil {
			id.Customer = customer
			var principalID string
			if principalID, result = h.customerSigninPrincipal(w, r, id); result != "" {
				return
			}
			issue("", principalID)
			return
		}
	}

	if z.opts.Store == nil {
		result = "store_unavailable"
		renderOAuthPage(w, http.StatusServiceUnavailable, oauthPageData{Title: "Sign-in unavailable", Lines: []string{
			"MCTL cannot look up linked identities right now, so it cannot tell who you are. Try again later.",
		}})
		return
	}
	p, gh, err := z.opts.Store.LinkedGitHub(r.Context(), id)
	var login, principalID string
	switch {
	case err == nil && (p == nil || !auth.ValidPrincipalID(p.ID) || gh == nil || gh.Display == ""):
		// A link reported without the principal or its GitHub login is a
		// failed read: minting would issue a token for nobody, or one
		// principal mode refuses on every request.
		result = zitadelStoreUnavailable(w, errors.New("the link store answered without a principal or GitHub login"))
		return
	case err == nil:
		// The GitHub callback's tail, for the linked principal's GitHub
		// login: same groups, same admin decision, same code. The principal
		// is the one the store just found the link on.
		login, principalID = gh.Display, p.ID
	case h.opts.TenantAuthzMode == TenantAuthzPrincipal && zitadelOnly(p, err):
		// Principal mode needs no GitHub login (mctl-api#377, Q5): the
		// identity signs in as its principal, provisioned on first sight,
		// and gets exactly the GitOps membership keyed by that principal.
		var stopped string
		if principalID, stopped = h.signinPrincipal(w, r, id); stopped != "" {
			result = stopped
			return
		}
		if p != nil && principalID != p.ID {
			// The resolver and the store disagree on whose identity this
			// is; minting for either would be a guess.
			slog.Error("oauth: ZITADEL identity resolved to another principal", "store", p.ID, "resolver", principalID)
			result = zitadelStoreUnavailable(w, errors.New("principal resolution disagrees with the link store"))
			return
		}
	default:
		result = h.refuseZitadelSignin(w, display, p, err)
		return
	}

	issue(login, principalID)
}

// zitadelOnly reports whether a LinkedGitHub refusal only says the
// identity has no single GitHub login to sign in as: not linked to any
// principal yet, or a principal without exactly one live GitHub login.
// Principal mode signs those in as the principal. A refusal that names no
// principal where it must is a failed read, never this.
func zitadelOnly(p *principals.Principal, err error) bool {
	switch {
	case errors.Is(err, principals.ErrNotFound):
		return true
	case errors.Is(err, principals.ErrNoGitHubIdentity), errors.Is(err, principals.ErrGitHubLoginUnknown), errors.Is(err, principals.ErrAmbiguousGitHubIdentity):
		return p != nil
	}
	return false
}

// refuseZitadelSignin answers a ZITADEL identity that cannot sign in and
// returns the metric result. Only the store's documented refusals mean
// "not linked"; any other error is a failed read and answers 503.
func (h *Handlers) refuseZitadelSignin(w http.ResponseWriter, display string, p *principals.Principal, err error) string {
	linkHint := &oauthPageLink{Href: linkStartPath, Text: "Link your ZITADEL identity"}
	switch {
	case errors.Is(err, principals.ErrNotFound):
		renderOAuthPage(w, http.StatusForbidden, oauthPageData{
			Title: "Your ZITADEL identity is not linked yet",
			Lines: []string{
				"ZITADEL user " + display + " is not linked to an MCTL principal, so MCTL cannot tell which account you are.",
				"Link it once: you sign in with GitHub and then with ZITADEL in the same browser. After that, start the connection again.",
			},
			Primary: linkHint,
		})
		return "unlinked"
	case p == nil && (errors.Is(err, principals.ErrNoGitHubIdentity) ||
		errors.Is(err, principals.ErrGitHubLoginUnknown) || errors.Is(err, principals.ErrAmbiguousGitHubIdentity)):
		// These refusals name the principal; without one the store broke its
		// contract, which is a failed read, not a refusal.
		return zitadelStoreUnavailable(w, err)
	case errors.Is(err, principals.ErrNoGitHubIdentity):
		renderOAuthPage(w, http.StatusForbidden, oauthPageData{
			Title: "Your ZITADEL identity is not linked to your account",
			Lines: []string{
				"ZITADEL user " + display + " has its own MCTL principal (" + p.ID + "), which is not your existing account.",
				"Linking will report that this identity already has a principal. A platform admin can then merge " + p.ID + " into your account; ask one, quoting the id.",
			},
			Primary: linkHint,
		})
		return "unlinked"
	case errors.Is(err, auth.ErrIdentityRefused):
		renderOAuthPage(w, http.StatusForbidden, oauthPageData{Title: "Sign-in refused", Lines: []string{
			"This ZITADEL identity was unlinked from its MCTL principal and cannot sign in. Only a platform admin can restore it.",
		}})
		return "refused"
	case errors.Is(err, auth.ErrPrincipalDisabled):
		renderOAuthPage(w, http.StatusForbidden, oauthPageData{Title: "Sign-in refused", Lines: []string{"Your MCTL principal is disabled."}})
		return "refused"
	case errors.Is(err, principals.ErrGitHubLoginUnknown), errors.Is(err, principals.ErrAmbiguousGitHubIdentity):
		slog.Warn("oauth: ZITADEL sign-in has no single GitHub login", "principal_id", p.ID, "error", err)
		renderOAuthPage(w, http.StatusConflict, oauthPageData{Title: "Sign-in refused", Lines: []string{
			"MCTL cannot tell which GitHub login your principal (" + p.ID + ") uses, so it does not guess. Ask a platform admin, quoting the id.",
		}})
		return "refused"
	default:
		return zitadelStoreUnavailable(w, err)
	}
}

func zitadelStoreUnavailable(w http.ResponseWriter, err error) string {
	slog.Error("oauth: principal store lookup failed", "error", err)
	renderOAuthPage(w, http.StatusServiceUnavailable, oauthPageData{Title: "Sign-in unavailable", Lines: []string{
		"MCTL cannot look up linked identities right now, so it cannot tell who you are. Try again later.",
	}})
	return "store_unavailable"
}
