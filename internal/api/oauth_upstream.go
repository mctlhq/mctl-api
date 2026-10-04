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
	"html/template"
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
// the same person yields. Nothing is linked or provisioned here.

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
}

const (
	oauthZitadelCallbackPath = "/oauth/zitadel/callback"
	oauthUpstreamParam       = "upstream"
)

var oauthUpstreamSignins = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "oauth_upstream_signins_total",
	Help: "Completed /oauth/authorize sign-ins by upstream identity provider and result (mctl-api#467).",
}, []string{"upstream", "result"})

func init() { prometheus.MustRegister(oauthUpstreamSignins) }

type oauthZitadel struct {
	opts *OAuthZitadelOptions

	mu       sync.Mutex
	provider *oidc.Provider
}

// oidcProvider runs discovery once it first succeeds; a failure is retried
// on the next sign-in, so ZITADEL being down never delays mctl-api's start.
func (z *oauthZitadel) oidcProvider(ctx context.Context) (*oidc.Provider, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.provider != nil {
		return z.provider, nil
	}
	p, err := oidc.NewProvider(ctx, z.opts.Issuer)
	if err != nil {
		return nil, err
	}
	z.provider = p
	return p, nil
}

func (z *oauthZitadel) oauthConfig(p *oidc.Provider, baseURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     z.opts.ClientID,
		ClientSecret: z.opts.ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  baseURL + oauthZitadelCallbackPath,
		Scopes:       []string{oidc.ScopeOpenID, "profile"},
	}
}

var oauthPage = template.Must(template.New("oauth").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} · mctl</title>
<style>body{font-family:system-ui,sans-serif;max-width:36rem;margin:3rem auto;padding:0 1rem;line-height:1.5}
.primary{display:inline-block;font-size:1rem;padding:.5rem 1rem;border:1px solid;border-radius:.25rem;text-decoration:none}
small{color:#666}</style></head>
<body><h1>{{.Title}}</h1>{{range .Lines}}<p>{{.}}</p>{{end}}
{{if .Primary}}<p><a class="primary" href="{{.Primary.Href}}">{{.Primary.Text}}</a></p>{{end}}
{{if .Secondary}}<p><small><a href="{{.Secondary.Href}}">{{.Secondary.Text}}</a></small></p>{{end}}
</body></html>`))

type oauthPageLink struct{ Href, Text string }

type oauthPageData struct {
	Title     string
	Lines     []string
	Primary   *oauthPageLink
	Secondary *oauthPageLink
}

func renderOAuthPage(w http.ResponseWriter, status int, d oauthPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
	w.WriteHeader(status)
	_ = oauthPage.Execute(w, d)
}

// pickOAuthUpstream decides where an already validated authorization goes.
// Under "both" a request that has not chosen yet gets the chooser page and
// ok=false; the choice comes back as the same request plus upstream=.
func (h *Handlers) pickOAuthUpstream(w http.ResponseWriter, r *http.Request) (upstream string, ok bool) {
	switch h.opts.OAuthUpstream {
	case OAuthUpstreamZitadel:
		return auth.UpstreamZitadel, true
	case OAuthUpstreamBoth:
		if u := r.URL.Query().Get(oauthUpstreamParam); h.opts.OAuthUpstream.allows(u) {
			return u, true
		}
		choose := func(u string) string {
			q := r.URL.Query()
			q.Set(oauthUpstreamParam, u)
			return "/oauth/authorize?" + q.Encode()
		}
		renderOAuthPage(w, http.StatusOK, oauthPageData{
			Title:   "Sign in to mctl",
			Lines:   []string{"Sign in with your MCTL account at auth.mctl.ai. GitHub sign-in still works while it is being retired."},
			Primary: &oauthPageLink{Href: choose(auth.UpstreamZitadel), Text: "Sign in with MCTL (ZITADEL)"},
			Secondary: &oauthPageLink{Href: choose(auth.UpstreamGitHub),
				Text: "Sign in with GitHub (legacy, being retired)"},
		})
		return "", false
	default:
		return auth.UpstreamGitHub, true
	}
}

// startZitadelAuthorize sends a validated authorization to ZITADEL.
func (h *Handlers) startZitadelAuthorize(w http.ResponseWriter, r *http.Request, clientID, redirectURI, clientState, codeChallenge string) {
	o, z := h.opts.OAuthServer, h.oauthZitadel
	if z == nil {
		http.Error(w, "ZITADEL sign-in is not configured", http.StatusServiceUnavailable)
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
	o.StorePendingOIDCAuth(state, auth.PendingOIDCAuth{
		Upstream: auth.UpstreamZitadel, ClientID: clientID, RedirectURI: redirectURI,
		CodeChallenge: codeChallenge, ClientState: clientState, Nonce: nonce, Verifier: verifier,
	})
	// No prompt=login: an existing ZITADEL session is the single sign-on
	// this upstream is for. Freshness matters to linking, not to sign-in.
	authURL := z.oauthConfig(prov, o.BaseURL).AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce))
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
	pending, ok := o.LoadPendingAuth(q.Get("state"))
	if !ok || pending.Upstream != auth.UpstreamZitadel || !h.opts.OAuthUpstream.allows(auth.UpstreamZitadel) {
		http.Error(w, "invalid or expired state", http.StatusBadRequest)
		return
	}
	result := "error"
	defer func() { oauthUpstreamSignins.WithLabelValues(auth.UpstreamZitadel, result).Inc() }()

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

	if z.opts.Store == nil {
		result = "store_unavailable"
		renderOAuthPage(w, http.StatusServiceUnavailable, oauthPageData{Title: "Sign-in unavailable", Lines: []string{
			"mctl cannot look up linked identities right now, so it cannot tell who you are. Try again later.",
		}})
		return
	}
	id := auth.Identity{Provider: z.opts.ProviderName, Issuer: idt.Issuer, Subject: idt.Subject, Display: display, Kind: auth.KindHuman}
	p, gh, err := z.opts.Store.LinkedGitHub(r.Context(), id)
	if err != nil {
		result = h.refuseZitadelSignin(w, display, p, err)
		return
	}

	// From here on this is the GitHub callback's tail, for the linked
	// principal's GitHub login: same groups, same admin decision, same code.
	login := gh.Display
	groups := o.ResolveGroups(login)
	mctlCode, err := o.IssueCode(login, pending.ClientID, pending.RedirectURI, pending.CodeChallenge, groups)
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
	slog.Info("oauth: ZITADEL sign-in", "principal_id", p.ID, "login", login, "zitadel_subject", idt.Subject)
	http.Redirect(w, r, target.String(), http.StatusFound)
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
				"ZITADEL user " + display + " is not linked to an mctl principal, so mctl cannot tell which account you are.",
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
				"ZITADEL user " + display + " has its own mctl principal (" + p.ID + "), which is not your existing account.",
				"Linking will report that this identity already has a principal. A platform admin can then merge " + p.ID + " into your account; ask one, quoting the id.",
			},
			Primary: linkHint,
		})
		return "unlinked"
	case errors.Is(err, auth.ErrIdentityRefused):
		renderOAuthPage(w, http.StatusForbidden, oauthPageData{Title: "Sign-in refused", Lines: []string{
			"This ZITADEL identity was unlinked from its mctl principal and cannot sign in. Only a platform admin can restore it.",
		}})
		return "refused"
	case errors.Is(err, auth.ErrPrincipalDisabled):
		renderOAuthPage(w, http.StatusForbidden, oauthPageData{Title: "Sign-in refused", Lines: []string{"Your mctl principal is disabled."}})
		return "refused"
	case errors.Is(err, principals.ErrGitHubLoginUnknown), errors.Is(err, principals.ErrAmbiguousGitHubIdentity):
		slog.Warn("oauth: ZITADEL sign-in has no single GitHub login", "principal_id", p.ID, "error", err)
		renderOAuthPage(w, http.StatusConflict, oauthPageData{Title: "Sign-in refused", Lines: []string{
			"mctl cannot tell which GitHub login your principal (" + p.ID + ") uses, so it does not guess. Ask a platform admin, quoting the id.",
		}})
		return "refused"
	default:
		return zitadelStoreUnavailable(w, err)
	}
}

func zitadelStoreUnavailable(w http.ResponseWriter, err error) string {
	slog.Error("oauth: principal store lookup failed", "error", err)
	renderOAuthPage(w, http.StatusServiceUnavailable, oauthPageData{Title: "Sign-in unavailable", Lines: []string{
		"mctl cannot look up linked identities right now, so it cannot tell who you are. Try again later.",
	}})
	return "store_unavailable"
}
