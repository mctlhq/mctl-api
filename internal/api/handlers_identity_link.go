package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/oauth2"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/principals"
)

// Explicit linking of a ZITADEL identity to an existing principal
// (mctl-api#435, docs/principals.md "Linking"). The person proves both
// identities in one browser session: GitHub first (mctl-api's own GitHub
// OAuth app, the identity the principal already has), then ZITADEL (a
// confidential client with PKCE), then confirms. Nothing is ever linked by
// matching a username or an e-mail (#373).
//
// The session is one in-memory challenge, bound to the browser by an
// httpOnly cookie whose value only the browser holds (the server keeps its
// SHA-256). A link started in one browser cannot be finished in another, so
// nobody can hand a victim the second half of their own challenge. In
// memory like the OAuth server's pending authorizations: mctl-api runs one
// replica, and a restart only cancels links in flight.

// IdentityLinkStore is the principal store as linking uses it.
type IdentityLinkStore interface {
	Provision(ctx context.Context, id auth.Identity) (*principals.Principal, error)
	LinkIdentity(ctx context.Context, principalID string, id auth.Identity) (string, error)
	UnlinkIdentity(ctx context.Context, principalID, identityID string) (*principals.ExternalIdentity, error)
	MergePrincipals(ctx context.Context, from, into string) (int, error)
	Identities(ctx context.Context, principalID string) ([]principals.ExternalIdentity, error)
}

// IdentityLinkOptions configures linking. Store alone enables the API
// endpoints (list, unlink, admin merge); the browser flow also needs the
// ZITADEL client and the GitHub leg.
type IdentityLinkOptions struct {
	Store IdentityLinkStore
	// ProviderName and Issuer are those of the federation entry the linked
	// identity must match (MCTL_OIDC_PROVIDERS), so that a later ZITADEL
	// token resolves to the row written here.
	ProviderName string
	Issuer       string
	ClientID     string
	ClientSecret string
	// BaseURL is mctl-api's public URL; both callbacks hang off it.
	BaseURL string
	// GitHubClientID is the OAuth app of the existing GitHub flow; its
	// registered callback /oauth/github/callback serves this flow too.
	GitHubClientID string
	// ProveGitHub exchanges a GitHub code and returns who it proves.
	ProveGitHub func(ctx context.Context, code, redirectURI string) (login string, id int64, err error)
}

func (o *IdentityLinkOptions) browserFlowEnabled() bool {
	return o != nil && o.Store != nil && o.ProviderName != "" && o.Issuer != "" &&
		o.ClientID != "" && o.ClientSecret != "" && o.BaseURL != "" &&
		o.GitHubClientID != "" && o.ProveGitHub != nil
}

const (
	linkCookieName     = "mctl_identity_link"
	linkGitHubPrefix   = "link."
	linkChallengeTTL   = 10 * time.Minute
	linkMaxChallenges  = 1000
	linkStartPath      = "/identity/link/zitadel"
	linkCallbackPath   = "/identity/link/zitadel/callback"
	linkConfirmPath    = "/identity/link/zitadel/confirm"
	githubCallbackPath = "/oauth/github/callback"
)

// Error codes of the link API and pages.
const (
	linkCodeUnavailable    = "identity_link_unavailable"
	linkCodeOwnedElsewhere = "identity_belongs_to_other_principal"
	linkCodeAlreadyLinked  = "principal_already_linked"
	linkCodeRevoked        = "identity_revoked"
	linkCodeLastIdentity   = "last_identity"
	linkCodeMergeConflict  = "merge_conflict"
)

var identityLinksTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "identity_links_total",
	Help: "Explicit identity link attempts (mctl-api#435) by provider and result.",
}, []string{"provider", "result"})

func init() { prometheus.MustRegister(identityLinksTotal) }

type linkPhase int

const (
	linkStarted linkPhase = iota
	linkGitHubProven
	linkZitadelProven
	linkUsed
)

type linkChallenge struct {
	id          string
	browserHash [32]byte
	expiresAt   time.Time
	phase       linkPhase

	githubState string

	principalID string
	githubLogin string
	githubID    int64

	zitadelState string
	nonce        string
	verifier     string
	startedAt    time.Time

	identity auth.Identity
	csrfHash [32]byte
}

type identityLinker struct {
	opts *IdentityLinkOptions

	mu       sync.Mutex
	byID     map[string]*linkChallenge
	byGitHub map[string]*linkChallenge
	byZState map[string]*linkChallenge

	oidcMu   sync.Mutex
	provider *oidc.Provider
	now      func() time.Time
}

func newIdentityLinker(opts *IdentityLinkOptions) *identityLinker {
	return &identityLinker{
		opts:     opts,
		byID:     map[string]*linkChallenge{},
		byGitHub: map[string]*linkChallenge{},
		byZState: map[string]*linkChallenge{},
		now:      time.Now,
	}
}

func randomLinkToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// sweepLocked drops expired challenges.
func (l *identityLinker) sweepLocked(now time.Time) {
	for id, c := range l.byID {
		if now.After(c.expiresAt) {
			l.dropLocked(id, c)
		}
	}
}

func (l *identityLinker) dropLocked(id string, c *linkChallenge) {
	delete(l.byID, id)
	delete(l.byGitHub, c.githubState)
	delete(l.byZState, c.zitadelState)
}

// oidcProvider runs discovery once it first succeeds; a failure is retried
// on the next link rather than at boot, so ZITADEL being down never delays
// mctl-api's start.
func (l *identityLinker) oidcProvider(ctx context.Context) (*oidc.Provider, error) {
	l.oidcMu.Lock()
	defer l.oidcMu.Unlock()
	if l.provider != nil {
		return l.provider, nil
	}
	p, err := oidc.NewProvider(ctx, l.opts.Issuer)
	if err != nil {
		return nil, err
	}
	l.provider = p
	return p, nil
}

func (l *identityLinker) oauthConfig(p *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     l.opts.ClientID,
		ClientSecret: l.opts.ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  l.opts.BaseURL + linkCallbackPath,
		Scopes:       []string{oidc.ScopeOpenID, "profile"},
	}
}

// browserMatches checks the request's link cookie against the challenge.
func browserMatches(r *http.Request, c *linkChallenge) bool {
	ck, err := r.Cookie(linkCookieName)
	if err != nil || ck.Value == "" {
		return false
	}
	sum := sha256.Sum256([]byte(ck.Value))
	return subtle.ConstantTimeCompare(sum[:], c.browserHash[:]) == 1
}

func setLinkCookie(w http.ResponseWriter, value string, maxAge int) {
	// Path "/": the cookie must reach /oauth/github/callback as well.
	// SameSite=Lax still sends it on the top-level redirects back from
	// GitHub and ZITADEL, and on the same-site confirm POST.
	http.SetCookie(w, &http.Cookie{
		Name: linkCookieName, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
}

var linkPage = template.Must(template.New("link").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} · mctl</title>
<style>body{font-family:system-ui,sans-serif;max-width:36rem;margin:3rem auto;padding:0 1rem;line-height:1.5}
code{background:#f2f2f2;padding:0 .25rem}button{font-size:1rem;padding:.5rem 1rem}</style></head>
<body><h1>{{.Title}}</h1>{{range .Lines}}<p>{{.}}</p>{{end}}
{{if .Confirm}}<form method="post" action="{{.Confirm.Action}}">
<input type="hidden" name="challenge" value="{{.Confirm.Challenge}}">
<input type="hidden" name="csrf" value="{{.Confirm.CSRF}}">
<button type="submit">Link these identities</button></form>{{end}}
</body></html>`))

type linkPageData struct {
	Title   string
	Lines   []string
	Confirm *struct{ Action, Challenge, CSRF string }
}

func renderLinkPage(w http.ResponseWriter, status int, d linkPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
	w.WriteHeader(status)
	_ = linkPage.Execute(w, d)
}

func linkFailed(w http.ResponseWriter, status int, msg string) {
	renderLinkPage(w, status, linkPageData{Title: "Linking failed", Lines: []string{msg, "Start again from " + linkStartPath + "."}})
}

// handleIdentityLinkStart: GET /identity/link/zitadel.
func (h *Handlers) handleIdentityLinkStart(w http.ResponseWriter, r *http.Request) {
	l := h.identityLink
	if l == nil || !l.opts.browserFlowEnabled() {
		linkFailed(w, http.StatusServiceUnavailable, "Linking a ZITADEL identity is not configured on this server.")
		return
	}
	browser, err1 := randomLinkToken()
	id, err2 := randomLinkToken()
	ghState, err3 := randomLinkToken()
	if err := errors.Join(err1, err2, err3); err != nil {
		linkFailed(w, http.StatusInternalServerError, "Internal error.")
		return
	}
	now := l.now()
	c := &linkChallenge{
		id: id, browserHash: sha256.Sum256([]byte(browser)), expiresAt: now.Add(linkChallengeTTL),
		githubState: linkGitHubPrefix + ghState, startedAt: now,
	}
	l.mu.Lock()
	l.sweepLocked(now)
	if len(l.byID) >= linkMaxChallenges {
		l.mu.Unlock()
		linkFailed(w, http.StatusServiceUnavailable, "Too many links in progress; try again in a few minutes.")
		return
	}
	l.byID[c.id] = c
	l.byGitHub[c.githubState] = c
	l.mu.Unlock()

	setLinkCookie(w, browser, int(linkChallengeTTL.Seconds()))
	q := url.Values{}
	q.Set("client_id", l.opts.GitHubClientID)
	q.Set("redirect_uri", l.opts.BaseURL+githubCallbackPath)
	q.Set("scope", "read:user")
	q.Set("state", c.githubState)
	http.Redirect(w, r, "https://github.com/login/oauth/authorize?"+q.Encode(), http.StatusFound)
}

// isIdentityLinkState reports a GitHub callback that belongs to linking.
func isIdentityLinkState(state string) bool { return strings.HasPrefix(state, linkGitHubPrefix) }

// handleIdentityLinkGitHubCallback: the GitHub half, reached through
// /oauth/github/callback with a link state.
func (h *Handlers) handleIdentityLinkGitHubCallback(w http.ResponseWriter, r *http.Request) {
	l := h.identityLink
	if l == nil || !l.opts.browserFlowEnabled() {
		linkFailed(w, http.StatusServiceUnavailable, "Linking a ZITADEL identity is not configured on this server.")
		return
	}
	q := r.URL.Query()
	l.mu.Lock()
	l.sweepLocked(l.now())
	c, ok := l.byGitHub[q.Get("state")]
	valid := ok && c.phase == linkStarted && browserMatches(r, c)
	if valid {
		// Single use: a replayed GitHub callback finds nothing.
		delete(l.byGitHub, c.githubState)
	}
	l.mu.Unlock()
	if !valid {
		linkFailed(w, http.StatusBadRequest, "This link session is unknown, expired, or was started in another browser.")
		return
	}
	if e := q.Get("error"); e != "" {
		linkFailed(w, http.StatusBadRequest, "GitHub refused the sign-in: "+e+".")
		return
	}
	code := q.Get("code")
	if code == "" {
		linkFailed(w, http.StatusBadRequest, "GitHub returned no code.")
		return
	}
	login, ghID, err := l.opts.ProveGitHub(r.Context(), code, l.opts.BaseURL+githubCallbackPath)
	if err != nil {
		slog.Warn("identity link: GitHub proof failed", "error", err)
		linkFailed(w, http.StatusBadGateway, "Could not verify the GitHub sign-in.")
		return
	}
	p, err := l.opts.Store.Provision(r.Context(), auth.Identity{
		Provider: auth.ProviderGitHub, Subject: strconv.FormatInt(ghID, 10), Display: login, Kind: auth.KindHuman,
	})
	if err != nil {
		slog.Warn("identity link: GitHub principal unavailable", "login", login, "error", err)
		linkFailed(w, http.StatusForbidden, "Your GitHub identity cannot be used for linking ("+err.Error()+").")
		return
	}

	prov, err := l.oidcProvider(r.Context())
	if err != nil {
		slog.Warn("identity link: ZITADEL discovery failed", "issuer", l.opts.Issuer, "error", err)
		linkFailed(w, http.StatusBadGateway, "ZITADEL is not reachable right now.")
		return
	}
	zState, err1 := randomLinkToken()
	nonce, err2 := randomLinkToken()
	if err := errors.Join(err1, err2); err != nil {
		linkFailed(w, http.StatusInternalServerError, "Internal error.")
		return
	}
	verifier := oauth2.GenerateVerifier()

	l.mu.Lock()
	c.principalID, c.githubLogin, c.githubID = p.ID, login, ghID
	c.zitadelState, c.nonce, c.verifier = zState, nonce, verifier
	c.phase = linkGitHubProven
	l.byZState[zState] = c
	l.mu.Unlock()

	// prompt=login: the ZITADEL half is proven in this session, not taken
	// from an older ZITADEL session in this browser.
	authURL := l.oauthConfig(prov).AuthCodeURL(zState, oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("prompt", "login"))
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleIdentityLinkCallback: GET /identity/link/zitadel/callback.
func (h *Handlers) handleIdentityLinkCallback(w http.ResponseWriter, r *http.Request) {
	l := h.identityLink
	if l == nil || !l.opts.browserFlowEnabled() {
		linkFailed(w, http.StatusServiceUnavailable, "Linking a ZITADEL identity is not configured on this server.")
		return
	}
	q := r.URL.Query()
	l.mu.Lock()
	l.sweepLocked(l.now())
	c, ok := l.byZState[q.Get("state")]
	valid := ok && c.phase == linkGitHubProven && browserMatches(r, c)
	if valid {
		delete(l.byZState, c.zitadelState)
	}
	l.mu.Unlock()
	if !valid {
		linkFailed(w, http.StatusBadRequest, "This link session is unknown, expired, or was started in another browser.")
		return
	}
	if e := q.Get("error"); e != "" {
		linkFailed(w, http.StatusBadRequest, "ZITADEL refused the sign-in: "+e+".")
		return
	}
	prov, err := l.oidcProvider(r.Context())
	if err != nil {
		linkFailed(w, http.StatusBadGateway, "ZITADEL is not reachable right now.")
		return
	}
	tok, err := l.oauthConfig(prov).Exchange(r.Context(), q.Get("code"), oauth2.VerifierOption(c.verifier))
	if err != nil {
		slog.Warn("identity link: ZITADEL code exchange failed", "error", err)
		linkFailed(w, http.StatusBadGateway, "Could not complete the ZITADEL sign-in.")
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := prov.Verifier(&oidc.Config{ClientID: l.opts.ClientID}).Verify(r.Context(), raw)
	if err != nil {
		slog.Warn("identity link: ZITADEL ID token refused", "error", err)
		linkFailed(w, http.StatusBadRequest, "The ZITADEL ID token was not valid.")
		return
	}
	var claims struct {
		Nonce             string `json:"nonce"`
		AuthTime          int64  `json:"auth_time"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idt.Claims(&claims); err != nil || subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(c.nonce)) != 1 {
		linkFailed(w, http.StatusBadRequest, "The ZITADEL sign-in does not belong to this link session.")
		return
	}
	// The sign-in must have happened inside this session (prompt=login).
	if claims.AuthTime == 0 || time.Unix(claims.AuthTime, 0).Before(c.startedAt.Add(-time.Minute)) {
		linkFailed(w, http.StatusBadRequest, "ZITADEL did not report a fresh sign-in for this link session.")
		return
	}
	display := claims.PreferredUsername
	if display == "" {
		display = idt.Subject
	}
	csrf, err := randomLinkToken()
	if err != nil {
		linkFailed(w, http.StatusInternalServerError, "Internal error.")
		return
	}
	l.mu.Lock()
	c.identity = auth.Identity{Provider: l.opts.ProviderName, Issuer: idt.Issuer, Subject: idt.Subject, Display: display, Kind: auth.KindHuman}
	c.csrfHash = sha256.Sum256([]byte(csrf))
	c.phase = linkZitadelProven
	l.mu.Unlock()

	renderLinkPage(w, http.StatusOK, linkPageData{
		Title: "Link your ZITADEL identity",
		Lines: []string{
			"GitHub: " + c.githubLogin,
			"ZITADEL: " + display,
			"Linking lets you sign in to mctl with ZITADEL as the same principal you use with GitHub (" + c.principalID + ").",
		},
		Confirm: &struct{ Action, Challenge, CSRF string }{Action: linkConfirmPath, Challenge: c.id, CSRF: csrf},
	})
}

// handleIdentityLinkConfirm: POST /identity/link/zitadel/confirm.
func (h *Handlers) handleIdentityLinkConfirm(w http.ResponseWriter, r *http.Request) {
	l := h.identityLink
	if l == nil || !l.opts.browserFlowEnabled() {
		linkFailed(w, http.StatusServiceUnavailable, "Linking a ZITADEL identity is not configured on this server.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		linkFailed(w, http.StatusBadRequest, "Malformed request.")
		return
	}
	csrfSum := sha256.Sum256([]byte(r.PostForm.Get("csrf")))
	l.mu.Lock()
	l.sweepLocked(l.now())
	c, ok := l.byID[r.PostForm.Get("challenge")]
	valid := ok && c.phase == linkZitadelProven && browserMatches(r, c) &&
		subtle.ConstantTimeCompare(csrfSum[:], c.csrfHash[:]) == 1
	if valid {
		c.phase = linkUsed
		l.dropLocked(c.id, c)
	}
	l.mu.Unlock()
	if !valid {
		linkFailed(w, http.StatusBadRequest, "This link session is unknown, expired, already used, or was started in another browser.")
		return
	}
	setLinkCookie(w, "", -1)

	outcome, err := l.opts.Store.LinkIdentity(r.Context(), c.principalID, c.identity)
	result, status, code := outcome, http.StatusOK, ""
	var owned *principals.OwnedElsewhereError
	switch {
	case err == nil:
	case errors.As(err, &owned):
		result, status, code = "refused_owned_elsewhere", http.StatusConflict, linkCodeOwnedElsewhere
	case errors.Is(err, principals.ErrPrincipalAlreadyLinked):
		result, status, code = "refused_already_linked", http.StatusConflict, linkCodeAlreadyLinked
	case errors.Is(err, principals.ErrIdentityRevoked):
		result, status, code = "refused_revoked", http.StatusConflict, linkCodeRevoked
	case errors.Is(err, auth.ErrPrincipalDisabled):
		result, status, code = "refused_disabled", http.StatusForbidden, "principal_disabled"
	default:
		result, status = "error", http.StatusServiceUnavailable
	}
	identityLinksTotal.WithLabelValues(l.opts.ProviderName, result).Inc()
	params := map[string]string{
		"principal_id": c.principalID, "github_login": c.githubLogin, "github_id": strconv.FormatInt(c.githubID, 10),
		"provider": c.identity.Provider, "issuer": c.identity.Issuer, "subject": c.identity.Subject, "result": result,
	}
	if owned != nil {
		params["other_principal_id"] = owned.PrincipalID
	}
	auditStatus := "succeeded"
	if err != nil {
		auditStatus = "failed"
	}
	h.logAudit(r, audit.Entry{
		UserID: c.githubLogin, PrincipalID: c.principalID, Operation: "identity.link", Status: auditStatus,
		RiskLevel: string(operations.RiskMedium), Parameters: params,
	})

	switch {
	case err == nil:
		renderLinkPage(w, status, linkPageData{Title: "Identities linked", Lines: []string{
			"ZITADEL user " + c.identity.Display + " now signs in as your mctl principal " + c.principalID + ".",
			"You can review or remove linked identities with GET /api/v1/identity/links.",
		}})
	case code == linkCodeOwnedElsewhere:
		renderLinkPage(w, status, linkPageData{Title: "Not linked: this ZITADEL identity already has its own principal", Lines: []string{
			"ZITADEL user " + c.identity.Display + " has already signed in to mctl on its own, which created a separate principal (" + owned.PrincipalID + ").",
			"Self-service never moves an identity between principals. A platform admin can merge " + owned.PrincipalID + " into " + c.principalID + " (an audited admin operation); ask one, quoting both ids.",
		}})
	case code == linkCodeAlreadyLinked:
		linkFailed(w, status, "Your principal already has a different ZITADEL identity linked. Unlink it first (DELETE /api/v1/identity/links/{id}).")
	case code == linkCodeRevoked:
		linkFailed(w, status, "This ZITADEL identity was unlinked from your principal earlier. Only a platform admin can restore it.")
	case code != "":
		linkFailed(w, status, "Your principal is disabled.")
	default:
		slog.Error("identity link: store failed", "error", err)
		linkFailed(w, status, "The link could not be stored; nothing was changed.")
	}
}

// ListIdentityLinks: GET /api/v1/identity/links, the caller's identities.
func (h *Handlers) ListIdentityLinks(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if h.identityLink == nil || h.identityLink.opts.Store == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, linkCodeUnavailable, "identity linking not configured", nil)
		return
	}
	pid := user.PrincipalID()
	if pid == "" {
		writeErrorCode(w, http.StatusServiceUnavailable, linkCodeUnavailable, "the caller's principal could not be resolved", nil)
		return
	}
	ids, err := h.identityLink.opts.Store.Identities(r.Context(), pid)
	if err != nil {
		writeErrorCode(w, http.StatusServiceUnavailable, linkCodeUnavailable, "principal store unavailable", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"principal_id": pid, "identities": ids})
}

// UnlinkIdentity: DELETE /api/v1/identity/links/{id}, one of the caller's
// own identities. The last live identity cannot be unlinked.
func (h *Handlers) UnlinkIdentity(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if h.identityLink == nil || h.identityLink.opts.Store == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, linkCodeUnavailable, "identity linking not configured", nil)
		return
	}
	if _, relayed := user.RelaySurface(); relayed || user.IsService() {
		writeError(w, http.StatusForbidden, "identities are unlinked by the person, not through a surface or service")
		return
	}
	pid := user.PrincipalID()
	if pid == "" {
		writeErrorCode(w, http.StatusServiceUnavailable, linkCodeUnavailable, "the caller's principal could not be resolved", nil)
		return
	}
	xid := chi.URLParam(r, "id")
	x, err := h.identityLink.opts.Store.UnlinkIdentity(r.Context(), pid, xid)
	switch {
	case errors.Is(err, principals.ErrNotFound):
		writeError(w, http.StatusNotFound, "no such identity on your principal")
		return
	case errors.Is(err, principals.ErrLastIdentity):
		writeErrorCode(w, http.StatusConflict, linkCodeLastIdentity, "cannot unlink your last live identity", nil)
		return
	case err != nil:
		writeErrorCode(w, http.StatusServiceUnavailable, linkCodeUnavailable, "principal store unavailable", nil)
		return
	}
	h.logAudit(r, audit.Entry{
		UserID: user.ID, Operation: "identity.unlink", Status: "succeeded", RiskLevel: string(operations.RiskMedium),
		Parameters: map[string]string{"principal_id": pid, "identity_id": x.ID, "provider": x.Provider, "issuer": x.Issuer, "subject": x.Subject},
	})
	writeJSON(w, http.StatusOK, x)
}

// MergePrincipals: POST /api/v1/admin/principals/{from}/merge-into/{into}.
// The admin side of a refused self-service link (owner decision A on #435).
func (h *Handlers) MergePrincipals(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if !isHumanAdmin(user) {
		writeError(w, http.StatusForbidden, "only a platform admin acting directly may merge principals")
		return
	}
	if h.identityLink == nil || h.identityLink.opts.Store == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, linkCodeUnavailable, "identity linking not configured", nil)
		return
	}
	from, into := chi.URLParam(r, "from"), chi.URLParam(r, "into")
	moved, err := h.identityLink.opts.Store.MergePrincipals(r.Context(), from, into)
	params := map[string]string{"from_principal_id": from, "into_principal_id": into, "moved": strconv.Itoa(moved)}
	status := "succeeded"
	if err != nil {
		status = "failed"
		params["error"] = err.Error()
	}
	h.logAudit(r, audit.Entry{
		UserID: user.ID, Operation: "principal.merge", Status: status, RiskLevel: string(operations.RiskHigh), Parameters: params,
	})
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]interface{}{"from": from, "into": into, "moved_identities": moved, "from_status": principals.StatusDisabled})
	case errors.Is(err, principals.ErrNotFound):
		writeError(w, http.StatusNotFound, "principal not found")
	case errors.Is(err, principals.ErrMergeConflict):
		writeErrorCode(w, http.StatusConflict, linkCodeMergeConflict, err.Error(), nil)
	case errors.Is(err, principals.ErrInvalid), errors.Is(err, auth.ErrPrincipalDisabled):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		writeErrorCode(w, http.StatusServiceUnavailable, linkCodeUnavailable, "principal store unavailable", nil)
	}
}
