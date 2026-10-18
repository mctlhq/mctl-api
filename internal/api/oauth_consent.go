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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// consentCookie prefixes the per-flow consent cookie. It is a CSRF defence
// that also keeps flows apart: SameSite=Lax keeps it off a cross-site form
// POST, and each flow's cookie is named after its token hash, so two consent
// pages open in one browser do not overwrite each other. It is not a second
// factor: its value is sha256(token), so any HTTP client holding the token can
// send it. The single-use token is the secret that guards a consent.
const consentCookie = "__Host-mctl_consent"

// consentCookieName is the cookie of the flow whose token hashes to hash.
func consentCookieName(hash string) string { return consentCookie + "_" + hash[:16] }

func clearConsentCookie(w http.ResponseWriter, hash string) {
	http.SetCookie(w, &http.Cookie{Name: consentCookieName(hash), Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

// oauthConsentDecisions counts POST /oauth/consent outcomes: approve, deny,
// or why the decision was refused (invalid_request, wrong_browser,
// invalid_token, store_error, internal_error). It picks up a CIMD sign-in
// where oauth_upstream_signins{result="consent_required"} leaves it.
var oauthConsentDecisions = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "oauth_consent_decisions_total",
	Help: "POST /oauth/consent outcomes by result (mctl-api#684).",
}, []string{"result"})

func init() { prometheus.MustRegister(oauthConsentDecisions) }

// authzCompletion is an authorization the upstream has signed a human in
// for. Login, PrincipalID and Groups come from the upstream sign-in only;
// ClientID and the rest from the authorization request.
type authzCompletion struct {
	Login         string
	PrincipalID   string
	Groups        []string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	ClientState   string
	Upstream      string
	ClientName    string
	// AuthMethod is a CIMD client's token_endpoint_auth_method, read from
	// its document at consent; empty for every other client.
	AuthMethod string
}

// issueGrant issues the authorization code, writes the oauth.grant_issued
// audit entry and returns the URL to send the client to.
func (h *Handlers) issueGrant(r *http.Request, c authzCompletion) (string, error) {
	o := h.opts.OAuthServer
	code, err := o.IssueCodeWithAuthMethod(r.Context(), c.Login, c.PrincipalID, c.ClientID, c.RedirectURI, c.CodeChallenge, c.Groups, c.AuthMethod)
	if err != nil {
		return "", err
	}
	target, err := url.Parse(c.RedirectURI)
	if err != nil {
		return "", err
	}
	// The principal goes in the principal column; the client only in
	// parameters, so the two identities are never merged.
	h.logAudit(r, audit.Entry{
		UserID: c.Login, PrincipalID: c.PrincipalID,
		Operation: "oauth.grant_issued", Status: "succeeded",
		RiskLevel: string(operations.RiskLow),
		Parameters: map[string]string{
			"client_id":     c.ClientID,
			"client_kind":   o.ClientKind(c.ClientID),
			"client_name":   truncateEchoedValue(c.ClientName),
			"redirect_host": target.Host,
			"upstream":      c.Upstream,
		},
	})
	cq := target.Query()
	cq.Set("code", code)
	if c.ClientState != "" {
		cq.Set("state", c.ClientState)
	}
	target.RawQuery = cq.Encode()
	return target.String(), nil
}

// finishAuthorization completes an authorization after the upstream sign-in:
// a CIMD client is first shown the consent page, every other client gets its
// code at once, as before. It writes the response and returns the metric
// result.
func (h *Handlers) finishAuthorization(w http.ResponseWriter, r *http.Request, c authzCompletion) string {
	o := h.opts.OAuthServer
	if o.IsCIMDClient(c.ClientID) {
		return h.requestConsent(w, r, c)
	}
	loc, err := h.issueGrant(r, c)
	if err != nil {
		slog.Error("failed to issue auth code", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return "internal_error"
	}
	http.Redirect(w, r, loc, http.StatusFound)
	return "issued"
}

func consentHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (h *Handlers) requestConsent(w http.ResponseWriter, r *http.Request, c authzCompletion) string {
	o := h.opts.OAuthServer
	client, err := o.ResolveCIMDClient(r.Context(), c.ClientID)
	if err != nil {
		slog.Warn("oauth: client metadata document refused at consent", "client_id", c.ClientID, "error", err)
		http.Error(w, "the client's metadata document is unavailable", http.StatusBadRequest)
		return "client_unavailable"
	}
	redirect, err := url.Parse(c.RedirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return "internal_error"
	}
	clientURL, _ := url.Parse(c.ClientID)
	name := client.ClientName
	if name == "" && clientURL != nil {
		name = clientURL.Hostname()
	}
	token, err := auth.NewConsentToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return "internal_error"
	}
	err = o.StoreConsent(r.Context(), token, auth.ConsentEntry{
		Login: c.Login, PrincipalID: c.PrincipalID, Groups: c.Groups,
		ClientID: c.ClientID, ClientName: client.ClientName, RedirectURI: c.RedirectURI,
		CodeChallenge: c.CodeChallenge, ClientState: []byte(c.ClientState), Upstream: c.Upstream,
		AuthMethod: client.AuthMethod, BrowserHash: consentHash(token),
	})
	if err != nil {
		slog.Error("failed to store consent", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return "internal_error"
	}
	http.SetCookie(w, &http.Cookie{
		Name: consentCookieName(consentHash(token)), Value: consentHash(token), Path: "/", MaxAge: 300,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	// A customer or a ZITADEL-only human in principal mode signs in with no
	// GitHub login; the page then names the principal instead.
	account := c.Login
	if account == "" {
		account = c.PrincipalID
	}
	renderShellPage(w, http.StatusOK, "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'", consentPage,
		shellData{Title: "Authorize this application?", Lines: []string{
			"An application is asking to access MCTL on your behalf.",
			"Application: " + name,
			"Client ID: " + c.ClientID,
			"Returns to: " + redirect.Host,
			"You are signed in as " + account + ". The application does not choose this account.",
		}, Page: consentPageData{Token: token}})
	return "consent_required"
}

type consentPageData struct{ Token string }

// consentPage is drawn in the page shell, which escapes every line,
// client_name included.
var consentPage = shellPage("consent", `<form class="actions" method="post" action="/oauth/consent">
<input type="hidden" name="token" value="{{.Token}}">
<button type="submit" name="decision" value="approve">Allow</button>
<button class="secondary" type="submit" name="decision" value="deny">Deny</button>
</form>`)

// handleOAuthConsent takes the consent decision of the human who signed in.
//
// POST /oauth/consent  (form: token, decision=approve|deny)
func (h *Handlers) handleOAuthConsent(w http.ResponseWriter, r *http.Request) {
	if h.opts.OAuthServer == nil {
		http.NotFound(w, r)
		return
	}
	oauthConsentDecisions.WithLabelValues(h.takeConsentDecision(w, r)).Inc()
}

// takeConsentDecision writes the response to a consent decision and returns
// the metric result.
func (h *Handlers) takeConsentDecision(w http.ResponseWriter, r *http.Request) string {
	o := h.opts.OAuthServer
	r.Body = http.MaxBytesReader(w, r.Body, maxOAuthFormBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return "invalid_request"
	}
	token, decision := r.PostForm.Get("token"), r.PostForm.Get("decision")
	if token == "" || (decision != "approve" && decision != "deny") {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return "invalid_request"
	}
	// The cookie is checked before the token is spent, so a cross-site POST
	// or a replay from a browser without the flow's cookie is refused without
	// burning the consent out from under the human. This rests on the
	// browser's SameSite handling: the hash is computable from the token, so
	// a non-browser client holding the token passes this check.
	hash := consentHash(token)
	cookie, cerr := r.Cookie(consentCookieName(hash))
	if cerr != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(hash)) != 1 {
		http.Error(w, "invalid or expired consent", http.StatusBadRequest)
		return "wrong_browser"
	}
	// From here the token is spent whatever happens next, so a replay cannot
	// retry it.
	e, ok, err := o.TakeConsent(r.Context(), token)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return "store_error"
	}
	if !ok {
		// A replayed or expired token tidies up its flow cookie too.
		clearConsentCookie(w, hash)
		http.Error(w, "invalid or expired consent", http.StatusBadRequest)
		return "invalid_token"
	}
	if subtle.ConstantTimeCompare([]byte(hash), []byte(e.BrowserHash)) != 1 {
		http.Error(w, "invalid or expired consent", http.StatusBadRequest)
		return "wrong_browser"
	}
	clearConsentCookie(w, hash)
	state := string(e.ClientState)
	if decision == "deny" {
		oauthError(w, e.RedirectURI, state, "access_denied", "the user denied the request")
		return "deny"
	}
	loc, err := h.issueGrant(r, authzCompletion{
		Login: e.Login, PrincipalID: e.PrincipalID, Groups: e.Groups, ClientID: e.ClientID,
		RedirectURI: e.RedirectURI, CodeChallenge: e.CodeChallenge, ClientState: state,
		Upstream: e.Upstream, ClientName: e.ClientName, AuthMethod: e.AuthMethod,
	})
	if err != nil {
		slog.Error("failed to issue auth code", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return "internal_error"
	}
	http.Redirect(w, r, loc, http.StatusFound)
	return "approve"
}
