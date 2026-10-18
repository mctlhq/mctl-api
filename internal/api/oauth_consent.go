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

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// consentCookie binds a consent decision to the browser that signed in.
const consentCookie = "__Host-mctl_consent"

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
}

// issueGrant issues the authorization code, writes the oauth.grant_issued
// audit entry and returns the URL to send the client to.
func (h *Handlers) issueGrant(r *http.Request, c authzCompletion) (string, error) {
	o := h.opts.OAuthServer
	code, err := o.IssueCode(r.Context(), c.Login, c.PrincipalID, c.ClientID, c.RedirectURI, c.CodeChallenge, c.Groups)
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
		BrowserHash: consentHash(token),
	})
	if err != nil {
		slog.Error("failed to store consent", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return "internal_error"
	}
	http.SetCookie(w, &http.Cookie{
		Name: consentCookie, Value: consentHash(token), Path: "/", MaxAge: 300,
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
	o := h.opts.OAuthServer
	if o == nil {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxOAuthFormBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	token, decision := r.PostForm.Get("token"), r.PostForm.Get("decision")
	if token == "" || (decision != "approve" && decision != "deny") {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	// The token is spent whatever happens next, so a replay or a wrong
	// browser cannot retry it.
	e, ok, err := o.TakeConsent(r.Context(), token)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "invalid or expired consent", http.StatusBadRequest)
		return
	}
	cookie, cerr := r.Cookie(consentCookie)
	if cerr != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(e.BrowserHash)) != 1 ||
		subtle.ConstantTimeCompare([]byte(consentHash(token)), []byte(e.BrowserHash)) != 1 {
		http.Error(w, "invalid or expired consent", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: consentCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	state := string(e.ClientState)
	if decision == "deny" {
		oauthError(w, e.RedirectURI, state, "access_denied", "the user denied the request")
		return
	}
	loc, err := h.issueGrant(r, authzCompletion{
		Login: e.Login, PrincipalID: e.PrincipalID, Groups: e.Groups, ClientID: e.ClientID,
		RedirectURI: e.RedirectURI, CodeChallenge: e.CodeChallenge, ClientState: state,
		Upstream: e.Upstream, ClientName: e.ClientName,
	})
	if err != nil {
		slog.Error("failed to issue auth code", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, loc, http.StatusFound)
}
