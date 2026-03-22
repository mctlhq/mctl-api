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
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// OAuthMeta is returned by /.well-known/oauth-authorization-server (RFC 8414).
type OAuthMeta struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

// handleOAuthMeta serves the RFC 8414 OAuth server metadata document.
func (h *Handlers) handleOAuthMeta(w http.ResponseWriter, r *http.Request) {
	if h.opts.OAuthServer == nil {
		http.NotFound(w, r)
		return
	}
	base := h.opts.OAuthServer.BaseURL
	meta := OAuthMeta{
		Issuer:                            base,
		AuthorizationEndpoint:             base + "/oauth/authorize",
		TokenEndpoint:                     base + "/oauth/token",
		RegistrationEndpoint:              base + "/oauth/register",
		RevocationEndpoint:                base + "/oauth/revoke",
		ScopesSupported:                   []string{"mctl"},
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{"none"},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meta)
}

// handleOAuthAuthorize initiates the OAuth Authorization Code flow.
// It validates the request parameters, stores pending state, and redirects to GitHub.
//
// Required query params: client_id, redirect_uri, response_type=code, state,
//
//	code_challenge, code_challenge_method=S256
func (h *Handlers) handleOAuthAuthorize(w http.ResponseWriter, r *http.Request) {
	o := h.opts.OAuthServer
	if o == nil {
		http.Error(w, "OAuth not configured", http.StatusNotFound)
		return
	}

	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	responseType := q.Get("response_type")
	state := q.Get("state")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")

	if responseType != "code" {
		oauthError(w, redirectURI, state, "unsupported_response_type", "only response_type=code is supported")
		return
	}
	if clientID == "" {
		oauthError(w, redirectURI, state, "invalid_request", "client_id is required")
		return
	}
	if redirectURI == "" || !o.IsRedirectURIAllowed(redirectURI) {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	if state == "" {
		oauthError(w, redirectURI, state, "invalid_request", "state is required")
		return
	}
	if codeChallenge == "" {
		oauthError(w, redirectURI, state, "invalid_request", "code_challenge is required")
		return
	}
	if codeChallengeMethod != "S256" {
		oauthError(w, redirectURI, state, "invalid_request", "only code_challenge_method=S256 is supported")
		return
	}

	// Generate a random state for the GitHub OAuth leg (different from client state).
	ghState, err := auth.GenerateState()
	if err != nil {
		slog.Error("failed to generate state", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Prefix the GitHub state with client state so we can recover it in the callback.
	// Format: "<ghState>:<clientState>" (clientState can't contain ":" because it's
	// base64url-encoded, but we use a separator prefix to be explicit).
	combinedState := ghState + "|" + state

	// Persist all pending auth details keyed by combined state.
	o.StorePendingAuth(combinedState, clientID, redirectURI, codeChallenge)

	// Build GitHub OAuth authorization URL.
	ghAuthURL := url.URL{
		Scheme: "https",
		Host:   "github.com",
		Path:   "/login/oauth/authorize",
	}
	ghQ := ghAuthURL.Query()
	ghQ.Set("client_id", o.GitHubClientID)
	ghQ.Set("redirect_uri", o.BaseURL+"/oauth/github/callback")
	ghQ.Set("scope", "read:user user:email")
	ghQ.Set("state", combinedState)
	ghAuthURL.RawQuery = ghQ.Encode()

	http.Redirect(w, r, ghAuthURL.String(), http.StatusFound)
}

// handleOAuthGitHubCallback handles the GitHub OAuth callback.
// It exchanges the GitHub code for a GitHub token, resolves the user identity,
// issues a mctl authorization code, and redirects back to the client.
func (h *Handlers) handleOAuthGitHubCallback(w http.ResponseWriter, r *http.Request) {
	o := h.opts.OAuthServer
	if o == nil {
		http.Error(w, "OAuth not configured", http.StatusNotFound)
		return
	}

	q := r.URL.Query()
	code := q.Get("code")
	combinedState := q.Get("state")
	errParam := q.Get("error")
	errDesc := q.Get("error_description")

	if errParam != "" {
		slog.Warn("GitHub OAuth returned error", "error", errParam, "description", errDesc)
		http.Error(w, fmt.Sprintf("GitHub auth error: %s", errParam), http.StatusBadRequest)
		return
	}
	if code == "" || combinedState == "" {
		http.Error(w, "missing code or state", http.StatusBadRequest)
		return
	}

	// Recover pending auth from state.
	pending, ok := o.LoadPendingAuth(combinedState)
	if !ok {
		http.Error(w, "invalid or expired state", http.StatusBadRequest)
		return
	}

	// Extract client state (everything after the first "|").
	idx := strings.Index(combinedState, "|")
	var clientState string
	if idx >= 0 {
		clientState = combinedState[idx+1:]
	}

	// Exchange GitHub code for access token.
	ghToken, err := exchangeGitHubCode(r.Context(), o.GitHubClientID, o.GitHubClientSecret, code, o.BaseURL+"/oauth/github/callback")
	if err != nil {
		slog.Error("failed to exchange GitHub code", "error", err)
		http.Error(w, "failed to exchange GitHub code", http.StatusBadGateway)
		return
	}

	// Validate the GitHub token and get the login.
	login, err := o.GitHubValidator.Validate(r.Context(), ghToken)
	if err != nil {
		slog.Error("failed to validate GitHub token", "error", err)
		http.Error(w, "GitHub token validation failed", http.StatusBadGateway)
		return
	}

	// Resolve tenant groups (same as regular GitHub auth path).
	groups := o.ResolveGroups(login)

	// Issue a mctl authorization code.
	mctlCode, err := o.IssueCode(login, pending.ClientID, pending.RedirectURI, pending.CodeChallenge, groups)
	if err != nil {
		slog.Error("failed to issue auth code", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Redirect back to client with code + state.
	target, err := url.Parse(pending.RedirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusInternalServerError)
		return
	}
	cq := target.Query()
	cq.Set("code", mctlCode)
	if clientState != "" {
		cq.Set("state", clientState)
	}
	target.RawQuery = cq.Encode()

	http.Redirect(w, r, target.String(), http.StatusFound)
}

// handleOAuthToken exchanges an authorization code or refresh token for an access token.
//
// POST /oauth/token
// Content-Type: application/x-www-form-urlencoded
// grant_type=authorization_code&code=...&code_verifier=...&client_id=...&redirect_uri=...
// grant_type=refresh_token&refresh_token=...&client_id=...
func (h *Handlers) handleOAuthToken(w http.ResponseWriter, r *http.Request) {
	o := h.opts.OAuthServer
	if o == nil {
		http.Error(w, "OAuth not configured", http.StatusNotFound)
		return
	}

	if err := r.ParseForm(); err != nil {
		tokenError(w, "invalid_request", "failed to parse request body")
		return
	}

	grantType := r.FormValue("grant_type")
	clientID := r.FormValue("client_id")
	var (
		accessToken  string
		refreshToken string
		err          error
	)

	switch grantType {
	case "authorization_code":
		code := r.FormValue("code")
		codeVerifier := r.FormValue("code_verifier")
		redirectURI := r.FormValue("redirect_uri")
		if code == "" || codeVerifier == "" || clientID == "" || redirectURI == "" {
			tokenError(w, "invalid_request", "code, code_verifier, client_id and redirect_uri are required")
			return
		}
		accessToken, refreshToken, err = o.ExchangeCode(code, codeVerifier, clientID, redirectURI)
	case "refresh_token":
		refreshGrant := r.FormValue("refresh_token")
		if refreshGrant == "" || clientID == "" {
			tokenError(w, "invalid_request", "refresh_token and client_id are required")
			return
		}
		accessToken, refreshToken, err = o.RefreshAccessToken(refreshGrant, clientID)
	default:
		tokenError(w, "unsupported_grant_type", "supported grant_type values are authorization_code and refresh_token")
		return
	}
	if err != nil {
		slog.Warn("token exchange failed", "grant_type", grantType, "error", err)
		tokenError(w, "invalid_grant", err.Error())
		return
	}

	ttl := o.AccessTokenTTL
	if ttl == 0 {
		ttl = time.Hour
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    int(ttl.Seconds()),
		"scope":         "mctl",
	})
}

// handleOAuthRevoke accepts a token revocation request.
// Access tokens remain stateless JWTs, but refresh tokens are actively revoked.
func (h *Handlers) handleOAuthRevoke(w http.ResponseWriter, r *http.Request) {
	o := h.opts.OAuthServer
	if o == nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err == nil {
		o.RevokeRefreshToken(r.FormValue("token"))
	}
	// Per RFC 7009, a successful revocation always returns 200.
	w.WriteHeader(http.StatusOK)
}

// handleOAuthRegister implements RFC 7591 Dynamic Client Registration.
// MCP clients (e.g. Claude Desktop) call this to register before starting OAuth flow.
//
// POST /oauth/register
// Content-Type: application/json
// {"client_name":"...","redirect_uris":["..."]}
func (h *Handlers) handleOAuthRegister(w http.ResponseWriter, r *http.Request) {
	o := h.opts.OAuthServer
	if o == nil {
		http.Error(w, "OAuth not configured", http.StatusNotFound)
		return
	}

	var req struct {
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_client_metadata",
			"error_description": "failed to parse request body",
		})
		return
	}

	if len(req.RedirectURIs) == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_client_metadata",
			"error_description": "redirect_uris is required",
		})
		return
	}

	client := o.RegisterClient(req.ClientName, req.RedirectURIs)

	slog.Info("OAuth client registered", "client_id", client.ClientID, "client_name", client.ClientName, "redirect_uris", client.RedirectURIs)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"client_id":                  client.ClientID,
		"client_name":                client.ClientName,
		"redirect_uris":              client.RedirectURIs,
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"client_id_issued_at":        client.CreatedAt.Unix(),
	})
}

// ─── GitHub OAuth helpers ─────────────────────────────────────────────────────

func exchangeGitHubCode(ctx context.Context, clientID, clientSecret, code, redirectURI string) (string, error) {
	body := url.Values{}
	body.Set("client_id", clientID)
	body.Set("client_secret", clientSecret)
	body.Set("code", code)
	body.Set("redirect_uri", redirectURI)

	req, err := http.NewRequestWithContext(ctx, "POST", "https://github.com/login/oauth/access_token", strings.NewReader(body.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("GitHub token exchange failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading GitHub response: %w", err)
	}

	var result struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parsing GitHub response: %w", err)
	}
	if result.Error != "" {
		return "", fmt.Errorf("GitHub returned error: %s — %s", result.Error, result.ErrorDesc)
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("GitHub returned empty access token")
	}
	return result.AccessToken, nil
}

// ─── Error helpers ────────────────────────────────────────────────────────────

// oauthError redirects to redirect_uri with error params, or writes plain HTTP error
// if redirect_uri is empty/invalid.
func oauthError(w http.ResponseWriter, redirectURI, state, errCode, errDesc string) {
	if redirectURI == "" {
		http.Error(w, fmt.Sprintf("%s: %s", errCode, errDesc), http.StatusBadRequest)
		return
	}
	target, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, fmt.Sprintf("%s: %s", errCode, errDesc), http.StatusBadRequest)
		return
	}
	q := target.Query()
	q.Set("error", errCode)
	if errDesc != "" {
		q.Set("error_description", errDesc)
	}
	if state != "" {
		q.Set("state", state)
	}
	target.RawQuery = q.Encode()
	w.Header().Set("Location", target.String())
	w.WriteHeader(http.StatusFound)
}

func tokenError(w http.ResponseWriter, errCode, errDesc string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": errDesc,
	})
}
