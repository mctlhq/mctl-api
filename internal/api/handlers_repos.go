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
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// backstageReposProxy is a shared HTTP client for proxying repo requests to Backstage.
var backstageReposClient = &http.Client{Timeout: 15 * time.Second}

// authorizeGithubAppConnect attaches the service credentials the
// github-app-connect plugin now requires. mctl-portal#79 dropped that
// plugin's unauthenticated allowlist, so every proxied call below comes back
// 401 without this header. Custom domains (handlers_domains.go) no longer
// proxy to Backstage at all — mctl-api owns that registry directly — so this
// token is scoped to github-app-connect only and rotates independently.
func (h *Handlers) authorizeGithubAppConnect(req *http.Request) {
	if h.opts.BackstageGithubAppConnectToken != "" {
		req.Header.Set("Authorization", "Bearer "+h.opts.BackstageGithubAppConnectToken)
	}
}

// Service-authenticated github-app-connect plugin routes. The plugin's
// user-facing routes (/repos, /install-url, /repos/sync) accept only Backstage
// user sessions, so the static service token is always refused there. These
// routes accept the mctl-api service principal (like /repo-binding) and trust
// the team and user mctl-api asserts after its own authorization.
const (
	githubAppConnectServiceReposPath      = "/api/github-app-connect/service/repos"
	githubAppConnectServiceInstallURLPath = "/api/github-app-connect/service/install-url"
	githubAppConnectServiceSyncPath       = "/api/github-app-connect/service/repos/sync"
)

// maxBackstageReposBody caps how much of an upstream response is relayed.
const maxBackstageReposBody = 1 << 20

// proxyGithubAppConnect calls a service route of the github-app-connect plugin
// and relays the result. It refuses (503) when the URL or token is unset, so no
// anonymous call is ever made. An upstream 401/403 means Backstage refused
// mctl-api's own credential, and 404 means the route is not deployed; both,
// like any 5xx, surface as 502 rather than as a caller authentication failure.
func (h *Handlers) proxyGithubAppConnect(w http.ResponseWriter, r *http.Request, method, path string, query url.Values) {
	baseURL := h.opts.BackstageInternalURL
	if baseURL == "" {
		writeError(w, http.StatusServiceUnavailable, "backstage internal URL not configured")
		return
	}
	if h.opts.BackstageGithubAppConnectToken == "" {
		writeError(w, http.StatusServiceUnavailable, "backstage github-app-connect credential not configured")
		return
	}

	upstream := baseURL + path + "?" + query.Encode()
	upReq, err := http.NewRequestWithContext(r.Context(), method, upstream, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	h.authorizeGithubAppConnect(upReq)

	resp, err := backstageReposClient.Do(upReq)
	if err != nil {
		slog.Error("failed to proxy to backstage github-app-connect", "error", err, "route", path, "team", query.Get("team"))
		writeError(w, http.StatusBadGateway, "backstage unavailable")
		return
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		slog.Error("backstage refused the platform credential", "status", resp.StatusCode, "route", path, "team", query.Get("team"))
		writeError(w, http.StatusBadGateway, "backstage refused the platform credential")
		return
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode >= 500:
		slog.Error("backstage github-app-connect upstream error", "status", resp.StatusCode, "route", path, "team", query.Get("team"))
		writeError(w, http.StatusBadGateway, "backstage upstream error")
		return
	}

	// A body that failed mid-read or exceeds the cap is a failed read, not a
	// shorter answer: relaying it would hand the caller a truncated repo list
	// (or broken JSON) under the upstream's 200.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBackstageReposBody+1))
	if err != nil {
		slog.Error("failed to read backstage github-app-connect response", "error", err, "route", path, "team", query.Get("team"))
		writeError(w, http.StatusBadGateway, "failed to read backstage response")
		return
	}
	if len(body) > maxBackstageReposBody {
		slog.Error("backstage github-app-connect response exceeds cap", "limit", maxBackstageReposBody, "route", path, "team", query.Get("team"))
		writeError(w, http.StatusBadGateway, "backstage response too large")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body) //nolint:errcheck
}

// githubLoginOf returns the caller's linked GitHub login, validated against
// GitHub's login grammar. The plugin binds install state and syncs to it.
func githubLoginOf(user *auth.User) (string, bool) {
	login, ok := user.GitHubLogin()
	if !ok || !auth.ValidGitHubLogin(login) {
		return "", false
	}
	return login, true
}

// ListRepos proxies to Backstage's github-app-connect plugin to list repos for a team.
// GET /api/v1/repos?team=<teamName>
func (h *Handlers) ListRepos(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	team := r.URL.Query().Get("team")
	if team == "" {
		http.Error(w, `{"error":"missing required param: team"}`, http.StatusBadRequest)
		return
	}
	if !user.HasTenantAccess(team) {
		http.Error(w, `{"error":"access denied to team"}`, http.StatusForbidden)
		return
	}

	h.proxyGithubAppConnect(w, r, http.MethodGet, githubAppConnectServiceReposPath, url.Values{"team": {team}})
}

// GetRepoInstallURL returns the GitHub App installation URL for granting access to a repo.
// GET /api/v1/repos/install-url?team=<team>&repo=<owner/name>[&service=<service>]
func (h *Handlers) GetRepoInstallURL(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	team := r.URL.Query().Get("team")
	repo := r.URL.Query().Get("repo")
	service := r.URL.Query().Get("service")

	if team == "" {
		http.Error(w, `{"error":"missing required param: team"}`, http.StatusBadRequest)
		return
	}
	if repo == "" {
		http.Error(w, `{"error":"missing required param: repo"}`, http.StatusBadRequest)
		return
	}
	if service == "" {
		service = "_auto"
	}
	if !user.HasTenantAccess(team) {
		http.Error(w, `{"error":"access denied to team"}`, http.StatusForbidden)
		return
	}
	login, ok := githubLoginOf(user)
	if !ok {
		writeError(w, http.StatusConflict, "a linked GitHub identity is required")
		return
	}

	h.proxyGithubAppConnect(w, r, http.MethodGet, githubAppConnectServiceInstallURLPath,
		url.Values{"team": {team}, "service": {service}, "repo": {repo}, "user": {login}})
}

// SyncRepos triggers a repo sync for a team via Backstage's github-app-connect plugin.
// POST /api/v1/repos/sync  body: {"team": "admins"}
// The syncing identity always comes from the authenticated caller
// (auth.UserFromContext); it is never read from the request body.
func (h *Handlers) SyncRepos(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req struct {
		Team string `json:"team"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.Team == "" {
		http.Error(w, `{"error":"missing required field: team"}`, http.StatusBadRequest)
		return
	}
	if !user.HasTenantAccess(req.Team) {
		http.Error(w, `{"error":"access denied to team"}`, http.StatusForbidden)
		return
	}
	if !h.requireTenantRole(w, r, user, req.Team, reposSyncRole, "repos-sync", operations.RiskLow) {
		return
	}
	login, ok := githubLoginOf(user)
	if !ok {
		writeError(w, http.StatusConflict, "a linked GitHub identity is required")
		return
	}

	h.proxyGithubAppConnect(w, r, http.MethodPost, githubAppConnectServiceSyncPath,
		url.Values{"team": {req.Team}, "user": {login}})
}
