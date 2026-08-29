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
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// backstageReposProxy is a shared HTTP client for proxying repo requests to Backstage.
var backstageReposClient = &http.Client{Timeout: 15 * time.Second}

// ListRepos proxies to Backstage's github-app-connect plugin to list repos for a team.
// GET /api/v1/repos?team=<teamName>
func (h *Handlers) ListRepos(w http.ResponseWriter, r *http.Request) {
	baseURL := h.opts.BackstageInternalURL
	if baseURL == "" {
		http.Error(w, `{"error":"backstage internal URL not configured"}`, http.StatusServiceUnavailable)
		return
	}

	user := auth.UserFromContext(r.Context())
	team := r.URL.Query().Get("team")
	if team == "" {
		http.Error(w, `{"error":"missing required param: team"}`, http.StatusBadRequest)
		return
	}
	if user != nil && !user.HasTenantAccess(team) {
		http.Error(w, `{"error":"access denied to team"}`, http.StatusForbidden)
		return
	}

	upstream := fmt.Sprintf("%s/api/github-app-connect/repos?team=%s", baseURL, url.QueryEscape(team))
	resp, err := backstageReposClient.Get(upstream)
	if err != nil {
		slog.Error("failed to proxy repos list to backstage", "error", err, "team", team)
		http.Error(w, `{"error":"backstage unavailable"}`, http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body) //nolint:errcheck
}

// GetRepoInstallURL returns the GitHub App installation URL for granting access to a repo.
// GET /api/v1/repos/install-url?team=<team>&repo=<owner/name>[&service=<service>]
func (h *Handlers) GetRepoInstallURL(w http.ResponseWriter, r *http.Request) {
	baseURL := h.opts.BackstageInternalURL
	if baseURL == "" {
		http.Error(w, `{"error":"backstage internal URL not configured"}`, http.StatusServiceUnavailable)
		return
	}

	user := auth.UserFromContext(r.Context())
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
	if user != nil && !user.HasTenantAccess(team) {
		http.Error(w, `{"error":"access denied to team"}`, http.StatusForbidden)
		return
	}

	upstream := fmt.Sprintf("%s/api/github-app-connect/install-url?team=%s&service=%s&repo=%s",
		baseURL, url.QueryEscape(team), url.QueryEscape(service), url.QueryEscape(repo))
	resp, err := backstageReposClient.Get(upstream)
	if err != nil {
		slog.Error("failed to proxy install-url to backstage", "error", err, "team", team, "repo", repo)
		http.Error(w, `{"error":"backstage unavailable"}`, http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body) //nolint:errcheck
}

// SyncRepos triggers a repo sync for a team via Backstage's github-app-connect plugin.
// POST /api/v1/repos/sync  body: {"team": "admins"}
// The syncing identity always comes from the authenticated caller
// (auth.UserFromContext); it is never read from the request body.
func (h *Handlers) SyncRepos(w http.ResponseWriter, r *http.Request) {
	baseURL := h.opts.BackstageInternalURL
	if baseURL == "" {
		http.Error(w, `{"error":"backstage internal URL not configured"}`, http.StatusServiceUnavailable)
		return
	}

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

	upstream := fmt.Sprintf("%s/api/github-app-connect/repos/sync?team=%s&user=%s",
		baseURL, url.QueryEscape(req.Team), url.QueryEscape(user.ID))

	upReq, err := http.NewRequestWithContext(r.Context(), "POST", upstream, nil)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	resp, err := backstageReposClient.Do(upReq)
	if err != nil {
		slog.Error("failed to proxy repos sync to backstage", "error", err, "team", req.Team)
		http.Error(w, `{"error":"backstage unavailable"}`, http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body) //nolint:errcheck
}
