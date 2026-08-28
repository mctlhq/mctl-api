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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-api/internal/auth"
)

var backstageDomainsClient = &http.Client{Timeout: 15 * time.Second}

// authorizeBackstage attaches the service credentials the custom-domains plugin
// requires. mctl-portal 951d450 dropped the unauthenticated policy from
// /domains* to close a domain-hijack vector, so every proxied call below comes
// back 401 "Missing credentials" without this header. Per-team authorization is
// still enforced here via user.HasTenantAccess before we ever reach Backstage.
func (h *Handlers) authorizeBackstage(req *http.Request) {
	if h.opts.BackstageToken != "" {
		req.Header.Set("Authorization", "Bearer "+h.opts.BackstageToken)
	}
}

// ListDomains proxies to Backstage custom-domains plugin.
// GET /api/v1/domains?team=X&service=Y
func (h *Handlers) ListDomains(w http.ResponseWriter, r *http.Request) {
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

	upstream := fmt.Sprintf("%s/api/custom-domains/domains?team=%s", baseURL, url.QueryEscape(team))
	service := r.URL.Query().Get("service")
	if service != "" {
		upstream += "&service=" + url.QueryEscape(service)
	}

	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, upstream, nil)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	h.authorizeBackstage(upReq)

	resp, err := backstageDomainsClient.Do(upReq)
	if err != nil {
		slog.Error("failed to proxy domains list to backstage", "error", err)
		http.Error(w, `{"error":"backstage unavailable"}`, http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

// AddDomain registers a custom domain via Backstage.
// POST /api/v1/domains  body: {"team","service","domain"}
func (h *Handlers) AddDomain(w http.ResponseWriter, r *http.Request) {
	baseURL := h.opts.BackstageInternalURL
	if baseURL == "" {
		http.Error(w, `{"error":"backstage internal URL not configured"}`, http.StatusServiceUnavailable)
		return
	}

	user := auth.UserFromContext(r.Context())

	var req struct {
		Team    string `json:"team"`
		Service string `json:"service"`
		Domain  string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.Team == "" || req.Service == "" || req.Domain == "" {
		http.Error(w, `{"error":"missing required fields: team, service, domain"}`, http.StatusBadRequest)
		return
	}
	if user != nil && !user.HasTenantAccess(req.Team) {
		http.Error(w, `{"error":"access denied to team"}`, http.StatusForbidden)
		return
	}

	createdBy := "unknown"
	if user != nil {
		createdBy = user.ID
	}

	payload, _ := json.Marshal(map[string]string{
		"team":       req.Team,
		"service":    req.Service,
		"domain":     req.Domain,
		"created_by": createdBy,
	})

	upstream := fmt.Sprintf("%s/api/custom-domains/domains", baseURL)
	upReq, err := http.NewRequestWithContext(r.Context(), "POST", upstream, bytes.NewReader(payload))
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	upReq.Header.Set("Content-Type", "application/json")
	h.authorizeBackstage(upReq)

	resp, err := backstageDomainsClient.Do(upReq)
	if err != nil {
		slog.Error("failed to register domain in backstage", "error", err)
		http.Error(w, `{"error":"backstage unavailable"}`, http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

// backstageDomainIDs fetches the ids of every custom domain registered for a
// team, so callers can check `id` membership without trusting the URL alone.
func (h *Handlers) backstageDomainIDs(ctx context.Context, baseURL, team string) (map[string]struct{}, error) {
	upstream := fmt.Sprintf("%s/api/custom-domains/domains?team=%s", baseURL, url.QueryEscape(team))

	upReq, err := http.NewRequestWithContext(ctx, http.MethodGet, upstream, nil)
	if err != nil {
		return nil, fmt.Errorf("build backstage list request: %w", err)
	}
	h.authorizeBackstage(upReq)

	resp, err := backstageDomainsClient.Do(upReq)
	if err != nil {
		return nil, fmt.Errorf("backstage unavailable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("backstage returned status %d listing domains for team %q", resp.StatusCode, team)
	}

	var decoded struct {
		Domains []struct {
			ID string `json:"id"`
		} `json:"domains"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, fmt.Errorf("decode backstage domains response: %w", err)
	}

	ids := make(map[string]struct{}, len(decoded.Domains))
	for _, d := range decoded.Domains {
		ids[d.ID] = struct{}{}
	}
	return ids, nil
}

// authorizeDomainMutation enforces RBAC for VerifyDomain/DeleteDomain, the
// two single-domain mutating endpoints that identify their target only by
// `id` in the URL. Unlike ListDomains/AddDomain, a nil user fails closed
// here (401) instead of skipping the check.
//
// If the caller supplies ?team=, HasTenantAccess is checked directly against
// it and a 404 is returned when `id` isn't in that team's domain list (so we
// never leak which team owns an id the caller can't access). If team is
// omitted, ownership is resolved by checking `id` against each tenant the
// caller belongs to; a 404 is returned if none of them own it. Admins skip
// straight through.
func (h *Handlers) authorizeDomainMutation(w http.ResponseWriter, r *http.Request, baseURL, id string) bool {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
		return false
	}
	if user.IsAdmin() {
		return true
	}

	ctx := r.Context()

	if team := r.URL.Query().Get("team"); team != "" {
		if !user.HasTenantAccess(team) {
			http.Error(w, `{"error":"access denied to team"}`, http.StatusForbidden)
			return false
		}
		ids, err := h.backstageDomainIDs(ctx, baseURL, team)
		if err != nil {
			slog.Error("failed to list domains from backstage", "error", err, "team", team)
			http.Error(w, `{"error":"backstage unavailable"}`, http.StatusBadGateway)
			return false
		}
		if _, ok := ids[id]; !ok {
			http.Error(w, `{"error":"domain not found"}`, http.StatusNotFound)
			return false
		}
		return true
	}

	for _, group := range user.Groups {
		if group == "admins" {
			continue
		}
		ids, err := h.backstageDomainIDs(ctx, baseURL, group)
		if err != nil {
			slog.Error("failed to list domains from backstage", "error", err, "team", group)
			http.Error(w, `{"error":"backstage unavailable"}`, http.StatusBadGateway)
			return false
		}
		if _, ok := ids[id]; ok {
			return true
		}
	}

	http.Error(w, `{"error":"domain not found"}`, http.StatusNotFound)
	return false
}

// VerifyDomain triggers DNS verification for a domain.
// POST /api/v1/domains/:id/verify?team=X (team optional, resolved via the
// caller's groups when omitted)
func (h *Handlers) VerifyDomain(w http.ResponseWriter, r *http.Request) {
	baseURL := h.opts.BackstageInternalURL
	if baseURL == "" {
		http.Error(w, `{"error":"backstage internal URL not configured"}`, http.StatusServiceUnavailable)
		return
	}

	id := chi.URLParam(r, "id")
	if !h.authorizeDomainMutation(w, r, baseURL, id) {
		return
	}

	upstream := fmt.Sprintf("%s/api/custom-domains/domains/%s/verify", baseURL, url.PathEscape(id))

	upReq, err := http.NewRequestWithContext(r.Context(), "POST", upstream, nil)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	h.authorizeBackstage(upReq)

	resp, err := backstageDomainsClient.Do(upReq)
	if err != nil {
		slog.Error("failed to verify domain", "error", err)
		http.Error(w, `{"error":"backstage unavailable"}`, http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

// DeleteDomain removes a custom domain.
// DELETE /api/v1/domains/:id?team=X (team optional, resolved via the
// caller's groups when omitted)
func (h *Handlers) DeleteDomain(w http.ResponseWriter, r *http.Request) {
	baseURL := h.opts.BackstageInternalURL
	if baseURL == "" {
		http.Error(w, `{"error":"backstage internal URL not configured"}`, http.StatusServiceUnavailable)
		return
	}

	id := chi.URLParam(r, "id")
	if !h.authorizeDomainMutation(w, r, baseURL, id) {
		return
	}

	upstream := fmt.Sprintf("%s/api/custom-domains/domains/%s", baseURL, url.PathEscape(id))

	upReq, err := http.NewRequestWithContext(r.Context(), "DELETE", upstream, nil)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	h.authorizeBackstage(upReq)

	resp, err := backstageDomainsClient.Do(upReq)
	if err != nil {
		slog.Error("failed to delete domain", "error", err)
		http.Error(w, `{"error":"backstage unavailable"}`, http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}
