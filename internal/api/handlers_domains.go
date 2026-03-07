package api

import (
	"bytes"
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

	resp, err := backstageDomainsClient.Get(upstream)
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

// VerifyDomain triggers DNS verification for a domain.
// POST /api/v1/domains/:id/verify
func (h *Handlers) VerifyDomain(w http.ResponseWriter, r *http.Request) {
	baseURL := h.opts.BackstageInternalURL
	if baseURL == "" {
		http.Error(w, `{"error":"backstage internal URL not configured"}`, http.StatusServiceUnavailable)
		return
	}

	id := chi.URLParam(r, "id")
	upstream := fmt.Sprintf("%s/api/custom-domains/domains/%s/verify", baseURL, url.PathEscape(id))

	upReq, err := http.NewRequestWithContext(r.Context(), "POST", upstream, nil)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

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
// DELETE /api/v1/domains/:id
func (h *Handlers) DeleteDomain(w http.ResponseWriter, r *http.Request) {
	baseURL := h.opts.BackstageInternalURL
	if baseURL == "" {
		http.Error(w, `{"error":"backstage internal URL not configured"}`, http.StatusServiceUnavailable)
		return
	}

	id := chi.URLParam(r, "id")
	upstream := fmt.Sprintf("%s/api/custom-domains/domains/%s", baseURL, url.PathEscape(id))

	upReq, err := http.NewRequestWithContext(r.Context(), "DELETE", upstream, nil)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

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
