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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/domains"
)

// mctl-api is the system of record for custom domains: it persists
// registrations in its own PostgreSQL-backed store (internal/domains) and
// proves ownership with a TXT challenge, resolved through h.opts.DomainVerifier.
// This replaced a proxy to the Backstage custom-domains plugin, whose write
// route requires a Backstage user principal that none of mctl-api's callers
// (GitHub PAT, Dex JWT, the static service token, or the MCP tool with no
// browser session at all) can ever produce.

// domainResponse is a Domain plus the additive fields a caller needs to
// finish registration: the TXT challenge to create, and the CNAME target the
// fast-path check accepts.
type domainResponse struct {
	*domains.Domain
	ChallengeRecord string `json:"challenge_record,omitempty"`
	ChallengeValue  string `json:"challenge_value,omitempty"`
	CNAMETarget     string `json:"cname_target,omitempty"`
}

// domainResponseFor builds the response for a domain row, adding the TXT
// challenge and CNAME target a caller needs to finish registration.
// ChallengeRecord/ChallengeValue are only populated for a row still in
// StatusPending or StatusFailed: a row that has already reached
// StatusVerified or StatusActive has already proved ownership, so echoing
// its challenge back is misleading — it invites a caller to (re-)publish a
// TXT record that verification no longer needs, or to believe a stale
// pending state that has since moved on. CNAMETarget stays populated
// regardless of status: it is not a proof-of-ownership artifact like the
// challenge, just the fast-path target a caller may still want to know.
func (h *Handlers) domainResponseFor(d *domains.Domain) domainResponse {
	resp := domainResponse{
		Domain:      d,
		CNAMETarget: h.cnameTarget(d.Team, d.Service),
	}
	if d.Status == domains.StatusPending || d.Status == domains.StatusFailed {
		resp.ChallengeRecord = domains.ChallengeRecord(d.Domain)
		resp.ChallengeValue = domains.ChallengeValue(d.VerificationToken)
	}
	return resp
}

func (h *Handlers) cnameTarget(team, service string) string {
	return fmt.Sprintf("%s-%s.%s", team, service, h.platformDomain())
}

func (h *Handlers) platformDomain() string {
	// Normalized the same way a request's domain is: isPlatformDomain only
	// lowercases the host it's comparing against, so an uppercase or
	// trailing-dot PLATFORM_DOMAIN would otherwise silently disable the
	// guard it exists to enforce.
	if h.opts.PlatformDomain != "" {
		return normalizeHostname(h.opts.PlatformDomain)
	}
	return "mctl.ai"
}

// isPlatformDomain reports whether host is the platform domain itself or any
// subdomain of it. Platform-domain hostnames are GitOps-only, declared via
// ingress.hosts — see the rejection message in platformDomainRejection.
func (h *Handlers) isPlatformDomain(host string) bool {
	pd := h.platformDomain()
	host = strings.ToLower(host)
	return host == pd || strings.HasSuffix(host, "."+pd)
}

func platformDomainRejection(team, service, domain, platformDomain string) string {
	return fmt.Sprintf(
		"domain %q is inside the platform domain (%s) and cannot be self-registered; "+
			"add it to ingress.hosts and the matching ingress.tls[].hosts entry in "+
			"platform-gitops/services/%s/%s/values.yaml instead",
		domain, platformDomain, team, service,
	)
}

// normalizeHostname lowercases, trims surrounding whitespace, and strips a
// trailing dot (the root-label separator in a fully-qualified DNS name).
// Without stripping it, "api.mctl.ai." is the same DNS name as
// "api.mctl.ai" but matches neither isPlatformDomain comparison, and
// custom_domains_domain's uniqueness index would treat the two spellings as
// different rows a different team could separately claim.
func normalizeHostname(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

// normalizeIdentifier lowercases and trims a team or service name before it
// reaches the tenant-access check, the store, or a CNAME target
// construction. Team/service names are not DNS names (no trailing-dot
// root-label concern), but they do end up compared against
// gitops-normalized values (tenant/service names are lowercase by
// convention) and interpolated into cnameTarget, so an unnormalized
// "Labs"/"labs" pair must not be allowed to register or verify as if they
// were different identities.
func normalizeIdentifier(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// hostnameLabelPattern matches one DNS label: 1-63 lowercase alphanumerics
// or hyphens, no leading or trailing hyphen.
var hostnameLabelPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// validateHostname rejects a domain value before it can reach the
// add-custom-domain workflow and, from there, ingress.hosts /
// ingress.tls[].hosts in a GitOps values.yaml. Backstage previously owned
// this value and mctl-api merely forwarded it; now mctl-api is the system
// of record, so the same syntax checks a DNS name must satisfy belong here.
func validateHostname(domain string) error {
	if len(domain) > 253 {
		return fmt.Errorf("domain %q exceeds the maximum hostname length of 253 characters", domain)
	}
	if !strings.Contains(domain, ".") {
		return fmt.Errorf("domain %q must contain at least one dot", domain)
	}
	if strings.Contains(domain, "*") {
		return fmt.Errorf("domain %q must not contain a wildcard", domain)
	}
	for _, label := range strings.Split(domain, ".") {
		if !hostnameLabelPattern.MatchString(label) {
			return fmt.Errorf("domain %q contains an invalid label %q: labels must be 1-63 lowercase alphanumerics or hyphens, with no leading or trailing hyphen", domain, label)
		}
	}
	return nil
}

// newVerificationToken mints a 32-byte random hex token used in the TXT
// challenge value.
func newVerificationToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate verification token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// ListDomains returns the caller's registered domains from mctl-api's own store.
// GET /api/v1/domains?team=X&service=Y
func (h *Handlers) ListDomains(w http.ResponseWriter, r *http.Request) {
	if h.opts.DomainStore == nil {
		writeError(w, http.StatusServiceUnavailable, "domains registry not configured")
		return
	}

	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	team := r.URL.Query().Get("team")
	if team == "" {
		writeError(w, http.StatusBadRequest, "missing required param: team")
		return
	}
	if !user.HasTenantAccess(team) {
		writeError(w, http.StatusForbidden, "access denied to team")
		return
	}

	service := r.URL.Query().Get("service")
	list, err := h.opts.DomainStore.ListByTeam(r.Context(), team, service)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list domains")
		return
	}

	// Mapped through domainResponseFor, not written as raw []domains.Domain:
	// the TXT challenge is the whole point of a pending row, and list is the
	// natural "what do I still have to create" endpoint for a caller who
	// lost the response from AddDomain. make(..., 0, ...) keeps the
	// non-null-when-empty shape ListByTeam already guarantees.
	out := make([]domainResponse, 0, len(list))
	for i := range list {
		out = append(out, h.domainResponseFor(&list[i]))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"domains": out})
}

// AddDomain registers a custom domain in mctl-api's own store.
// POST /api/v1/domains  body: {"team","service","domain"}
func (h *Handlers) AddDomain(w http.ResponseWriter, r *http.Request) {
	if h.opts.DomainStore == nil {
		writeError(w, http.StatusServiceUnavailable, "domains registry not configured")
		return
	}

	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req struct {
		Team    string `json:"team"`
		Service string `json:"service"`
		Domain  string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Team = normalizeIdentifier(req.Team)
	req.Service = normalizeIdentifier(req.Service)
	req.Domain = normalizeHostname(req.Domain)
	if req.Team == "" || req.Service == "" || req.Domain == "" {
		writeError(w, http.StatusBadRequest, "missing required fields: team, service, domain")
		return
	}
	if !user.HasTenantAccess(req.Team) {
		writeError(w, http.StatusForbidden, "access denied to team")
		return
	}
	if err := validateHostname(req.Domain); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if h.isPlatformDomain(req.Domain) {
		writeError(w, http.StatusBadRequest, platformDomainRejection(req.Team, req.Service, req.Domain, h.platformDomain()))
		return
	}

	token, err := newVerificationToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	d := &domains.Domain{
		ID:                uuid.New().String(),
		Team:              req.Team,
		Service:           req.Service,
		Domain:            req.Domain,
		Status:            domains.StatusPending,
		VerificationToken: token,
		CreatedBy:         user.ID,
	}

	stored, err := h.opts.DomainStore.Create(r.Context(), d)
	if err != nil {
		if errors.Is(err, domains.ErrDomainConflict) {
			writeError(w, http.StatusConflict, "domain already registered")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to register domain")
		return
	}

	status := http.StatusCreated
	if stored.ID != d.ID {
		// Idempotent re-registration of the same (team, service, domain): the
		// existing row was returned rather than a new one.
		status = http.StatusOK
	}
	writeJSON(w, status, h.domainResponseFor(stored))
}

// resolveDomainForMutation loads the domain identified by id and checks the
// caller's access to it. A nil user fails closed (401). Admins (including
// the service principal, which is always in the "admins" group) bypass the
// ownership check. Otherwise the domain's actual team must be one the
// caller has access to; an id whose team the caller cannot see 404s rather
// than 403s, so it never discloses which team owns it. If the caller passed
// an explicit ?team=, that team must itself be one the caller has access to
// (403 otherwise) before a mismatch against the domain's real team 404s.
func (h *Handlers) resolveDomainForMutation(w http.ResponseWriter, r *http.Request, id string) (*domains.Domain, bool) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}

	d, err := h.opts.DomainStore.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, domains.ErrNotFound) {
			writeError(w, http.StatusNotFound, "domain not found")
			return nil, false
		}
		writeError(w, http.StatusInternalServerError, "failed to look up domain")
		return nil, false
	}

	if user.IsAdmin() {
		return d, true
	}

	if team := r.URL.Query().Get("team"); team != "" {
		if !user.HasTenantAccess(team) {
			writeError(w, http.StatusForbidden, "access denied to team")
			return nil, false
		}
		if d.Team != team {
			writeError(w, http.StatusNotFound, "domain not found")
			return nil, false
		}
		return d, true
	}

	if !user.HasTenantAccess(d.Team) {
		writeError(w, http.StatusNotFound, "domain not found")
		return nil, false
	}
	return d, true
}

// VerifyDomain triggers DNS verification for a domain by id.
// POST /api/v1/domains/:id/verify?team=X (team optional)
func (h *Handlers) VerifyDomain(w http.ResponseWriter, r *http.Request) {
	if h.opts.DomainStore == nil {
		writeError(w, http.StatusServiceUnavailable, "domains registry not configured")
		return
	}

	id := chi.URLParam(r, "id")
	d, ok := h.resolveDomainForMutation(w, r, id)
	if !ok {
		return
	}

	h.verifyAndRespond(w, r, d)
}

// VerifyDomainByName resolves the domain by (team, service, domain) instead
// of id, for callers that know the hostname but not the row id — chiefly
// the add-custom-domain Argo workflow.
// POST /api/v1/domains/verify  body: {"team","service","domain"}
func (h *Handlers) VerifyDomainByName(w http.ResponseWriter, r *http.Request) {
	if h.opts.DomainStore == nil {
		writeError(w, http.StatusServiceUnavailable, "domains registry not configured")
		return
	}

	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req struct {
		Team    string `json:"team"`
		Service string `json:"service"`
		Domain  string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Team = normalizeIdentifier(req.Team)
	req.Service = normalizeIdentifier(req.Service)
	req.Domain = normalizeHostname(req.Domain)
	if req.Team == "" || req.Service == "" || req.Domain == "" {
		writeError(w, http.StatusBadRequest, "missing required fields: team, service, domain")
		return
	}
	if !user.IsAdmin() && !user.HasTenantAccess(req.Team) {
		writeError(w, http.StatusForbidden, "access denied to team")
		return
	}

	d, err := h.opts.DomainStore.GetByDomain(r.Context(), req.Domain)
	if err != nil {
		if errors.Is(err, domains.ErrNotFound) {
			writeError(w, http.StatusNotFound, "domain not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to look up domain")
		return
	}
	// Compared case-insensitively so a legacy row stored with mixed-case
	// team/service (from before AddDomain normalized on write) stays
	// reachable by a caller sending normalized values. Still 404, never
	// 403: an id/name mismatch must not disclose whether a differently-cased
	// row exists.
	if !strings.EqualFold(d.Team, req.Team) || !strings.EqualFold(d.Service, req.Service) {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}

	h.verifyAndRespond(w, r, d)
}

// verifyAndRespond runs the TXT/CNAME verification for d and writes the
// result. A negative verdict is not an error status — it is 200 with
// verified:false plus the exact record the tenant still has to create, so
// the workflow and the MCP tool can report it.
func (h *Handlers) verifyAndRespond(w http.ResponseWriter, r *http.Request, d *domains.Domain) {
	if h.opts.DomainVerifier == nil {
		writeError(w, http.StatusServiceUnavailable, "domain verifier not configured")
		return
	}

	result, err := h.opts.DomainVerifier.Verify(r.Context(), *d, h.cnameTarget(d.Team, d.Service))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "verification failed")
		return
	}

	if result.Verified {
		if err := h.opts.DomainStore.MarkVerified(r.Context(), d.ID); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to record verification")
			return
		}
	}

	writeJSON(w, http.StatusOK, result)
}

// DeleteDomain removes a custom domain.
// DELETE /api/v1/domains/:id?team=X (team optional)
//
// Teardown contract: before the row is deleted, this triggers the
// remove-custom-domain workflow so ingress hosts and the TLS certificate
// entry actually get cleaned up — deleting only the registry row would
// leave a dangling ingress rule with no domains row left to reconcile it
// against. If the workflow submission fails, the row is kept (not deleted)
// so the caller can retry rather than lose the only record of what still
// needs cleanup. If no Executor/Registry is configured (e.g. local/test),
// cleanup is skipped and the row is deleted anyway — this mirrors every
// other domains handler's already-optional-dependency behavior rather than
// making delete newly unavailable in those environments.
func (h *Handlers) DeleteDomain(w http.ResponseWriter, r *http.Request) {
	if h.opts.DomainStore == nil {
		writeError(w, http.StatusServiceUnavailable, "domains registry not configured")
		return
	}

	id := chi.URLParam(r, "id")
	d, ok := h.resolveDomainForMutation(w, r, id)
	if !ok {
		return
	}

	workflowName, skipped, err := h.triggerRemoveCustomDomain(r.Context(), r, d)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to submit ingress cleanup: "+err.Error())
		return
	}

	if err := h.opts.DomainStore.Delete(r.Context(), d.ID); err != nil {
		if errors.Is(err, domains.ErrNotFound) {
			writeError(w, http.StatusNotFound, "domain not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to delete domain")
		return
	}

	if skipped {
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "ingress_cleanup": "skipped"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "ingress_cleanup": "workflow-submitted", "workflow_name": workflowName})
}

// triggerRemoveCustomDomain submits the remove-custom-domain workflow for d
// so ingress/TLS teardown actually happens once the registry row is gone.
// Returns skipped=true (not an error) when the workflow executor or
// operations registry is not configured — that is an expected local/test
// state, not a caller-facing failure. An error is only returned when
// submission itself fails, so the caller (DeleteDomain) can keep the row
// rather than delete a domain whose ingress was never actually cleaned up.
func (h *Handlers) triggerRemoveCustomDomain(ctx context.Context, r *http.Request, d *domains.Domain) (workflowName string, skipped bool, err error) {
	if h.opts.Executor == nil || h.opts.Registry == nil {
		slog.Warn("skipping remove-custom-domain workflow: executor or operations registry not configured",
			"team", d.Team, "service", d.Service, "domain", d.Domain)
		return "", true, nil
	}

	op, ok := h.opts.Registry.Get("remove-custom-domain")
	if !ok {
		slog.Warn("skipping remove-custom-domain workflow: operation not found in registry",
			"team", d.Team, "service", d.Service, "domain", d.Domain)
		return "", true, nil
	}

	user := auth.UserFromContext(ctx)
	userID := ""
	if user != nil {
		userID = user.ID
	}

	params := map[string]string{
		"team_name":    d.Team,
		"service_name": d.Service,
		"domain":       d.Domain,
	}

	result, submitErr := h.opts.Executor.Submit(ctx, op, params, userID, d.Team)
	if submitErr != nil {
		h.logAudit(r, audit.Entry{
			UserID:     userID,
			Operation:  "remove-custom-domain",
			Parameters: params,
			Status:     "failed",
			RiskLevel:  string(op.RiskLevel),
			Message:    "submit failed: " + submitErr.Error(),
		})
		return "", false, fmt.Errorf("submit remove-custom-domain workflow: %w", submitErr)
	}

	h.logAudit(r, audit.Entry{
		UserID:       userID,
		Operation:    "remove-custom-domain",
		Parameters:   params,
		WorkflowName: result.WorkflowName,
		Status:       "submitted",
		RiskLevel:    string(op.RiskLevel),
	})

	return result.WorkflowName, false, nil
}

// UpdateDomainStatus accepts the add-custom-domain workflow's status
// callback once it has finished updating ingress and TLS. Restricted to the
// service principal so a human token — even an admin's — cannot move a row
// to active/failed directly.
// PATCH /api/v1/domains/{id}  body: {"status","error"}
func (h *Handlers) UpdateDomainStatus(w http.ResponseWriter, r *http.Request) {
	if h.opts.DomainStore == nil {
		writeError(w, http.StatusServiceUnavailable, "domains registry not configured")
		return
	}

	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !user.IsService() {
		writeError(w, http.StatusForbidden, "only the platform service principal may update domain status")
		return
	}

	var req struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	switch req.Status {
	case domains.StatusVerified, domains.StatusActive, domains.StatusFailed:
	default:
		writeError(w, http.StatusBadRequest, "status must be one of: verified, active, failed")
		return
	}

	id := chi.URLParam(r, "id")
	if err := h.opts.DomainStore.SetStatus(r.Context(), id, req.Status, req.Error); err != nil {
		if errors.Is(err, domains.ErrNotFound) {
			writeError(w, http.StatusNotFound, "domain not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to update domain status")
		return
	}

	d, err := h.opts.DomainStore.Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read updated domain")
		return
	}
	writeJSON(w, http.StatusOK, d)
}
