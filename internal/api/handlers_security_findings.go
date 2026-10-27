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

// SecurityFinding v1 (mctlhq/.github#209, mctl-api#774). See
// internal/securityfindings for the store and docs/security-findings.md for
// the contract.
//
// Authorization, in one place:
//
//   - Ingest needs security:ingest: a configured security-provider principal
//     (confined to this one route by securityProviderGate; its ref, tenants
//     and strength ceiling come from server configuration, never from the
//     payload) or an admin.
//   - Reads are tenant-scoped: a row in a tenant the caller cannot access
//     answers 404, exactly like a row that does not exist.
//   - Triage, start-remediation, fix and verification need security:remediate
//     (the direct service principal, or an agent run minted with it) or a
//     human with at least the developer role on the tenant.
//   - Dismissal is human-only: a human platform admin, or a human holding at
//     least the owner role on the tenant. A service, agent, surface, relayed
//     or provider principal is refused with 403.

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/securityfindings"
)

// securityIngestRoute is the one route a security-provider principal may call.
const securityIngestRoute = "/api/v1/security/observations"

// securityIngestPerMinute is ingest's own per-principal budget, so a
// provider's retry burst is not throttled into a gap.
const securityIngestPerMinute = 120

const (
	maxSecurityIngestBodyBytes = 1 << 20
	maxSecurityBodyBytes       = 64 << 10
	maxIdempotencyKeyLen       = 255
)

// Typed error codes a client can branch on.
const (
	codeSecurityStoreUnavailable = "security_findings_store_unavailable"
	codeSecurityNotFound         = "not_found"
	codeSecurityInvalid          = "invalid_request"
	codeSecurityInvalidTransit   = "invalid_transition"
	codeSecurityAttemptActive    = "remediation_attempt_active"
	codeSecurityNotBound         = "verification_not_bound"
	codeSecuritySubjectTooWeak   = "subject_too_weak"
	codeSecurityAliasConflict    = "finding_alias_conflict"
	codeSecurityIdempotency      = "idempotency_key_reused"
	codeSecurityVersionConflict  = "version_conflict"
	codeSecurityWorkItemNotFound = "work_item_not_found"
	codeSecurityWorkItemsDown    = "work_items_unavailable"
	codeSecurityForbidden        = "forbidden"
	codeSecurityProviderGate     = "security_provider_route_not_allowed"
)

// securityProviderGate confines a security-provider principal to the
// observation ingest route. Everything else answers 403 before any handler
// runs, mirroring evidenceWriterGate.
func securityProviderGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user := auth.UserFromContext(r.Context()); user.SecurityProviderRef() != "" &&
			(r.Method != http.MethodPost || r.URL.Path != securityIngestRoute) {
			writeErrorCode(w, http.StatusForbidden, codeSecurityProviderGate,
				"a security provider may only call POST "+securityIngestRoute, nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// securityUser answers 503 for a missing store and 401 for no caller.
func (h *Handlers) securityUser(w http.ResponseWriter, r *http.Request) (*auth.User, bool) {
	if h.opts.SecurityFindings == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, codeSecurityStoreUnavailable, "security findings store not configured", nil)
		return nil, false
	}
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}
	return user, true
}

func writeSecurityError(w http.ResponseWriter, err error) {
	type mapping struct {
		err    error
		status int
		code   string
	}
	for _, m := range []mapping{
		{securityfindings.ErrNotFound, http.StatusNotFound, codeSecurityNotFound},
		{securityfindings.ErrWorkItemNotFound, http.StatusNotFound, codeSecurityWorkItemNotFound},
		{securityfindings.ErrInvalid, http.StatusBadRequest, codeSecurityInvalid},
		{securityfindings.ErrInvalidTransition, http.StatusConflict, codeSecurityInvalidTransit},
		{securityfindings.ErrAttemptActive, http.StatusConflict, codeSecurityAttemptActive},
		{securityfindings.ErrAliasConflict, http.StatusConflict, codeSecurityAliasConflict},
		{securityfindings.ErrIdempotencyKeyReuse, http.StatusConflict, codeSecurityIdempotency},
		{securityfindings.ErrVersionConflict, http.StatusConflict, codeSecurityVersionConflict},
		{securityfindings.ErrNotBound, http.StatusUnprocessableEntity, codeSecurityNotBound},
		{securityfindings.ErrSubjectTooWeak, http.StatusUnprocessableEntity, codeSecuritySubjectTooWeak},
		{securityfindings.ErrWorkItemsUnavail, http.StatusServiceUnavailable, codeSecurityWorkItemsDown},
	} {
		if errors.Is(err, m.err) {
			writeErrorCode(w, m.status, m.code, err.Error(), nil)
			return
		}
	}
	slog.Error("security findings request failed", "error", err)
	writeErrorCode(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
}

// securityVisibility is what the caller may read: admins and read-all agents
// everything, anyone else the tenants they belong to.
func securityVisibility(u *auth.User) securityfindings.Visibility {
	if u.IsAdmin() {
		return securityfindings.Visibility{All: true}
	}
	if s, ok := u.AgentScope(); ok && s.ReadAllTenants {
		return securityfindings.Visibility{All: true}
	}
	return securityfindings.Visibility{Tenants: append([]string{}, u.Groups...)}
}

// isHumanCaller is a person acting directly: not a service, agent, surface,
// relay, delegation, CI job or any of the single-purpose writer principals.
func isHumanCaller(u *auth.User) bool {
	if u == nil || u.IsService() || u.IsAgent() || u.IsCI() || u.IsUsageWriter() || u.IsEvidenceWriter() ||
		u.IsRegistryPublisher() || u.IsSupportIncidentProducer() || u.SecurityProviderRef() != "" {
		return false
	}
	if _, relayed := u.RelaySurface(); relayed {
		return false
	}
	if _, surface := u.Surface(); surface {
		return false
	}
	if _, delegated := u.DelegatingAgent(); delegated {
		return false
	}
	return true
}

func securityActor(u *auth.User) securityfindings.Actor {
	a := securityfindings.Actor{Principal: principalOf(u), PrincipalID: u.PrincipalID(), ViaID: u.ViaPrincipalID(), Source: "api"}
	if name, ok := u.AgentName(); ok {
		a.Source = "agent:" + name
	}
	return a
}

// securityRecorderCeiling is the strongest verification the authenticated
// recorder may assert. It is decided by who the caller is, never by the
// request.
func securityRecorderCeiling(u *auth.User) securityfindings.Strength {
	if u.HasPermission(auth.PermissionSecurityRemediate) {
		return securityfindings.StrengthDeterministicRegressionTest
	}
	return securityfindings.StrengthManual
}

func idempotencyKey(r *http.Request) (string, bool) {
	k := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	return k, len(k) <= maxIdempotencyKeyLen
}

func decodeSecurityBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxSecurityBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeErrorCode(w, http.StatusBadRequest, codeSecurityInvalid, "invalid JSON body: "+err.Error(), nil)
		return false
	}
	return true
}

// securityTenantOf resolves the tenant of an occurrence or an attempt for the
// caller's authorization, answering 404 for a row the caller cannot see.
func securityTenantOf(w http.ResponseWriter, user *auth.User, tenant string, err error) (string, bool) {
	if err != nil {
		writeSecurityError(w, err)
		return "", false
	}
	if !user.HasTenantAccess(tenant) && !user.HasPermission(auth.PermissionSecurityRemediate) {
		writeSecurityError(w, securityfindings.ErrNotFound)
		return "", false
	}
	return tenant, true
}

// authorizeRemediation admits security:remediate holders and humans with at
// least the developer role on the tenant.
func (h *Handlers) authorizeRemediation(w http.ResponseWriter, r *http.Request, user *auth.User, tenant, operation string) bool {
	if user.HasPermission(auth.PermissionSecurityRemediate) {
		return true
	}
	if !isHumanCaller(user) {
		writeErrorCode(w, http.StatusForbidden, codeSecurityForbidden, operation+" requires "+auth.PermissionSecurityRemediate+" or a human with the developer role", nil)
		return false
	}
	return h.requireTenantRole(w, r, user, tenant, operations.RoleDeveloper, "security."+operation, operations.RiskLow)
}

// agentOwnsAttempt confines an agent run to attempts started for its own work
// item; other principals pass.
func (h *Handlers) agentOwnsAttempt(w http.ResponseWriter, r *http.Request, user *auth.User, attempt string) bool {
	if !user.IsAgent() {
		return true
	}
	wi, err := h.opts.SecurityFindings.AttemptWorkItem(r.Context(), attempt)
	if err != nil {
		writeSecurityError(w, err)
		return false
	}
	if wi != user.WorkItemID() {
		writeErrorCode(w, http.StatusForbidden, codeSecurityForbidden, "agent run may only act on its own work item", nil)
		return false
	}
	return true
}

func (h *Handlers) auditSecurity(r *http.Request, user *auth.User, operation string, params map[string]string) {
	h.logAudit(r, audit.Entry{
		UserID: user.ID, Operation: "security." + operation, Parameters: params,
		Status: "succeeded", RiskLevel: string(operations.RiskLow),
	})
}

// ----- ingest -----

// securityIngestItem is one batch item on the wire: the typed observation
// plus the provider identity text a payload may carry. That text is
// untrusted evidence only.
type securityIngestItem struct {
	securityfindings.ObservationInput
	Provider    string `json:"provider"`
	ProviderRef string `json:"provider_ref"`
	Source      string `json:"source"`
}

type securityIngestRequest struct {
	DeliveryID   string               `json:"delivery_id"`
	Provider     string               `json:"provider"`
	ProviderRef  string               `json:"provider_ref"`
	Observations []securityIngestItem `json:"observations"`
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// providerContext derives the trusted provider context from the
// authenticated principal and server configuration.
func (h *Handlers) providerContext(user *auth.User) (securityfindings.ProviderContext, bool) {
	if ref := user.SecurityProviderRef(); ref != "" {
		cfg, ok := h.opts.SecurityProviders[ref]
		if !ok {
			return securityfindings.ProviderContext{}, false
		}
		max, err := securityfindings.ParseStrength(cfg.MaxStrength)
		if err != nil {
			slog.Error("security provider has an invalid max_strength; refusing ingest", "ref", ref, "max_strength", cfg.MaxStrength)
			return securityfindings.ProviderContext{}, false
		}
		return securityfindings.ProviderContext{Ref: ref, MaxStrength: max, Tenants: cfg.Tenants, PrincipalID: user.PrincipalID()}, true
	}
	// An admin ingesting directly (bootstrap, testing): its own ref and the
	// weakest provider ceiling, so it can never manufacture a resolution.
	return securityfindings.ProviderContext{
		Ref: "admin:" + user.ID, MaxStrength: securityfindings.StrengthProviderClaim, AnyTenant: true, PrincipalID: user.PrincipalID(),
	}, true
}

// IngestSecurityObservations handles POST /api/v1/security/observations.
func (h *Handlers) IngestSecurityObservations(w http.ResponseWriter, r *http.Request) {
	user, ok := h.securityUser(w, r)
	if !ok {
		return
	}
	if !user.HasPermission(auth.PermissionSecurityIngest) {
		writeErrorCode(w, http.StatusForbidden, codeSecurityForbidden, "ingesting observations requires "+auth.PermissionSecurityIngest, nil)
		return
	}
	pc, ok := h.providerContext(user)
	if !ok {
		writeErrorCode(w, http.StatusForbidden, codeSecurityForbidden, "this provider is not configured", nil)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSecurityIngestBodyBytes)
	var req securityIngestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorCode(w, http.StatusBadRequest, codeSecurityInvalid, "invalid JSON body", nil)
		return
	}
	batch := securityfindings.Batch{DeliveryID: strings.TrimSpace(req.DeliveryID), Observations: make([]securityfindings.ObservationInput, len(req.Observations))}
	for i := range req.Observations {
		it := &req.Observations[i]
		obs := it.ObservationInput
		// Any provider text in the payload is untrusted evidence. It never
		// reaches identity, dedup scope, authority or strength.
		if claimed := firstNonEmpty(it.Provider, it.ProviderRef, it.Source, req.Provider, req.ProviderRef); claimed != "" {
			obs.Untrusted.ClaimedProvider = truncate(claimed, securityfindings.MaxUntrustedProvider)
		}
		batch.Observations[i] = obs
	}
	results, err := h.opts.SecurityFindings.IngestBatch(r.Context(), pc, batch)
	if err != nil {
		writeSecurityError(w, err)
		return
	}
	counts := map[string]int{}
	for _, res := range results {
		counts[res.Status]++
	}
	h.auditSecurity(r, user, "observations.ingest", map[string]string{
		"provider": pc.Ref, "created": strconv.Itoa(counts[securityfindings.ItemCreated]),
		"duplicate": strconv.Itoa(counts[securityfindings.ItemDuplicate]), "rejected": strconv.Itoa(counts[securityfindings.ItemRejected]),
	})
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

// ----- reads -----

func securityListFilter(w http.ResponseWriter, r *http.Request, user *auth.User) (securityfindings.ListFilter, bool) {
	q := r.URL.Query()
	f := securityfindings.ListFilter{
		Tenant: q.Get("tenant"), State: q.Get("state"), Repository: q.Get("repository"),
		Identity: q.Get("identity"), FindingID: q.Get("finding_id"), Cursor: q.Get("cursor"),
	}
	if f.State != "" {
		valid := false
		for _, s := range securityfindings.States {
			valid = valid || s == f.State
		}
		if !valid {
			writeErrorCode(w, http.StatusBadRequest, codeSecurityInvalid, "unknown state "+strconv.Quote(f.State), nil)
			return f, false
		}
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeErrorCode(w, http.StatusBadRequest, codeSecurityInvalid, "limit must be a positive integer", nil)
			return f, false
		}
		f.Limit = n
	}
	if f.Tenant != "" && !user.HasTenantAccess(f.Tenant) {
		writeSecurityError(w, securityfindings.ErrNotFound)
		return f, false
	}
	return f, true
}

// ListSecurityFindings handles GET /api/v1/security/findings.
func (h *Handlers) ListSecurityFindings(w http.ResponseWriter, r *http.Request) {
	user, ok := h.securityUser(w, r)
	if !ok {
		return
	}
	f, ok := securityListFilter(w, r, user)
	if !ok {
		return
	}
	items, next, err := h.opts.SecurityFindings.ListFindings(r.Context(), securityVisibility(user), f)
	if err != nil {
		writeSecurityError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": items, "next_cursor": next})
}

// GetSecurityFinding handles GET /api/v1/security/findings/{id}.
func (h *Handlers) GetSecurityFinding(w http.ResponseWriter, r *http.Request) {
	user, ok := h.securityUser(w, r)
	if !ok {
		return
	}
	f, err := h.opts.SecurityFindings.GetFinding(r.Context(), securityVisibility(user), chi.URLParam(r, "id"))
	if err != nil {
		writeSecurityError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, f)
}

// ListSecurityOccurrences handles GET /api/v1/security/occurrences.
func (h *Handlers) ListSecurityOccurrences(w http.ResponseWriter, r *http.Request) {
	user, ok := h.securityUser(w, r)
	if !ok {
		return
	}
	f, ok := securityListFilter(w, r, user)
	if !ok {
		return
	}
	items, next, err := h.opts.SecurityFindings.ListOccurrences(r.Context(), securityVisibility(user), f)
	if err != nil {
		writeSecurityError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"occurrences": items, "next_cursor": next})
}

// GetSecurityOccurrence handles GET /api/v1/security/occurrences/{id}.
func (h *Handlers) GetSecurityOccurrence(w http.ResponseWriter, r *http.Request) {
	user, ok := h.securityUser(w, r)
	if !ok {
		return
	}
	o, err := h.opts.SecurityFindings.GetOccurrence(r.Context(), securityVisibility(user), chi.URLParam(r, "id"))
	if err != nil {
		writeSecurityError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, o)
}

// ----- mutations -----

type securityTriageBody struct {
	Reason          string `json:"reason"`
	ExpectedVersion *int64 `json:"expected_state_version"`
}

// occurrenceMutation does the checks every occurrence-scoped write shares and
// returns the occurrence id, the idempotency key and the actor.
func (h *Handlers) occurrenceMutation(w http.ResponseWriter, r *http.Request) (user *auth.User, occ, tenant, key string, ok bool) {
	user, ok = h.securityUser(w, r)
	if !ok {
		return nil, "", "", "", false
	}
	occ = chi.URLParam(r, "id")
	t, err := h.opts.SecurityFindings.OccurrenceTenant(r.Context(), occ)
	if tenant, ok = securityTenantOf(w, user, t, err); !ok {
		return nil, "", "", "", false
	}
	if key, ok = idempotencyKey(r); !ok {
		writeErrorCode(w, http.StatusBadRequest, codeSecurityInvalid, "Idempotency-Key is too long", nil)
		return nil, "", "", "", false
	}
	return user, occ, tenant, key, true
}

// TriageSecurityOccurrence handles POST /api/v1/security/occurrences/{id}/triage.
func (h *Handlers) TriageSecurityOccurrence(w http.ResponseWriter, r *http.Request) {
	user, occ, tenant, key, ok := h.occurrenceMutation(w, r)
	if !ok || !h.authorizeRemediation(w, r, user, tenant, "triage") {
		return
	}
	var body securityTriageBody
	if r.ContentLength != 0 && !decodeSecurityBody(w, r, &body) {
		return
	}
	res, err := h.opts.SecurityFindings.Triage(r.Context(), securityfindings.TriageInput{
		OccurrenceID: occ, ExpectedVersion: body.ExpectedVersion, IdempotencyKey: key,
		Reason: truncate(body.Reason, 1024), Actor: securityActor(user),
	})
	if err != nil {
		writeSecurityError(w, err)
		return
	}
	h.auditSecurity(r, user, "occurrence.triage", map[string]string{"occurrence_id": occ, "tenant": tenant})
	writeJSON(w, http.StatusOK, res)
}

// StartSecurityRemediation handles
// POST /api/v1/security/occurrences/{id}/remediation-attempts.
func (h *Handlers) StartSecurityRemediation(w http.ResponseWriter, r *http.Request) {
	user, occ, tenant, key, ok := h.occurrenceMutation(w, r)
	if !ok || !h.authorizeRemediation(w, r, user, tenant, "start_remediation") {
		return
	}
	var in securityfindings.StartRemediationInput
	if !decodeSecurityBody(w, r, &in) {
		return
	}
	// An agent run acts only for the work item and execution it was minted for.
	if user.IsAgent() && (strings.TrimSpace(in.WorkItemID) != user.WorkItemID() ||
		(strings.TrimSpace(in.ExecutionID) != "" && strings.TrimSpace(in.ExecutionID) != user.ExecutionID())) {
		writeErrorCode(w, http.StatusForbidden, codeSecurityForbidden, "agent run may only act on its own work item", nil)
		return
	}
	in.OccurrenceID, in.IdempotencyKey, in.Actor = occ, key, securityActor(user)
	if in.StartSource == "" {
		in.StartSource = in.Actor.Source
	}
	res, err := h.opts.SecurityFindings.StartRemediation(r.Context(), in)
	if err != nil {
		writeSecurityError(w, err)
		return
	}
	h.auditSecurity(r, user, "remediation.start", map[string]string{"occurrence_id": occ, "attempt_id": res.AttemptID, "work_item_id": in.WorkItemID, "tenant": tenant})
	writeJSON(w, http.StatusCreated, res)
}

// DismissSecurityOccurrence handles POST /api/v1/security/occurrences/{id}/dismiss.
// Human-only: accepted risk is a decision a person owns.
func (h *Handlers) DismissSecurityOccurrence(w http.ResponseWriter, r *http.Request) {
	// Refused before any lookup: a non-human principal learns nothing about
	// the occurrence, whichever tenant it is in.
	caller, ok := h.securityUser(w, r)
	if !ok {
		return
	}
	if !isHumanCaller(caller) {
		writeErrorCode(w, http.StatusForbidden, codeSecurityForbidden, "dismissal is a human decision; this principal may not dismiss", nil)
		return
	}
	user, occ, tenant, key, ok := h.occurrenceMutation(w, r)
	if !ok {
		return
	}
	if !user.IsAdmin() && !h.requireTenantRole(w, r, user, tenant, operations.RoleOwner, "security.dismiss", operations.RiskMedium) {
		return
	}
	var in securityfindings.DismissInput
	if !decodeSecurityBody(w, r, &in) {
		return
	}
	in.OccurrenceID, in.IdempotencyKey, in.Actor = occ, key, securityActor(user)
	res, err := h.opts.SecurityFindings.Dismiss(r.Context(), in)
	if err != nil {
		writeSecurityError(w, err)
		return
	}
	h.auditSecurity(r, user, "occurrence.dismiss", map[string]string{
		"occurrence_id": occ, "tenant": tenant, "reason": in.Reason, "authority_ref": in.AuthorityRef,
	})
	writeJSON(w, http.StatusOK, res)
}

// attemptMutation is occurrenceMutation for attempt-scoped writes.
func (h *Handlers) attemptMutation(w http.ResponseWriter, r *http.Request) (user *auth.User, attempt, tenant, key string, ok bool) {
	user, ok = h.securityUser(w, r)
	if !ok {
		return nil, "", "", "", false
	}
	attempt = chi.URLParam(r, "id")
	_, t, err := h.opts.SecurityFindings.AttemptRef(r.Context(), attempt)
	if tenant, ok = securityTenantOf(w, user, t, err); !ok {
		return nil, "", "", "", false
	}
	if key, ok = idempotencyKey(r); !ok {
		writeErrorCode(w, http.StatusBadRequest, codeSecurityInvalid, "Idempotency-Key is too long", nil)
		return nil, "", "", "", false
	}
	return user, attempt, tenant, key, true
}

// RecordSecurityFix handles POST /api/v1/security/remediation-attempts/{id}/fix.
func (h *Handlers) RecordSecurityFix(w http.ResponseWriter, r *http.Request) {
	user, attempt, tenant, key, ok := h.attemptMutation(w, r)
	if !ok || !h.authorizeRemediation(w, r, user, tenant, "record_fix") {
		return
	}
	if !h.agentOwnsAttempt(w, r, user, attempt) {
		return
	}
	var in securityfindings.RecordFixInput
	if !decodeSecurityBody(w, r, &in) {
		return
	}
	in.AttemptID, in.IdempotencyKey, in.Actor = attempt, key, securityActor(user)
	res, err := h.opts.SecurityFindings.RecordFix(r.Context(), in)
	if err != nil {
		writeSecurityError(w, err)
		return
	}
	h.auditSecurity(r, user, "remediation.fix", map[string]string{"attempt_id": attempt, "tenant": tenant, "landed": strconv.FormatBool(in.Landed)})
	writeJSON(w, http.StatusOK, res)
}

// RecordSecurityVerification handles
// POST /api/v1/security/remediation-attempts/{id}/verifications.
func (h *Handlers) RecordSecurityVerification(w http.ResponseWriter, r *http.Request) {
	user, attempt, tenant, key, ok := h.attemptMutation(w, r)
	if !ok || !h.authorizeRemediation(w, r, user, tenant, "record_verification") {
		return
	}
	if !h.agentOwnsAttempt(w, r, user, attempt) {
		return
	}
	var in securityfindings.RecordVerificationInput
	if !decodeSecurityBody(w, r, &in) {
		return
	}
	// The ceiling is decided by who is recording, never by the request.
	in.AttemptID, in.IdempotencyKey, in.Actor, in.Ceiling = attempt, key, securityActor(user), securityRecorderCeiling(user)
	res, err := h.opts.SecurityFindings.RecordVerification(r.Context(), in)
	if err != nil {
		writeSecurityError(w, err)
		return
	}
	h.auditSecurity(r, user, "remediation.verification", map[string]string{
		"attempt_id": attempt, "tenant": tenant, "result": in.Result, "verification_id": res.VerificationID,
	})
	writeJSON(w, http.StatusCreated, res)
}
