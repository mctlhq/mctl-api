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
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/commerce"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Commerce ledger endpoints (mctl-api#547), implementing ADR 020 secs. 4-6,
// 11-13: terms, quotes, invocations and their history.
//
// Identity binding (ADR 020 sec. 3): tenant_id comes from the path,
// principal_id from the canonical principal the auth middleware resolved,
// payer_account_id is derived from the tenant, and the subject is the
// principal itself. None of them is read from a request body; a body naming
// one is an unknown field. Delegated subjects (subject_principal_id with a
// delegation_grant_id) are not accepted yet: they must come from
// internal/delegation.Resolver, never from a caller, and C3/C4 wire that
// when the gateway starts minting on behalf of a subject. A caller whose principal is unresolved is refused with
// identity-unresolved: a quote with no canonical principal cannot be
// idempotent, cannot be approved and cannot be charged, so it is never
// minted.
//
// Authorization (ADR 020 sec. 12): every tenant-scoped read and write needs
// tenant authority at commerceTenantRole; the milestone rule is tenant
// admin, and mctl-api#489 decides the final roles. Terms publication and
// phase transitions are platform operations: the first sets prices, the
// second moves money state and belongs to mctl-api's own components (C3,
// the reconciler) and the gateway, never to a tenant human.

const commerceMaxBodyBytes = 64 << 10 // identifiers and digests, never a payload

// commerceTenantRole is the milestone rule of ADR 020 sec. 12.
const commerceTenantRole = operations.RoleOwner

// payerAccountFor is the one payer account a tenant has in the simulated
// milestone. C3 may introduce a real account model; the derivation stays
// server-side either way.
func payerAccountFor(tenant string) string { return "acct_tenant_" + tenant }

func (h *Handlers) requireCommerce(w http.ResponseWriter, r *http.Request) (*auth.User, bool) {
	if h.opts.Commerce == nil {
		// 503, never 404: "the ledger is off" and "this tenant has no
		// invocations" must not be the same answer.
		writeError(w, http.StatusServiceUnavailable, "commerce ledger not configured")
		return nil, false
	}
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}
	return user, true
}

func (h *Handlers) requireCommerceAdmin(w http.ResponseWriter, r *http.Request) (*auth.User, bool) {
	user, ok := h.requireCommerce(w, r)
	if !ok {
		return nil, false
	}
	if !user.IsAdmin() {
		writeError(w, http.StatusForbidden, "commerce administration is admin-only")
		return nil, false
	}
	return user, true
}

// requireCommerceTenant admits a caller with tenant authority on the path
// tenant and a resolved canonical principal.
func (h *Handlers) requireCommerceTenant(w http.ResponseWriter, r *http.Request, operation string) (*auth.User, string, bool) {
	user, ok := h.requireCommerce(w, r)
	if !ok {
		return nil, "", false
	}
	// Normalized like every other tenant path param: an admin passes
	// HasTenantAccess for any string, and a case variant would store rows
	// no tenant-scoped read could find.
	tenant := normalizeIdentifier(chi.URLParam(r, "tenant"))
	if tenant == "" {
		writeError(w, http.StatusBadRequest, "tenant is required")
		return nil, "", false
	}
	if !user.HasTenantAccess(tenant) {
		// The same answer as a tenant that does not exist (ADR 020 sec. 12).
		writeError(w, http.StatusNotFound, "not found")
		return nil, "", false
	}
	if !h.requireTenantRole(w, r, user, tenant, commerceTenantRole, operation, operations.RiskMedium) {
		return nil, "", false
	}
	if user.PrincipalID() == "" {
		h.logAudit(r, audit.Entry{
			UserID: user.ID, Operation: operation, Parameters: map[string]string{"tenant": tenant},
			Status: "denied", RiskLevel: string(operations.RiskMedium),
			Message: "caller has no canonical principal; commerce refuses an unresolved identity",
		})
		writeErrorCode(w, http.StatusForbidden, commerce.ReasonIdentityUnresolved,
			"commerce requires a resolved canonical principal", nil)
		return nil, "", false
	}
	return user, tenant, true
}

// refuseIfAcceptDisabled implements COMMERCE_ACCEPT_DISABLED (mctl-api#570):
// it stops new paid acceptances only. It runs after requireCommerceTenant, so
// a caller without access still gets 404 and an unresolved one still gets
// identity-unresolved, and before the body is decoded, so nothing is written.
func (h *Handlers) refuseIfAcceptDisabled(w http.ResponseWriter, r *http.Request, user *auth.User, tenant, operation string) bool {
	if !h.opts.CommerceAcceptDisabled {
		return false
	}
	h.logAudit(r, audit.Entry{
		UserID: user.ID, Operation: operation, Parameters: map[string]string{"tenant": tenant},
		Status: "denied", RiskLevel: string(operations.RiskMedium),
		Message: "COMMERCE_ACCEPT_DISABLED is on; new paid acceptances are refused",
	})
	// 422, not 503: mctl-agents reads every 5xx as "ledger unknown", and this
	// is a final refusal with nothing held.
	writeErrorCode(w, http.StatusUnprocessableEntity, commerce.ReasonUnsupportedExecution,
		"commerce is not accepting new paid invocations", nil)
	return true
}

func decodeCommerceBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, commerceMaxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "body exceeds "+strconv.Itoa(commerceMaxBodyBytes)+" bytes")
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

// decodeOptionalCommerceBody is decodeCommerceBody for a body that may be
// absent: an empty body leaves v at its zero value, anything else is held
// to the same strictness.
func decodeOptionalCommerceBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, commerceMaxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "body exceeds "+strconv.Itoa(commerceMaxBodyBytes)+" bytes")
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

// writeCommerceError maps store errors to the reason codes of ADR 020
// sec. 13. Every refusal is a code the gateway can carry verbatim.
func writeCommerceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, commerce.ErrInvalid):
		writeErrorCode(w, http.StatusBadRequest, "invalid-request", err.Error(), nil)
	case errors.Is(err, commerce.ErrTermsNotFound):
		writeErrorCode(w, http.StatusUnprocessableEntity, commerce.ReasonTermsUnknown, "no commerce terms resolve for this capability", nil)
	case errors.Is(err, commerce.ErrTermsVersionMissing):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, commerce.ErrTermsRetired):
		writeErrorCode(w, http.StatusConflict, "terms-retired", "this terms version is already retired", nil)
	case errors.Is(err, commerce.ErrQuoteNotFound), errors.Is(err, commerce.ErrInvocationNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, commerce.ErrIdempotencyConflict):
		writeErrorCode(w, http.StatusConflict, commerce.ReasonIdempotencyConflict, "idempotency key reused with a different quote", nil)
	case errors.Is(err, commerce.ErrQuoteExpired):
		writeErrorCode(w, http.StatusConflict, commerce.ReasonQuoteExpired, "quote has expired", nil)
	case errors.Is(err, commerce.ErrQuoteStale):
		writeErrorCode(w, http.StatusConflict, commerce.ReasonQuoteStale, "quote no longer matches the terms in force", nil)
	case errors.Is(err, commerce.ErrQuoteMismatch):
		writeErrorCode(w, http.StatusConflict, commerce.ReasonQuoteMismatch, err.Error(), nil)
	case errors.Is(err, commerce.ErrFundsModeUnavailable):
		writeErrorCode(w, http.StatusUnprocessableEntity, commerce.ReasonFundsModeUnavailable, err.Error(), nil)
	case errors.Is(err, commerce.ErrTerminal), errors.Is(err, commerce.ErrPhaseConflict):
		writeErrorCode(w, http.StatusConflict, "phase-conflict", err.Error(), nil)
	case errors.Is(err, commerce.ErrBudgetNotFound):
		// The same answer as a tenant that does not exist: a budget's
		// absence is not shown across tenants either (ADR 020 sec. 12).
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, commerce.ErrBudgetExhausted):
		writeErrorCode(w, http.StatusUnprocessableEntity, commerce.ReasonBudgetExhausted, "budget exhausted; the invocation is refused", nil)
	case errors.Is(err, commerce.ErrCurrencyMismatch):
		writeErrorCode(w, http.StatusUnprocessableEntity, commerce.ReasonCurrencyMismatch, err.Error(), nil)
	case errors.Is(err, commerce.ErrPaymentDenied):
		writeErrorCode(w, http.StatusUnprocessableEntity, commerce.ReasonPaymentDenied, err.Error(), nil)
	case errors.Is(err, commerce.ErrPaymentUnknown):
		// Unknown is never denied: nothing changed, the hold stays, and
		// only status on the same key resolves it.
		writeErrorCode(w, http.StatusConflict, "payment-unknown", err.Error(), nil)
	case errors.Is(err, commerce.ErrPaymentConflict):
		writeErrorCode(w, http.StatusConflict, commerce.ReasonIdempotencyConflict, err.Error(), nil)
	case errors.Is(err, commerce.ErrApprovalBound):
		// An approval authorizes one invocation (ADR 020 sec. 8); a second
		// one naming it is refused like any other approval that does not
		// cover the action.
		writeErrorCode(w, http.StatusConflict, "policy-denied", "the approval is already bound to another invocation", nil)
	case errors.Is(err, errApprovalNotOwned):
		// The same answer for an approval that does not exist and for one
		// that belongs to another call: the refusal is no existence oracle.
		writeErrorCode(w, http.StatusConflict, "policy-denied", "the approval does not belong to this call", nil)
	case errors.Is(err, errApprovalUnobservable):
		// Could not read the approval is not "not owned": retryable, and
		// never a pass.
		writeErrorCode(w, http.StatusServiceUnavailable, "approval-unavailable", "the approval could not be read; try again", nil)
	case errors.Is(err, commerce.ErrDispatchUnavailable):
		writeErrorCode(w, http.StatusServiceUnavailable, "dispatch-unavailable", "commerce dispatch signing is not configured", nil)
	case errors.Is(err, commerce.ErrReservationMissing):
		// A reserved row with no hold is an invariant broken behind the
		// API, never a caller's mistake.
		slog.Error("commerce ledger invariant broken", "error", err)
		writeError(w, http.StatusInternalServerError, "commerce ledger invariant broken")
	default:
		slog.Error("commerce ledger request failed", "error", err)
		writeError(w, http.StatusInternalServerError, "commerce ledger request failed")
	}
}

// ---- terms --------------------------------------------------------------

type publishTermsRequest struct {
	TermsID         string         `json:"terms_id,omitempty"`
	CapabilityID    string         `json:"capability_id"`
	InputSchemaHash string         `json:"input_schema_hash"`
	ProviderID      string         `json:"provider_id"`
	PriceMode       string         `json:"price_mode"`
	Price           commerce.Money `json:"price"`
	FundsMode       string         `json:"funds_mode"`
	QuoteTTLSeconds int            `json:"quote_ttl_seconds"`
	EffectiveFrom   *time.Time     `json:"effective_from,omitempty"`
}

// PublishCommerceTerms publishes the next version of a capability's terms
// (ADR 020 sec. 4). Admin-only: it sets a price.
func (h *Handlers) PublishCommerceTerms(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireCommerceAdmin(w, r)
	if !ok {
		return
	}
	var req publishTermsRequest
	if !decodeCommerceBody(w, r, &req) {
		return
	}
	effective := time.Now().UTC()
	if req.EffectiveFrom != nil {
		effective = req.EffectiveFrom.UTC()
	}
	publisher := user.PrincipalID()
	if publisher == "" {
		publisher = principalOf(user)
	}
	terms, err := h.opts.Commerce.PublishTerms(r.Context(), commerce.PublishTermsInput{
		TermsID: req.TermsID, CapabilityID: req.CapabilityID, InputSchemaHash: req.InputSchemaHash,
		ProviderID: req.ProviderID, PriceMode: req.PriceMode, Price: req.Price, FundsMode: req.FundsMode,
		QuoteTTLSeconds: req.QuoteTTLSeconds, EffectiveFrom: effective, PublishedBy: publisher,
	})
	if err != nil {
		writeCommerceError(w, err)
		return
	}
	h.logAudit(r, audit.Entry{
		UserID: user.ID, Operation: "commerce-terms-publish", Status: "succeeded", RiskLevel: string(operations.RiskHigh),
		Parameters: map[string]string{
			"terms_id": terms.TermsID, "terms_version": strconv.FormatInt(terms.TermsVersion, 10),
			"capability_id": terms.CapabilityID, "price_mode": terms.PriceMode,
			"amount_minor": strconv.FormatInt(terms.Price.AmountMinor, 10), "currency": terms.Price.Currency,
		},
	})
	writeJSON(w, http.StatusCreated, terms)
}

// RetireCommerceTerms retires one version. Quotes minted against it become
// stale; invocations already accepted keep their price.
func (h *Handlers) RetireCommerceTerms(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireCommerceAdmin(w, r)
	if !ok {
		return
	}
	version, err := strconv.ParseInt(chi.URLParam(r, "version"), 10, 64)
	if err != nil || version < 1 {
		writeError(w, http.StatusBadRequest, "version must be a positive integer")
		return
	}
	terms, err := h.opts.Commerce.RetireTerms(r.Context(), chi.URLParam(r, "terms_id"), version)
	if err != nil {
		writeCommerceError(w, err)
		return
	}
	h.logAudit(r, audit.Entry{
		UserID: user.ID, Operation: "commerce-terms-retire", Status: "succeeded", RiskLevel: string(operations.RiskHigh),
		Parameters: map[string]string{"terms_id": terms.TermsID, "terms_version": strconv.FormatInt(terms.TermsVersion, 10)},
	})
	writeJSON(w, http.StatusOK, terms)
}

// ListCommerceTerms lists every version for a capability, or resolves the
// version in force with current=true.
func (h *Handlers) ListCommerceTerms(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireCommerce(w, r); !ok {
		return
	}
	q := r.URL.Query()
	capID := q.Get("capability_id")
	if capID == "" {
		writeError(w, http.StatusBadRequest, "capability_id is required")
		return
	}
	if q.Get("current") == "true" {
		terms, err := h.opts.Commerce.CurrentTerms(r.Context(), capID, q.Get("input_schema_hash"))
		if err != nil {
			writeCommerceError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, terms)
		return
	}
	terms, err := h.opts.Commerce.ListTerms(r.Context(), capID)
	if err != nil {
		writeCommerceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"terms": terms})
}

// GetCommerceTerms returns one exact version.
func (h *Handlers) GetCommerceTerms(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireCommerce(w, r); !ok {
		return
	}
	version, err := strconv.ParseInt(chi.URLParam(r, "version"), 10, 64)
	if err != nil || version < 1 {
		writeError(w, http.StatusBadRequest, "version must be a positive integer")
		return
	}
	terms, err := h.opts.Commerce.GetTerms(r.Context(), chi.URLParam(r, "terms_id"), version)
	if err != nil {
		writeCommerceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, terms)
}

// ---- quotes -------------------------------------------------------------

// commerceIdentityRequest is the only thing a body may say about the call's
// context: which execution it belongs to. Every party is resolved
// server-side.
type commerceIdentityRequest struct {
	ExecutionID string `json:"execution_id"`
}

func resolveIdentities(user *auth.User, tenant string, req commerceIdentityRequest) commerce.Identities {
	principal := user.PrincipalID()
	return commerce.Identities{
		TenantID:           tenant,
		PrincipalID:        principal,
		SubjectPrincipalID: principal,
		PayerAccountID:     payerAccountFor(tenant),
		ExecutionID:        req.ExecutionID,
	}
}

type mintQuoteRequest struct {
	commerceIdentityRequest
	CapabilityID    string `json:"capability_id"`
	InputSchemaHash string `json:"input_schema_hash"`
	ArgsDigest      string `json:"args_digest"`
}

// MintCommerceQuote is step 5 of ADR 020 sec. 7.
func (h *Handlers) MintCommerceQuote(w http.ResponseWriter, r *http.Request) {
	user, tenant, ok := h.requireCommerceTenant(w, r, "commerce-quote-mint")
	if !ok || h.refuseIfAcceptDisabled(w, r, user, tenant, "commerce-quote-mint") {
		return
	}
	var req mintQuoteRequest
	if !decodeCommerceBody(w, r, &req) {
		return
	}
	quote, err := h.opts.Commerce.MintQuote(r.Context(), commerce.MintQuoteInput{
		CapabilityID: req.CapabilityID, InputSchemaHash: req.InputSchemaHash,
		Identities: resolveIdentities(user, tenant, req.commerceIdentityRequest), ArgsDigest: req.ArgsDigest,
	})
	if err != nil {
		writeCommerceError(w, err)
		return
	}
	h.logAudit(r, audit.Entry{
		UserID: user.ID, Operation: "commerce-quote-mint", Status: "succeeded", RiskLevel: string(operations.RiskMedium),
		Parameters: map[string]string{
			"tenant": tenant, "quote_id": quote.QuoteID, "capability_id": quote.CapabilityID,
			"terms_version": strconv.FormatInt(quote.TermsVersion, 10), "execution_id": quote.ExecutionID,
		},
	})
	writeJSON(w, http.StatusCreated, quote)
}

// GetCommerceQuote returns a quote of the path tenant.
func (h *Handlers) GetCommerceQuote(w http.ResponseWriter, r *http.Request) {
	_, tenant, ok := h.requireCommerceTenant(w, r, "commerce-quote-read")
	if !ok {
		return
	}
	quote, err := h.opts.Commerce.GetQuote(r.Context(), tenant, chi.URLParam(r, "quote_id"))
	if err != nil {
		writeCommerceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, quote)
}

// ---- invocations --------------------------------------------------------

type acceptInvocationRequest struct {
	commerceIdentityRequest
	QuoteID        string `json:"quote_id"`
	QuoteDigest    string `json:"quote_digest"`
	IdempotencyKey string `json:"idempotency_key"`
	ArgsDigest     string `json:"args_digest"`
	ApprovalID     string `json:"approval_id,omitempty"`
	TermsBinding   string `json:"terms_binding,omitempty"`
}

type acceptInvocationResponse struct {
	*commerce.Invocation
	Replayed bool `json:"replayed"`
}

// AcceptCommerceInvocation is step 6 of ADR 020 sec. 7. 201 is a new row,
// 200 the existing row for the same idempotency key and quote digest.
func (h *Handlers) AcceptCommerceInvocation(w http.ResponseWriter, r *http.Request) {
	user, tenant, ok := h.requireCommerceTenant(w, r, "commerce-invocation-accept")
	if !ok || h.refuseIfAcceptDisabled(w, r, user, tenant, "commerce-invocation-accept") {
		return
	}
	var req acceptInvocationRequest
	if !decodeCommerceBody(w, r, &req) {
		return
	}
	ids := resolveIdentities(user, tenant, req.commerceIdentityRequest)
	var res *commerce.AcceptResult
	err := h.checkApprovalOwner(r, user, req.ApprovalID, ids.ExecutionID)
	if err == nil {
		res, err = h.opts.Commerce.AcceptInvocation(r.Context(), commerce.AcceptInvocationInput{
			QuoteID: req.QuoteID, QuoteDigest: req.QuoteDigest, IdempotencyKey: req.IdempotencyKey,
			Identities: ids, ArgsDigest: req.ArgsDigest,
			ApprovalID: req.ApprovalID, TermsBinding: req.TermsBinding,
		})
	}
	if err != nil {
		h.logAudit(r, audit.Entry{
			UserID: user.ID, Operation: "commerce-invocation-accept", Status: "failed", RiskLevel: string(operations.RiskMedium),
			Parameters: map[string]string{"tenant": tenant, "quote_id": req.QuoteID, "execution_id": req.ExecutionID},
			Message:    err.Error(),
		})
		writeCommerceError(w, err)
		return
	}
	status := http.StatusCreated
	if res.Replayed {
		status = http.StatusOK
	} else {
		h.logAudit(r, audit.Entry{
			UserID: user.ID, Operation: "commerce-invocation-accept", Status: "succeeded", RiskLevel: string(operations.RiskMedium),
			Parameters: map[string]string{
				"tenant": tenant, "invocation_id": res.Invocation.InvocationID, "quote_id": res.Invocation.QuoteID,
				"execution_id": res.Invocation.ExecutionID, "approval_id": res.Invocation.ApprovalID,
				"amount_minor": strconv.FormatInt(res.Invocation.Price.AmountMinor, 10), "currency": res.Invocation.Price.Currency,
			},
		})
	}
	writeJSON(w, status, acceptInvocationResponse{Invocation: res.Invocation, Replayed: res.Replayed})
}

var (
	errApprovalNotOwned     = errors.New("approval does not belong to this call")
	errApprovalUnobservable = errors.New("approval could not be read")
)

// checkApprovalOwner binds a caller-supplied approval_id to the call that
// names it (mctl-agents#626 item 6). The ledger's (tenant, approval_id)
// index makes an approval authorize one invocation, but approval_id is
// caller input: without this check another execution in the same tenant
// could bind someone else's approval first and refuse the real call. An
// action approval is requested by a service for one execution, so the
// approval must have been requested by this caller (the same principal
// rendering the approval routes use) for this execution. Its state is not
// checked here: the gateway consumes it after accept, so a replayed accept
// legitimately names a consumed approval.
//
// A failed read is errApprovalUnobservable, never "not owned" and never a
// pass. Approvals carry no tenant yet; binding one to a tenant is
// mctl-api#489 / mctl-agents#631.
func (h *Handlers) checkApprovalOwner(r *http.Request, user *auth.User, approvalID, executionID string) error {
	if approvalID == "" {
		return nil
	}
	if h.opts.WorkItems == nil {
		return errApprovalUnobservable
	}
	a, err := h.opts.WorkItems.ActionApproval(r.Context(), approvalID)
	if errors.Is(err, workitems.ErrApprovalNotFound) {
		return errApprovalNotOwned
	}
	if err != nil {
		slog.Error("commerce accept: action approval not read", "approval_id", approvalID, "error", err)
		return errApprovalUnobservable
	}
	if a.RequestedBy != principalOf(user) || a.ExecutionID != executionID || executionID == "" {
		return errApprovalNotOwned
	}
	return nil
}

// GetCommerceInvocation returns one invocation record of the path tenant,
// ledger fields included; the redacted receipt is GetCommerceReceipt.
func (h *Handlers) GetCommerceInvocation(w http.ResponseWriter, r *http.Request) {
	_, tenant, ok := h.requireCommerceTenant(w, r, "commerce-invocation-read")
	if !ok {
		return
	}
	inv, err := h.opts.Commerce.GetInvocation(r.Context(), tenant, chi.URLParam(r, "invocation_id"))
	if err != nil {
		writeCommerceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, inv)
}

// policyDecisionOf reads the policy decision reference of an invocation from
// its action approval. A failed read is reported as "unavailable", never as
// "none": the ledger facts stay readable, and the reference is never blanked.
func (h *Handlers) policyDecisionOf(ctx context.Context, approvalID string) commerce.PolicyDecisionRef {
	if approvalID == "" {
		return commerce.PolicyDecisionRef{Status: commerce.PolicyNone}
	}
	if h.opts.WorkItems == nil {
		return commerce.PolicyDecisionRef{Status: commerce.PolicyUnavailable, ApprovalID: approvalID}
	}
	a, err := h.opts.WorkItems.ActionApproval(ctx, approvalID)
	if errors.Is(err, workitems.ErrApprovalNotFound) {
		return commerce.PolicyDecisionRef{Status: commerce.PolicyMissing, ApprovalID: approvalID}
	}
	if err != nil {
		slog.Error("commerce receipt: action approval not read", "approval_id", approvalID, "error", err)
		return commerce.PolicyDecisionRef{Status: commerce.PolicyUnavailable, ApprovalID: approvalID}
	}
	return commerce.PolicyDecisionRef{
		Status: commerce.PolicyRecorded, ApprovalID: approvalID,
		PolicyRuleID: a.PolicyRuleID, PolicyVersion: a.PolicyVersion,
	}
}

// GetCommerceReceipt returns the ADR 020 sec. 12 receipt of one invocation of
// the path tenant. A foreign tenant and a missing id answer identically.
func (h *Handlers) GetCommerceReceipt(w http.ResponseWriter, r *http.Request) {
	_, tenant, ok := h.requireCommerceTenant(w, r, "commerce-invocation-read")
	if !ok {
		return
	}
	inv, err := h.opts.Commerce.GetInvocation(r.Context(), tenant, chi.URLParam(r, "invocation_id"))
	if err != nil {
		writeCommerceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, commerce.ReceiptOf(*inv, h.policyDecisionOf(r.Context(), inv.ApprovalID)))
}

// ListCommerceInvocations lists the path tenant's invocation records,
// filtered by capability, phase or period.
func (h *Handlers) ListCommerceInvocations(w http.ResponseWriter, r *http.Request) {
	user, tenant, ok := h.requireCommerceTenant(w, r, "commerce-invocation-read")
	if !ok {
		return
	}
	q := r.URL.Query()
	f := commerce.ListFilter{TenantID: tenant, CapabilityID: q.Get("capability_id"), Phase: q.Get("phase")}
	if key := q.Get("idempotency_key"); key != "" {
		// The idempotency scope is (tenant, principal, key), and the
		// principal is always the caller's own: a key never finds another
		// principal's invocation (ADR 020 sec. 6).
		f.IdempotencyKey = key
		f.PrincipalID = user.PrincipalID()
	}
	for _, p := range []struct {
		name string
		dst  *time.Time
	}{{"since", &f.Since}, {"until", &f.Until}} {
		if v := q.Get(p.name); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				writeError(w, http.StatusBadRequest, p.name+" must be RFC 3339")
				return
			}
			*p.dst = t
		}
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			writeError(w, http.StatusBadRequest, "limit must be 1..500")
			return
		}
		f.Limit = n
	}
	list, err := h.opts.Commerce.ListInvocations(r.Context(), f)
	if err != nil {
		writeCommerceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"invocations": list})
}

// ListCommerceInvocationTransitions returns the append-only history.
func (h *Handlers) ListCommerceInvocationTransitions(w http.ResponseWriter, r *http.Request) {
	_, tenant, ok := h.requireCommerceTenant(w, r, "commerce-invocation-read")
	if !ok {
		return
	}
	list, err := h.opts.Commerce.ListTransitions(r.Context(), tenant, chi.URLParam(r, "invocation_id"))
	if err != nil {
		writeCommerceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"transitions": list})
}

type transitionRequest struct {
	ExpectedPhase       string     `json:"expected_phase"`
	ToPhase             string     `json:"to_phase"`
	ReasonCode          string     `json:"reason_code,omitempty"`
	Note                string     `json:"note,omitempty"`
	ExecutionOutcome    string     `json:"execution_outcome,omitempty"`
	UsageQuantity       *int64     `json:"usage_quantity,omitempty"`
	ChargeStatus        string     `json:"charge_status,omitempty"`
	PaymentStatus       string     `json:"payment_status,omitempty"`
	SettlementStatus    string     `json:"settlement_status,omitempty"`
	ReservationDeadline *time.Time `json:"reservation_deadline,omitempty"`
}

// ownedEdges are the phases only a dedicated endpoint may enter: reserved
// holds budget, released and finalized settle it, and dispatching writes the
// dispatch fence and signs the authorization (C4). Entering one through the
// generic transition would bypass the atomic check, leave a hold behind or
// produce a dispatching row with no fence, so the generic route refuses them
// and names the endpoint that owns each.
var ownedEdges = map[string]string{
	commerce.PhaseReserved:    "reserve",
	commerce.PhaseDispatching: "dispatch",
	commerce.PhaseReleased:    "release",
	commerce.PhaseFinalized:   "finalize",
}

// TransitionCommerceInvocation applies one phase change (ADR 020 sec. 11).
// Platform-only: a tenant must not finalize or release its own charge. The
// edges a dedicated endpoint owns are not accepted here (see ownedEdges).
func (h *Handlers) TransitionCommerceInvocation(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireCommerceAdmin(w, r)
	if !ok {
		return
	}
	tenant := normalizeIdentifier(chi.URLParam(r, "tenant"))
	id := chi.URLParam(r, "invocation_id")
	var req transitionRequest
	if !decodeCommerceBody(w, r, &req) {
		return
	}
	if owner, owned := ownedEdges[req.ToPhase]; owned {
		writeErrorCode(w, http.StatusBadRequest, "invalid-request",
			"to_phase "+req.ToPhase+" is owned by POST .../invocations/{invocation_id}/"+owner, nil)
		return
	}
	actor := user.PrincipalID()
	if actor == "" {
		actor = principalOf(user)
	}
	inv, err := h.opts.Commerce.Transition(r.Context(), tenant, commerce.TransitionInput{
		InvocationID: id, ExpectedPhase: req.ExpectedPhase, ToPhase: req.ToPhase, ReasonCode: req.ReasonCode,
		Actor: actor, Note: req.Note, ExecutionOutcome: req.ExecutionOutcome, UsageQuantity: req.UsageQuantity,
		ChargeStatus: req.ChargeStatus, PaymentStatus: req.PaymentStatus, SettlementStatus: req.SettlementStatus,
		ReservationDeadline: req.ReservationDeadline,
	})
	params := map[string]string{"tenant": tenant, "invocation_id": id, "expected_phase": req.ExpectedPhase,
		"to_phase": req.ToPhase, "reason_code": req.ReasonCode, "actor": actor}
	if err != nil {
		h.logAudit(r, audit.Entry{UserID: user.ID, Operation: "commerce-invocation-transition", Status: "failed",
			RiskLevel: string(operations.RiskHigh), Parameters: params, Message: err.Error()})
		writeCommerceError(w, err)
		return
	}
	h.logAudit(r, audit.Entry{UserID: user.ID, Operation: "commerce-invocation-transition", Status: "succeeded",
		RiskLevel: string(operations.RiskHigh), Parameters: params})
	writeJSON(w, http.StatusOK, inv)
}

// ListOverdueCommerceInvocations lists non-terminal invocations past their
// reconciliation deadline, for the operator alert of ADR 020 sec. 11.
func (h *Handlers) ListOverdueCommerceInvocations(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireCommerceAdmin(w, r); !ok {
		return
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			writeError(w, http.StatusBadRequest, "limit must be 1..500")
			return
		}
		limit = n
	}
	list, err := h.opts.Commerce.ListOverdue(r.Context(), limit)
	if err != nil {
		writeCommerceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"invocations": list})
}
