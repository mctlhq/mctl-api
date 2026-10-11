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
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/commerce"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// Budget and payment endpoints (mctl-api#548), implementing ADR 020 secs. 7,
// 10 and 12 on top of the ledger of handlers_commerce.go.
//
// Who may do what:
//   - setting a budget is a platform operation: a limit is granted by an
//     admin with a reason, never self-granted by the tenant it binds;
//   - reading the balance, its history and the non-binding precheck needs
//     tenant authority and a resolved principal, like every receipt read;
//   - reserve, finalize, release and the reconciler move money state and
//     are platform-only, like the generic transition: the gateway and the
//     reconciler call them, a tenant never moves its own charge.
//
// The payer account is derived from the tenant (payerAccountFor), never read
// from a body.

type setBudgetRequest struct {
	Currency           string `json:"currency"`
	MonthlyLimitMinor  int64  `json:"monthly_limit_minor"`
	PerRequestMaxMinor int64  `json:"per_request_max_minor"`
	Reason             string `json:"reason"`
}

// SetCommerceBudget creates or changes the tenant's budget. Admin-only and
// audited at high risk: it is the one write that raises what a tenant can
// spend.
func (h *Handlers) SetCommerceBudget(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireCommerceAdmin(w, r)
	if !ok {
		return
	}
	tenant := normalizeIdentifier(chi.URLParam(r, "tenant"))
	if tenant == "" {
		writeError(w, http.StatusBadRequest, "tenant is required")
		return
	}
	var req setBudgetRequest
	if !decodeCommerceBody(w, r, &req) {
		return
	}
	actor := user.PrincipalID()
	if actor == "" {
		actor = principalOf(user)
	}
	params := map[string]string{"tenant": tenant, "currency": req.Currency,
		"monthly_limit_minor":   strconv.FormatInt(req.MonthlyLimitMinor, 10),
		"per_request_max_minor": strconv.FormatInt(req.PerRequestMaxMinor, 10), "reason": req.Reason}
	b, err := h.opts.Commerce.SetBudget(r.Context(), commerce.SetBudgetInput{
		TenantID: tenant, PayerAccountID: payerAccountFor(tenant), Currency: req.Currency,
		MonthlyLimitMinor: req.MonthlyLimitMinor, PerRequestMaxMinor: req.PerRequestMaxMinor, Actor: actor, Reason: req.Reason,
	})
	if err != nil {
		h.logAudit(r, audit.Entry{UserID: user.ID, Operation: "commerce-budget-set", Status: "failed",
			RiskLevel: string(operations.RiskHigh), Parameters: params, Message: err.Error()})
		writeCommerceError(w, err)
		return
	}
	h.logAudit(r, audit.Entry{UserID: user.ID, Operation: "commerce-budget-set", Status: "succeeded",
		RiskLevel: string(operations.RiskHigh), Parameters: params})
	writeJSON(w, http.StatusOK, b)
}

// GetCommerceBudget is the tenant budget read of ADR 020 sec. 12: limits,
// committed, reserved, pending liability and available, in the tenant
// currency and funds mode.
func (h *Handlers) GetCommerceBudget(w http.ResponseWriter, r *http.Request) {
	_, tenant, ok := h.requireCommerceTenant(w, r, "commerce-budget-read")
	if !ok {
		return
	}
	bal, err := h.opts.Commerce.GetBalance(r.Context(), tenant, payerAccountFor(tenant))
	if err != nil {
		writeCommerceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, bal)
}

// ListCommerceBudgetChanges returns who changed the tenant's limits, when
// and why.
func (h *Handlers) ListCommerceBudgetChanges(w http.ResponseWriter, r *http.Request) {
	_, tenant, ok := h.requireCommerceTenant(w, r, "commerce-budget-read")
	if !ok {
		return
	}
	if _, err := h.opts.Commerce.GetBudget(r.Context(), tenant, payerAccountFor(tenant)); err != nil {
		writeCommerceError(w, err)
		return
	}
	list, err := h.opts.Commerce.ListBudgetChanges(r.Context(), tenant, payerAccountFor(tenant))
	if err != nil {
		writeCommerceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"changes": list})
}

type precheckRequest struct {
	Amount commerce.Money `json:"amount"`
}

// PrecheckCommerceBudget is the preliminary, non-binding check of ADR 020
// sec. 7 step 4. It holds nothing and promises nothing: the reservation
// after the approval decides again.
func (h *Handlers) PrecheckCommerceBudget(w http.ResponseWriter, r *http.Request) {
	_, tenant, ok := h.requireCommerceTenant(w, r, "commerce-budget-read")
	if !ok {
		return
	}
	var req precheckRequest
	if !decodeCommerceBody(w, r, &req) {
		return
	}
	res, err := h.opts.Commerce.Precheck(r.Context(), tenant, payerAccountFor(tenant), req.Amount)
	if err != nil {
		writeCommerceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// moneyActor is the admin principal a money-moving endpoint records.
func (h *Handlers) moneyActor(w http.ResponseWriter, r *http.Request) (userID, actor, tenant, invocationID string, ok bool) {
	user, ok := h.requireCommerceAdmin(w, r)
	if !ok {
		return "", "", "", "", false
	}
	tenant = normalizeIdentifier(chi.URLParam(r, "tenant"))
	actor = user.PrincipalID()
	if actor == "" {
		actor = principalOf(user)
	}
	return user.ID, actor, tenant, chi.URLParam(r, "invocation_id"), true
}

// ReserveCommerceInvocation is step 8 of ADR 020 sec. 7: in one transaction
// it compares committed plus held against the limit, holds the quoted
// amount and authorizes payment. A denial is 422 with the reason and the
// invocation refused for good; a repeat returns the existing hold.
func (h *Handlers) ReserveCommerceInvocation(w http.ResponseWriter, r *http.Request) {
	userID, actor, tenant, id, ok := h.moneyActor(w, r)
	if !ok {
		return
	}
	res, err := h.opts.Commerce.Reserve(r.Context(), commerce.ReserveInput{TenantID: tenant, InvocationID: id, Actor: actor})
	params := map[string]string{"tenant": tenant, "invocation_id": id, "actor": actor}
	if err != nil {
		if res != nil && res.Invocation != nil {
			params["reason_code"] = res.Invocation.ReasonCode
		}
		h.logAudit(r, audit.Entry{UserID: userID, Operation: "commerce-reserve", Status: "denied",
			RiskLevel: string(operations.RiskHigh), Parameters: params, Message: err.Error()})
		if res != nil && res.Invocation != nil && res.Invocation.Phase == commerce.PhaseRefused {
			// Every denial reserve commits is final: the row is refused
			// with its reason, and a retry answers the same. 422 for all
			// of them, including quote-expired, which elsewhere (accept)
			// is the 409 "mint a new quote" answer; here there is nothing
			// left to retry against.
			writeErrorCode(w, http.StatusUnprocessableEntity, res.Invocation.ReasonCode, err.Error(), nil)
			return
		}
		writeCommerceError(w, err)
		return
	}
	if res.Reservation != nil {
		params["reservation_id"] = res.Reservation.ReservationID
		params["amount_minor"] = strconv.FormatInt(res.Reservation.AmountMinor, 10)
		params["currency"] = res.Reservation.Currency
	}
	params["payment_status"] = res.Invocation.PaymentStatus
	if !res.Replayed {
		h.logAudit(r, audit.Entry{UserID: userID, Operation: "commerce-reserve", Status: "succeeded",
			RiskLevel: string(operations.RiskHigh), Parameters: params})
	}
	writeJSON(w, http.StatusOK, res)
}

type finalizeRequest struct {
	ExecutionOutcome string `json:"execution_outcome"`
	UsageQuantity    *int64 `json:"usage_quantity,omitempty"`
	Note             string `json:"note,omitempty"`
}

// FinalizeCommerceInvocation records the confirmed outcome and captures or
// releases exactly once (ADR 020 sec. 7 steps 10-11).
func (h *Handlers) FinalizeCommerceInvocation(w http.ResponseWriter, r *http.Request) {
	userID, actor, tenant, id, ok := h.moneyActor(w, r)
	if !ok {
		return
	}
	var req finalizeRequest
	if !decodeCommerceBody(w, r, &req) {
		return
	}
	res, err := h.opts.Commerce.Finalize(r.Context(), commerce.FinalizeInput{TenantID: tenant, InvocationID: id, Actor: actor,
		ExecutionOutcome: req.ExecutionOutcome, UsageQuantity: req.UsageQuantity, Note: req.Note})
	params := map[string]string{"tenant": tenant, "invocation_id": id, "actor": actor, "execution_outcome": req.ExecutionOutcome}
	if err != nil {
		h.logAudit(r, audit.Entry{UserID: userID, Operation: "commerce-finalize", Status: "failed",
			RiskLevel: string(operations.RiskHigh), Parameters: params, Message: err.Error()})
		writeCommerceError(w, err)
		return
	}
	params["charge_status"] = res.Invocation.ChargeStatus
	params["amount_minor"] = strconv.FormatInt(res.Invocation.Price.AmountMinor, 10)
	params["currency"] = res.Invocation.Price.Currency
	if !res.Replayed {
		h.logAudit(r, audit.Entry{UserID: userID, Operation: "commerce-finalize", Status: "succeeded",
			RiskLevel: string(operations.RiskHigh), Parameters: params})
	}
	writeJSON(w, http.StatusOK, res)
}

type releaseRequest struct {
	ReasonCode string `json:"reason_code"`
	Note       string `json:"note,omitempty"`
}

// ReleaseCommerceInvocation voids the authorization and releases the hold
// of a reserved or dispatching invocation (ADR 020 sec. 11). A dispatched
// row answers too-late-to-cancel as a phase conflict.
func (h *Handlers) ReleaseCommerceInvocation(w http.ResponseWriter, r *http.Request) {
	userID, actor, tenant, id, ok := h.moneyActor(w, r)
	if !ok {
		return
	}
	var req releaseRequest
	if !decodeCommerceBody(w, r, &req) {
		return
	}
	res, err := h.opts.Commerce.Release(r.Context(), commerce.ReleaseInput{TenantID: tenant, InvocationID: id, Actor: actor,
		ReasonCode: req.ReasonCode, Note: req.Note})
	params := map[string]string{"tenant": tenant, "invocation_id": id, "actor": actor, "reason_code": req.ReasonCode}
	if err != nil {
		h.logAudit(r, audit.Entry{UserID: userID, Operation: "commerce-release", Status: "failed",
			RiskLevel: string(operations.RiskHigh), Parameters: params, Message: err.Error()})
		writeCommerceError(w, err)
		return
	}
	if !res.Replayed {
		h.logAudit(r, audit.Entry{UserID: userID, Operation: "commerce-release", Status: "succeeded",
			RiskLevel: string(operations.RiskHigh), Parameters: params})
	}
	writeJSON(w, http.StatusOK, res)
}

// ReconcileCommerceExpired runs one reconciler pass (ADR 020 sec. 11): it
// refuses accepted rows whose quote expired and releases reserved rows past
// their deadline with no dispatch intent. Nothing past dispatch is touched.
func (h *Handlers) ReconcileCommerceExpired(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireCommerceAdmin(w, r)
	if !ok {
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
	actor := user.PrincipalID()
	if actor == "" {
		actor = principalOf(user)
	}
	res, err := h.opts.Commerce.ExpireStale(r.Context(), actor, limit)
	params := map[string]string{"actor": actor}
	if res != nil {
		params["refused"] = strconv.Itoa(len(res.Refused))
		params["released"] = strconv.Itoa(len(res.Released))
		params["unresolved"] = strconv.Itoa(len(res.Unresolved))
	}
	if err != nil {
		h.logAudit(r, audit.Entry{UserID: user.ID, Operation: "commerce-reconcile-expired", Status: "failed",
			RiskLevel: string(operations.RiskHigh), Parameters: params, Message: err.Error()})
		if res != nil {
			// The rows already moved stay moved; the caller must know how
			// far the pass got before the failure, so a retry is informed.
			err = fmt.Errorf("%w (before the failure: refused %d, released %d, unresolved %d)",
				err, len(res.Refused), len(res.Released), len(res.Unresolved))
		}
		writeCommerceError(w, err)
		return
	}
	h.logAudit(r, audit.Entry{UserID: user.ID, Operation: "commerce-reconcile-expired", Status: "succeeded",
		RiskLevel: string(operations.RiskHigh), Parameters: params})
	writeJSON(w, http.StatusOK, res)
}
