// Copyright 2026 MCTL Authors
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
	"errors"
	"net/http"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovoconsent"
)

// Self-service access (mctl-glovo#82, design section 4). Dark: the routes
// exist only when GlovoConsentRoutes.Access is set, and capacity accounting
// changes only with GLOVO_ACCESS_REQUIRED (a store option).
//
//   - GET/PUT/DELETE /api/v1/glovo/access-request: the human reads, opens and
//     withdraws their own access request. Same caller rules as the consent
//     routes (glovoConsentCaller).
//   - the `access` field of the service read.
const glovoAccessHumanPath = "/glovo/access-request"

// Access route error codes.
const (
	// gcCodeAccessApproved is the fixed refusal of a request while the access
	// is already approved.
	gcCodeAccessApproved = "glovo_access_already_approved"
)

// GlovoAccessStore is the access side of the consent store.
type GlovoAccessStore interface {
	// GetAccess is the effective state with the row's times.
	GetAccess(ctx context.Context, principalID string) (glovoconsent.Access, error)
	// AccessState is the effective state; an error is never none.
	AccessState(ctx context.Context, principalID string) (glovoconsent.AccessStatus, error)
	RequestAccess(ctx context.Context, principalID string) (glovoconsent.Access, bool, error)
	// RejectAccess withdraws a pending request when the actor is its owner.
	RejectAccess(ctx context.Context, principalID, actor, reason string) (glovoconsent.Access, error)
}

// glovoAccessWithdrawReason is the reason recorded on a requester's own
// withdrawal, which the store keeps as a rejection by the requester.
const glovoAccessWithdrawReason = "withdrawn by requester"

func (g *GlovoConsentRoutes) accessMounted() bool {
	return g.mounted() && !glovo.IsNil(g.Access)
}

// glovoAccessView is the human routes' answer.
type glovoAccessView struct {
	Status      string     `json:"status"`
	RequestedAt *time.Time `json:"requested_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

func accessView(a glovoconsent.Access) glovoAccessView {
	v := glovoAccessView{Status: string(a.Status)}
	if a.Status != glovoconsent.AccessNone && !a.RequestedAt.IsZero() {
		req, exp := a.RequestedAt.UTC(), a.ExpiresAt.UTC()
		v.RequestedAt, v.ExpiresAt = &req, &exp
	}
	return v
}

// validAccessOf reports whether a store answer is a usable state of pid: a
// faulty store must not expose another principal's row or an unknown status.
func validAccessOf(a glovoconsent.Access, pid string) bool {
	if a.PrincipalID != pid {
		return false
	}
	switch a.Status {
	case glovoconsent.AccessNone, glovoconsent.AccessPending, glovoconsent.AccessApproved,
		glovoconsent.AccessRejected, glovoconsent.AccessRevoked:
		return true
	}
	return false
}

func (h *Handlers) auditGlovoAccess(r *http.Request, user *auth.User, op, status, pid, refusal string) {
	h.auditGlovoConsent(r, user, op, status, pid, nil, refusal)
}

func accessUnavailable(w http.ResponseWriter, msg string) {
	writeErrorCode(w, http.StatusServiceUnavailable, gcCodeUnavailable, msg, nil)
}

// GetGlovoAccessRequest handles GET /api/v1/glovo/access-request.
func (h *Handlers) GetGlovoAccessRequest(w http.ResponseWriter, r *http.Request) {
	_, pid, ok := h.glovoConsentCaller(w, r, "access_read", "")
	if !ok {
		return
	}
	a, err := h.opts.GlovoConsent.Access.GetAccess(r.Context(), pid)
	if err != nil || !validAccessOf(a, pid) {
		glovoConsentEvents.WithLabelValues("access_read", "store_error").Inc()
		accessUnavailable(w, "the access request could not be read")
		return
	}
	writeJSON(w, http.StatusOK, accessView(a))
}

// PutGlovoAccessRequest handles PUT /api/v1/glovo/access-request: open a
// request. Idempotent while pending (200, same expiry), 201 when a new one
// opens, 409 glovo_access_already_approved when access is approved.
func (h *Handlers) PutGlovoAccessRequest(w http.ResponseWriter, r *http.Request) {
	const op = "glovo.access_request.open"
	user, pid, ok := h.glovoConsentCaller(w, r, "access_request", op)
	if !ok {
		return
	}
	a, created, err := h.opts.GlovoConsent.Access.RequestAccess(r.Context(), pid)
	if errors.Is(err, glovoconsent.ErrAccessApproved) {
		glovoConsentEvents.WithLabelValues("access_request", "already_approved").Inc()
		h.auditGlovoAccess(r, user, op, "refused", pid, gcCodeAccessApproved)
		writeErrorCode(w, http.StatusConflict, gcCodeAccessApproved, "your access is already approved", nil)
		return
	}
	if err != nil || !validAccessOf(a, pid) || a.Status != glovoconsent.AccessPending {
		glovoConsentEvents.WithLabelValues("access_request", "store_error").Inc()
		h.auditGlovoAccess(r, user, op, "failed", pid, gcCodeUnavailable)
		accessUnavailable(w, "the access request could not be opened")
		return
	}
	status, outcome := http.StatusOK, "unchanged"
	if created {
		status, outcome = http.StatusCreated, "opened"
	}
	glovoConsentEvents.WithLabelValues("access_request", outcome).Inc()
	h.auditGlovoAccess(r, user, op, outcome, pid, "")
	writeJSON(w, status, accessView(a))
}

// DeleteGlovoAccessRequest handles DELETE /api/v1/glovo/access-request: the
// caller withdraws their own pending request. Anything that is not pending
// is left as it is and its state is returned (idempotent); approved access
// is withdrawn through the consent route, not this one.
func (h *Handlers) DeleteGlovoAccessRequest(w http.ResponseWriter, r *http.Request) {
	const op = "glovo.access_request.withdraw"
	user, pid, ok := h.glovoConsentCaller(w, r, "access_withdraw", op)
	if !ok {
		return
	}
	store := h.opts.GlovoConsent.Access
	_, err := store.RejectAccess(r.Context(), pid, pid, glovoAccessWithdrawReason)
	outcome := "withdrawn"
	switch {
	case err == nil:
	case errors.Is(err, glovoconsent.ErrAccessNotPending):
		outcome = "unchanged"
	default:
		glovoConsentEvents.WithLabelValues("access_withdraw", "store_error").Inc()
		h.auditGlovoAccess(r, user, op, "failed", pid, gcCodeUnavailable)
		accessUnavailable(w, "the access request could not be withdrawn")
		return
	}
	a, err := store.GetAccess(r.Context(), pid)
	if err != nil || !validAccessOf(a, pid) {
		glovoConsentEvents.WithLabelValues("access_withdraw", "store_error").Inc()
		h.auditGlovoAccess(r, user, op, "failed", pid, gcCodeUnavailable)
		accessUnavailable(w, "the access request could not be read")
		return
	}
	glovoConsentEvents.WithLabelValues("access_withdraw", outcome).Inc()
	h.auditGlovoAccess(r, user, op, outcome, pid, "")
	writeJSON(w, http.StatusOK, accessView(a))
}

// serviceAccess reads the access field of the service read. ok false means
// the response is already written as 503: a failed access read fails the
// whole response, it is never an absent field. Unwired (nil Access) leaves
// the field out, which is configuration, not a failed read.
func (h *Handlers) serviceAccess(w http.ResponseWriter, r *http.Request, g *GlovoConsentRoutes, pid string) (string, bool) {
	if glovo.IsNil(g.Access) {
		return "", true
	}
	st, err := g.Access.AccessState(r.Context(), pid)
	valid := validAccessOf(glovoconsent.Access{PrincipalID: pid, Status: st}, pid)
	if err != nil || !valid {
		glovoConsentEvents.WithLabelValues("service_read", "access_error").Inc()
		accessUnavailable(w, "the access state could not be read")
		return "", false
	}
	return string(st), true
}
