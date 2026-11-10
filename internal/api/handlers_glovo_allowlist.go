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
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// GlovoAllowlist is the write side of the Glovo pilot allowlist (glovo.Store).
type GlovoAllowlist interface {
	AllowlistAdd(ctx context.Context, tenantID, principalID, addedBy string) error
	AllowlistRemove(ctx context.Context, tenantID, principalID string) error
}

// GlovoAllowlistAdd handles PUT /api/v1/glovo/pilot/{tenant}/principals/{principal_id}.
func (h *Handlers) GlovoAllowlistAdd(w http.ResponseWriter, r *http.Request) {
	h.glovoAllowlistWrite(w, r, true)
}

// GlovoAllowlistRemove handles DELETE of the same path.
func (h *Handlers) GlovoAllowlistRemove(w http.ResponseWriter, r *http.Request) {
	h.glovoAllowlistWrite(w, r, false)
}

// glovoAllowlistWrite is human-admin-only: isHumanAdmin refuses a service
// user, a relayed or surface identity, and anyone who is not a platform admin
// (a tenant owner is not enough); an agent run token is refused as well. A
// Glovo-audience token never gets here (glovoAudienceGate).
func (h *Handlers) glovoAllowlistWrite(w http.ResponseWriter, r *http.Request, add bool) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !isHumanAdmin(user) || user.IsAgent() || user.IsGlovoAudience() || user.PrincipalID() == "" {
		writeError(w, http.StatusForbidden, "the Glovo pilot allowlist is changed by a platform administrator acting directly")
		return
	}
	tenant, prn := chi.URLParam(r, "tenant"), chi.URLParam(r, "principal_id")
	if !auth.ValidPrincipalID(prn) {
		writeError(w, http.StatusBadRequest, "principal_id must be a prn_ principal id")
		return
	}
	if h.opts.GlovoAllowlist == nil || h.opts.GitReader == nil {
		writeError(w, http.StatusServiceUnavailable, "the Glovo pilot allowlist is not available")
		return
	}
	// TenantExists validates the name and the checkout's freshness: only a
	// definite miss is a 404, a failed read is a 503.
	exists, err := h.opts.GitReader.TenantExists(tenant)
	if err != nil {
		slog.Warn("glovo allowlist: tenant lookup failed", "tenant", tenant, "error", err)
		writeError(w, http.StatusServiceUnavailable, "the tenant could not be looked up; try again")
		return
	}
	if !exists {
		writeError(w, http.StatusNotFound, "tenant not found")
		return
	}
	op := "glovo.allowlist_remove"
	if add {
		op = "glovo.allowlist_add"
		err = h.opts.GlovoAllowlist.AllowlistAdd(r.Context(), tenant, prn, user.PrincipalID())
	} else {
		err = h.opts.GlovoAllowlist.AllowlistRemove(r.Context(), tenant, prn)
	}
	if err != nil {
		var ge *glovo.Error
		if errors.As(err, &ge) && ge.Code == glovo.CodeInvalidRequest {
			writeError(w, http.StatusBadRequest, "invalid tenant or principal")
			return
		}
		slog.Error("glovo allowlist write failed", "operation", op, "error", err)
		writeError(w, http.StatusServiceUnavailable, "the Glovo pilot allowlist is unavailable")
		return
	}
	h.logAudit(r, audit.Entry{
		UserID: user.ID, PrincipalID: user.PrincipalID(),
		Operation: op, Status: "succeeded", RiskLevel: string(operations.RiskMedium),
		Parameters: map[string]string{"tenant": tenant, "principal_id": prn},
	})
	w.WriteHeader(http.StatusNoContent)
}
