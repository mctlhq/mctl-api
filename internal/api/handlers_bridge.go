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
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/telemetry"
	"go.opentelemetry.io/otel/attribute"
)

// The command bridge (mctl-api#962). Three provider-only routes under
// /api/v1/bridge, disabled (404) unless MCTL_BRIDGE_ENABLED is set. The
// provider authenticates as a bridge-provider principal; which provider and
// which tenants come from server-side configuration, never from a body.
const (
	bridgeRoutePrefix = "/api/v1/bridge/"

	bridgeMaxBody      = 16 << 10
	bridgeClaimPerMin  = 120
	codeBridgeGate     = "bridge_provider_gate"
	codeBridgeNotAllow = "bridge_provider_required"
)

// BridgeService is the slice of *bridge.Store the handlers use.
type BridgeService interface {
	Claim(ctx context.Context, c bridge.Caller, max int, leaseTTL time.Duration) ([]bridge.Claimed, error)
	SubmitResult(ctx context.Context, c bridge.Caller, commandID string, body []byte) (*bridge.SubmitOutcome, error)
	IssueWritePermit(ctx context.Context, c bridge.Caller, commandID, leaseToken string) (*bridge.Permit, error)
}

// bridgeProviderGate confines a bridge-provider principal to the bridge
// routes. Everything else answers 403 before any handler runs, so the
// principal cannot reach DevLoop, work items, operations or MCP even if a
// per-route gate were misconfigured.
func bridgeProviderGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user := auth.UserFromContext(r.Context()); user.BridgeProviderRef() != "" &&
			(r.Method != http.MethodPost || !strings.HasPrefix(r.URL.Path, bridgeRoutePrefix)) {
			writeErrorCode(w, http.StatusForbidden, codeBridgeGate, "a bridge provider may only call the /api/v1/bridge routes", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireBridgeProvider admits only a bridge-provider principal.
func requireBridgeProvider(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if user.BridgeProviderRef() == "" || !user.HasPermission(auth.PermissionBridgeProvider) {
			writeErrorCode(w, http.StatusForbidden, codeBridgeNotAllow, "bridge provider credential required", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// bridgeCaller derives the store caller from the authenticated principal and
// the server-side provider configuration. A principal with no configured
// entry gets no tenants, and so no commands.
func (h *Handlers) bridgeCaller(user *auth.User) bridge.Caller {
	ref := user.BridgeProviderRef()
	cfg := h.opts.BridgeProviders[ref]
	return bridge.Caller{ProviderRef: ref, Actor: user.ID, Tenants: cfg.Tenants, Versions: cfg.WireVersions()}
}

func bridgeStatus(err error) (int, string) {
	code := bridge.Code(err)
	switch code {
	case "invalid_document", "invalid_input":
		return http.StatusBadRequest, code
	case "command_not_found":
		return http.StatusNotFound, code
	case "result_inconsistent":
		return http.StatusUnprocessableEntity, code
	case "write_fence_unavailable", "read_unavailable":
		return http.StatusServiceUnavailable, code
	case "write_fence_refused", "read_not_authorized":
		return http.StatusForbidden, code
	case "payload_too_large":
		return http.StatusRequestEntityTooLarge, code
	case "":
		return http.StatusInternalServerError, "bridge_internal"
	}
	// lease_stale, binding_mismatch, command_cancelled, command_expired,
	// result_conflict, already_completed, not_mutating, permit_already_issued.
	return http.StatusConflict, code
}

func (h *Handlers) bridgeFail(w http.ResponseWriter, r *http.Request, user *auth.User, op, commandID string, err error) {
	status, code := bridgeStatus(err)
	msg := code
	if status == http.StatusInternalServerError {
		msg = "internal error"
	}
	h.auditBridge(r, user, op, "failed", map[string]string{"command_id": commandID, "reason": code})
	writeErrorCode(w, status, code, msg, nil)
}

// auditBridge records ids, digests and codes only: never a nonce, a lease
// token, a payload or a credential.
func (h *Handlers) auditBridge(r *http.Request, user *auth.User, op, status string, params map[string]string) {
	params["provider"] = user.BridgeProviderRef()
	h.logAudit(r, audit.Entry{
		UserID: user.ID, Operation: op, Parameters: params, Status: status, RiskLevel: string(operations.RiskMedium),
	})
}

func (h *Handlers) bridgeReady(w http.ResponseWriter, r *http.Request) (*auth.User, bool) {
	if h.opts.Bridge == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, "bridge_unavailable", "bridge store not configured", nil)
		return nil, false
	}
	user := auth.UserFromContext(r.Context())
	if user == nil || user.BridgeProviderRef() == "" {
		writeErrorCode(w, http.StatusForbidden, codeBridgeNotAllow, "bridge provider credential required", nil)
		return nil, false
	}
	return user, true
}

// readStrictJSON reads a bounded body and decodes it into dst with unknown
// fields refused. An empty body is allowed when allowEmpty.
func readStrictJSON(r *http.Request, dst any, allowEmpty bool) error {
	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, bridgeMaxBody))
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		if allowEmpty {
			return nil
		}
		return errors.New("empty body")
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

// BridgeClaim handles POST /api/v1/bridge/commands/claim.
func (h *Handlers) BridgeClaim(w http.ResponseWriter, r *http.Request) {
	user, ok := h.bridgeReady(w, r)
	if !ok {
		return
	}
	ctx, span := telemetry.Tracer().Start(r.Context(), "bridge.claim")
	defer span.End()
	var req struct {
		Max int `json:"max,omitempty"`
	}
	if err := readStrictJSON(r, &req, true); err != nil {
		writeErrorCode(w, http.StatusBadRequest, "invalid_document", "invalid claim request", nil)
		return
	}
	caller := h.bridgeCaller(user)
	claimed, err := h.opts.Bridge.Claim(ctx, caller, req.Max, bridge.DefaultLeaseTTL)
	if err != nil {
		h.bridgeFail(w, r, user, "bridge-claim", "", err)
		return
	}
	span.SetAttributes(attribute.Int("bridge.claimed", len(claimed)))
	cmds := make([]json.RawMessage, 0, len(claimed))
	ids := make([]string, 0, len(claimed))
	for _, c := range claimed {
		cmds = append(cmds, c.Command)
		ids = append(ids, c.CommandID)
	}
	h.auditBridge(r, user, "bridge-claim", "success", map[string]string{"command_ids": strings.Join(ids, ",")})
	// The envelope version follows the caller alone: a provider that declares
	// only v1alpha1 gets the v1alpha1 envelope byte for byte as before.
	writeJSON(w, http.StatusOK, map[string]any{"schema_version": caller.ClaimEnvelopeVersion(), "commands": cmds})
}

// BridgeResult handles POST /api/v1/bridge/commands/{command_id}/result.
func (h *Handlers) BridgeResult(w http.ResponseWriter, r *http.Request) {
	user, ok := h.bridgeReady(w, r)
	if !ok {
		return
	}
	ctx, span := telemetry.Tracer().Start(r.Context(), "bridge.result")
	defer span.End()
	id := chi.URLParam(r, "command_id")
	if !bridge.IsCommandID(id) {
		writeErrorCode(w, http.StatusBadRequest, "invalid_input", "malformed command id", nil)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, bridgeMaxBody))
	if err != nil {
		writeErrorCode(w, http.StatusBadRequest, "invalid_document", "unreadable body", nil)
		return
	}
	out, err := h.opts.Bridge.SubmitResult(ctx, h.bridgeCaller(user), id, body)
	if err != nil {
		h.bridgeFail(w, r, user, "bridge-result", id, err)
		return
	}
	h.auditBridge(r, user, "bridge-result", "success", map[string]string{
		"command_id": id, "result_digest": out.ResultDigest, "effect_state": out.EffectState,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"command_id": out.CommandID, "status": out.Status, "effect_state": out.EffectState,
		"result_digest": out.ResultDigest, "replayed": out.Replayed,
	})
}

// BridgeWritePermit handles POST /api/v1/bridge/commands/{command_id}/write-permit.
// Its request and response are a private model, not part of the v1alpha1
// command or result schema.
func (h *Handlers) BridgeWritePermit(w http.ResponseWriter, r *http.Request) {
	user, ok := h.bridgeReady(w, r)
	if !ok {
		return
	}
	ctx, span := telemetry.Tracer().Start(r.Context(), "bridge.permit")
	defer span.End()
	id := chi.URLParam(r, "command_id")
	if !bridge.IsCommandID(id) {
		writeErrorCode(w, http.StatusBadRequest, "invalid_input", "malformed command id", nil)
		return
	}
	var req struct {
		LeaseToken string `json:"lease_token"`
	}
	if err := readStrictJSON(r, &req, false); err != nil || req.LeaseToken == "" {
		writeErrorCode(w, http.StatusBadRequest, "invalid_document", "invalid write-permit request", nil)
		return
	}
	p, err := h.opts.Bridge.IssueWritePermit(ctx, h.bridgeCaller(user), id, req.LeaseToken)
	if err != nil {
		h.bridgeFail(w, r, user, "bridge-write-permit", id, err)
		return
	}
	h.auditBridge(r, user, "bridge-write-permit", "success", map[string]string{"command_id": id, "fence_ref": p.FenceRef})
	writeJSON(w, http.StatusOK, map[string]any{
		"command_id": p.CommandID, "fence_ref": p.FenceRef, "issued_at": p.IssuedAt.UTC().Format(time.RFC3339),
	})
}
