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

// Surface identity links (mctl-api#350). A human links a surface-native
// identity to themself by possession proof on both sides:
//
//  1. The human (GitHub-authenticated) asks for a challenge for one surface.
//  2. The code travels through that surface (the human sends it to the bot).
//  3. That surface's own principal redeems it with the external id it saw.
//
// The human never names the external id and the surface never names the
// human, so neither can create a link alone. Surface principals are
// non-admin, distinct from mctl-agent, and gated to an explicit route
// allowlist (surfacePrincipalGate).

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/surfaceid"
)

// SurfaceActorHeader names the surface-native end user (a Telegram user id,
// a portal subject) a surface principal is calling for. Only a surface
// principal may send it. Rate limits key a surface principal's budget on
// it, so one end user cannot spend the whole surface's budget.
const SurfaceActorHeader = "X-MCTL-Surface-Actor"

const (
	sidCodeUnavailable      = "surface_identity_unavailable"
	sidCodeInvalid          = "invalid_request"
	sidCodeHumanOnly        = "human_principal_required"
	sidCodeSurfaceOnly      = "surface_principal_required"
	sidCodeChallengeInvalid = "challenge_invalid"
	sidCodeTooMany          = "too_many_challenges"
	sidCodeLinkConflict     = "link_conflict"
	sidCodeNotFound         = "link_not_found"
	sidCodeRouteNotAllowed  = "surface_route_not_allowed"
	sidCodeActorNotAccepted = "actor_not_accepted"
	sidMaxBodyBytes         = 4 << 10
)

// surfaceRoutes are the only routes a surface principal may call. Anything
// else answers 403 before any handler runs: a surface credential is a narrow
// relay capability, not an API key.
var surfaceRoutes = []struct {
	method  string
	pattern *regexp.Regexp
}{
	{http.MethodPost, regexp.MustCompile(`^/api/v1/surface-identities/redeem$`)},
}

// surfacePrincipalGate confines surface principals to surfaceRoutes and
// refuses the surface-actor header from anyone else.
//
// It runs before the rate limiters, whose keys trust the header only
// because it has passed here.
func surfacePrincipalGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			next.ServeHTTP(w, r)
			return
		}
		surface, isSurface := user.Surface()
		if !isSurface {
			if r.Header.Get(SurfaceActorHeader) != "" {
				writeErrorCode(w, http.StatusBadRequest, sidCodeActorNotAccepted,
					SurfaceActorHeader+" may only be sent by a surface principal", nil)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		for _, route := range surfaceRoutes {
			if r.Method == route.method && route.pattern.MatchString(r.URL.Path) {
				// The rate limiters key on this value: it must be one of
				// the surface's own ids, not arbitrary bytes.
				if actor := r.Header.Get(SurfaceActorHeader); actor != "" && !surfaceid.ValidExternalID(surface, actor) {
					writeErrorCode(w, http.StatusBadRequest, sidCodeInvalid,
						SurfaceActorHeader+" is not a valid "+surface+" identity", nil)
					return
				}
				next.ServeHTTP(w, r)
				return
			}
		}
		writeErrorCode(w, http.StatusForbidden, sidCodeRouteNotAllowed,
			"a surface principal may not call "+r.Method+" "+r.URL.Path, nil)
	})
}

// humanPrincipal is the principal a caller may link: a GitHub login proven
// by authentication, and nothing else (not the service principal, not a
// surface, not a Dex username).
func humanPrincipal(u *auth.User) (string, bool) {
	if u.IsService() {
		return "", false
	}
	if _, isSurface := u.Surface(); isSurface {
		return "", false
	}
	login, ok := u.GitHubLogin()
	if !ok {
		return "", false
	}
	return "github:" + login, true
}

func (h *Handlers) surfaceIdentityUser(w http.ResponseWriter, r *http.Request) (*auth.User, bool) {
	if h.opts.SurfaceIdentities == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, sidCodeUnavailable, "surface identity store not configured", nil)
		return nil, false
	}
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}
	return user, true
}

// forbiddenLinkFields would let a caller name who is being linked.
var forbiddenLinkFields = []string{
	"principal", "actor", "login", "github_login", "user", "user_id", "subject", "on_behalf_of", "owner",
}

// decodeSurfaceBody decodes a small JSON body, refusing identity fields and
// unknown keys.
func decodeSurfaceBody(w http.ResponseWriter, r *http.Request, v any) bool {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, sidMaxBodyBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeErrorCode(w, http.StatusRequestEntityTooLarge, sidCodeInvalid, "request body exceeds "+strconv.Itoa(sidMaxBodyBytes)+" bytes", nil)
			return false
		}
		writeErrorCode(w, http.StatusBadRequest, sidCodeInvalid, "could not read the body", nil)
		return false
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		writeErrorCode(w, http.StatusBadRequest, sidCodeInvalid, "invalid JSON body", nil)
		return false
	}
	for _, k := range forbiddenLinkFields {
		if _, present := raw[k]; present {
			writeErrorCode(w, http.StatusBadRequest, sidCodeActorNotAccepted,
				"who is linked is taken from authentication; field "+strconv.Quote(k)+" is not accepted", nil)
			return false
		}
	}
	// json.Unmarshal above already refused trailing data.
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErrorCode(w, http.StatusBadRequest, sidCodeInvalid, "invalid body: "+err.Error(), nil)
		return false
	}
	return true
}

func (h *Handlers) auditSurfaceIdentity(r *http.Request, user *auth.User, op, status string, params map[string]string) {
	params["acting_principal"] = user.ID
	h.logAudit(r, audit.Entry{
		UserID:     user.ID,
		Operation:  op,
		Parameters: params,
		Status:     status,
		RiskLevel:  string(operations.RiskMedium),
	})
}

// CreateSurfaceChallenge handles POST /api/v1/surface-identities/challenges.
func (h *Handlers) CreateSurfaceChallenge(w http.ResponseWriter, r *http.Request) {
	user, ok := h.surfaceIdentityUser(w, r)
	if !ok {
		return
	}
	principal, ok := humanPrincipal(user)
	if !ok {
		writeErrorCode(w, http.StatusForbidden, sidCodeHumanOnly,
			"only a human authenticated by GitHub can request a link challenge", nil)
		return
	}
	var body struct {
		Surface string `json:"surface"`
	}
	if !decodeSurfaceBody(w, r, &body) {
		return
	}
	if !surfaceid.IsSurface(body.Surface) {
		writeErrorCode(w, http.StatusBadRequest, sidCodeInvalid, "surface must be telegram or portal", nil)
		return
	}
	c, err := h.opts.SurfaceIdentities.CreateChallenge(r.Context(), principal, body.Surface)
	switch {
	case errors.Is(err, surfaceid.ErrTooManyChallenges):
		writeErrorCode(w, http.StatusTooManyRequests, sidCodeTooMany, "too many open challenges; redeem or wait for one to expire", nil)
		return
	case err != nil:
		slog.Error("surface identity challenge failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not create a challenge")
		return
	}
	// The code is never audited or logged: it is a bearer secret until used.
	h.auditSurfaceIdentity(r, user, "surface_identity.challenge_created", "succeeded",
		map[string]string{"principal": principal, "surface": c.Surface, "challenge_id": c.ID})
	writeJSON(w, http.StatusCreated, map[string]any{"challenge": c})
}

// RedeemSurfaceChallenge handles POST /api/v1/surface-identities/redeem.
func (h *Handlers) RedeemSurfaceChallenge(w http.ResponseWriter, r *http.Request) {
	user, ok := h.surfaceIdentityUser(w, r)
	if !ok {
		return
	}
	surface, isSurface := user.Surface()
	if !isSurface {
		writeErrorCode(w, http.StatusForbidden, sidCodeSurfaceOnly,
			"only a surface principal can redeem a challenge", nil)
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if !decodeSurfaceBody(w, r, &body) {
		return
	}
	// The identity the surface observed travels in the same header on every
	// surface call, so the rate limiters key on it here too.
	externalID := r.Header.Get(SurfaceActorHeader)
	if !surfaceid.ValidExternalID(surface, externalID) {
		writeErrorCode(w, http.StatusBadRequest, sidCodeInvalid,
			SurfaceActorHeader+" must name a valid "+surface+" identity", nil)
		return
	}
	link, err := h.opts.SurfaceIdentities.Redeem(r.Context(), surface, body.Code, externalID)
	params := map[string]string{"surface": surface, "external_id": externalID}
	var ce *surfaceid.ChallengeError
	switch {
	case errors.As(err, &ce):
		params["reason"] = ce.Reason
		h.auditSurfaceIdentity(r, user, "surface_identity.redeem_refused", "failed", params)
		writeErrorCode(w, http.StatusForbidden, sidCodeChallengeInvalid,
			"the challenge is unknown, used, expired or for another surface", nil)
		return
	case errors.Is(err, surfaceid.ErrLinkConflict):
		params["reason"] = surfaceid.ReasonConflict
		h.auditSurfaceIdentity(r, user, "surface_identity.redeem_refused", "failed", params)
		writeErrorCode(w, http.StatusConflict, sidCodeLinkConflict,
			"this identity is linked to another principal; that link must be revoked first", nil)
		return
	case errors.Is(err, surfaceid.ErrInvalid):
		writeErrorCode(w, http.StatusBadRequest, sidCodeInvalid, err.Error(), nil)
		return
	case err != nil:
		slog.Error("surface identity redeem failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not redeem the challenge")
		return
	}
	params["link_id"] = link.ID
	params["subject"] = link.Principal
	h.auditSurfaceIdentity(r, user, "surface_identity.linked", "succeeded", params)
	writeJSON(w, http.StatusCreated, map[string]any{"link": link})
}

// ListSurfaceIdentities handles GET /api/v1/surface-identities: the caller's
// own links; an admin may pass ?principal=github:<login>.
func (h *Handlers) ListSurfaceIdentities(w http.ResponseWriter, r *http.Request) {
	user, ok := h.surfaceIdentityUser(w, r)
	if !ok {
		return
	}
	principal := r.URL.Query().Get("principal")
	switch {
	case principal != "" && (!user.IsAdmin() || user.IsService()):
		writeErrorCode(w, http.StatusForbidden, sidCodeHumanOnly, "only an admin may list another principal's links", nil)
		return
	case principal == "":
		p, ok := humanPrincipal(user)
		if !ok {
			writeErrorCode(w, http.StatusForbidden, sidCodeHumanOnly, "only a human authenticated by GitHub has links", nil)
			return
		}
		principal = p
	}
	links, err := h.opts.SurfaceIdentities.Links(r.Context(), principal)
	if err != nil {
		slog.Error("surface identity list failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not list links")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"principal": principal, "links": links})
}

// RevokeSurfaceIdentity handles POST /api/v1/surface-identities/{id}/revoke:
// the link's own principal, or a human admin. The service principal is an
// admin too, but links are a human matter: it gets no say over them.
func (h *Handlers) RevokeSurfaceIdentity(w http.ResponseWriter, r *http.Request) {
	user, ok := h.surfaceIdentityUser(w, r)
	if !ok {
		return
	}
	by, human := humanPrincipal(user)
	if !human {
		writeErrorCode(w, http.StatusForbidden, sidCodeHumanOnly, "only the linked human or a human admin can revoke a link", nil)
		return
	}
	link, err := h.opts.SurfaceIdentities.Revoke(r.Context(), chi.URLParam(r, "id"), by, user.IsAdmin())
	switch {
	case errors.Is(err, surfaceid.ErrLinkNotFound):
		writeErrorCode(w, http.StatusNotFound, sidCodeNotFound, "link not found", nil)
		return
	case err != nil:
		slog.Error("surface identity revoke failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not revoke the link")
		return
	}
	h.auditSurfaceIdentity(r, user, "surface_identity.revoked", "succeeded",
		map[string]string{"link_id": link.ID, "surface": link.Surface, "external_id": link.ExternalID, "subject": link.Principal})
	writeJSON(w, http.StatusOK, map[string]any{"link": link})
}
