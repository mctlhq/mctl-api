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
//  1. The human (authenticated directly) asks for a challenge for one
//     surface. A GitHub-verified human is linked as github:<login>, a human
//     with no GitHub identity as its canonical principal (mctl-api#646).
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
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/surfaceid"
)

// SurfaceActorHeader names the surface-native end user (a Telegram user id,
// a portal subject) a surface principal is calling for. Only a surface
// principal may send it. On redeem, the per-user rate limits key the
// surface principal's budget on it, so one end user cannot spend the whole
// surface's budget; on a relay route they count against the linked human.
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
	// sidCodePrincipalModeRequired refuses a prn_ link outside principal
	// mode (mctl-api#646).
	sidCodePrincipalModeRequired = "principal_mode_required"
	sidMaxBodyBytes              = 4 << 10
)

// surfaceRoute is one route a surface principal may call. relay routes run
// as the linked human (the subject), never as the surface principal; the
// rest run as the surface principal itself.
type surfaceRoute struct {
	method  string
	pattern *regexp.Regexp
	relay   bool
}

// surfaceRoutes are the only routes a surface principal may call. Anything
// else answers 403 before any handler runs: a surface credential is a narrow
// relay capability, not an API key. Relay is opt-in per route, here.
var surfaceRoutes = []surfaceRoute{
	{http.MethodGet, regexp.MustCompile(`^/api/v1/surface-principals/workspace-access/[^/]+$`), false},
	{http.MethodPost, regexp.MustCompile(`^/api/v1/surface-identities/redeem$`), false},
	// The portal surface resolves a tenant creator's GitHub login to a
	// principal (mctl-api#377); the handler refuses every other surface.
	{http.MethodPost, regexp.MustCompile(`^/api/v1/surface-principals/github$`), false},
	// The portal surface resolves a self-service customer by the ZITADEL
	// ID token the customer signed in with (mctl-web site onboarding, C0).
	{http.MethodPost, regexp.MustCompile(`^/api/v1/surface-principals/zitadel$`), false},
	// Who the API resolved the relayed call to (mctl-api#376 D3): the
	// surface as actor, the linked human as subject.
	{http.MethodGet, regexp.MustCompile(`^/api/v1/identity/self$`), true},
	// Human input (mctl-api#261): see and answer what the linked human may.
	{http.MethodGet, regexp.MustCompile(`^/api/v1/human-input$`), true},
	{http.MethodGet, regexp.MustCompile(`^/api/v1/human-input/[^/]+$`), true},
	{http.MethodPost, regexp.MustCompile(`^/api/v1/human-input/[^/]+/response$`), true},
	// Work items (workitem/v1): the surface operations of the contract.
	{http.MethodPost, regexp.MustCompile(`^/api/v1/work-items$`), true},
	{http.MethodGet, regexp.MustCompile(`^/api/v1/work-items/[^/]+$`), true},
	{http.MethodPost, regexp.MustCompile(`^/api/v1/work-items/[^/]+/intents$`), true},
	{http.MethodPost, regexp.MustCompile(`^/api/v1/work-items/[^/]+/surface-refs$`), true},
	// Intent reads (mctl-api#430): relayed, so they run as the linked human
	// and inherit that human's visibility -- never admin.
	{http.MethodGet, regexp.MustCompile(`^/api/v1/work-items/[^/]+/intents$`), true},
	{http.MethodGet, regexp.MustCompile(`^/api/v1/work-items/[^/]+/intents/[^/]+$`), true},
	// Execution requests (mctl-api#368): a surface REQUESTS execution and
	// never declares its identity. POST /work-items/{id}/resume is
	// deliberately absent: it takes engine and engine_ref, which only the
	// execution platform supplies (by fulfilling a request).
	{http.MethodPost, regexp.MustCompile(`^/api/v1/work-items/[^/]+/execution-requests$`), true},
	{http.MethodGet, regexp.MustCompile(`^/api/v1/work-items/[^/]+/execution-requests$`), true},
	{http.MethodGet, regexp.MustCompile(`^/api/v1/work-items/[^/]+/execution-requests/[^/]+$`), true},
	// Work-item history (mctl-api#436): read-only and relayed, so a surface
	// sees exactly what the linked human sees. A relayed snapshot read is
	// metadata only (GetWorkItemSnapshot); GET .../executions/{id}/snapshot
	// stays off the allowlist because it serves the canonical bytes.
	{http.MethodGet, regexp.MustCompile(`^/api/v1/work-items/[^/]+/executions$`), true},
	{http.MethodGet, regexp.MustCompile(`^/api/v1/work-items/[^/]+/snapshots$`), true},
	{http.MethodGet, regexp.MustCompile(`^/api/v1/work-items/[^/]+/snapshots/[^/]+$`), true},
	{http.MethodGet, regexp.MustCompile(`^/api/v1/work-items/[^/]+/events$`), true},
	{http.MethodGet, regexp.MustCompile(`^/api/v1/work-items/[^/]+/evidence$`), true},
}

const (
	sidCodeRelayRequired = "relay_required"
	sidCodeLinkRevoked   = "link_revoked"
	sidCodeLinkExpired   = "link_expired"
	// sidCodePrincipalDisabled: the linked human's principal is disabled.
	sidCodePrincipalDisabled = "principal_disabled"
	// sidCodeIdentityRefused: the linked human's GitHub identity is refused
	// (revoked), exactly as it would be at direct authentication.
	sidCodeIdentityRefused = "identity_refused"
)

// surfacePrincipalGate confines surface principals to surfaceRoutes, turns a
// relay route's surface principal into the linked human, and refuses the
// surface-actor header from anyone else.
//
// Relay resolves here, in one place, rather than per route: a relay route
// can then never be reached by a surface principal as itself. The
// header-keyed rate limiters run after the gate and trust the header only
// because it has passed here; the per-surface ceiling deliberately runs
// before it (see router.go).
func (h *Handlers) surfacePrincipalGate(next http.Handler) http.Handler {
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
			if r.Method != route.method || !route.pattern.MatchString(r.URL.Path) {
				continue
			}
			// The rate limiters key on this value: it must be one of the
			// surface's own ids, not arbitrary bytes.
			if actor := r.Header.Get(SurfaceActorHeader); actor != "" && !surfaceid.ValidExternalID(surface, actor) {
				writeErrorCode(w, http.StatusBadRequest, sidCodeInvalid,
					SurfaceActorHeader+" is not a valid "+surface+" identity", nil)
				return
			}
			if !route.relay {
				// Redeem: the surface acts as itself, naming the identity
				// it observed. Required here, so no limiter ever keys on
				// an absent one.
				if r.Header.Get(SurfaceActorHeader) == "" {
					writeErrorCode(w, http.StatusBadRequest, sidCodeInvalid,
						SurfaceActorHeader+" must name the "+surface+" identity", nil)
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			subject, ok := h.relaySubject(w, r, user)
			if !ok {
				return
			}
			next.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), subject)))
			return
		}
		writeErrorCode(w, http.StatusForbidden, sidCodeRouteNotAllowed,
			"a surface principal may not call "+r.Method+" "+r.URL.Path, nil)
	})
}

// relaySubject resolves the human a surface principal speaks for: the
// verified link for (its own surface, the X-MCTL-Surface-Actor id). Every
// gap fails closed with a typed 403, or 503 when links cannot be read.
func (h *Handlers) relaySubject(w http.ResponseWriter, r *http.Request, acting *auth.User) (*auth.User, bool) {
	surface, _ := acting.Surface()
	externalID := r.Header.Get(SurfaceActorHeader)
	refuse := func(code, msg string) (*auth.User, bool) {
		h.logAudit(r, audit.Entry{
			UserID: acting.ID, Operation: "surface_identity.relay_refused", Status: "failed",
			RiskLevel:  string(operations.RiskMedium),
			Parameters: map[string]string{"acting_principal": acting.ID, "surface": surface, "external_id": externalID, "reason": code},
		})
		writeErrorCode(w, http.StatusForbidden, code, msg, nil)
		return nil, false
	}
	if externalID == "" {
		return refuse(sidCodeRelayRequired, "a surface principal must name the linked actor in "+SurfaceActorHeader)
	}
	if h.opts.SurfaceIdentities == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, sidCodeUnavailable, "surface identity store not configured", nil)
		return nil, false
	}
	link, err := h.opts.SurfaceIdentities.Resolve(r.Context(), surface, externalID)
	switch {
	case errors.Is(err, surfaceid.ErrLinkRevoked):
		return refuse(sidCodeLinkRevoked, "the link for this "+surface+" identity was revoked")
	case errors.Is(err, surfaceid.ErrLinkExpired):
		return refuse(sidCodeLinkExpired, "the link for this "+surface+" identity expired")
	case errors.Is(err, surfaceid.ErrLinkNotFound):
		return refuse(sidCodeNotFound, "no verified link for this "+surface+" identity")
	case err != nil:
		slog.Error("surface relay resolve failed", "error", err)
		writeErrorCode(w, http.StatusServiceUnavailable, sidCodeUnavailable, "could not resolve the surface identity", nil)
		return nil, false
	}
	if surfaceid.IsPrincipalID(link.Principal) {
		return h.relayPrincipalSubject(w, r, acting, link, refuse)
	}
	login, isGitHub := strings.CutPrefix(link.Principal, "github:")
	if !isGitHub || login == "" {
		return refuse(sidCodeNotFound, "the link does not name a GitHub principal")
	}
	var groups []string
	// In principal mode the subject's tenants come from its principal
	// (authorizeSubject below), never from its login.
	if h.opts.TenantResolver != nil && !h.principalMode() {
		// Same as authentication: a failed lookup grants no tenant, even
		// if the resolver returned a partial list alongside the error.
		if g, err := h.opts.TenantResolver.GetTenantsForUser(login); err != nil {
			slog.Warn("surface relay: tenant lookup failed; relaying with no tenant access", "subject", link.Principal, "error", err)
		} else {
			groups = g
		}
	}
	// Never nil here: acting is a surface principal and login is set.
	subject := auth.NewRelayedUser(login, groups, acting)
	// The human's canonical principal, the same way authentication resolves
	// a direct caller: whatever authentication refuses (a disabled
	// principal, a revoked identity) is refused here too, so a surface never
	// carries someone the direct path would turn away. Anything else relays
	// without a principal id (phase 1 records, it does not authorize).
	if err := auth.AttachPrincipal(r.Context(), h.opts.Principals, subject); err != nil {
		switch {
		case errors.Is(err, auth.ErrPrincipalDisabled):
			return refuse(sidCodePrincipalDisabled, "the principal linked to this "+surface+" identity is disabled")
		case errors.Is(err, auth.ErrIdentityRefused):
			return refuse(sidCodeIdentityRefused, "the identity linked to this "+surface+" identity is refused")
		}
		slog.Warn("surface relay: principal not resolved; relaying without a principal id", "subject", link.Principal, "error", err)
	}
	// In principal mode a subject without a principal is refused here, as
	// delegation refuses it (design.md B5): its tenants cannot be decided.
	if err := h.authorizeSubject(subject); err != nil {
		slog.Warn("surface relay: tenant access undecided", "subject", link.Principal, "principal", subject.PrincipalID(), "error", err)
		writeErrorCode(w, http.StatusServiceUnavailable, sidCodeUnavailable, "cannot determine the relayed subject's tenant access right now", nil)
		return nil, false
	}
	return subject, true
}

// relayPrincipalSubject is relaySubject for a link that names a canonical
// principal (mctl-api#646). The principal is the authority and the link's
// recorded oidc: name is the subject's name. Unlike a github: link, a
// principal that cannot be checked is refused (503), never relayed without
// one: the principal is all this subject is.
func (h *Handlers) relayPrincipalSubject(w http.ResponseWriter, r *http.Request, acting *auth.User, link *surfaceid.Link,
	refuse func(code, msg string) (*auth.User, bool)) (*auth.User, bool) {
	surface, _ := acting.Surface()
	name, ok := strings.CutPrefix(link.Subject, "oidc:")
	if !ok || name == "" {
		return refuse(sidCodeNotFound, "the link does not name a human principal")
	}
	subject := auth.NewRelayedPrincipalUser(name, link.Principal, acting)
	if subject == nil {
		return refuse(sidCodeNotFound, "the link does not name a human principal")
	}
	if err := auth.AttachPrincipal(r.Context(), h.opts.Principals, subject); err != nil {
		switch {
		case errors.Is(err, auth.ErrPrincipalDisabled):
			return refuse(sidCodePrincipalDisabled, "the principal linked to this "+surface+" identity is disabled")
		case errors.Is(err, auth.ErrIdentityRefused):
			return refuse(sidCodeIdentityRefused, "the principal linked to this "+surface+" identity is refused")
		}
		slog.Error("surface relay: linked principal could not be checked", "principal", link.Principal, "error", err)
		writeErrorCode(w, http.StatusServiceUnavailable, sidCodeUnavailable, "could not verify the linked principal", nil)
		return nil, false
	}
	if subject.PrincipalID() != link.Principal {
		// AttachPrincipal keeps a token principal or clears it while
		// returning an error (refused above); kept so a change there cannot
		// swap the relayed principal.
		return refuse(sidCodeNotFound, "the link does not name a resolvable principal")
	}
	if err := h.authorizeSubject(subject); err != nil {
		slog.Warn("surface relay: tenant access undecided", "subject", link.Subject, "principal", link.Principal, "error", err)
		writeErrorCode(w, http.StatusServiceUnavailable, sidCodeUnavailable, "cannot determine the relayed subject's tenant access right now", nil)
		return nil, false
	}
	return subject, true
}

// humanPrincipal is who a caller may link, acting directly: a GitHub login
// proven by authentication as github:<login> (subject ""), or else a human
// whose canonical principal authentication resolved, as that prn_ with its
// request name principalOf(u) as subject (mctl-api#646). Never the service
// principal, a surface, an agent, or a relayed or delegated subject.
func humanPrincipal(u *auth.User) (principal, subject string, ok bool) {
	if u.IsService() || u.ActingPrincipal() != "" {
		// Nor a relayed subject: a link is made by the human directly.
		return "", "", false
	}
	if _, isSurface := u.Surface(); isSurface {
		return "", "", false
	}
	if login, ok := u.GitHubLogin(); ok {
		return "github:" + login, "", true
	}
	// An agent, a service or a surface has an identity of another kind.
	id, ok := u.Identity()
	if !ok || id.Kind != auth.KindHuman {
		return "", "", false
	}
	pid := u.PrincipalID()
	if !auth.ValidPrincipalID(pid) {
		return "", "", false
	}
	return pid, principalOf(u), true
}

// ownHolders is every holder form a human acting directly holds links under:
// humanPrincipal's, and for a GitHub session whose canonical principal
// resolved, that prn_ too. One human can sign in through GitHub and through
// ZITADEL onto one principal (mctl-api#646), and a link made in the ZITADEL
// session must stay theirs to list and revoke from the GitHub one.
func ownHolders(u *auth.User, primary string) []string {
	owners := []string{primary}
	if strings.HasPrefix(primary, "github:") {
		if pid := u.PrincipalID(); auth.ValidPrincipalID(pid) {
			owners = append(owners, pid)
		}
	}
	return owners
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
	return decodeSurfaceBodyLimit(w, r, v, sidMaxBodyBytes)
}

// decodeSurfaceBodyLimit is decodeSurfaceBody with its own size limit.
func decodeSurfaceBodyLimit(w http.ResponseWriter, r *http.Request, v any, limit int) bool {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(limit)))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeErrorCode(w, http.StatusRequestEntityTooLarge, sidCodeInvalid, "request body exceeds "+strconv.Itoa(limit)+" bytes", nil)
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
	principal, subject, ok := humanPrincipal(user)
	if !ok {
		writeErrorCode(w, http.StatusForbidden, sidCodeHumanOnly,
			"only a human acting directly, with a resolved principal, can request a link challenge", nil)
		return
	}
	if subject != "" && !h.principalMode() {
		// A prn_ link relays a subject whose tenants come from its
		// principal, and only principal mode resolves them: outside it the
		// link would be made and then refused on every tenant-scoped call.
		writeErrorCode(w, http.StatusForbidden, sidCodePrincipalModeRequired,
			"linking an account without a GitHub login requires TENANT_AUTHZ_MODE=principal", nil)
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
	c, err := h.opts.SurfaceIdentities.CreateChallenge(r.Context(), principal, subject, body.Surface)
	switch {
	case errors.Is(err, surfaceid.ErrInvalid):
		// A name the link cannot record (validHolder); the surface was
		// checked above.
		writeErrorCode(w, http.StatusForbidden, sidCodeHumanOnly, "this account cannot hold a surface link", nil)
		return
	case errors.Is(err, surfaceid.ErrTooManyChallenges):
		writeErrorCode(w, http.StatusTooManyRequests, sidCodeTooMany, "too many open challenges; redeem or wait for one to expire", nil)
		return
	case err != nil:
		slog.Error("surface identity challenge failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not create a challenge")
		return
	}
	// The code is never audited or logged: it is a bearer secret until used.
	params := map[string]string{"principal": principal, "surface": c.Surface, "challenge_id": c.ID}
	if subject != "" {
		params["subject"] = subject
	}
	h.auditSurfaceIdentity(r, user, "surface_identity.challenge_created", "succeeded", params)
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
	if old := link.Retired; old != nil {
		// Retiring someone's expired link is a state change like any
		// revoke: it leaves a trace.
		h.auditSurfaceIdentity(r, user, "surface_identity.revoked", "succeeded", map[string]string{
			"link_id": old.ID, "surface": old.Surface, "external_id": old.ExternalID,
			"subject": old.Principal, "revoked_by": old.RevokedBy,
		})
	}
	params["link_id"] = link.ID
	params["subject"] = link.Principal
	h.auditSurfaceIdentity(r, user, "surface_identity.linked", "succeeded", params)
	writeJSON(w, http.StatusCreated, map[string]any{"link": link})
}

// ListSurfaceIdentities handles GET /api/v1/surface-identities: the caller's
// own links; an admin may pass ?principal=github:<login> or ?principal=prn_….
func (h *Handlers) ListSurfaceIdentities(w http.ResponseWriter, r *http.Request) {
	user, ok := h.surfaceIdentityUser(w, r)
	if !ok {
		return
	}
	// Same reading as revoke: a human acting directly first, and only then,
	// if an admin, anyone's links.
	own, _, ok := humanPrincipal(user)
	if !ok {
		writeErrorCode(w, http.StatusForbidden, sidCodeHumanOnly, "only a human acting directly has links", nil)
		return
	}
	owners := ownHolders(user, own)
	principal := r.URL.Query().Get("principal")
	holders := []string{principal}
	switch {
	case principal == "":
		principal, holders = own, owners
	case !slices.Contains(owners, principal) && !user.IsAdmin():
		writeErrorCode(w, http.StatusForbidden, sidCodeHumanOnly, "only an admin may list another principal's links", nil)
		return
	}
	links := []surfaceid.Link{}
	for _, holder := range holders {
		held, err := h.opts.SurfaceIdentities.Links(r.Context(), holder)
		if err != nil {
			slog.Error("surface identity list failed", "error", err)
			writeError(w, http.StatusInternalServerError, "could not list links")
			return
		}
		links = append(links, held...)
	}
	if len(holders) > 1 {
		// Each holder's list is newest first; keep the merged one so.
		sort.SliceStable(links, func(i, j int) bool { return links[i].CreatedAt.After(links[j].CreatedAt) })
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
	by, _, human := humanPrincipal(user)
	if !human {
		writeErrorCode(w, http.StatusForbidden, sidCodeHumanOnly, "only the linked human or a human admin can revoke a link", nil)
		return
	}
	link, err := h.opts.SurfaceIdentities.RevokeAs(r.Context(), chi.URLParam(r, "id"), by, ownHolders(user, by), user.IsAdmin())
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
