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
	"errors"
	"log/slog"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/principals"
	"github.com/mctlhq/mctl-api/internal/surfaceid"
)

// POST /api/v1/surface-principals/zitadel (mctl-web site onboarding, stage
// C0). The portal resolves a self-service customer to a principal by the
// ID token the customer signed in with: the mctl-web site's token when a
// workspace is created (purpose "create"), the portal's own at sign-in
// (purpose "signin"). mctl-api verifies the token itself (signature, issuer,
// expiry, and that it was issued to the client the purpose names) and keys
// the principal on the GitHub id the identity hook proved, never on a login.
//
// Only the portal surface may call it, naming the token's subject as its
// actor (zitadel:<sub>), so the per-actor rate limits key on the customer.

const (
	surfaceZitadelPurposeCreate = "create"
	surfaceZitadelPurposeSignin = "signin"

	sidCodeTokenInvalid     = "id_token_invalid"
	sidCodeNotCustomer      = "not_a_customer"
	sidCodeCustomerUnproven = "customer_unproven"
	sidCodeCustomerConflict = "customer_conflict"
)

// SurfaceZitadelOptions configures the route. Nil leaves it answering 503.
type SurfaceZitadelOptions struct {
	// ProviderName, Issuer and CustomersOrgID come from the MCTL_OIDC_PROVIDERS
	// entry with customers_org_id, so the identity resolved here is the one
	// the bearer path and the OAuth sign-in resolve.
	ProviderName   string
	Issuer         string
	CustomersOrgID string
	// CreateClientID is the mctl-web site's client (purpose "create");
	// SigninClientID the portal's (purpose "signin"). An empty one leaves
	// its purpose answering 503.
	CreateClientID string
	SigninClientID string
}

type surfaceZitadel struct {
	opts *SurfaceZitadelOptions
	lazyOIDCProvider
}

func (z *surfaceZitadel) clientFor(purpose string) (string, bool) {
	switch purpose {
	case surfaceZitadelPurposeCreate:
		return z.opts.CreateClientID, true
	case surfaceZitadelPurposeSignin:
		return z.opts.SigninClientID, true
	}
	return "", false
}

// ResolveZitadelPrincipal handles POST /api/v1/surface-principals/zitadel.
func (h *Handlers) ResolveZitadelPrincipal(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if surface, ok := user.Surface(); !ok || surface != surfaceid.SurfacePortal {
		writeErrorCode(w, http.StatusForbidden, sidCodePortalOnly,
			"only the portal surface principal can resolve a ZITADEL customer to a principal", nil)
		return
	}
	z := h.surfaceZitadel
	if z == nil || h.opts.Principals == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, sidCodeUnavailable, "ZITADEL customer resolution is not configured", nil)
		return
	}
	var body struct {
		IDToken string `json:"idToken"`
		Purpose string `json:"purpose"`
	}
	if !decodeSurfaceBody(w, r, &body) {
		return
	}
	clientID, known := z.clientFor(body.Purpose)
	switch {
	case !known:
		writeErrorCode(w, http.StatusBadRequest, sidCodeInvalid, `purpose must be "create" or "signin"`, nil)
		return
	case body.IDToken == "":
		writeErrorCode(w, http.StatusBadRequest, sidCodeInvalid, "idToken is required", nil)
		return
	case clientID == "":
		writeErrorCode(w, http.StatusServiceUnavailable, sidCodeUnavailable, "purpose "+body.Purpose+" is not configured", nil)
		return
	}
	prov, err := z.oidcProvider(r.Context())
	if err != nil {
		slog.Warn("surface-principals/zitadel: ZITADEL discovery failed", "issuer", z.opts.Issuer, "error", err)
		writeErrorCode(w, http.StatusServiceUnavailable, sidCodeUnavailable, "ZITADEL is not reachable right now", nil)
		return
	}
	// Verify checks the signature, the issuer, expiry and that clientID is
	// an audience; azp then says the token was issued to that client, not
	// to another one in the same project.
	idt, err := prov.Verifier(&oidc.Config{ClientID: clientID}).Verify(r.Context(), body.IDToken)
	var claims map[string]any
	if err == nil {
		err = idt.Claims(&claims)
	}
	if err == nil {
		if azp, _ := claims["azp"].(string); azp != clientID {
			err = errors.New("the token was issued to another client (azp)")
		}
	}
	if err != nil {
		slog.Warn("surface-principals/zitadel: ID token refused", "purpose", body.Purpose, "error", err)
		writeErrorCode(w, http.StatusUnauthorized, sidCodeTokenInvalid, "the ID token is not valid for purpose "+body.Purpose, nil)
		return
	}
	if actor := r.Header.Get(SurfaceActorHeader); actor != "zitadel:"+idt.Subject {
		writeErrorCode(w, http.StatusBadRequest, sidCodeInvalid, SurfaceActorHeader+" must be zitadel:<sub> of the ID token", nil)
		return
	}

	params := map[string]string{"purpose": body.Purpose, "zitadel_subject": idt.Subject}
	customer, err := auth.ReadCustomerProof(claims, z.opts.CustomersOrgID)
	switch {
	case errors.Is(err, auth.ErrCustomerUnproven):
		params["reason"] = sidCodeCustomerUnproven
		h.auditSurfaceIdentity(r, user, "principal.resolve_zitadel_refused", "failed", params)
		writeErrorCode(w, http.StatusForbidden, sidCodeCustomerUnproven, "the customer token carries no proven GitHub identity", nil)
		return
	case err != nil:
		// The organization could not be observed: never "not a customer".
		writeErrorCode(w, http.StatusUnauthorized, sidCodeTokenInvalid, "the ID token does not name its user's organization", nil)
		return
	case customer == nil:
		writeErrorCode(w, http.StatusBadRequest, sidCodeNotCustomer, "the ID token is not a self-service customer's", nil)
		return
	}
	params["github_id"], params["github_login"] = customer.GitHubID, customer.GitHubLogin
	display, _ := claims["preferred_username"].(string)
	if display == "" {
		display = idt.Subject
	}
	pid, err := h.opts.Principals.ResolvePrincipal(r.Context(), auth.Identity{
		Provider: z.opts.ProviderName, Issuer: idt.Issuer, Subject: idt.Subject, Display: display,
		Kind: auth.KindHuman, Customer: customer,
	})
	refuse := func(status int, code, msg string) {
		params["reason"] = code
		h.auditSurfaceIdentity(r, user, "principal.resolve_zitadel_refused", "failed", params)
		writeErrorCode(w, status, code, msg, nil)
	}
	switch {
	case errors.Is(err, principals.ErrCustomerConflict):
		refuse(http.StatusConflict, sidCodeCustomerConflict, "this ZITADEL identity belongs to another principal than its GitHub id; a platform admin must resolve it")
		return
	case errors.Is(err, auth.ErrPrincipalDisabled):
		refuse(http.StatusForbidden, sidCodePrincipalDisabled, "the customer's principal is disabled")
		return
	case errors.Is(err, auth.ErrIdentityRefused):
		refuse(http.StatusForbidden, sidCodeIdentityRefused, "the customer's identity is refused")
		return
	case err != nil:
		slog.Warn("surface-principals/zitadel: resolution failed", "github_id", customer.GitHubID, "error", err)
		writeErrorCode(w, http.StatusServiceUnavailable, sidCodeUnavailable, "could not resolve the customer right now", nil)
		return
	case !auth.ValidPrincipalID(pid):
		slog.Error("principal resolver returned no valid principal id", "github_id", customer.GitHubID, "principal", pid)
		writeErrorCode(w, http.StatusServiceUnavailable, sidCodeUnavailable, "could not resolve the customer right now", nil)
		return
	}
	params["principal_id"] = pid
	h.auditSurfaceIdentity(r, user, "principal.resolve_zitadel", "succeeded", params)
	writeJSON(w, http.StatusOK, map[string]string{
		"principalId": pid, "githubId": customer.GitHubID, "githubLogin": customer.GitHubLogin,
	})
}
