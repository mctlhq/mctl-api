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
	"regexp"
	"strings"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/surfaceid"
)

// The portal creates tenants itself (its POST /tenants, called by the
// mctl.me signup form, the portal's own page and the Backstage scaffolder)
// and names the creator by GitHub login only. Principal-mode authorization
// grants by the owner entry's principalId (mctl-api#377), so the portal has
// to ask for it: this route resolves the GitHub login named by the actor
// header to its canonical principal, provisioning one the way a first
// sign-in would.
//
// Only the portal surface may call it. It confers nothing the portal does
// not already hold: the portal can already make any login the owner of a
// new tenant, and a principal grants nothing until a member entry names it.

const sidCodePortalOnly = "portal_surface_required"

// githubLoginRE is GitHub's own login grammar: alphanumerics and single
// inner hyphens, at most 39 characters (the repetition bound caps it).
var githubLoginRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9]|-[A-Za-z0-9]){0,38}$`)

// ResolveGitHubPrincipal handles POST /api/v1/surface-principals/github.
func (h *Handlers) ResolveGitHubPrincipal(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if surface, ok := user.Surface(); !ok || surface != surfaceid.SurfacePortal {
		writeErrorCode(w, http.StatusForbidden, sidCodePortalOnly,
			"only the portal surface principal can resolve a GitHub login to a principal", nil)
		return
	}
	if h.opts.Principals == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, sidCodeUnavailable, "principal store not configured", nil)
		return
	}
	// The login is the actor the portal acts for, named by the actor header
	// the surface gate already requires and rate-limits on; the body names
	// nobody (decodeSurfaceBody refuses identity fields) and may only be {}.
	if r.ContentLength != 0 {
		var none struct{}
		if !decodeSurfaceBody(w, r, &none) {
			return
		}
	}
	actor := r.Header.Get(SurfaceActorHeader)
	login, ok := strings.CutPrefix(actor, "github:")
	if !ok || !githubLoginRE.MatchString(login) {
		writeErrorCode(w, http.StatusBadRequest, sidCodeInvalid,
			SurfaceActorHeader+" must be github:<login> with a GitHub login", nil)
		return
	}

	params := map[string]string{"github_login": login}
	pid, err := h.opts.Principals.ResolvePrincipal(r.Context(), auth.Identity{
		Provider: auth.ProviderGitHub, Display: login, Kind: auth.KindHuman,
	})
	switch {
	case errors.Is(err, auth.ErrPrincipalDisabled):
		params["reason"] = sidCodePrincipalDisabled
		h.auditSurfaceIdentity(r, user, "principal.resolve_github_refused", "failed", params)
		writeErrorCode(w, http.StatusForbidden, sidCodePrincipalDisabled, "the principal of this GitHub login is disabled", nil)
		return
	case errors.Is(err, auth.ErrIdentityRefused):
		params["reason"] = sidCodeIdentityRefused
		h.auditSurfaceIdentity(r, user, "principal.resolve_github_refused", "failed", params)
		writeErrorCode(w, http.StatusForbidden, sidCodeIdentityRefused, "this GitHub identity is refused", nil)
		return
	case err != nil:
		slog.Warn("resolving a GitHub login for the portal failed", "login", login, "error", err)
		writeErrorCode(w, http.StatusServiceUnavailable, sidCodeUnavailable, "could not resolve the GitHub login right now", nil)
		return
	case !auth.ValidPrincipalID(pid):
		// A resolver answering without an id is a failed read, never
		// "no principal".
		slog.Error("principal resolver returned no valid principal id", "login", login, "principal", pid)
		writeErrorCode(w, http.StatusServiceUnavailable, sidCodeUnavailable, "could not resolve the GitHub login right now", nil)
		return
	}
	params["principal_id"] = pid
	h.auditSurfaceIdentity(r, user, "principal.resolve_github", "success", params)
	writeJSON(w, http.StatusOK, map[string]string{"principalId": pid})
}
