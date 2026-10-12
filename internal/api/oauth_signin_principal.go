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
	"strconv"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// githubSigninIdentity is the identity a GitHub OAuth sign-in proved: by
// numeric id when GitHub reported one, else (never in practice) the login.
func githubSigninIdentity(login string, githubID int64) auth.Identity {
	id := auth.Identity{Provider: auth.ProviderGitHub, Display: login, Kind: auth.KindHuman}
	if githubID > 0 {
		id.Subject = strconv.FormatInt(githubID, 10)
	}
	return id
}

// signinPrincipal resolves the principal an OAuth sign-in mints its tokens
// for, recorded as their pid claim (mctl-api#377). When the sign-in must
// stop it writes the response and answers a non-empty result for the
// sign-in metric (principal_refused or principal_unavailable):
//
//   - a disabled or refused principal, in every mode: every request with
//     the token would be refused anyway;
//   - in principal mode, any other failure, since a token with no principal
//     is refused there on every request.
//
// Outside principal mode any other failure mints without a principal, as
// before; the request path still resolves one per request.
func (h *Handlers) signinPrincipal(w http.ResponseWriter, r *http.Request, id auth.Identity) (prn, stopped string) {
	principalMode := h.opts.TenantAuthzMode == TenantAuthzPrincipal
	if h.opts.Principals == nil {
		if principalMode {
			renderSigninUnavailable(w)
			return "", "principal_unavailable"
		}
		return "", ""
	}
	prn, err := h.opts.Principals.ResolvePrincipal(r.Context(), id)
	switch {
	case err == nil:
		return prn, ""
	case errors.Is(err, auth.ErrPrincipalDisabled), errors.Is(err, auth.ErrIdentityRefused):
		slog.Warn("oauth: sign-in refused for its principal", "provider", id.Provider, "display", id.Display, "error", err)
		renderOAuthPage(w, http.StatusForbidden, oauthPageData{Title: "Sign-in refused", Lines: []string{
			"This account is disabled on mctl. Ask a platform admin if you think that is a mistake.",
		}})
		return "", "principal_refused"
	case principalMode:
		slog.Warn("oauth: principal not resolved; sign-in refused", "provider", id.Provider, "display", id.Display, "error", err)
		renderSigninUnavailable(w)
		return "", "principal_unavailable"
	default:
		slog.Warn("oauth: principal not resolved; minting without one", "provider", id.Provider, "display", id.Display, "error", err)
		return "", ""
	}
}

func renderSigninUnavailable(w http.ResponseWriter) {
	renderOAuthPage(w, http.StatusServiceUnavailable, oauthPageData{Title: "Sign-in unavailable", Lines: []string{
		"mctl cannot look up your account right now, so it cannot sign you in. Try again later.",
	}})
}
