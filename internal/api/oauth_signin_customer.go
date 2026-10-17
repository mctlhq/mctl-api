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
)

// readSigninCustomer reads the customer proof of a verified ZITADEL ID
// token (stage C0 of mctl-web's site onboarding). It answers (nil, "") for
// a user of another organization. When the sign-in must stop it writes the
// response and answers the sign-in metric's result: a token that does not
// name its organization is a broken sign-in, never "not a customer"; a
// customers token without a proven GitHub identity is refused.
func readSigninCustomer(w http.ResponseWriter, idt *oidc.IDToken, customersOrgID string) (*auth.CustomerProof, string) {
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		slog.Warn("oauth: ZITADEL ID token claims unreadable", "error", err)
		http.Error(w, "the ZITADEL ID token was not valid", http.StatusBadGateway)
		return nil, "invalid_token"
	}
	customer, err := auth.ReadCustomerProof(claims, customersOrgID)
	switch {
	case err == nil:
		return customer, ""
	case errors.Is(err, auth.ErrCustomerUnproven):
		slog.Warn("oauth: ZITADEL customer sign-in without a proven GitHub identity", "zitadel_subject", idt.Subject, "error", err)
		renderOAuthPage(w, http.StatusForbidden, oauthPageData{Title: "Sign-in refused", Lines: []string{
			"Your MCTL account has no GitHub identity MCTL can rely on, so it cannot tell which account you are.",
			"Sign in again with GitHub. If this keeps happening, contact MCTL support.",
		}})
		return nil, "customer_unproven"
	default:
		slog.Error("oauth: ZITADEL ID token does not name its organization", "zitadel_subject", idt.Subject, "error", err)
		http.Error(w, "the ZITADEL ID token does not say which organization you belong to", http.StatusBadGateway)
		return nil, "invalid_token"
	}
}

// customerSigninPrincipal resolves a customer's principal by the GitHub id
// its token proved. Customers sign in only in principal mode: elsewhere a
// token is authorized by a GitHub login and its groups, which a
// self-service account must not borrow. A ZITADEL subject that belongs to
// another principal is a conflict for an admin, not a sign-in.
func (h *Handlers) customerSigninPrincipal(w http.ResponseWriter, r *http.Request, id auth.Identity) (prn, stopped string) {
	if h.opts.TenantAuthzMode != TenantAuthzPrincipal {
		renderOAuthPage(w, http.StatusForbidden, oauthPageData{Title: "Not available yet", Lines: []string{
			"Self-service MCTL accounts cannot connect AI clients yet. Use the portal, or contact MCTL support.",
		}})
		return "", "customer_not_enabled"
	}
	if h.opts.Principals == nil {
		renderSigninUnavailable(w)
		return "", "principal_unavailable"
	}
	prn, err := h.opts.Principals.ResolvePrincipal(r.Context(), id)
	if errors.Is(err, principals.ErrCustomerConflict) {
		slog.Warn("oauth: customer identity conflicts with another principal", "github_id", id.Customer.GitHubID, "zitadel_subject", id.Subject, "error", err)
		renderOAuthPage(w, http.StatusConflict, oauthPageData{Title: "Sign-in refused", Lines: []string{
			"Your MCTL account is already tied to a different MCTL principal than your GitHub account, so MCTL does not guess which one you are.",
			// The usual cause: a staff or partner user who already has a
			// principal pressed the customer entry.
			"If you have an MCTL staff or partner account, start the connection again and choose \"Sign in with MCTL account\" instead of \"Sign in with GitHub\".",
			"Otherwise ask a platform admin to resolve it, quoting GitHub id " + id.Customer.GitHubID + ".",
		}})
		return "", "customer_conflict"
	}
	return signinPrincipalResult(w, id, true, prn, err)
}
