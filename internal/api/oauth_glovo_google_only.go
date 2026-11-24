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
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// "Google only" on the Glovo resources, in shadow mode (stage D of the Glovo
// self-service onboarding design, section 5.1, decision D5).
//
// The rule being prepared: a code for the Glovo MCP resource or the Glovo
// link resource is issued only to a customers-organization identity proven
// through Google. This file only observes. It decides what the rule would
// do and writes that down; it refuses nothing and has no way to change the
// response, the redirect or the code. The refusal is a later change with its
// own tests, which is why "enforce" does not parse here.

// GlovoGoogleOnlyMode is GLOVO_GOOGLE_ONLY_MODE.
type GlovoGoogleOnlyMode string

const (
	// GlovoGoogleOnlyOff is the default: nothing is evaluated or logged.
	GlovoGoogleOnlyOff GlovoGoogleOnlyMode = "off"
	// GlovoGoogleOnlyShadow evaluates the rule for every Glovo-resource
	// sign-in and logs the decision. It refuses nothing.
	GlovoGoogleOnlyShadow GlovoGoogleOnlyMode = "shadow"
	// glovoGoogleOnlyEnforce is the reserved name of the refusing mode. It
	// is not implemented, so it is refused at boot like any unknown value.
	glovoGoogleOnlyEnforce = "enforce"
)

// ParseGlovoGoogleOnlyMode reads GLOVO_GOOGLE_ONLY_MODE. Empty is off.
// "enforce" and anything unknown are errors, so the boot is refused rather
// than a refusal switched on that has no implementation and no tests, or a
// typo quietly read as off.
func ParseGlovoGoogleOnlyMode(s string) (GlovoGoogleOnlyMode, error) {
	switch m := GlovoGoogleOnlyMode(s); m {
	case "":
		return GlovoGoogleOnlyOff, nil
	case GlovoGoogleOnlyOff, GlovoGoogleOnlyShadow:
		return m, nil
	case glovoGoogleOnlyEnforce:
		return "", fmt.Errorf("GLOVO_GOOGLE_ONLY_MODE=enforce is not implemented in this version: use off or shadow")
	default:
		return "", fmt.Errorf("GLOVO_GOOGLE_ONLY_MODE must be off or shadow, not %q", s)
	}
}

// The provider kinds of a sign-in, as the guard sees them. They say how the
// signed-in identity was proven, which is not the upstream label of the
// sign-in metric.
const (
	// glovoSigninGoogle is a customers-organization identity whose token
	// carries the identity hook's Google proof.
	glovoSigninGoogle = "google"
	// glovoSigninGitHub is a customers-organization identity whose token
	// carries the identity hook's GitHub proof.
	glovoSigninGitHub = "github"
	// glovoSigninStaff is a ZITADEL identity of any other organization:
	// staff and partner accounts. The token does not say how such a user
	// authenticated, so a password, a passkey and an instance-level IdP are
	// all this one kind.
	glovoSigninStaff = "staff"
	// glovoSigninGitHubLegacy is the direct GitHub upstream, which never
	// passes through ZITADEL.
	glovoSigninGitHubLegacy = "github_legacy"
	// glovoSigninUnknown is a provider that could not be determined. It is
	// neither a pass nor a refusal.
	glovoSigninUnknown = "unknown"
)

// The decisions the shadow log carries. Unknown is its own value: a provider
// that could not be observed is never reported as a pass or as a refusal.
const (
	glovoWouldRefuseFalse   = "false"
	glovoWouldRefuseTrue    = "true"
	glovoWouldRefuseUnknown = "unknown"
)

// zitadelSigninProviderKind classifies a completed ZITADEL sign-in.
// customer is the proof readSigninCustomer returned: nil when the verified
// token names another organization.
//
// Without a configured customers organization the callback never reads the
// token's organization, so whether this is a customers identity was not
// observed: unknown, never staff.
func zitadelSigninProviderKind(customersOrgID string, customer *auth.CustomerProof) string {
	switch {
	case customersOrgID == "":
		return glovoSigninUnknown
	case customer == nil:
		return glovoSigninStaff
	case customer.Provider == auth.ProviderGoogle:
		return glovoSigninGoogle
	case customer.Provider == auth.ProviderGitHub:
		return glovoSigninGitHub
	}
	return glovoSigninUnknown
}

// glovoGoogleOnlyWouldRefuse is the rule: only a Google-proven customers
// identity passes. Each known kind is listed, so a kind added later is
// unknown until someone decides it, not a silent pass or refusal.
func glovoGoogleOnlyWouldRefuse(provider string) string {
	switch provider {
	case glovoSigninGoogle:
		return glovoWouldRefuseFalse
	case glovoSigninGitHub, glovoSigninStaff, glovoSigninGitHubLegacy:
		return glovoWouldRefuseTrue
	}
	return glovoWouldRefuseUnknown
}

// maskedPrincipalID is a principal id as the shadow log shows it: the last
// four characters only, enough for an operator who already knows their own
// id to recognise it and not enough to recover one. A value that is not a
// well-formed principal id is never echoed.
func maskedPrincipalID(id string) string {
	switch {
	case id == "":
		return "none"
	case !auth.ValidPrincipalID(id):
		return "invalid"
	}
	return "prn_***" + id[len(id)-4:]
}

var glovoGoogleOnlyShadow = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "oauth_glovo_google_only_shadow_total",
	Help: "Glovo-resource sign-ins evaluated by the Google-only guard in shadow mode, by resource kind, provider kind and the decision it would have made.",
}, []string{"resource", "provider", "would_refuse"})

func init() { prometheus.MustRegister(glovoGoogleOnlyShadow) }

// observeGlovoGoogleOnly records what the Google-only rule would decide for
// a sign-in that is about to be completed. It returns nothing on purpose:
// in shadow mode the caller has no decision to act on. Off, and every
// resource that is not one of the two Glovo resources, do nothing at all.
func (h *Handlers) observeGlovoGoogleOnly(resource, provider, principalID string) {
	if h.opts.GlovoGoogleOnly != GlovoGoogleOnlyShadow {
		return
	}
	o := h.opts.OAuthServer
	var kind string
	switch {
	case o.IsGlovoFlow(resource):
		kind = "mcp"
	case o.IsGlovoLinkFlow(resource):
		kind = "link"
	default:
		return
	}
	wouldRefuse := glovoGoogleOnlyWouldRefuse(provider)
	glovoGoogleOnlyShadow.WithLabelValues(kind, provider, wouldRefuse).Inc()
	slog.Info("oauth: glovo google-only shadow", "mode", string(GlovoGoogleOnlyShadow),
		"would_refuse", wouldRefuse, "provider", provider, "resource", kind, "principal", maskedPrincipalID(principalID))
}
