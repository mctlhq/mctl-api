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

package auth

// Federation boundary (mctl-api#374, slice A). This is the seam that turns a
// verified external token into a (provider, issuer, subject) identity, so
// that adding or replacing an identity provider is a configuration change,
// not an edit to auth.Middleware. Everything downstream -- auth.Identity,
// PrincipalResolver, principals.Resolver, the surface-link flow -- is
// unchanged; this file only adds the registry in front of them.
//
// It lives in package auth, not a new top-level package, because *User's
// safety property is that its discriminating fields (service, githubLogin,
// surface, usageWriter, actingPrincipal, ...) are unexported and set only by
// constructors in this package (oidc.go:44-95). A provider in another
// package could not set them without exporting them -- exactly the
// weakening that design avoids. Providers therefore return data (Verified),
// and userFromVerified, the one new place a *User is built, mints the User.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/mctlhq/mctl-api/internal/surfaceid"
)

// Verified is everything a provider may assert about a token it has proven.
// It has no field able to express "speaking for someone else" -- that is
// the non-impersonation invariant of this boundary (issue #374), enforced
// by the type, not by review. actingPrincipal, relaySurface and
// viaPrincipalID stay reachable only through NewRelayedUser (oidc.go:287),
// which no provider can call.
type Verified struct {
	// Identity is what the provider proved: Provider, Issuer, Subject,
	// Display, Kind (principal.go:52-63).
	Identity Identity
	// Claims carries provider-native data that Identity does not model but
	// userFromVerified needs: group memberships, the numeric GitHub id.
	Claims Claims
}

// Claims are the provider-native claims carried alongside an Identity.
// Nothing outside this package's userFromVerified reads them; they exist so
// a provider can hand over data Identity has no field for, without growing
// Identity into a delegation-shaped type.
type Claims struct {
	// Groups are the tenant/group names the provider (or its GroupSource)
	// resolved for this caller.
	Groups []string
	// GitHubID is the numeric GitHub user id, when the provider proved one
	// (the GitHub PAT provider always; the local-OAuth provider only once
	// slice B mints ghid).
	GitHubID int64
}

// tokenShape is computed once per request from the existing isJWT/jwtIssuer
// helpers (oidc.go:218-240): opaque vs. JWT, plus the JWT's unverified iss.
//
// Nothing but routing reads this. The iss it carries is an UNVERIFIED peek
// at a claim inside an unverified signature -- informational for deciding
// which provider to ask, never a trust decision. A provider's Claims method
// must not derive identity, kind, groups or trust from it; only Verify, after
// checking the signature, may do that.
type tokenShape struct {
	jwt bool
	iss string // unverified iss claim; only meaningful when jwt is true.
}

// shapeOf computes the tokenShape of a raw bearer token.
func shapeOf(raw string) tokenShape {
	if !isJWT(raw) {
		return tokenShape{}
	}
	return tokenShape{jwt: true, iss: jwtIssuer(raw)}
}

// normalizeIssuer trims a trailing slash so "https://issuer" and
// "https://issuer/" are recognized as the same issuer both for duplicate
// detection at construction and for exact-match routing at request time.
func normalizeIssuer(iss string) string {
	return strings.TrimSuffix(strings.TrimSpace(iss), "/")
}

// Provider verifies one kind of bearer token and proves an identity in its
// own namespace (design.md "The contract").
type Provider interface {
	// Name is the registry key and the external_identities.provider value
	// this provider's Verified.Identity.Provider must equal (the one
	// modelled exception is the local-OAuth provider, which declares
	// namespace "github" explicitly -- see provider_localoauth.go).
	Name() string
	// Claims decides routing only, from the cheap unverified tokenShape. It
	// must never perform verification or be used to derive trust.
	Claims(t tokenShape) bool
	// Verify proves raw and returns the identity it proves. A static-secret
	// provider that does not recognize raw returns ErrNoProvider so the
	// registry can try the next static-secret provider in order; any other
	// error is a proven-claimed-but-invalid token and is never retried
	// against a different provider.
	Verify(ctx context.Context, raw string) (*Verified, error)
}

// issuerNamer is implemented by every JWT-routed provider (the local-OAuth
// provider, each OIDC provider): the exact issuer it claims, used by the
// registry to build the issuer index and to detect a duplicate issuer at
// construction. Kept separate from Provider because a static-secret or
// opaque provider has no issuer to report.
type issuerNamer interface {
	Provider
	issuerName() string
}

// ErrNoProvider is returned when no registered provider claims a token, and
// (from a static-secret provider's Verify) when that one provider's secret
// does not match this token.
var ErrNoProvider = errors.New("no provider claims this token")

// ErrProviderContractViolation marks a Verified result that failed the
// registry's contract checks: a namespace the provider does not own, an
// empty subject outside the GitHubLoginOnly exception, or an invalid Kind.
var ErrProviderContractViolation = errors.New("provider returned identity outside its contract")

// reservedProviderNames are identity namespaces already owned by a fixed
// built-in principal type; no configured (or otherwise additional) provider
// may declare one. "agent" is reserved for #376's auth.ProviderAgent, so a
// federation provider can never mint an (agent, ...) identity ahead of that
// work landing. "dex" is deliberately NOT in this set: an operator replacing
// the legacy shim with an explicit MCTL_OIDC_PROVIDERS entry is expected to
// keep using the name "dex" so existing external_identities rows keep
// resolving (design.md "Configuration and swappability").
var reservedProviderNames = map[string]bool{
	ProviderGitHub:  true,
	ProviderService: true,
	ProviderDev:     true,
	ProviderAgent:   true,
}

// Registry routes a bearer token to at most one provider and enforces the
// provider contract on its result.
type Registry struct {
	// static are tried first, unconditionally, in the order they were
	// given -- design.md's "unchanged order: service, surface,
	// usage-writer". Each returns ErrNoProvider when its own secret does
	// not match, so the registry tries the next.
	static []Provider
	// jwt providers are claimed by exact match of the token's unverified
	// iss against the provider's own declared issuer.
	jwt []Provider
	// opaque is the last-resort provider for anything that is not a JWT
	// once no static-secret provider matched (the GitHub PAT provider).
	// nil when none is registered.
	opaque Provider
}

// NewRegistry builds a Registry and enforces its construction-time
// invariants (design.md "Registry invariants refused at boot"). static is
// tried in the given order; jwt providers are indexed by their own declared,
// normalized issuer; opaque holds zero or one opaque-token providers.
func NewRegistry(static, jwt, opaque []Provider) (*Registry, error) {
	if len(opaque) > 1 {
		names := make([]string, len(opaque))
		for i, p := range opaque {
			names[i] = p.Name()
		}
		return nil, fmt.Errorf("federation: more than one opaque-token provider registered (%s): an opaque token carries nothing to route on", strings.Join(names, ", "))
	}

	seenNames := map[string]bool{}
	seenIssuers := map[string]string{} // normalized issuer -> provider name
	for _, p := range jwt {
		name := p.Name()
		if seenNames[name] {
			return nil, fmt.Errorf("federation: duplicate provider name %q", name)
		}
		seenNames[name] = true

		// The local-OAuth provider is the one modelled exception that may
		// declare the reserved namespace "github" (design.md "The
		// contract"); every other JWT provider is refused.
		if _, exempt := p.(*localOAuthProvider); !exempt && reservedProviderNames[name] {
			return nil, fmt.Errorf("federation: provider name %q is reserved", name)
		}
		if surfaceid.IsSurface(name) {
			return nil, fmt.Errorf("federation: provider name %q collides with a registered surface name", name)
		}

		in, ok := p.(issuerNamer)
		if !ok {
			return nil, fmt.Errorf("federation: JWT-routed provider %q does not declare an issuer", name)
		}
		iss := normalizeIssuer(in.issuerName())
		if iss == "" {
			return nil, fmt.Errorf("federation: provider %q has no issuer", name)
		}
		if other, dup := seenIssuers[iss]; dup {
			return nil, fmt.Errorf("federation: providers %q and %q both claim issuer %q", other, name, iss)
		}
		seenIssuers[iss] = name
	}

	if len(opaque) == 1 {
		name := opaque[0].Name()
		if reservedProviderNames[name] && name != ProviderGitHub {
			return nil, fmt.Errorf("federation: provider name %q is reserved", name)
		}
	}

	r := &Registry{static: append([]Provider(nil), static...), jwt: append([]Provider(nil), jwt...)}
	if len(opaque) == 1 {
		r.opaque = opaque[0]
	}
	return r, nil
}

// Verify routes raw to at most one provider: constant-time match against
// every static-secret provider first, then exact issuer lookup for a JWT,
// then the single opaque provider, else ErrNoProvider (design.md
// "Registry.Verify"). There is deliberately no scan-every-provider fallback
// once a JWT or opaque candidate is chosen: a proven-invalid token is never
// re-routed to a different provider (T5).
func (r *Registry) Verify(ctx context.Context, raw string) (*Verified, error) {
	start := time.Now()

	for _, p := range r.static {
		v, err := p.Verify(ctx, raw)
		switch {
		case err == nil:
			return r.finish(p, v, start)
		case errors.Is(err, ErrNoProvider):
			continue
		default:
			recordVerification(p.Name(), "invalid", start)
			return nil, err
		}
	}

	shape := shapeOf(raw)
	var candidate Provider
	for _, p := range r.jwt {
		if p.Claims(shape) {
			candidate = p
			break
		}
	}
	if candidate == nil && !shape.jwt {
		candidate = r.opaque
	}
	if candidate == nil {
		federationVerifications.WithLabelValues("none", "unclaimed").Inc()
		return nil, ErrNoProvider
	}

	v, err := candidate.Verify(ctx, raw)
	if err != nil {
		recordVerification(candidate.Name(), "invalid", start)
		return nil, err
	}
	return r.finish(candidate, v, start)
}

// finish enforces the provider contract on a successful Verify and records
// the outcome.
func (r *Registry) finish(p Provider, v *Verified, start time.Time) (*Verified, error) {
	if err := checkProviderContract(p, v); err != nil {
		federationContractViolations.WithLabelValues(p.Name()).Inc()
		recordVerification(p.Name(), "invalid", start)
		return nil, err
	}
	recordVerification(p.Name(), "ok", start)
	return v, nil
}

func recordVerification(provider, result string, start time.Time) {
	federationVerifications.WithLabelValues(provider, result).Inc()
	federationVerifyDuration.WithLabelValues(provider).Observe(time.Since(start).Seconds())
}

// checkProviderContract enforces the invariants requirements.md states under
// "Verification contract": the identity's namespace must be the provider's
// own, the subject must be non-empty unless GitHubLoginOnly, and Kind must be
// one of the three modelled kinds.
func checkProviderContract(p Provider, v *Verified) error {
	if v == nil {
		return fmt.Errorf("%w: provider %q returned no result", ErrProviderContractViolation, p.Name())
	}
	if v.Identity.Provider != p.Name() {
		return fmt.Errorf("%w: provider %q returned identity in namespace %q", ErrProviderContractViolation, p.Name(), v.Identity.Provider)
	}
	if v.Identity.Subject == "" && !v.Identity.GitHubLoginOnly() {
		return fmt.Errorf("%w: provider %q returned an empty subject", ErrProviderContractViolation, p.Name())
	}
	switch v.Identity.Kind {
	case KindHuman, KindAgent, KindService:
	default:
		return fmt.Errorf("%w: provider %q returned kind %q", ErrProviderContractViolation, p.Name(), v.Identity.Kind)
	}
	return nil
}

// Federation metrics (design.md "Observability"), registered once following
// the prometheus.NewCounter + init() pattern already used by
// internal/principals/resolver.go.
var (
	federationVerifications = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "federation_token_verifications_total",
		Help: "Bearer token verifications through the federation registry, by provider and result (ok, invalid, unclaimed).",
	}, []string{"provider", "result"})

	federationVerifyDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "federation_verify_duration_seconds",
		Help: "Time spent verifying a bearer token through the federation registry, by provider.",
	}, []string{"provider"})

	federationAudienceCheckSkipped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "federation_audience_check_skipped_total",
		Help: "OIDC verifications where no audience decision was computed at all (the legacy Dex shim with an empty DEX_CLIENT_ID), by provider.",
	}, []string{"provider"})

	federationAudienceMismatch = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "federation_audience_mismatch_total",
		Help: "OIDC verifications in audit mode where the audience decision was computed, came out negative, and the token was accepted anyway, by provider.",
	}, []string{"provider"})

	federationAudienceRejected = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "federation_audience_rejected_total",
		Help: "OIDC verifications in enforce mode refused because the token's aud held none of the provider's configured audiences, by provider.",
	}, []string{"provider"})

	federationGroupsWithheld = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "federation_groups_withheld_total",
		Help: "OIDC verifications whose non-empty groups claim was withheld from authorization because the provider is not granted groups (grant_groups off), by provider.",
	}, []string{"provider"})

	federationGroupsClaimUnreadable = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "federation_groups_claim_unreadable_total",
		Help: "OIDC verifications whose groups claim had a shape that could not be fully read (not an array of strings, nor an object outside the Dex slot), by provider. Non-zero usually means a misconfigured groups_claim.",
	}, []string{"provider"})

	federationContractViolations = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "federation_provider_contract_violations_total",
		Help: "Verified results rejected because a provider returned an identity outside its own namespace, by provider. Should stay zero.",
	}, []string{"provider"})
)

func init() {
	prometheus.MustRegister(
		federationVerifications,
		federationVerifyDuration,
		federationAudienceCheckSkipped,
		federationAudienceMismatch,
		federationAudienceRejected,
		federationGroupsWithheld,
		federationGroupsClaimUnreadable,
		federationContractViolations,
	)
}
