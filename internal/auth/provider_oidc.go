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

import (
	"context"
	"fmt"
	"slices"

	"github.com/coreos/go-oidc/v3/oidc"
)

// AudienceEnforcement decides what a generic OIDC provider does when a
// token's aud does not contain any of its configured audiences
// (requirements.md "Issuer and audience validation").
type AudienceEnforcement string

const (
	// AudienceAudit accepts the token anyway and increments
	// federation_audience_mismatch_total: a production canary counting what
	// enforcement would refuse, with no staging environment to try it in
	// first (design.md "Cut-over: a production canary, not a staging soak").
	AudienceAudit AudienceEnforcement = "audit"
	// AudienceEnforce refuses the token. The default for any new entry;
	// the canary sets audit explicitly.
	AudienceEnforce AudienceEnforcement = "enforce"
)

// OIDCProviderSpec is the fully-resolved configuration for one generic OIDC
// provider entry -- of which Dex becomes one instance (design.md
// "Configuration and swappability"). Zero-valued optional fields are
// defaulted by newOIDCProvider to reproduce DexVerifier.Verify's existing
// behaviour exactly.
type OIDCProviderSpec struct {
	// Name is this provider's identity namespace ("dex" for the Dex slot,
	// whichever of the legacy shim or an explicit MCTL_OIDC_PROVIDERS entry
	// is active).
	Name string
	// Issuer is required and matched exactly against the token's iss both
	// for routing (the unverified peek) and by the underlying verifier
	// (the token's signature is checked against this issuer's keys).
	Issuer string
	// Audiences is the configured audience allowlist. Required non-empty
	// for any entry from MCTL_OIDC_PROVIDERS (federation_config.go); the
	// legacy shim is the one caller allowed to leave it empty, paired with
	// SkipAudienceCheck.
	Audiences []string
	// AudienceEnforcement is "audit" or "enforce". Defaults to "enforce".
	AudienceEnforcement AudienceEnforcement
	// SkipAudienceCheck marks the legacy shim's DEX_CLIENT_ID=="" mode: no
	// audience decision is even computed, and
	// federation_audience_check_skipped_total is incremented instead of
	// federation_audience_mismatch_total. Never set for an
	// MCTL_OIDC_PROVIDERS entry, which always requires a non-empty
	// Audiences list.
	SkipAudienceCheck bool
	// SubjectClaim names the claim that becomes Identity.Subject. Defaults
	// to "sub".
	SubjectClaim string
	// DisplayClaims is tried in order for Identity.Display, reproducing
	// DexVerifier.Verify's preferred_username -> email -> sub fallback
	// (oidc.go:206-212). Defaults to that same order.
	DisplayClaims []string
	// GroupsClaim names the claim read into Claims.Groups. Defaults to
	// "groups".
	GroupsClaim string
	// Kind is the auth.Kind* value minted for this provider's identities.
	// Defaults to KindHuman.
	Kind string
	// LegacyDexGroups makes this provider reproduce DexVerifier.Verify's
	// unfiltered-groups behaviour bit-for-bit, i.e. keep "admins". It is set
	// by BuildFederationRegistry, never parsed from MCTL_OIDC_PROVIDERS, and
	// only for the trusted Dex slot: the provider named "dex" on the issuer
	// the operator already configured in DEX_ISSUER_URL, whether that is the
	// synthesized shim or an explicit entry replacing it (the documented
	// audit canary). Neither the bare name "dex" nor any other issuer
	// qualifies: repointing "dex" at a new issuer is a new trust decision
	// and must not inherit unfiltered admins.
	LegacyDexGroups bool
}

func (s OIDCProviderSpec) withDefaults() OIDCProviderSpec {
	if s.SubjectClaim == "" {
		s.SubjectClaim = "sub"
	}
	if len(s.DisplayClaims) == 0 {
		s.DisplayClaims = []string{"preferred_username", "email", "sub"}
	}
	if s.GroupsClaim == "" {
		s.GroupsClaim = "groups"
	}
	if s.Kind == "" {
		s.Kind = KindHuman
	}
	if s.AudienceEnforcement == "" {
		s.AudienceEnforcement = AudienceEnforce
	}
	return s
}

// oidcVerifiedToken is what real signature and expiry verification proves
// about a JWT: its issuer, audience list and claims. Decoupled from
// *oidc.IDToken so tests can exercise the audience/claims-mapping logic
// below without standing up an OIDC discovery document and JWKS.
type oidcVerifiedToken struct {
	Issuer   string
	Audience []string
	Claims   map[string]any
}

// oidcTokenVerifier proves a raw JWT's signature and expiry against one
// issuer's keys. *goOIDCVerifier is the production implementation; tests
// substitute a fake.
type oidcTokenVerifier interface {
	Verify(ctx context.Context, raw string) (*oidcVerifiedToken, error)
}

// goOIDCVerifier adapts *oidc.IDTokenVerifier to oidcTokenVerifier.
type goOIDCVerifier struct{ v *oidc.IDTokenVerifier }

func (g goOIDCVerifier) Verify(ctx context.Context, raw string) (*oidcVerifiedToken, error) {
	idToken, err := g.v.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}
	return &oidcVerifiedToken{Issuer: idToken.Issuer, Audience: idToken.Audience, Claims: claims}, nil
}

// oidcProvider is the generic OIDC JWT provider (design.md "provider_oidc.go").
type oidcProvider struct {
	spec     OIDCProviderSpec
	verifier oidcTokenVerifier
}

// newOIDCProvider builds an oidcProvider that verifies against the real
// issuer over the network (OIDC discovery + JWKS). SkipClientIDCheck is
// always set on the underlying library verifier: this provider computes its
// own audience decision (audit vs. enforce) below, which the library's
// binary enforce-or-skip cannot express.
// newOIDCProviderFn is the constructor BuildFederationRegistry calls. A
// package-level seam so its shim-vs-explicit composition is table-testable
// without a live issuer (discovery + JWKS).
var newOIDCProviderFn = newOIDCProvider

func newOIDCProvider(ctx context.Context, spec OIDCProviderSpec) (*oidcProvider, error) {
	spec = spec.withDefaults()
	p, err := oidc.NewProvider(ctx, spec.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc provider init failed for %s: %w", spec.Issuer, err)
	}
	verifier := p.Verifier(&oidc.Config{SkipClientIDCheck: true})
	return &oidcProvider{spec: spec, verifier: goOIDCVerifier{v: verifier}}, nil
}

// newOIDCProviderForTest builds an oidcProvider over a fake verifier, so
// tests can exercise audience/claims-mapping logic without a real JWKS.
func newOIDCProviderForTest(spec OIDCProviderSpec, verifier oidcTokenVerifier) *oidcProvider {
	return &oidcProvider{spec: spec.withDefaults(), verifier: verifier}
}

func (p *oidcProvider) Name() string       { return p.spec.Name }
func (p *oidcProvider) issuerName() string { return p.spec.Issuer }

func (p *oidcProvider) Claims(t tokenShape) bool {
	return t.jwt && normalizeIssuer(t.iss) == normalizeIssuer(p.spec.Issuer)
}

func (p *oidcProvider) Verify(ctx context.Context, raw string) (*Verified, error) {
	tok, err := p.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("invalid %s JWT: %w", p.spec.Name, err)
	}

	switch {
	case p.spec.SkipAudienceCheck:
		federationAudienceCheckSkipped.WithLabelValues(p.spec.Name).Inc()
	case audienceMatches(tok.Audience, p.spec.Audiences):
		// Matched; nothing to count.
	case p.spec.AudienceEnforcement == AudienceEnforce:
		return nil, fmt.Errorf("token audience %v not in configured audiences %v", tok.Audience, p.spec.Audiences)
	default:
		federationAudienceMismatch.WithLabelValues(p.spec.Name).Inc()
	}

	subject, _ := stringClaim(tok.Claims, p.spec.SubjectClaim)
	var display string
	for _, c := range p.spec.DisplayClaims {
		if v, ok := stringClaim(tok.Claims, c); ok && v != "" {
			display = v
			break
		}
	}
	var groups []string
	if raw, ok := tok.Claims[p.spec.GroupsClaim]; ok {
		groups = toStringSlice(raw)
		// docs/federation.md and requirements.md promise this proposal only
		// relocates the existing group resolution without changing who counts
		// as an admin. This same code path is now reachable by any
		// operator-configured MCTL_OIDC_PROVIDERS entry, so "admins" is
		// dropped here exactly as NewRelayedUser drops it for a relayed
		// subject -- except for the trusted Dex slot (see LegacyDexGroups),
		// which must keep reproducing DexVerifier.Verify's unfiltered-groups
		// behaviour bit-for-bit. Gated on LegacyDexGroups rather than the
		// bare name "dex": ParseOIDCProviders deliberately leaves "dex"
		// unreserved for an operator's own entry, so a name check alone
		// would hand a "dex" entry on an arbitrary issuer the same
		// unfiltered-admins behaviour.
		if !p.spec.LegacyDexGroups {
			kept := make([]string, 0, len(groups))
			for _, g := range groups {
				if g != "admins" {
					kept = append(kept, g)
				}
			}
			groups = kept
		}
	}

	return &Verified{
		Identity: Identity{Provider: p.spec.Name, Issuer: tok.Issuer, Subject: subject, Display: display, Kind: p.spec.Kind},
		Claims:   Claims{Groups: groups},
	}, nil
}

func audienceMatches(tokenAudiences, configured []string) bool {
	for _, a := range tokenAudiences {
		if slices.Contains(configured, a) {
			return true
		}
	}
	return false
}

func stringClaim(claims map[string]any, name string) (string, bool) {
	v, ok := claims[name]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func toStringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
