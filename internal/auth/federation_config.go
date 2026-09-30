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

// federation_config.go parses MCTL_OIDC_PROVIDERS and builds the legacy Dex
// shim (design.md "Configuration and swappability", "Cut-over"). Called from
// cmd/api/main.go's loadConfig/config.validate (shape validation, in the
// style of OAUTH_PREREGISTERED_CLIENTS) and from main() itself to build the
// real Registry passed to Middleware via WithFederationRegistry.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/mctlhq/mctl-api/internal/surfaceid"
)

// OIDCProviderConfigEntry is one entry of the MCTL_OIDC_PROVIDERS JSON array
// (design.md "Configuration and swappability").
type OIDCProviderConfigEntry struct {
	Name                string   `json:"name"`
	Issuer              string   `json:"issuer"`
	Audiences           []string `json:"audiences"`
	AudienceEnforcement string   `json:"audience_enforcement,omitempty"`
	SubjectClaim        string   `json:"subject_claim,omitempty"`
	DisplayClaims       []string `json:"display_claims,omitempty"`
	GroupsClaim         string   `json:"groups_claim,omitempty"`
	Kind                string   `json:"kind,omitempty"`
}

func (e OIDCProviderConfigEntry) spec() OIDCProviderSpec {
	return OIDCProviderSpec{
		Name:                e.Name,
		Issuer:              e.Issuer,
		Audiences:           e.Audiences,
		AudienceEnforcement: AudienceEnforcement(e.AudienceEnforcement),
		SubjectClaim:        e.SubjectClaim,
		DisplayClaims:       e.DisplayClaims,
		GroupsClaim:         e.GroupsClaim,
		Kind:                e.Kind,
	}
}

// ParseOIDCProviders decodes and validates the MCTL_OIDC_PROVIDERS value.
// Unset or blank means no explicitly configured providers -- only the legacy
// Dex shim applies. A malformed value, an entry with no name/issuer/
// audiences, an invalid audience_enforcement, a name colliding with a
// reserved name or a registered surface, or two entries sharing a name or a
// normalized issuer all refuse with an error naming the offending entry
// (requirements.md "Issuer and audience validation", "Registry and
// routing").
func ParseOIDCProviders(raw string) ([]OIDCProviderConfigEntry, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if raw == "null" {
		// Decodes to a nil slice and would read as "no providers"; far more
		// likely a templating accident than a decision (same reasoning as
		// OAUTH_PREREGISTERED_CLIENTS, main.go's parsePreregisteredClients).
		return nil, fmt.Errorf("MCTL_OIDC_PROVIDERS: null is not a provider list (unset the variable for none)")
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	var out []OIDCProviderConfigEntry
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("MCTL_OIDC_PROVIDERS: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("MCTL_OIDC_PROVIDERS: trailing data after the JSON array")
	}

	seenNames := map[string]bool{}
	seenIssuers := map[string]string{}
	for i := range out {
		e := &out[i]
		if e.Name == "" {
			return nil, fmt.Errorf("MCTL_OIDC_PROVIDERS: an entry has no name")
		}
		if e.Issuer == "" {
			return nil, fmt.Errorf("MCTL_OIDC_PROVIDERS: entry %q has no issuer", e.Name)
		}
		if len(e.Audiences) == 0 {
			return nil, fmt.Errorf("MCTL_OIDC_PROVIDERS: entry %q has no audiences (required; the SkipClientIDCheck branch is not reachable from this variable)", e.Name)
		}
		switch AudienceEnforcement(e.AudienceEnforcement) {
		case "", AudienceEnforce, AudienceAudit:
		default:
			return nil, fmt.Errorf("MCTL_OIDC_PROVIDERS: entry %q has invalid audience_enforcement %q (must be \"audit\" or \"enforce\")", e.Name, e.AudienceEnforcement)
		}
		switch e.Kind {
		case "", KindHuman, KindAgent, KindService:
		default:
			return nil, fmt.Errorf("MCTL_OIDC_PROVIDERS: entry %q has invalid kind %q (must be %q, %q, or %q)", e.Name, e.Kind, KindHuman, KindAgent, KindService)
		}
		if reservedProviderNames[e.Name] {
			return nil, fmt.Errorf("MCTL_OIDC_PROVIDERS: entry %q uses reserved provider name %q", e.Name, e.Name)
		}
		if surfaceid.IsSurface(e.Name) {
			return nil, fmt.Errorf("MCTL_OIDC_PROVIDERS: entry %q collides with a registered surface name", e.Name)
		}
		if seenNames[e.Name] {
			return nil, fmt.Errorf("MCTL_OIDC_PROVIDERS: provider name %q listed twice", e.Name)
		}
		seenNames[e.Name] = true
		iss := normalizeIssuer(e.Issuer)
		if other, dup := seenIssuers[iss]; dup {
			return nil, fmt.Errorf("MCTL_OIDC_PROVIDERS: entries %q and %q both claim issuer %q", other, e.Name, iss)
		}
		seenIssuers[iss] = e.Name
	}
	return out, nil
}

// FederationProvidersConfig groups the raw inputs BuildFederationRegistry
// needs beyond the already-constructed validator/oauth server: the legacy
// Dex env vars and the new MCTL_OIDC_PROVIDERS value.
type FederationProvidersConfig struct {
	OIDCProvidersRaw string
	DexIssuerURL     string
	DexClientID      string
}

// BuildFederationRegistry builds the full production Registry: the three
// static-secret providers, the local-OAuth provider (if oauth is non-nil),
// the GitHub PAT provider (if validator is non-nil), every explicit
// MCTL_OIDC_PROVIDERS entry, and -- unless an explicit entry already claims
// the Dex issuer -- the legacy Dex shim synthesized from
// DexIssuerURL/DexClientID (requirements.md "IF an explicit provider entry
// claims the same issuer as the legacy Dex shim").
//
// A malformed MCTL_OIDC_PROVIDERS value, or a registry invariant violated by
// the combined provider set (duplicate name/issuer, a reserved name, a
// surfaceid collision, more than one opaque provider), is returned as an
// error -- these are the conditions requirements.md says must refuse boot.
// A single OIDC provider entry (explicit or the legacy shim) that cannot
// reach its issuer over the network at boot is NOT one of them: it is
// logged and that one provider is simply omitted, the same graceful
// degradation cmd/api/main.go already gives Dex today
// (main.go:97-107 "A Dex init failure only logs a warning").
func BuildFederationRegistry(ctx context.Context, cfg FederationProvidersConfig, validator *GitHubValidator, resolver TenantResolver, oauth *OAuthServer) (*Registry, error) {
	entries, err := ParseOIDCProviders(cfg.OIDCProvidersRaw)
	if err != nil {
		return nil, err
	}

	surfaces := surfaceTokens()
	usageWriter := usageWriterToken()
	evidenceWriter := evidenceWriterToken()
	static := []Provider{
		newServiceTokenProvider(func() string { return strings.TrimSpace(os.Getenv("MCTL_AGENT_SERVICE_TOKEN")) }),
		newSurfaceProvider(func() map[string]string { return surfaces }),
		newUsageWriterProvider(func() string { return usageWriter }),
		newEvidenceWriterProvider(func() string { return evidenceWriter }),
	}

	var jwtProviders []Provider
	if oauth != nil && oauth.BaseURL != "" {
		jwtProviders = append(jwtProviders, newLocalOAuthProvider(oauth))
	} else if oauth != nil {
		slog.Warn("oauth server has empty BaseURL; local-oauth provider disabled")
	}

	dexIssuer := normalizeIssuer(cfg.DexIssuerURL)
	dexClaimedExplicitly := false
	for i := range entries {
		e := &entries[i]
		// The provider NAME is the identity namespace, so an entry named
		// "dex" replaces the shim whatever its issuer: that is how an
		// operator repoints Dex while existing external_identities rows with
		// provider='dex' keep resolving (docs/federation.md). "dex" is the
		// one name ParseOIDCProviders leaves unreserved for exactly this.
		// An entry under a DIFFERENT name on the Dex issuer is not that
		// replacement: the shim is still synthesized under "dex", and
		// NewRegistry refuses boot with a duplicate-issuer error naming
		// both, rather than silently re-namespacing every Dex identity.
		if e.Name == ProviderDex {
			dexClaimedExplicitly = true
		}
		spec := e.spec()
		// Unfiltered "admins" (LegacyDexGroups) only for the trusted Dex
		// slot: "dex" on the issuer already configured in DEX_ISSUER_URL.
		// That keeps the documented audit canary (an explicit "dex" entry on
		// the Dex issuer) from silently stripping admin from every Dex
		// caller, while "dex" on any other issuer is a new trust decision
		// and gets the filtered behaviour.
		spec.LegacyDexGroups = e.Name == ProviderDex && dexIssuer != "" && normalizeIssuer(e.Issuer) == dexIssuer
		p, err := newOIDCProviderFn(ctx, spec)
		if err != nil {
			slog.Warn("oidc provider init failed; provider disabled", "name", e.Name, "issuer", e.Issuer, "error", err)
			continue
		}
		jwtProviders = append(jwtProviders, p)
	}

	switch {
	case dexIssuer == "":
		// No legacy issuer configured at all: nothing to synthesize.
	case dexClaimedExplicitly:
		slog.Info("dex provider: using explicit MCTL_OIDC_PROVIDERS entry, legacy shim not synthesized", "issuer", cfg.DexIssuerURL)
	default:
		shimSpec := OIDCProviderSpec{Name: ProviderDex, Issuer: cfg.DexIssuerURL, Kind: KindHuman, LegacyDexGroups: true}
		if cfg.DexClientID != "" {
			shimSpec.Audiences = []string{cfg.DexClientID}
			shimSpec.AudienceEnforcement = AudienceEnforce
		} else {
			shimSpec.SkipAudienceCheck = true
			slog.Warn("DEX_CLIENT_ID is empty; dex audience check is skipped (compatibility) -- set DEX_CLIENT_ID to enable it", "issuer", cfg.DexIssuerURL)
		}
		p, err := newOIDCProviderFn(ctx, shimSpec)
		if err != nil {
			slog.Warn("dex OIDC init failed — JWT auth disabled for dex", "issuer", cfg.DexIssuerURL, "error", err)
		} else {
			slog.Info("dex provider: using legacy DEX_ISSUER_URL/DEX_CLIENT_ID shim", "issuer", cfg.DexIssuerURL)
			jwtProviders = append(jwtProviders, p)
		}
	}

	var opaque []Provider
	if validator != nil {
		opaque = append(opaque, newGitHubProvider(validator, legacyGroupSource{validator: validator, resolver: resolver}))
	}

	return NewRegistry(static, jwtProviders, opaque)
}
