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
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// Bridge-provider principal (mctl-api#962): the low-trust worker that claims
// commands from the bridge outbox and posts results. One principal per
// configured provider, "service:bridge-provider:<ref>", holding exactly one
// permission (PermissionBridgeProvider). It is not an admin, belongs to no
// tenant, and the API confines it to /api/v1/bridge/* (bridgeProviderGate);
// every other route, DevLoop, work items, operations and MCP, refuses it.
//
// The candidate production credential is a federated service OIDC token whose
// issuer, subject, audience, signature/JWKS trust, exp and nbf are pinned per
// provider (BridgeProviderConfig.PinClaims). Static tokens exist for tests
// only. No production issuer is assumed: ZITADEL versus Vault for the
// Temporal workload identity is the separate spike mctl-api#2506 and must not
// silently choose this token's issuer. The OIDC verifier wiring is deliberately
// not enabled here; see docs/bridge.md "Deployment gates".
const (
	// BridgeProviderUserPrefix prefixes the principal id.
	BridgeProviderUserPrefix = "service:bridge-provider:"
	// PermissionBridgeProvider is held only by a bridge-provider principal.
	PermissionBridgeProvider = "bridge:provide"
	// BridgeAudience is the exact audience a bridge workload token must carry.
	BridgeAudience = "mctl-api-bridge"

	bridgeProvidersEnv      = "MCTL_BRIDGE_PROVIDERS"
	bridgeProviderTokensEnv = "MCTL_BRIDGE_PROVIDER_TOKENS" //nolint:gosec // env var name, not a credential
)

var bridgeProviderRefPattern = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// BridgeProviderConfig is one entry of MCTL_BRIDGE_PROVIDERS. Tenants are an
// upper bound only: the tenant and owner of a command are read from its
// stored row.
type BridgeProviderConfig struct {
	Ref      string   `json:"ref"`
	Issuer   string   `json:"issuer"`
	Subject  string   `json:"subject"`
	Audience string   `json:"audience"`
	Tenants  []string `json:"tenants"`
	// SupportedVersions is the closed set of bridge wire versions the provider
	// declares. Absent means [bridge.mctl.ai/v1alpha1]. It must contain
	// bridge.mctl.ai/v1alpha1; mctl-api leases a v1alpha2 command only to a
	// provider whose entry lists bridge.mctl.ai/v1alpha2.
	SupportedVersions []string `json:"supported_versions,omitempty"`
}

// Bridge wire versions a provider may declare in supported_versions.
const (
	BridgeWireV1alpha1 = "bridge.mctl.ai/v1alpha1"
	BridgeWireV1alpha2 = "bridge.mctl.ai/v1alpha2"
)

// WireVersions is the provider's declared wire versions, never empty.
func (c BridgeProviderConfig) WireVersions() []string {
	if len(c.SupportedVersions) == 0 {
		return []string{BridgeWireV1alpha1}
	}
	return append([]string(nil), c.SupportedVersions...)
}

// NewBridgeProviderUser builds the principal of the provider named ref.
func NewBridgeProviderUser(ref string) *User {
	return &User{ID: BridgeProviderUserPrefix + ref, bridgeProvider: ref}
}

// BridgeProviderRef is the configured ref of a bridge-provider principal,
// empty for every other principal.
func (u *User) BridgeProviderRef() string {
	if u == nil {
		return ""
	}
	return u.bridgeProvider
}

// ParseBridgeProviders parses MCTL_BRIDGE_PROVIDERS strictly: unknown fields,
// trailing data, a malformed ref, a non-https issuer, an empty subject, an
// audience other than BridgeAudience or an empty tenant list are all errors.
// Empty input is no providers.
func ParseBridgeProviders(raw string) ([]BridgeProviderConfig, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	var out []BridgeProviderConfig
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("parse %s: %w", bridgeProvidersEnv, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%s: trailing data after the JSON array", bridgeProvidersEnv)
	}
	seen := map[string]bool{}
	for i := range out {
		c := &out[i]
		c.Ref = strings.TrimSpace(c.Ref)
		if !bridgeProviderRefPattern.MatchString(c.Ref) {
			return nil, fmt.Errorf("%s entry %d: ref %q must match %s", bridgeProvidersEnv, i, c.Ref, bridgeProviderRefPattern)
		}
		if seen[c.Ref] {
			return nil, fmt.Errorf("%s: duplicate ref %q", bridgeProvidersEnv, c.Ref)
		}
		seen[c.Ref] = true
		if u, err := url.Parse(c.Issuer); err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, fmt.Errorf("%s entry %q: issuer must be an https URL", bridgeProvidersEnv, c.Ref)
		}
		if strings.TrimSpace(c.Subject) == "" {
			return nil, fmt.Errorf("%s entry %q: subject is required", bridgeProvidersEnv, c.Ref)
		}
		if c.Audience != BridgeAudience {
			return nil, fmt.Errorf("%s entry %q: audience must be exactly %q", bridgeProvidersEnv, c.Ref, BridgeAudience)
		}
		if len(c.Tenants) == 0 {
			return nil, fmt.Errorf("%s entry %q: tenants must not be empty", bridgeProvidersEnv, c.Ref)
		}
		if c.SupportedVersions != nil {
			haveV1 := false
			seenV := map[string]bool{}
			for _, v := range c.SupportedVersions {
				if v != BridgeWireV1alpha1 && v != BridgeWireV1alpha2 {
					return nil, fmt.Errorf("%s entry %q: unknown supported_versions value", bridgeProvidersEnv, c.Ref)
				}
				if seenV[v] {
					return nil, fmt.Errorf("%s entry %q: duplicate supported_versions value %q", bridgeProvidersEnv, c.Ref, v)
				}
				seenV[v] = true
				haveV1 = haveV1 || v == BridgeWireV1alpha1
			}
			if !haveV1 {
				return nil, fmt.Errorf("%s entry %q: supported_versions must contain %q", bridgeProvidersEnv, c.Ref, BridgeWireV1alpha1)
			}
		}
		for j, t := range c.Tenants {
			c.Tenants[j] = strings.TrimSpace(t)
			if c.Tenants[j] == "" {
				return nil, fmt.Errorf("%s entry %q: empty tenant name", bridgeProvidersEnv, c.Ref)
			}
		}
	}
	return out, nil
}

// LoadBridgeProviders reads MCTL_BRIDGE_PROVIDERS. A malformed value enables
// no provider, with an error log.
func LoadBridgeProviders() map[string]BridgeProviderConfig {
	configs, err := ParseBridgeProviders(os.Getenv(bridgeProvidersEnv))
	if err != nil {
		slog.Error("invalid bridge provider configuration; no bridge providers enabled", "error", err)
		return nil
	}
	out := make(map[string]BridgeProviderConfig, len(configs))
	for _, c := range configs {
		out[c.Ref] = c
	}
	return out
}

// PinClaims is the exact-trust check for a verified service JWT: issuer,
// subject and audience must equal the pins, exp must be in the future and nbf,
// when present, must not be. It fails closed on any missing value. The
// signature and JWKS trust are the verifier's job, before this is called.
func (c BridgeProviderConfig) PinClaims(issuer string, audiences []string, subject string, exp, nbf, now time.Time) error {
	if issuer == "" || issuer != c.Issuer {
		return fmt.Errorf("bridge token issuer is not the pinned issuer")
	}
	if subject == "" || subject != c.Subject {
		return fmt.Errorf("bridge token subject is not the pinned subject")
	}
	ok := false
	for _, a := range audiences {
		if a == c.Audience {
			ok = true
		}
	}
	if !ok {
		return fmt.Errorf("bridge token audience is not %q", c.Audience)
	}
	if exp.IsZero() || !exp.After(now) {
		return fmt.Errorf("bridge token is expired or has no exp")
	}
	if !nbf.IsZero() && nbf.After(now) {
		return fmt.Errorf("bridge token is not yet valid")
	}
	return nil
}

// bridgeProviderTokens reads MCTL_BRIDGE_PROVIDER_TOKENS ("ref=token" lines;
// TESTS ONLY) and returns token -> ref for providers that may authenticate. A
// provider is disabled, with an error log, when it has no MCTL_BRIDGE_PROVIDERS
// entry, its token is short, or its token equals another principal's token or
// another provider's.
func bridgeProviderTokens() map[string]string {
	rawTokens := strings.TrimSpace(os.Getenv(bridgeProviderTokensEnv))
	if rawTokens == "" {
		return nil
	}
	configured := LoadBridgeProviders()
	others := []string{"MCTL_AGENT_SERVICE_TOKEN", usageWriterTokenEnv, evidenceWriterTokenEnv, registryPublisherTokenEnv, supportIncidentProducerTokenEnv, securityProviderTokensEnv}
	for _, env := range surfaceTokenEnv {
		others = append(others, env)
	}
	otherValues := map[string]string{}
	for _, env := range others {
		v := strings.TrimSpace(os.Getenv(env))
		if v == "" {
			continue
		}
		otherValues[v] = env
		// A multi-line "ref=token" variable: compare each token too.
		sc := bufio.NewScanner(strings.NewReader(v))
		for sc.Scan() {
			if _, tok, ok := strings.Cut(strings.TrimSpace(sc.Text()), "="); ok && strings.TrimSpace(tok) != "" {
				otherValues[strings.TrimSpace(tok)] = env
			}
		}
	}
	byRef := map[string]string{}
	count := map[string]int{}
	sc := bufio.NewScanner(strings.NewReader(rawTokens))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ref, token, ok := strings.Cut(line, "=")
		ref, token = strings.TrimSpace(ref), strings.TrimSpace(token)
		if !ok || ref == "" || token == "" {
			slog.Error("malformed bridge provider token line ignored", "env", bridgeProviderTokensEnv)
			continue
		}
		if _, dup := byRef[ref]; dup {
			slog.Error("bridge provider has two tokens; provider disabled", "ref", ref)
			byRef[ref] = ""
			continue
		}
		byRef[ref] = token
		count[token]++
	}
	out := map[string]string{}
	for ref, token := range byRef {
		switch {
		case token == "":
		case !bridgeProviderRefPattern.MatchString(ref):
			slog.Error("bridge provider ref invalid; provider disabled", "ref", ref)
		case configured[ref].Ref == "":
			slog.Error("bridge provider token has no MCTL_BRIDGE_PROVIDERS entry; provider disabled", "ref", ref)
		case len(token) < minSurfaceTokenLen:
			slog.Error("bridge provider token too short; provider disabled", "ref", ref, "min_length", minSurfaceTokenLen)
		case count[token] > 1:
			slog.Error("bridge provider token shared by two providers; providers disabled", "ref", ref)
		default:
			if env, clash := otherValues[token]; clash {
				slog.Error("bridge provider token equals another principal's token; provider disabled", "ref", ref, "equals", env)
				continue
			}
			out[token] = ref
		}
	}
	return out
}

// bridgeProviderUserFor matches a bearer token against the provider tokens in
// constant time per candidate.
func bridgeProviderUserFor(tokens map[string]string, token string) *User {
	var match string
	for candidate, ref := range tokens {
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(token)) == 1 {
			match = ref
		}
	}
	if match == "" {
		return nil
	}
	return NewBridgeProviderUser(match)
}

type bridgeProviderProvider struct{ tokens func() map[string]string }

func newBridgeProviderProvider(tokens func() map[string]string) *bridgeProviderProvider {
	return &bridgeProviderProvider{tokens: tokens}
}

func (*bridgeProviderProvider) Name() string           { return ProviderService }
func (*bridgeProviderProvider) Claims(tokenShape) bool { return true }

func (p *bridgeProviderProvider) Verify(_ context.Context, raw string) (*Verified, error) {
	u := bridgeProviderUserFor(p.tokens(), raw)
	if u == nil {
		return nil, ErrNoProvider
	}
	return &Verified{Identity: Identity{Provider: ProviderService, Subject: u.ID, Display: u.ID, Kind: KindService}}, nil
}
