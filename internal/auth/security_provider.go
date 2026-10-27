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
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
)

// Security-provider principal (mctl-api#774, SecurityFinding v1), modelled on
// the evidence-writer principal but one per configured provider: a Trivy,
// CodeQL, Dependabot or Runtime Assurance adapter submits observations with
// its own credential, and the server -- never the payload -- decides which
// provider it is.
//
// The principal holds exactly one permission, PermissionSecurityIngest, is not
// an admin, belongs to no tenant, and is confined by the API's
// security-provider gate to POST /api/v1/security/observations. Which tenants
// it may report for, and the strongest verification it may assert, come from
// the server-side SECURITY_PROVIDERS configuration (SecurityProviderConfig),
// looked up by the ref this principal carries.
const (
	// SecurityProviderUserPrefix prefixes the principal id: the full id is
	// "service:security-provider:<ref>".
	SecurityProviderUserPrefix = "service:security-provider:"
	// PermissionSecurityIngest is held by a security-provider principal and by
	// an admin.
	PermissionSecurityIngest = "security:ingest"
	// PermissionSecurityRemediate is what the remediation runner holds: it may
	// start remediation attempts and record fixes and verifications.
	PermissionSecurityRemediate = "security:remediate"

	securityProvidersEnv      = "SECURITY_PROVIDERS"
	securityProviderTokensEnv = "MCTL_SECURITY_PROVIDER_TOKENS" //nolint:gosec // env var name, not a credential
)

var securityProviderRefPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// SecurityProviderConfig is one entry of the non-secret SECURITY_PROVIDERS
// JSON: the provider's ref, the strongest verification it may assert, and the
// tenants it may report for.
type SecurityProviderConfig struct {
	Ref         string   `json:"ref"`
	MaxStrength string   `json:"max_strength"`
	Tenants     []string `json:"tenants"`
}

// NewSecurityProviderUser builds the principal of the provider named ref.
// Exported for tests; only the middleware mints it from a token.
func NewSecurityProviderUser(ref string) *User {
	return &User{ID: SecurityProviderUserPrefix + ref, securityProvider: ref}
}

// SecurityProviderRef is the configured ref of a security-provider
// principal, empty for every other principal.
func (u *User) SecurityProviderRef() string {
	if u == nil {
		return ""
	}
	return u.securityProvider
}

// ParseSecurityProviders parses the SECURITY_PROVIDERS value. An empty value
// is no providers. A malformed entry is an error, so the caller can refuse it
// loudly instead of silently dropping a provider.
func ParseSecurityProviders(raw string) ([]SecurityProviderConfig, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var out []SecurityProviderConfig
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("parse %s: %w", securityProvidersEnv, err)
	}
	seen := map[string]bool{}
	for i := range out {
		c := &out[i]
		c.Ref = strings.TrimSpace(c.Ref)
		if !securityProviderRefPattern.MatchString(c.Ref) {
			return nil, fmt.Errorf("%s entry %d: ref %q must match %s", securityProvidersEnv, i, c.Ref, securityProviderRefPattern)
		}
		if seen[c.Ref] {
			return nil, fmt.Errorf("%s: duplicate ref %q", securityProvidersEnv, c.Ref)
		}
		seen[c.Ref] = true
		if len(c.Tenants) == 0 {
			return nil, fmt.Errorf("%s entry %q: tenants must not be empty", securityProvidersEnv, c.Ref)
		}
		for j, t := range c.Tenants {
			c.Tenants[j] = strings.TrimSpace(t)
			if c.Tenants[j] == "" {
				return nil, fmt.Errorf("%s entry %q: empty tenant name", securityProvidersEnv, c.Ref)
			}
		}
	}
	return out, nil
}

// LoadSecurityProviders reads SECURITY_PROVIDERS and returns the providers
// that are also authenticatable (they have a valid token). It is the
// configuration the API consults for tenants and strength ceilings.
func LoadSecurityProviders() map[string]SecurityProviderConfig {
	configs, err := ParseSecurityProviders(os.Getenv(securityProvidersEnv))
	if err != nil {
		slog.Error("invalid security provider configuration; no security providers enabled", "error", err)
		return nil
	}
	out := make(map[string]SecurityProviderConfig, len(configs))
	for _, c := range configs {
		out[c.Ref] = c
	}
	return out
}

// securityProviderTokens reads MCTL_SECURITY_PROVIDER_TOKENS ("ref=token"
// lines) and returns token -> ref for the providers that may authenticate.
// A provider is disabled, with an error log, when it has no SECURITY_PROVIDERS
// entry, its token is short, or its token equals another principal's token
// or another provider's. The comparison tokens are re-read from the
// environment, so a token that was itself refused is still not reusable here.
func securityProviderTokens() map[string]string {
	rawTokens := strings.TrimSpace(os.Getenv(securityProviderTokensEnv))
	if rawTokens == "" {
		return nil
	}
	configured := LoadSecurityProviders()
	others := []string{"MCTL_AGENT_SERVICE_TOKEN", usageWriterTokenEnv, evidenceWriterTokenEnv, registryPublisherTokenEnv, supportIncidentProducerTokenEnv}
	for _, env := range surfaceTokenEnv {
		others = append(others, env)
	}
	otherValues := map[string]string{}
	for _, env := range others {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			otherValues[v] = env
		}
	}

	byRef := map[string]string{}
	count := map[string]int{} // token -> number of refs using it
	sc := bufio.NewScanner(strings.NewReader(rawTokens))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ref, token, ok := strings.Cut(line, "=")
		ref, token = strings.TrimSpace(ref), strings.TrimSpace(token)
		if !ok || ref == "" || token == "" {
			slog.Error("malformed security provider token line ignored", "env", securityProviderTokensEnv)
			continue
		}
		if _, dup := byRef[ref]; dup {
			slog.Error("security provider has two tokens; provider disabled", "ref", ref)
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
			continue
		case !securityProviderRefPattern.MatchString(ref):
			slog.Error("security provider ref invalid; provider disabled", "ref", ref)
		case configured[ref].Ref == "":
			slog.Error("security provider token has no SECURITY_PROVIDERS entry; provider disabled", "ref", ref)
		case len(token) < minSurfaceTokenLen:
			slog.Error("security provider token too short; provider disabled", "ref", ref, "min_length", minSurfaceTokenLen)
		case count[token] > 1:
			slog.Error("security provider token shared by two providers; providers disabled", "ref", ref)
		default:
			if env, clash := otherValues[token]; clash {
				slog.Error("security provider token equals another principal's token; provider disabled", "ref", ref, "equals", env)
				continue
			}
			out[token] = ref
		}
	}
	return out
}

// securityProviderUserFor matches a bearer token against the provider tokens
// in constant time per candidate.
func securityProviderUserFor(tokens map[string]string, token string) *User {
	var match string
	for candidate, ref := range tokens {
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(token)) == 1 {
			match = ref
		}
	}
	if match == "" {
		return nil
	}
	return NewSecurityProviderUser(match)
}
