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
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// DownstreamResource is one MCP server that trusts this authorization
// server (mctlhq/mctl-api#1062, line I of mctlhq/.github#236): clients ask
// for a token with RFC 8707 resource = Resource, and the server verifies it
// offline through the JWKS. Such a token is never accepted by this API.
type DownstreamResource struct {
	// Resource is the exact RFC 8707 resource and the aud minted for it,
	// e.g. https://tg.mctl.ai/mcp.
	Resource string `json:"resource"`
	// AdminOnly restricts minting to platform-admin principals
	// (ADMIN_PRINCIPALS), checked at code issue and on every token, so a
	// principal removed from the admins stops getting tokens at its next
	// refresh.
	AdminOnly bool `json:"admin_only,omitempty"`
}

// ErrDownstreamPrincipal: a token for a downstream resource was requested
// for a caller it may not be minted for (no principal, or not an admin for
// an admin-only resource). Nothing is minted.
var ErrDownstreamPrincipal = errors.New("principal may not get a token for this resource")

// ParseDownstreamResources parses OAUTH_MCP_RESOURCES: a JSON array of
// DownstreamResource. Empty or whitespace is no resources. Unknown fields
// are refused, so a typo such as "adminOnly" cannot silently open an
// admin-only resource to everyone.
func ParseDownstreamResources(raw string) ([]DownstreamResource, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	var out []DownstreamResource
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("OAUTH_MCP_RESOURCES must be a JSON array of {resource, admin_only}: %w", err)
	}
	if dec.More() {
		return nil, errors.New("OAUTH_MCP_RESOURCES has trailing data after the JSON array")
	}
	for i := range out {
		out[i].Resource = strings.TrimSpace(out[i].Resource)
	}
	return out, nil
}

// ValidateDownstreamResources refuses a registry that would mint a token
// nobody can verify or that collides with another audience: every entry is
// an absolute https URL without a fragment, names neither this API nor the
// support or Glovo resource, and appears once. Downstreams verify through
// the JWKS, so an entry needs asymmetric signing; an admin-only entry needs
// IsAdminPrincipal. Call it after the support and Glovo resources and
// ConfigureSigning are set.
func (s *OAuthServer) ValidateDownstreamResources() error {
	if len(s.DownstreamResources) == 0 {
		return nil
	}
	if s.signingAlg != JWTAlgEdDSA && s.signingAlg != JWTAlgES256 {
		return errors.New("OAUTH_MCP_RESOURCES needs asymmetric signing (OAUTH_JWT_SIGNING_ALG EdDSA or ES256): downstreams verify through the JWKS")
	}
	seen := map[string]bool{}
	for _, d := range s.DownstreamResources {
		r := d.Resource
		u, err := url.Parse(r)
		if r == "" || err != nil || !u.IsAbs() || u.Scheme != "https" || u.Host == "" || u.Fragment != "" || strings.Contains(r, "#") {
			return fmt.Errorf("OAUTH_MCP_RESOURCES entry %q must be an absolute https URL without a fragment", r)
		}
		n := normalizeIssuer(r)
		switch {
		case s.namesThisAPI(n):
			return fmt.Errorf("OAUTH_MCP_RESOURCES entry %q names this API (its audience, base URL or /mcp endpoint)", r)
		case s.SupportResource != "" && n == normalizeIssuer(s.SupportResource):
			return fmt.Errorf("OAUTH_MCP_RESOURCES entry %q equals OAUTH_SUPPORT_RESOURCE", r)
		case s.GlovoResource != "" && n == normalizeIssuer(s.GlovoResource):
			return fmt.Errorf("OAUTH_MCP_RESOURCES entry %q equals GLOVO_MCP_RESOURCE", r)
		case seen[n]:
			return fmt.Errorf("OAUTH_MCP_RESOURCES lists %q twice", r)
		}
		seen[n] = true
		if d.AdminOnly && s.IsAdminPrincipal == nil {
			return fmt.Errorf("OAUTH_MCP_RESOURCES entry %q is admin_only but no admin principals are configured", r)
		}
	}
	return nil
}

// downstreamResource returns the registry entry whose resource equals the
// normalized value n.
func (s *OAuthServer) downstreamResource(n string) (DownstreamResource, bool) {
	for _, d := range s.DownstreamResources {
		if n == normalizeIssuer(d.Resource) {
			return d, true
		}
	}
	return DownstreamResource{}, false
}

// audNamesDownstream reports whether any aud value is a downstream resource.
func (s *OAuthServer) audNamesDownstream(a audience) bool {
	for _, v := range a {
		if _, ok := s.downstreamResource(normalizeIssuer(v)); ok {
			return true
		}
	}
	return false
}

// checkDownstreamPrincipal refuses to mint aud for principalID when aud is a
// downstream resource the principal may not hold. A downstream keys its
// user by principal, so a token without one is refused too. It returns
// whether aud is a downstream resource.
func (s *OAuthServer) checkDownstreamPrincipal(aud, principalID string) (bool, error) {
	d, ok := s.downstreamResource(normalizeIssuer(aud))
	if !ok {
		return false, nil
	}
	if principalID == "" || !ValidPrincipalID(principalID) {
		return true, fmt.Errorf("%w: no principal", ErrDownstreamPrincipal)
	}
	if d.AdminOnly && (s.IsAdminPrincipal == nil || !s.IsAdminPrincipal(principalID)) {
		return true, fmt.Errorf("%w: %s is admin-only", ErrDownstreamPrincipal, d.Resource)
	}
	return true, nil
}
