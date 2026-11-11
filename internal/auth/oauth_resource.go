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
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// DefaultSupportResource is the RFC 8707 resource of the tenant support
// agent (support.mctl.ai) when OAUTH_SUPPORT_RESOURCE is unset.
const DefaultSupportResource = "https://support.mctl.ai"

// ErrInvalidTarget maps to the RFC 8707 invalid_target error: the requested
// resource is unknown, malformed, repeated, or differs from the one the
// grant was issued for.
var ErrInvalidTarget = errors.New("invalid_target")

// GlovoResourceIntended is the intended RFC 8707 resource of the Glovo MCP
// facade. Documentation and test data only; never a default.
const GlovoResourceIntended = "https://glovo.mctl.ai/mcp"

// ErrGlovoNotReady: the configured Glovo resource was requested while the
// feature gate is closed. It is an invalid_target, so nothing is minted.
var ErrGlovoNotReady = fmt.Errorf("%w: glovo resource not ready", ErrInvalidTarget)

// ResolveResource maps the RFC 8707 resource values of a request to the
// audience to mint. No value, or one naming this API (the audience, the base
// URL or its /mcp endpoint), is the default audience; those match exactly,
// so a local http base URL resolves too. The configured support resource is
// minted as itself and must be https. Anything else is ErrInvalidTarget.
func (s *OAuthServer) ResolveResource(values []string) (string, error) {
	if len(values) == 0 {
		return s.accessAudience(), nil
	}
	if len(values) > 1 {
		return "", ErrInvalidTarget
	}
	v := values[0]
	u, err := url.Parse(v)
	if err != nil || !u.IsAbs() || u.Host == "" || u.Fragment != "" || strings.Contains(v, "#") {
		return "", ErrInvalidTarget
	}
	n := normalizeIssuer(v)
	if s.namesThisAPI(n) {
		return s.accessAudience(), nil
	}
	if u.Scheme != "https" {
		return "", ErrInvalidTarget
	}
	if s.SupportResource != "" && n == normalizeIssuer(s.SupportResource) {
		return s.SupportResource, nil
	}
	if s.GlovoResource != "" && n == normalizeIssuer(s.GlovoResource) {
		// Admitted only with the kill switch on and every readiness
		// dependency present; GLOVO_MCP_RESOURCE alone never opens it.
		if !s.GlovoReady() {
			return "", ErrGlovoNotReady
		}
		return s.GlovoResource, nil
	}
	return "", ErrInvalidTarget
}

// namesThisAPI reports whether the normalized resource n is this API: its
// audience, its base URL or its /mcp endpoint.
func (s *OAuthServer) namesThisAPI(n string) bool {
	return n == normalizeIssuer(s.accessAudience()) || n == normalizeIssuer(s.BaseURL) || n == normalizeIssuer(s.BaseURL)+"/mcp"
}

// ValidateSupportResource refuses a SupportResource that would break every
// request: one naming this API makes verifyAccessToken classify every API
// token as a support token, so every API route answers 401; one that is not
// an absolute https URL without a fragment is never resolved, so every
// request for it is invalid_target. Empty (disabled) is valid.
func (s *OAuthServer) ValidateSupportResource() error {
	r := s.SupportResource
	if r == "" {
		return nil
	}
	u, err := url.Parse(r)
	if err != nil || !u.IsAbs() || u.Scheme != "https" || u.Host == "" || u.Fragment != "" || strings.Contains(r, "#") {
		return fmt.Errorf("OAUTH_SUPPORT_RESOURCE %q must be an absolute https URL without a fragment", r)
	}
	if s.namesThisAPI(normalizeIssuer(r)) {
		return fmt.Errorf("OAUTH_SUPPORT_RESOURCE %q names this API (its audience, base URL or /mcp endpoint)", r)
	}
	if s.GlovoResource != "" && normalizeIssuer(r) == normalizeIssuer(s.GlovoResource) {
		return fmt.Errorf("OAUTH_SUPPORT_RESOURCE %q equals GLOVO_MCP_RESOURCE", r)
	}
	return nil
}

// ValidateGlovoResource refuses a GlovoResource that is not an absolute
// https URL without a fragment, or that names this API or the support
// resource. Empty (disabled) is valid.
func (s *OAuthServer) ValidateGlovoResource() error {
	r := s.GlovoResource
	if r == "" {
		return nil
	}
	u, err := url.Parse(r)
	if err != nil || !u.IsAbs() || u.Scheme != "https" || u.Host == "" || u.Fragment != "" || strings.Contains(r, "#") {
		return fmt.Errorf("GLOVO_MCP_RESOURCE %q must be an absolute https URL without a fragment", r)
	}
	n := normalizeIssuer(r)
	if s.namesThisAPI(n) {
		return fmt.Errorf("GLOVO_MCP_RESOURCE %q names this API (its audience, base URL or /mcp endpoint)", r)
	}
	if s.SupportResource != "" && n == normalizeIssuer(s.SupportResource) {
		return fmt.Errorf("GLOVO_MCP_RESOURCE %q equals OAUTH_SUPPORT_RESOURCE", r)
	}
	return nil
}

// FlowResource is ResolveResource in the form the authorization flow and
// refresh sessions store: "" for the default API resource, so entries that
// predate the resource parameter mean the same thing.
func (s *OAuthServer) FlowResource(values []string) (string, error) {
	aud, err := s.ResolveResource(values)
	if err != nil {
		return "", err
	}
	if aud == s.accessAudience() {
		return "", nil
	}
	return aud, nil
}

// audienceForResource is the aud to mint for a stored flow resource.
func (s *OAuthServer) audienceForResource(resource string) string {
	if resource == "" {
		return s.accessAudience()
	}
	return resource
}
