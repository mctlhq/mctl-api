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

import "context"

// metricLabelLocalOAuth is the federation metrics' provider label for
// mctl-issued OAuth JWTs (OAuthServer.IssueJWT).
const metricLabelLocalOAuth = "mctl_oauth"

// localOAuthProvider is the local MCP OAuth HS256 JWT provider
// (OAuthServer.ValidateJWT, oauth_server.go:677-686). It is claimed by exact
// match of the token's unverified iss against OAuthServer.BaseURL.
type localOAuthProvider struct {
	oauth *OAuthServer
}

func newLocalOAuthProvider(o *OAuthServer) *localOAuthProvider {
	return &localOAuthProvider{oauth: o}
}

// Name declares this provider's identity namespace as ProviderGitHub
// explicitly, not derived: it mints only for a login the GitHub OAuth
// callback already validated before IssueCode (oauth_server.go:681-684), so
// "github" is its namespace by design. This is the one provider the
// registry allows to declare the reserved namespace "github" (see
// NewRegistry).
func (*localOAuthProvider) Name() string { return ProviderGitHub }

// metricLabel separates mctl-issued JWTs from raw GitHub tokens in the
// federation metrics; both are namespace "github", so without it
// provider="github" counts the two together.
func (*localOAuthProvider) metricLabel() string { return metricLabelLocalOAuth }

func (p *localOAuthProvider) issuerName() string {
	if p.oauth == nil {
		return ""
	}
	return p.oauth.BaseURL
}

func (p *localOAuthProvider) Claims(t tokenShape) bool {
	return t.jwt && p.oauth != nil && normalizeIssuer(t.iss) == normalizeIssuer(p.oauth.BaseURL)
}

func (p *localOAuthProvider) Verify(_ context.Context, raw string) (*Verified, error) {
	u, err := p.oauth.ValidateJWT(raw)
	if err != nil {
		return nil, err
	}
	return &Verified{
		Identity: Identity{Provider: ProviderGitHub, Display: u.ID, Kind: KindHuman},
		Claims:   Claims{Groups: u.Groups},
	}, nil
}
