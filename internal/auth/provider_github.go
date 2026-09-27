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
	"strconv"
)

// GroupSource resolves the groups (tenant names, "admins") for a GitHub
// login. The only implementation wraps today's resolveGroups verbatim
// (oidc.go:620-637); #377 replaces the implementation behind this seam with
// a principal-keyed one without touching this provider.
type GroupSource interface {
	GroupsFor(ctx context.Context, login string) []string
}

// legacyGroupSource wraps resolveGroups exactly as the pre-registry
// middleware called it, so ADMIN_USERS and gitops.Reader stay reached
// through the same call, unchanged (design.md "Isolating the GitHub
// couplings without changing them").
type legacyGroupSource struct {
	validator *GitHubValidator
	resolver  TenantResolver
}

func (s legacyGroupSource) GroupsFor(_ context.Context, login string) []string {
	return resolveGroups(login, s.validator, s.resolver)
}

// githubProvider is the opaque GitHub PAT provider: the last-resort match
// for any bearer token that is not a JWT and was not claimed by a
// static-secret provider (GitHubValidator.ValidateIdentity,
// internal/api's callers already depend on the same 401 wording on
// failure).
type githubProvider struct {
	validator *GitHubValidator
	groups    GroupSource
}

func newGitHubProvider(validator *GitHubValidator, groups GroupSource) *githubProvider {
	return &githubProvider{validator: validator, groups: groups}
}

func (*githubProvider) Name() string { return ProviderGitHub }

// Claims: the opaque fallback is chosen by the registry whenever the token
// is not a JWT and no static-secret provider matched; it does not need to
// inspect tokenShape itself, but implements Claims to satisfy Provider.
func (*githubProvider) Claims(t tokenShape) bool { return !t.jwt }

func (p *githubProvider) Verify(ctx context.Context, raw string) (*Verified, error) {
	login, id, err := p.validator.ValidateIdentity(ctx, raw)
	if err != nil {
		return nil, err
	}
	var groups []string
	if p.groups != nil {
		groups = p.groups.GroupsFor(ctx, login)
	}
	return &Verified{
		Identity: Identity{Provider: ProviderGitHub, Subject: strconv.FormatInt(id, 10), Display: login, Kind: KindHuman},
		Claims:   Claims{Groups: groups, GitHubID: id},
	}, nil
}
