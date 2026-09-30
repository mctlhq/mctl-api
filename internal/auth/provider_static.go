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
	"crypto/subtle"
)

// secretMatches is the one constant-time comparison every static-secret
// provider routes through, so a future static provider cannot reintroduce a
// timing-unsafe ==. An empty configured secret never matches, and no
// comparison against presented is even performed in that case: an unset
// secret must not leak a length- or byte-shaped timing signal either.
//
// This is what fixes the plain == that staticServiceUser used to compare
// MCTL_AGENT_SERVICE_TOKEN with (oidc.go:448): a deliberate, stated
// behaviour fix (requirements.md "Static-secret matching"), not a refactor.
// The accept/reject outcome is unchanged for every input; only the timing
// signal is removed. Pinned by TestSecretMatchesBehaviourTable (T13) and by
// a source-scanning test (T14) that this file contains no ==/!= comparison
// against the presented token.
func secretMatches(configured, presented string) bool {
	if configured == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(configured), []byte(presented)) == 1
}

// serviceTokenProvider is the static-secret provider for
// MCTL_AGENT_SERVICE_TOKEN, minting the platform-internal service principal
// (ServiceUserID). Its Verify reads the env var itself, like
// staticServiceUser did, so a token rotated at runtime (via pod restart)
// takes effect without rebuilding the registry.
type serviceTokenProvider struct{ token func() string }

func newServiceTokenProvider(token func() string) *serviceTokenProvider {
	return &serviceTokenProvider{token: token}
}

func (*serviceTokenProvider) Name() string { return ProviderService }

// Claims is unused for routing: the registry tries every static-secret
// provider unconditionally and in order (Registry.Verify), regardless of
// tokenShape, because a static secret is not a JWT and carries nothing to
// route on cheaply. It is implemented to satisfy the Provider contract.
func (*serviceTokenProvider) Claims(tokenShape) bool { return true }

func (p *serviceTokenProvider) Verify(_ context.Context, raw string) (*Verified, error) {
	if !secretMatches(p.token(), raw) {
		return nil, ErrNoProvider
	}
	return &Verified{Identity: Identity{Provider: ProviderService, Subject: ServiceUserID, Display: ServiceUserID, Kind: KindService}}, nil
}

// surfaceProvider is the static-secret provider for the per-surface tokens
// (MCTL_SURFACE_TELEGRAM_TOKEN, MCTL_SURFACE_PORTAL_TOKEN, mctl-api#350).
// Both construction sites (BuildFederationRegistry, defaultFederationRegistry)
// pass a closure over the map surfaceTokens() validated once at startup, as
// the pre-registry Middleware does: the process environment cannot change
// under a running pod, so rotating a surface token means a restart, and
// re-reading per request only repeated the validation's error logging.
type surfaceProvider struct{ tokens func() map[string]string }

func newSurfaceProvider(tokens func() map[string]string) *surfaceProvider {
	return &surfaceProvider{tokens: tokens}
}

func (*surfaceProvider) Name() string           { return ProviderService }
func (*surfaceProvider) Claims(tokenShape) bool { return true }

func (p *surfaceProvider) Verify(_ context.Context, raw string) (*Verified, error) {
	u := surfaceUserFor(p.tokens(), raw)
	if u == nil {
		return nil, ErrNoProvider
	}
	return &Verified{Identity: Identity{Provider: ProviderService, Subject: u.ID, Display: u.ID, Kind: KindService}}, nil
}

// usageWriterProvider is the static-secret provider for
// MCTL_USAGE_WRITER_TOKEN (mctlhq/.github#50, variant B).
type usageWriterProvider struct{ token func() string }

func newUsageWriterProvider(token func() string) *usageWriterProvider {
	return &usageWriterProvider{token: token}
}

func (*usageWriterProvider) Name() string           { return ProviderService }
func (*usageWriterProvider) Claims(tokenShape) bool { return true }

func (p *usageWriterProvider) Verify(_ context.Context, raw string) (*Verified, error) {
	if !secretMatches(p.token(), raw) {
		return nil, ErrNoProvider
	}
	return &Verified{Identity: Identity{Provider: ProviderService, Subject: UsageWriterUserID, Display: UsageWriterUserID, Kind: KindService}}, nil
}

// evidenceWriterProvider is the static-secret provider for
// MCTL_EVIDENCE_WRITER_TOKEN (mctl-api#409), modelled one-for-one on
// usageWriterProvider.
type evidenceWriterProvider struct{ token func() string }

func newEvidenceWriterProvider(token func() string) *evidenceWriterProvider {
	return &evidenceWriterProvider{token: token}
}

func (*evidenceWriterProvider) Name() string           { return ProviderService }
func (*evidenceWriterProvider) Claims(tokenShape) bool { return true }

func (p *evidenceWriterProvider) Verify(_ context.Context, raw string) (*Verified, error) {
	if !secretMatches(p.token(), raw) {
		return nil, ErrNoProvider
	}
	return &Verified{Identity: Identity{Provider: ProviderService, Subject: EvidenceWriterUserID, Display: EvidenceWriterUserID, Kind: KindService}}, nil
}
