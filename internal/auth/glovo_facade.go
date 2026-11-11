// Copyright 2026 MCTL Authors
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
	"log/slog"
	"os"
	"strings"
)

// The Glovo join facade principal (mctl-api#957 design 2) is the machine
// identity of the mctl-telegram Glovo facade when it calls the join routes
// under /api/v1/assistants/glovo/v1alpha1/. It is default OFF: it exists only
// while MCTL_GLOVO_FACADE_TOKEN holds a credential. It is distinct from every
// other principal (bridge provider, #961 worker, control worker, surfaces,
// usage and evidence writers, the service token), has no groups, no admin flag
// and no agent scope, and is confined to the join prefix by the join gate. It
// carries no user and no tenant: the tenant and the owner come from the
// verified subject token (SubjectVerifier), never from this identity.
const (
	// GlovoFacadeUserID is the identity of the Glovo join facade.
	GlovoFacadeUserID = "service:mctl-glovo-facade"

	glovoFacadeTokenEnv = "MCTL_GLOVO_FACADE_TOKEN" //nolint:gosec // env var name, not a credential
)

// NewGlovoFacadeUser builds the facade principal. Production builds it only
// from a matched credential.
func NewGlovoFacadeUser() *User {
	return &User{ID: GlovoFacadeUserID, glovoFacade: true}
}

// IsGlovoFacade reports whether the caller is the Glovo join facade. It is
// false for every other principal, admins included.
func (u *User) IsGlovoFacade() bool { return u != nil && u.glovoFacade }

// glovoFacadeToken reads the facade credential from MCTL_GLOVO_FACADE_TOKEN.
// Unset, too short, or equal to any other principal's static token is "no
// facade": the startup check (GlovoFacadeTokenProblem) names the reason and the
// principal is never built from a credential that another principal also
// accepts.
func glovoFacadeToken() string {
	token, problem := glovoFacadeTokenChecked()
	if problem != "" {
		slog.Error("glovo facade token unusable; glovo facade principal disabled", "env", glovoFacadeTokenEnv, "reason", problem)
		return ""
	}
	return token
}

// GlovoFacadeTokenProblem returns why a configured facade token is refused, or
// "" when the token is unset or acceptable. Startup uses it to refuse to boot
// with a facade token that equals another machine token.
func GlovoFacadeTokenProblem() string {
	_, problem := glovoFacadeTokenChecked()
	return problem
}

// GlovoFacadeConfigured reports whether a valid facade credential is
// configured. The join routes stay not_ready while it is false.
func GlovoFacadeConfigured() bool {
	token, problem := glovoFacadeTokenChecked()
	return token != "" && problem == ""
}

func glovoFacadeTokenChecked() (token, problem string) {
	token = strings.TrimSpace(os.Getenv(glovoFacadeTokenEnv))
	if token == "" {
		return "", ""
	}
	if len(token) < minSurfaceTokenLen {
		return "", "too_short"
	}
	others := []string{"MCTL_AGENT_SERVICE_TOKEN", usageWriterTokenEnv, evidenceWriterTokenEnv, registryPublisherTokenEnv,
		supportIncidentProducerTokenEnv, securityProviderTokensEnv, bridgeProviderTokensEnv}
	for _, env := range surfaceTokenEnv {
		others = append(others, env)
	}
	for _, env := range others {
		v := strings.TrimSpace(os.Getenv(env))
		if v == "" {
			continue
		}
		if v == token {
			return "", "equals_" + env
		}
		// Multi-line "ref=token" variables: compare each token too.
		sc := bufio.NewScanner(strings.NewReader(v))
		for sc.Scan() {
			if _, tok, ok := strings.Cut(strings.TrimSpace(sc.Text()), "="); ok && strings.TrimSpace(tok) == token {
				return "", "equals_" + env
			}
		}
	}
	// The #961 worker credential lives in a file, not an env value.
	if w := glovoWorkerToken(); w != "" && w == token {
		return "", "equals_" + glovoWorkerTokenFileEnv
	}
	return token, ""
}

// glovoFacadeUserFor matches a bearer token against the facade credential in
// constant time.
func glovoFacadeUserFor(configured, token string) *User {
	if !secretMatches(configured, token) {
		return nil
	}
	return NewGlovoFacadeUser()
}

type glovoFacadeProvider struct{ token func() string }

func newGlovoFacadeProvider(token func() string) *glovoFacadeProvider {
	return &glovoFacadeProvider{token: token}
}

func (*glovoFacadeProvider) Name() string           { return ProviderService }
func (*glovoFacadeProvider) Claims(tokenShape) bool { return true }

func (p *glovoFacadeProvider) Verify(_ context.Context, raw string) (*Verified, error) {
	if !secretMatches(p.token(), raw) {
		return nil, ErrNoProvider
	}
	return &Verified{Identity: Identity{Provider: ProviderService, Subject: GlovoFacadeUserID, Display: GlovoFacadeUserID, Kind: KindService}}, nil
}
