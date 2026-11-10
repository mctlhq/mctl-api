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

// The Glovo worker (mctl-api#961) is a narrow machine identity, default OFF:
// it exists only while MCTL_GLOVO_WORKER_TOKEN_FILE names a readable file that
// holds a credential. It is distinct from the bridge provider
// (service:bridge-provider:<ref>) and from every other static principal, has
// no groups, no admin flag and no agent scope, and is confined to
// /api/v1/glovo/worker/ by glovoWorkerGate. The credential is test-only until
// the issuer decision (mctl-gitops#2506, #2540); nothing issues one in
// production under this change.
const (
	// GlovoWorkerUserID is the identity of the Glovo worker.
	GlovoWorkerUserID = "service:mctl-glovo-worker"

	glovoWorkerTokenFileEnv = "MCTL_GLOVO_WORKER_TOKEN_FILE" //nolint:gosec // env var name, not a credential
)

// NewGlovoWorkerUser builds the Glovo worker principal. Production builds it
// only from a matched credential.
func NewGlovoWorkerUser() *User {
	return &User{ID: GlovoWorkerUserID, glovoWorker: true}
}

// glovoWorkerToken reads the worker credential from the file named by
// MCTL_GLOVO_WORKER_TOKEN_FILE. Unset, unreadable, too short, or equal to any
// other principal's static token is "no worker": it never falls back to
// another credential.
func glovoWorkerToken() string {
	path := strings.TrimSpace(os.Getenv(glovoWorkerTokenFileEnv))
	if path == "" {
		return ""
	}
	raw, err := os.ReadFile(path) //nolint:gosec // operator-configured path
	if err != nil {
		slog.Error("glovo worker token file unreadable; glovo worker principal disabled", "env", glovoWorkerTokenFileEnv)
		return ""
	}
	token := strings.TrimSpace(string(raw))
	if len(token) < minSurfaceTokenLen {
		slog.Error("glovo worker token too short; glovo worker principal disabled", "env", glovoWorkerTokenFileEnv, "min_length", minSurfaceTokenLen)
		return ""
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
			slog.Error("glovo worker token equals another principal's token; glovo worker principal disabled", "equals", env)
			return ""
		}
		// Multi-line "ref=token" variables: compare each token too.
		sc := bufio.NewScanner(strings.NewReader(v))
		for sc.Scan() {
			if _, tok, ok := strings.Cut(strings.TrimSpace(sc.Text()), "="); ok && strings.TrimSpace(tok) == token {
				slog.Error("glovo worker token equals another principal's token; glovo worker principal disabled", "equals", env)
				return ""
			}
		}
	}
	return token
}

// GlovoWorkerConfigured reports whether a valid worker credential is
// configured. The Glovo routes stay not_ready while it is false.
func GlovoWorkerConfigured() bool { return glovoWorkerToken() != "" }

// glovoWorkerUserFor matches a bearer token against the worker credential in
// constant time.
func glovoWorkerUserFor(configured, token string) *User {
	if !secretMatches(configured, token) {
		return nil
	}
	return NewGlovoWorkerUser()
}

type glovoWorkerProvider struct{ token func() string }

func newGlovoWorkerProvider(token func() string) *glovoWorkerProvider {
	return &glovoWorkerProvider{token: token}
}

func (*glovoWorkerProvider) Name() string           { return ProviderService }
func (*glovoWorkerProvider) Claims(tokenShape) bool { return true }

func (p *glovoWorkerProvider) Verify(_ context.Context, raw string) (*Verified, error) {
	if !secretMatches(p.token(), raw) {
		return nil, ErrNoProvider
	}
	return &Verified{Identity: Identity{Provider: ProviderService, Subject: GlovoWorkerUserID, Display: GlovoWorkerUserID, Kind: KindService}}, nil
}
