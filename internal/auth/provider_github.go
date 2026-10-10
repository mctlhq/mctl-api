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
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
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
	sightings sightingLog
}

func newGitHubProvider(validator *GitHubValidator, groups GroupSource) *githubProvider {
	return &githubProvider{validator: validator, groups: groups, sightings: sightingLog{seen: map[string]time.Time{}}}
}

func (*githubProvider) Name() string { return ProviderGitHub }

// Claims: the opaque fallback is chosen by the registry whenever the token
// is not a JWT and no static-secret provider matched; it does not need to
// inspect tokenShape itself, but implements Claims to satisfy Provider.
func (*githubProvider) Claims(t tokenShape) bool { return !t.jwt }

func (p *githubProvider) Verify(ctx context.Context, raw string) (*Verified, error) {
	kind := githubTokenKind(raw)
	login, id, err := p.validator.ValidateIdentity(ctx, raw)
	if err != nil {
		githubTokenVerifications.WithLabelValues(kind, "invalid").Inc()
		return nil, err
	}
	githubTokenVerifications.WithLabelValues(kind, "ok").Inc()
	p.sightings.log(login, kind, userAgentFromContext(ctx))
	var groups []string
	if p.groups != nil {
		groups = p.groups.GroupsFor(ctx, login)
	}
	return &Verified{
		Identity: Identity{Provider: ProviderGitHub, Subject: strconv.FormatInt(id, 10), Display: login, Kind: KindHuman},
		Claims:   Claims{Groups: groups, GitHubID: id},
	}, nil
}

// Raw GitHub tokens are being retired as a human credential (mctl-api#525).
// Before that can happen, the verifications have to be attributed: a person
// running `gh auth token` (an OAuth app token, gho_), a PAT in a script, or a
// GitHub App token in automation. The token kind is read from GitHub's
// documented prefixes; nothing past the prefix ever reaches a label or a log.
var githubTokenPrefixes = []struct{ prefix, kind string }{
	{"github_pat_", "fine_grained_pat"},
	{"ghp_", "classic_pat"},
	{"gho_", "oauth_app"},
	{"ghu_", "app_user"},
	{"ghs_", "app_installation"},
}

func githubTokenKind(raw string) string {
	for _, t := range githubTokenPrefixes {
		if strings.HasPrefix(raw, t.prefix) {
			return t.kind
		}
	}
	return "other"
}

var githubTokenVerifications = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "github_token_verifications_total",
	Help: "Raw GitHub tokens verified by the GitHub provider, by token kind (from the documented prefix) and result (ok, invalid).",
}, []string{"kind", "result"})

func init() {
	prometheus.MustRegister(githubTokenVerifications)
}

// userAgentKey carries the request's User-Agent into Verify, so a GitHub
// token can be attributed to the client that sent it (mctl CLI, curl, an
// MCP client). Only the auth middleware sets it.
const userAgentKey contextKey = "userAgent"

func withUserAgent(ctx context.Context, ua string) context.Context {
	return context.WithValue(ctx, userAgentKey, ua)
}

func userAgentFromContext(ctx context.Context) string {
	ua, _ := ctx.Value(userAgentKey).(string)
	if len(ua) > maxLoggedUserAgent {
		ua = ua[:maxLoggedUserAgent]
	}
	return ua
}

const (
	maxLoggedUserAgent = 200
	// sightingInterval bounds the log to one line per caller per hour: an
	// automation burst (hundreds of calls in minutes) is one line, not
	// hundreds, while the counter still counts every call.
	sightingInterval = time.Hour
	// maxSightings caps the dedupe map; past it the map is reset, which only
	// costs a few repeated lines.
	maxSightings = 1024
)

// sightingLog logs a successful GitHub-token verification once per (login,
// kind, user agent) per sightingInterval.
type sightingLog struct {
	mu   sync.Mutex
	seen map[string]time.Time
	now  func() time.Time
}

func (s *sightingLog) log(login, kind, ua string) {
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	key := login + "\x00" + kind + "\x00" + ua
	s.mu.Lock()
	if s.seen == nil || len(s.seen) >= maxSightings {
		s.seen = map[string]time.Time{}
	}
	t := now()
	if last, ok := s.seen[key]; ok && t.Sub(last) < sightingInterval {
		s.mu.Unlock()
		return
	}
	s.seen[key] = t
	s.mu.Unlock()
	slog.Info("github token verified", "login", login, "kind", kind, "user_agent", ua)
}
