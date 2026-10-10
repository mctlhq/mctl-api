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
	"errors"
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
	return &githubProvider{validator: validator, groups: groups}
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
		githubTokenVerifications.WithLabelValues(kind, githubFailureResult(err)).Inc()
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

// githubFailureResult separates GitHub refusing the token (invalid) from the
// lookup failing (unavailable: timeout, 5xx, cancelled request), so an outage
// does not read as callers presenting dead tokens.
func githubFailureResult(err error) string {
	if errors.Is(err, errGitHubTokenRejected) {
		return "invalid"
	}
	return "unavailable"
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
	Help: "Opaque bearer tokens verified as GitHub tokens, by kind (from the documented prefix) and result (ok, invalid = refused by GitHub, unavailable = lookup failed). Every non-JWT token no static provider claims lands here, so kind=other is mostly not GitHub traffic.",
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
		ua = strings.ToValidUTF8(ua[:maxLoggedUserAgent], "")
	}
	return ua
}

const (
	maxLoggedUserAgent = 200
	// sightingInterval is the dedupe window: an automation burst (hundreds
	// of calls in minutes) is one line, not hundreds, while the counter
	// still counts every call.
	sightingInterval = time.Hour
	// maxAgentsPerCaller bounds the lines per (login, kind) per window. The
	// User-Agent is client-controlled, so keying on it alone would let a
	// caller that varies it per request log on every request.
	maxAgentsPerCaller = 4
	// maxSightings caps the dedupe map; past it the map is reset, which only
	// costs a few repeated lines.
	maxSightings = 1024
)

// sightingLog logs a successful GitHub-token verification once per distinct
// user agent per (login, kind) per sightingInterval, at most
// maxAgentsPerCaller lines per window.
type sightingLog struct {
	mu   sync.Mutex
	seen map[string]*sighting
	now  func() time.Time
}

type sighting struct {
	start  time.Time
	agents map[string]struct{}
}

func (s *sightingLog) log(login, kind, ua string) {
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	key := login + "\x00" + kind
	t := now()
	s.mu.Lock()
	if s.seen == nil || len(s.seen) >= maxSightings {
		s.seen = map[string]*sighting{}
	}
	w, ok := s.seen[key]
	if !ok || t.Sub(w.start) >= sightingInterval {
		w = &sighting{start: t, agents: map[string]struct{}{}}
		s.seen[key] = w
	}
	if _, dup := w.agents[ua]; dup || len(w.agents) >= maxAgentsPerCaller {
		s.mu.Unlock()
		return
	}
	w.agents[ua] = struct{}{}
	s.mu.Unlock()
	slog.Info("github token verified", "login", login, "kind", kind, "user_agent", ua)
}
