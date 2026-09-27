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

// Tests for mctl-api#411: re-resolving tenant groups on OAuth refresh and
// validate instead of freezing them at first login. Every test here asserts
// on the *issued* JWT claim (via mustIssuedGroups, which decodes the payload
// directly with verifyJWT) rather than on a round-trip through ValidateJWT,
// so the assertion targets what RefreshAccessToken/ExchangeCode put on the
// token and is not itself laundered through ValidateJWT's own re-resolution.

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth/refreshstore"
)

// ─── Test doubles ───────────────────────────────────────────────────────────

// stubTenantResolver is a settable TenantResolver test double with no
// LastSync method: OAuthServer's freshness gate skips a resolver that cannot
// report sync state (resolveGroupsChecked / checkResolverFreshness), so most
// tests below never need to think about staleness at all.
type stubTenantResolver struct {
	mu      sync.Mutex
	tenants map[string][]string
	err     error
	calls   int
}

func (r *stubTenantResolver) GetTenantsForUser(login string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.err != nil {
		return nil, r.err
	}
	return append([]string(nil), r.tenants[login]...), nil
}

func (r *stubTenantResolver) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func (r *stubTenantResolver) setErr(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.err = err
}

func (r *stubTenantResolver) setTenants(login string, tenants []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tenants == nil {
		r.tenants = make(map[string][]string)
	}
	r.tenants[login] = tenants
}

// syncingTenantResolver adds an optional LastSync() to a stubTenantResolver,
// for the freshness-gate tests. A zero value (the default) means "never
// synced", matching gitops.Reader before its first successful clone.
type syncingTenantResolver struct {
	*stubTenantResolver
	mu       sync.Mutex
	lastSync time.Time
}

func newSyncingTenantResolver() *syncingTenantResolver {
	return &syncingTenantResolver{stubTenantResolver: &stubTenantResolver{}}
}

func (r *syncingTenantResolver) LastSync() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastSync
}

func (r *syncingTenantResolver) setLastSync(t time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastSync = t
}

// fakeRefreshToken is one row of fakeRefreshStore.
type fakeRefreshToken struct {
	login     string
	clientID  string
	groups    []string
	familyID  string
	rotatedTo string
	revoked   bool
}

// fakeRefreshStore is an in-memory refreshstore.Store test double, so the
// RefreshStore-backed path can be exercised without a PostgreSQL dependency.
// It reproduces just enough of PostgresStore's behaviour for these tests:
// rotation inheriting a family id, reuse detection revoking the whole
// family, and client_id scoping.
type fakeRefreshStore struct {
	mu     sync.Mutex
	tokens map[string]*fakeRefreshToken
	seq    int
}

func newFakeRefreshStore() *fakeRefreshStore {
	return &fakeRefreshStore{tokens: make(map[string]*fakeRefreshToken)}
}

func (f *fakeRefreshStore) Insert(rawToken, login, clientID string, groups []string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	f.tokens[rawToken] = &fakeRefreshToken{
		login:    login,
		clientID: clientID,
		groups:   append([]string(nil), groups...),
		familyID: fmt.Sprintf("%s-family-%d", login, f.seq),
	}
	return nil
}

func (f *fakeRefreshStore) Rotate(oldRawToken, newRawToken, clientID string, _ time.Time) (string, []string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	entry, ok := f.tokens[oldRawToken]
	if !ok {
		return "", nil, refreshstore.ErrInvalidToken
	}
	if entry.revoked {
		return "", nil, refreshstore.ErrInvalidToken
	}
	if entry.rotatedTo != "" {
		// Reuse of an already-rotated token: revoke the whole family, same
		// as PostgresStore.rotateTx.
		for _, e := range f.tokens {
			if e.familyID == entry.familyID {
				e.revoked = true
			}
		}
		return "", nil, refreshstore.ErrReuseDetected
	}
	if entry.clientID != clientID {
		return "", nil, refreshstore.ErrClientMismatch
	}
	entry.rotatedTo = newRawToken
	f.tokens[newRawToken] = &fakeRefreshToken{
		login:    entry.login,
		clientID: entry.clientID,
		groups:   append([]string(nil), entry.groups...),
		familyID: entry.familyID,
	}
	return entry.login, append([]string(nil), entry.groups...), nil
}

func (f *fakeRefreshStore) RevokeFamily(rawToken, clientID, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	entry, ok := f.tokens[rawToken]
	if !ok {
		return nil
	}
	for _, e := range f.tokens {
		if e.familyID == entry.familyID && (clientID == "" || e.clientID == clientID) {
			e.revoked = true
		}
	}
	return nil
}

func (f *fakeRefreshStore) GC() error { return nil }

// ─── Helpers ────────────────────────────────────────────────────────────────

func newTestOAuthServer(_ *testing.T) *OAuthServer {
	return NewOAuthServer(
		"https://api.mctl.ai",
		"gh-client",
		"gh-secret",
		[]byte("jwt-secret-for-groups-tests"),
		[]string{"https://client.example/callback"},
		NewGitHubValidator(nil),
	)
}

// mustIssuedGroups decodes the groups claim directly off the JWT payload,
// without going through ValidateJWT (which re-resolves groups itself and
// would defeat an assertion aimed at what RefreshAccessToken/ExchangeCode
// issued).
func mustIssuedGroups(t *testing.T, server *OAuthServer, token string) []string {
	t.Helper()
	payload, err := verifyJWT(token, server.JWTSecret, server.BaseURL)
	if err != nil {
		t.Fatalf("verifyJWT: %v", err)
	}
	return payload.Groups
}

// gitopsSyncAgeSeconds mirrors the scrape-time prometheus.GaugeFunc that
// cmd/api/main.go registers as mctl_api_gitops_last_sync_age_seconds next to
// the gitops reader. That registration closes over the concrete *gitops.
// Reader and cannot be unit-tested from this package; this pins the formula
// it must use instead: computed fresh from LastSync() on every call, never a
// value written only on a "stale" code path (which would never reset after
// recovery).
func gitopsSyncAgeSeconds(src interface{ LastSync() time.Time }) float64 {
	last := src.LastSync()
	if last.IsZero() {
		return -1
	}
	return time.Since(last).Seconds()
}

// ─── T1 / T2: RefreshStore path ─────────────────────────────────────────────

func TestGroupsRefreshStoreGrant(t *testing.T) {
	server := newTestOAuthServer(t)
	store := newFakeRefreshStore()
	server.RefreshStore = store
	resolver := &stubTenantResolver{}
	resolver.setTenants("dmitrii", []string{"acme", "karabu"})
	server.TenantResolver = resolver

	if err := store.Insert("refresh-t1", "dmitrii", "client-1", []string{"acme"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("insert: %v", err)
	}

	accessToken, _, err := server.RefreshAccessToken("refresh-t1", "client-1")
	if err != nil {
		t.Fatalf("RefreshAccessToken: %v", err)
	}
	groups := mustIssuedGroups(t, server, accessToken)
	if !slices.Contains(groups, "karabu") {
		t.Fatalf("expected karabu in the refreshed access token, got %v", groups)
	}
}

func TestGroupsRefreshStoreRevoke(t *testing.T) {
	server := newTestOAuthServer(t)
	store := newFakeRefreshStore()
	server.RefreshStore = store
	resolver := &stubTenantResolver{}
	resolver.setTenants("dmitrii", []string{"acme"})
	server.TenantResolver = resolver

	if err := store.Insert("refresh-t2", "dmitrii", "client-1", []string{"acme", "karabu"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("insert: %v", err)
	}

	accessToken, _, err := server.RefreshAccessToken("refresh-t2", "client-1")
	if err != nil {
		t.Fatalf("RefreshAccessToken: %v", err)
	}
	groups := mustIssuedGroups(t, server, accessToken)
	if slices.Contains(groups, "karabu") {
		t.Fatalf("expected karabu to be dropped from the refreshed access token, got %v", groups)
	}
}

// ─── T3 / T4: in-memory path ────────────────────────────────────────────────

func TestGroupsInMemoryGrant(t *testing.T) {
	server := newTestOAuthServer(t)
	resolver := &stubTenantResolver{}
	resolver.setTenants("dmitrii", []string{"acme", "karabu"})
	server.TenantResolver = resolver

	raw, err := server.IssueRefreshToken("dmitrii", []string{"acme"}, "client-1")
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}
	accessToken, _, err := server.RefreshAccessToken(raw, "client-1")
	if err != nil {
		t.Fatalf("RefreshAccessToken: %v", err)
	}
	groups := mustIssuedGroups(t, server, accessToken)
	if !slices.Contains(groups, "karabu") {
		t.Fatalf("expected karabu in the refreshed access token, got %v", groups)
	}
}

func TestGroupsInMemoryRevoke(t *testing.T) {
	server := newTestOAuthServer(t)
	resolver := &stubTenantResolver{}
	resolver.setTenants("dmitrii", []string{"acme"})
	server.TenantResolver = resolver

	raw, err := server.IssueRefreshToken("dmitrii", []string{"acme", "karabu"}, "client-1")
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}
	accessToken, newRefresh, err := server.RefreshAccessToken(raw, "client-1")
	if err != nil {
		t.Fatalf("RefreshAccessToken: %v", err)
	}
	groups := mustIssuedGroups(t, server, accessToken)
	if slices.Contains(groups, "karabu") {
		t.Fatalf("expected karabu dropped from the access token, got %v", groups)
	}

	// The successor refresh token (in-memory path only) should also carry
	// the re-resolved groups.
	entry, ok := server.refreshTokens.loadAndDelete(newRefresh)
	if !ok {
		t.Fatalf("expected successor refresh token to be present")
	}
	if slices.Contains(entry.Groups, "karabu") {
		t.Fatalf("expected successor refresh token to drop karabu, got %v", entry.Groups)
	}
}

// ─── T5 / T6: admins follows IsAdmin, not the stored/claimed snapshot ──────

func TestGroupsAdminsGained(t *testing.T) {
	server := newTestOAuthServer(t)
	server.GitHubValidator = NewGitHubValidator([]string{"dmitrii"})
	resolver := &stubTenantResolver{}
	resolver.setTenants("dmitrii", nil)
	server.TenantResolver = resolver

	raw, err := server.IssueRefreshToken("dmitrii", []string{"acme"}, "client-1")
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}
	accessToken, _, err := server.RefreshAccessToken(raw, "client-1")
	if err != nil {
		t.Fatalf("RefreshAccessToken: %v", err)
	}
	groups := mustIssuedGroups(t, server, accessToken)
	if !slices.Contains(groups, "admins") {
		t.Fatalf("expected admins to be granted, got %v", groups)
	}
}

func TestGroupsAdminsLost(t *testing.T) {
	server := newTestOAuthServer(t)
	server.GitHubValidator = NewGitHubValidator(nil)
	resolver := &stubTenantResolver{}
	resolver.setTenants("dmitrii", []string{"acme"})
	server.TenantResolver = resolver

	raw, err := server.IssueRefreshToken("dmitrii", []string{"acme", "admins"}, "client-1")
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}
	accessToken, _, err := server.RefreshAccessToken(raw, "client-1")
	if err != nil {
		t.Fatalf("RefreshAccessToken: %v", err)
	}
	groups := mustIssuedGroups(t, server, accessToken)
	if slices.Contains(groups, "admins") {
		t.Fatalf("expected admins to be withdrawn, got %v", groups)
	}
}

// ─── T7 / T8: degradation policy ────────────────────────────────────────────

func TestGroupsDegradedWithinGrace(t *testing.T) {
	server := newTestOAuthServer(t)
	resolver := &stubTenantResolver{}
	resolver.setErr(errors.New("gitops checkout unreachable"))
	server.TenantResolver = resolver
	server.GroupsDegradedGrace = time.Hour

	raw, err := server.IssueRefreshToken("dmitrii", []string{"acme"}, "client-1")
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}
	accessToken, newRefresh, err := server.RefreshAccessToken(raw, "client-1")
	if err != nil {
		t.Fatalf("expected the refresh to still succeed during a degraded resolution: %v", err)
	}
	if newRefresh == "" {
		t.Fatal("expected the refresh token to still rotate during a degraded resolution")
	}
	groups := mustIssuedGroups(t, server, accessToken)
	if !slices.Contains(groups, "acme") {
		t.Fatalf("expected stored tenant groups to survive a degraded resolution, got %v", groups)
	}
}

func TestGroupsFailClosedBeyondGrace(t *testing.T) {
	server := newTestOAuthServer(t)
	server.GitHubValidator = NewGitHubValidator([]string{"dmitrii"})
	resolver := &stubTenantResolver{}
	resolver.setErr(errors.New("gitops checkout unreachable"))
	server.TenantResolver = resolver
	server.GroupsDegradedGrace = time.Minute
	// Push the last successful resolution back beyond the grace window.
	server.lastResolveOK.Store(time.Now().Add(-time.Hour).UnixNano())

	raw, err := server.IssueRefreshToken("dmitrii", []string{"acme"}, "client-1")
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}
	accessToken, _, err := server.RefreshAccessToken(raw, "client-1")
	if err != nil {
		t.Fatalf("expected the refresh to still succeed beyond grace: %v", err)
	}
	groups := mustIssuedGroups(t, server, accessToken)
	if slices.Contains(groups, "acme") {
		t.Fatalf("expected tenant groups dropped once beyond grace, got %v", groups)
	}
	if !slices.Contains(groups, "admins") {
		t.Fatalf("expected admins retained beyond grace, got %v", groups)
	}
}

// ─── T9 / T9a / T9b / T9c / T9d: freshness gate ─────────────────────────────

func TestGroupsNeverSyncedIsNotNoTenants(t *testing.T) {
	server := newTestOAuthServer(t)
	resolver := newSyncingTenantResolver() // zero LastSync: never synced.
	server.TenantResolver = resolver
	server.GroupsDegradedGrace = time.Hour

	raw, err := server.IssueRefreshToken("dmitrii", []string{"acme"}, "client-1")
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}
	accessToken, _, err := server.RefreshAccessToken(raw, "client-1")
	if err != nil {
		t.Fatalf("expected the refresh to still succeed: %v", err)
	}
	groups := mustIssuedGroups(t, server, accessToken)
	if !slices.Contains(groups, "acme") {
		t.Fatalf("expected stored tenant groups to survive a never-synced checkout, got %v", groups)
	}
	if got := resolver.callCount(); got != 0 {
		t.Fatalf("expected GetTenantsForUser never to be called before a checkout has ever synced, got %d calls", got)
	}
}

func TestGroupsStaleButPresentStillAnswers(t *testing.T) {
	server := newTestOAuthServer(t)
	resolver := newSyncingTenantResolver()
	resolver.setLastSync(time.Now().Add(-2 * time.Hour))
	resolver.setTenants("dmitrii", []string{"acme", "karabu"})
	server.TenantResolver = resolver

	raw, err := server.IssueRefreshToken("dmitrii", []string{"acme"}, "client-1")
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}
	accessToken, _, err := server.RefreshAccessToken(raw, "client-1")
	if err != nil {
		t.Fatalf("expected the refresh to still succeed from a stale-but-present checkout: %v", err)
	}
	groups := mustIssuedGroups(t, server, accessToken)
	if !slices.Contains(groups, "karabu") {
		t.Fatalf("expected the resolved groups from the stale checkout, got %v", groups)
	}
	if since := time.Since(server.lastResolveOKTime()); since < 0 || since > time.Second {
		t.Fatalf("expected lastResolveOK to have just advanced (no drift toward fail-closed), age=%v", since)
	}
	age := time.Since(resolver.LastSync()).Seconds()
	if age < 7000 || age > 7300 {
		t.Fatalf("expected the checkout age to be around 7200s, got %v", age)
	}
}

func TestGroupsStrictMode(t *testing.T) {
	// A 2h-stale checkout is a failure once GroupsMaxStaleness=15m is set.
	server := newTestOAuthServer(t)
	resolver := newSyncingTenantResolver()
	resolver.setLastSync(time.Now().Add(-2 * time.Hour))
	resolver.setTenants("dmitrii", []string{"acme", "karabu"})
	server.TenantResolver = resolver
	server.GroupsMaxStaleness = 15 * time.Minute
	server.GroupsDegradedGrace = time.Hour

	raw, err := server.IssueRefreshToken("dmitrii", []string{"acme"}, "client-1")
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}
	accessToken, _, err := server.RefreshAccessToken(raw, "client-1")
	if err != nil {
		t.Fatalf("expected the refresh to still succeed via the degraded fallback: %v", err)
	}
	groups := mustIssuedGroups(t, server, accessToken)
	if slices.Contains(groups, "karabu") {
		t.Fatalf("expected strict mode to treat the stale checkout as failed, got %v", groups)
	}
	if !slices.Contains(groups, "acme") {
		t.Fatalf("expected the degraded fallback to keep stored tenant groups, got %v", groups)
	}

	// A stricter operator setting wins even when the checkout is *below* the
	// fixed 15m warn threshold: 10m old with GroupsMaxStaleness=5m fails too.
	server2 := newTestOAuthServer(t)
	resolver2 := newSyncingTenantResolver()
	resolver2.setLastSync(time.Now().Add(-10 * time.Minute))
	resolver2.setTenants("dmitrii", []string{"acme", "karabu"})
	server2.TenantResolver = resolver2
	server2.GroupsMaxStaleness = 5 * time.Minute
	server2.GroupsDegradedGrace = time.Hour

	raw2, err := server2.IssueRefreshToken("dmitrii", []string{"acme"}, "client-1")
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}
	accessToken2, _, err := server2.RefreshAccessToken(raw2, "client-1")
	if err != nil {
		t.Fatalf("expected the refresh to still succeed via the degraded fallback: %v", err)
	}
	groups2 := mustIssuedGroups(t, server2, accessToken2)
	if slices.Contains(groups2, "karabu") {
		t.Fatalf("expected a 5m OAUTH_GROUPS_MAX_STALENESS to fail a 10m-old checkout even though it is under the fixed 15m warn threshold, got %v", groups2)
	}
}

func TestGroupsMemoEviction(t *testing.T) {
	server := newTestOAuthServer(t)
	server.GroupsCacheTTL = 20 * time.Millisecond
	resolver := &stubTenantResolver{}
	resolver.setTenants("alice", []string{"acme"})
	resolver.setTenants("bob", []string{"beta"})
	server.TenantResolver = resolver

	if _, err := server.resolveGroupsChecked("alice"); err != nil {
		t.Fatalf("resolve alice: %v", err)
	}
	time.Sleep(40 * time.Millisecond)
	if _, err := server.resolveGroupsChecked("bob"); err != nil {
		t.Fatalf("resolve bob: %v", err)
	}

	server.groupsCacheMu.Lock()
	n := len(server.groupsCache)
	server.groupsCacheMu.Unlock()
	if n != 1 {
		t.Fatalf("expected alice's expired entry to be evicted on bob's write, map has %d entries", n)
	}
}

func TestGitopsSyncAgeGaugeFormula(t *testing.T) {
	resolver := newSyncingTenantResolver()

	resolver.setLastSync(time.Now().Add(-2 * time.Hour))
	if age := gitopsSyncAgeSeconds(resolver); age < 7000 || age > 7300 {
		t.Fatalf("expected ~7200s, got %v", age)
	}

	resolver.setLastSync(time.Now())
	if age := gitopsSyncAgeSeconds(resolver); age < 0 || age > 5 {
		t.Fatalf("expected the gauge to drop back to ~0s right after LastSync advances, got %v", age)
	}

	resolver.setLastSync(time.Time{})
	if got := gitopsSyncAgeSeconds(resolver); got != -1 {
		t.Fatalf("expected -1 while never synced, got %v", got)
	}
}

// ─── T10 / T11 / T12: back-compat, validate-time re-resolution, memo bound ─

func TestGroupsNoResolverBackCompat(t *testing.T) {
	server := newTestOAuthServer(t)
	// TenantResolver left nil.

	raw, err := server.IssueRefreshToken("dmitrii", []string{"acme"}, "client-1")
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}
	accessToken, _, err := server.RefreshAccessToken(raw, "client-1")
	if err != nil {
		t.Fatalf("RefreshAccessToken: %v", err)
	}
	groups := mustIssuedGroups(t, server, accessToken)
	if !slices.Equal(groups, []string{"acme"}) {
		t.Fatalf("expected stored groups unchanged with no resolver configured, got %v", groups)
	}

	user, err := server.ValidateJWT(accessToken)
	if err != nil {
		t.Fatalf("ValidateJWT: %v", err)
	}
	if !slices.Equal(user.Groups, []string{"acme"}) {
		t.Fatalf("expected ValidateJWT to pass the claimed groups through unchanged, got %v", user.Groups)
	}
}

func TestValidateJWTReResolves(t *testing.T) {
	server := newTestOAuthServer(t)
	server.GroupsCacheTTL = time.Millisecond
	resolver := &stubTenantResolver{}
	resolver.setTenants("dmitrii", []string{"acme"})
	server.TenantResolver = resolver

	token, err := server.IssueJWT("dmitrii", []string{"acme"})
	if err != nil {
		t.Fatalf("IssueJWT: %v", err)
	}

	user, err := server.ValidateJWT(token)
	if err != nil {
		t.Fatalf("ValidateJWT: %v", err)
	}
	if slices.Contains(user.Groups, "karabu") {
		t.Fatalf("did not expect karabu before the membership was granted, got %v", user.Groups)
	}

	resolver.setTenants("dmitrii", []string{"acme", "karabu"})
	time.Sleep(5 * time.Millisecond)
	user, err = server.ValidateJWT(token)
	if err != nil {
		t.Fatalf("ValidateJWT: %v", err)
	}
	if !slices.Contains(user.Groups, "karabu") {
		t.Fatalf("expected karabu after the membership was granted, got %v", user.Groups)
	}

	resolver.setTenants("dmitrii", []string{"acme"})
	time.Sleep(5 * time.Millisecond)
	user, err = server.ValidateJWT(token)
	if err != nil {
		t.Fatalf("ValidateJWT: %v", err)
	}
	if slices.Contains(user.Groups, "karabu") {
		t.Fatalf("expected karabu removed after the membership was revoked, got %v", user.Groups)
	}
}

func TestGroupsMemoBoundsResolverCalls(t *testing.T) {
	server := newTestOAuthServer(t)
	server.GroupsCacheTTL = time.Minute
	resolver := &stubTenantResolver{}
	resolver.setTenants("dmitrii", []string{"acme"})
	resolver.setTenants("other", []string{"beta"})
	server.TenantResolver = resolver

	token, err := server.IssueJWT("dmitrii", nil)
	if err != nil {
		t.Fatalf("IssueJWT: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := server.ValidateJWT(token); err != nil {
			t.Fatalf("ValidateJWT: %v", err)
		}
	}
	if got := resolver.callCount(); got != 1 {
		t.Fatalf("expected exactly one GetTenantsForUser call for one login within the memo TTL, got %d", got)
	}

	token2, err := server.IssueJWT("other", nil)
	if err != nil {
		t.Fatalf("IssueJWT: %v", err)
	}
	if _, err := server.ValidateJWT(token2); err != nil {
		t.Fatalf("ValidateJWT: %v", err)
	}
	if got := resolver.callCount(); got != 2 {
		t.Fatalf("expected a second call for a distinct login, got %d", got)
	}
}

// ─── T13: rotation mechanics are untouched ─────────────────────────────────

func TestGroupsRotationRegressionFakeStore(t *testing.T) {
	server := newTestOAuthServer(t)
	store := newFakeRefreshStore()
	server.RefreshStore = store
	if err := store.Insert("refresh-t13", "dmitrii", "client-1", []string{"acme"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("insert: %v", err)
	}

	_, rotated, err := server.RefreshAccessToken("refresh-t13", "client-1")
	if err != nil {
		t.Fatalf("RefreshAccessToken: %v", err)
	}
	if rotated == "" {
		t.Fatal("expected rotation to produce a new refresh token")
	}

	if _, _, err := server.RefreshAccessToken("refresh-t13", "client-1"); err == nil {
		t.Fatal("expected the replayed, rotated-out refresh token to be rejected (reuse detection)")
	}
}

// ─── Review round 2 on #412: failure path hardening ─────────────────────────

// busyTenantResolver implements nonBlockingTenantResolver and can be told to
// decline (as gitops.Reader does while a refresh holds its write lock).
type busyTenantResolver struct {
	*stubTenantResolver
	mu   sync.Mutex
	busy bool
}

func (r *busyTenantResolver) setBusy(b bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.busy = b
}

func (r *busyTenantResolver) TryGetTenantsForUser(login string) ([]string, bool, error) {
	r.mu.Lock()
	busy := r.busy
	r.mu.Unlock()
	if busy {
		return nil, false, nil
	}
	tenants, err := r.GetTenantsForUser(login)
	return tenants, true, err
}

// A resolver failure is memoized process-wide for resolverFailureTTL, so an
// outage costs one resolver lookup per TTL instead of one per authenticated
// request. Fails if failures are not negatively cached.
func TestGroupsFailureIsNegativelyCached(t *testing.T) {
	server := newTestOAuthServer(t)
	server.GroupsCacheTTL = time.Minute
	server.GroupsDegradedGrace = time.Hour
	resolver := &stubTenantResolver{}
	resolver.setErr(errors.New("reading tenants dir: permission denied"))
	server.TenantResolver = resolver

	for i := 0; i < 20; i++ {
		groups := server.groupsForSession("dmitrii", []string{"acme"})
		if !slices.Contains(groups, "acme") {
			t.Fatalf("call %d: expected the degraded fallback to keep stored groups, got %v", i, groups)
		}
	}
	if got := resolver.callCount(); got != 1 {
		t.Fatalf("expected 1 resolver lookup while the failure is cached, got %d", got)
	}

	// Another login during the same outage hits the same negative cache.
	server.groupsForSession("someone-else", nil)
	if got := resolver.callCount(); got != 1 {
		t.Fatalf("expected the negative cache to be process-wide, got %d lookups", got)
	}

	// Once the cached failure expires the resolver is consulted again, and a
	// recovered resolver answers normally.
	server.resolverFailMu.Lock()
	server.resolverFailUntil = time.Now().Add(-time.Second)
	server.resolverFailMu.Unlock()
	resolver.setErr(nil)
	resolver.setTenants("dmitrii", []string{"acme", "karabu"})
	if groups := server.groupsForSession("dmitrii", []string{"acme"}); !slices.Contains(groups, "karabu") {
		t.Fatalf("expected resolution to recover after the negative cache expired, got %v", groups)
	}
}

// A busy resolver (gitops refresh in progress) must not block, must fall back
// to the session's own groups, and must not be negatively cached: the next
// call after the refresh finishes resolves normally. Fails if the lookup
// waits on GetTenantsForUser or if busy is treated as a cached failure.
func TestGroupsBusyResolverFallsBackWithoutCaching(t *testing.T) {
	server := newTestOAuthServer(t)
	server.GroupsCacheTTL = time.Minute
	server.GroupsDegradedGrace = time.Hour
	resolver := &busyTenantResolver{stubTenantResolver: &stubTenantResolver{}}
	resolver.setTenants("dmitrii", []string{"acme", "karabu"})
	resolver.setBusy(true)
	server.TenantResolver = resolver

	groups := server.groupsForSession("dmitrii", []string{"acme"})
	if !slices.Equal(groups, []string{"acme"}) {
		t.Fatalf("expected the session's own tenant groups while busy, got %v", groups)
	}
	if got := resolver.callCount(); got != 0 {
		t.Fatalf("expected the blocking GetTenantsForUser never to be called, got %d calls", got)
	}

	resolver.setBusy(false)
	groups = server.groupsForSession("dmitrii", []string{"acme"})
	if !slices.Contains(groups, "karabu") {
		t.Fatalf("expected resolution right after the refresh finished (busy is not negatively cached), got %v", groups)
	}
}

// A memo hit recomputes "admins" from IsAdmin and hands every caller its own
// slice. Fails if the memo stores the assembled list (admins frozen for the
// TTL) or returns a shared backing array.
func TestGroupsCacheHitRecomputesAdminsAndCopies(t *testing.T) {
	server := newTestOAuthServer(t)
	server.GroupsCacheTTL = time.Minute
	server.GitHubValidator = NewGitHubValidator([]string{"dmitrii"})
	resolver := &stubTenantResolver{}
	resolver.setTenants("dmitrii", []string{"acme"})
	server.TenantResolver = resolver

	first, err := server.resolveGroupsChecked("dmitrii")
	if err != nil {
		t.Fatalf("resolveGroupsChecked: %v", err)
	}
	if !slices.Contains(first, "admins") {
		t.Fatalf("expected admins on the first resolution, got %v", first)
	}
	for i := range first {
		first[i] = "mutated"
	}

	server.GitHubValidator = NewGitHubValidator(nil)
	second, err := server.resolveGroupsChecked("dmitrii")
	if err != nil {
		t.Fatalf("resolveGroupsChecked: %v", err)
	}
	if resolver.callCount() != 1 {
		t.Fatalf("expected the second call to be a memo hit, got %d lookups", resolver.callCount())
	}
	if slices.Contains(second, "admins") {
		t.Fatalf("expected admins recomputed on a memo hit (no longer an admin), got %v", second)
	}
	if !slices.Equal(second, []string{"acme"}) {
		t.Fatalf("expected an unaliased copy of the memoized tenants, got %v", second)
	}

	// And the other direction: becoming an admin shows up on a memo hit too.
	server.GitHubValidator = NewGitHubValidator([]string{"dmitrii"})
	third, err := server.resolveGroupsChecked("dmitrii")
	if err != nil {
		t.Fatalf("resolveGroupsChecked: %v", err)
	}
	if resolver.callCount() != 1 {
		t.Fatalf("expected the third call to be a memo hit, got %d lookups", resolver.callCount())
	}
	if !slices.Equal(third, []string{"admins", "acme"}) {
		t.Fatalf("expected admins recomputed on a memo hit (admin again), got %v", third)
	}
}

func TestWarnLimiterAllowsOncePerInterval(t *testing.T) {
	var l warnLimiter
	if !l.allow(time.Minute) {
		t.Fatal("expected the first warning to be allowed")
	}
	for i := 0; i < 5; i++ {
		if l.allow(time.Minute) {
			t.Fatalf("expected warning %d within the interval to be suppressed", i+2)
		}
	}
	l.mu.Lock()
	l.last = time.Now().Add(-2 * time.Minute)
	l.mu.Unlock()
	if !l.allow(time.Minute) {
		t.Fatal("expected a warning to be allowed again after the interval")
	}
}

// Beyond grace, a busy resolver is waited for (boundedly) rather than
// trusting the session snapshot. Fails if busy beyond grace returns the
// stored groups instead of the fresh resolution.
func TestGroupsBusyBeyondGraceWaitsForResolver(t *testing.T) {
	server := newTestOAuthServer(t)
	server.GroupsDegradedGrace = time.Hour
	server.lastResolveOK.Store(time.Now().Add(-2 * time.Hour).UnixNano())
	resolver := &busyTenantResolver{stubTenantResolver: &stubTenantResolver{}}
	resolver.setTenants("dmitrii", []string{"globex"})
	resolver.setBusy(true)
	server.TenantResolver = resolver
	time.AfterFunc(50*time.Millisecond, func() { resolver.setBusy(false) })

	groups, fresh := server.sessionGroups("dmitrii", []string{"acme"})
	if !fresh || !slices.Equal(groups, []string{"globex"}) {
		t.Fatalf("expected the fresh resolution once the refresh ended, got %v (fresh=%v)", groups, fresh)
	}
}

// A resolver that stays busy beyond grace must not keep a removed user's
// tenant groups indefinitely: after busyWaitLimit it fails closed. Fails if
// busy beyond grace falls back to the session snapshot.
func TestGroupsBusyBeyondGraceFailsClosedWhenStillBusy(t *testing.T) {
	old := busyWaitLimit
	busyWaitLimit = 100 * time.Millisecond
	t.Cleanup(func() { busyWaitLimit = old })
	server := newTestOAuthServer(t)
	server.GroupsDegradedGrace = time.Hour
	server.lastResolveOK.Store(time.Now().Add(-2 * time.Hour).UnixNano())
	resolver := &busyTenantResolver{stubTenantResolver: &stubTenantResolver{}}
	resolver.setBusy(true)
	server.TenantResolver = resolver

	if groups := server.groupsForSession("dmitrii", []string{"acme"}); len(groups) != 0 {
		t.Fatalf("expected fail-closed (no tenant groups) while busy beyond grace, got %v", groups)
	}
}

// Within grace, busy uses the session's groups without waiting. Fails if
// the within-grace case also waits (it would then see the refresh end and
// return the fresh groups).
func TestGroupsBusyWithinGraceKeepsSessionGroups(t *testing.T) {
	server := newTestOAuthServer(t)
	server.GroupsDegradedGrace = time.Hour
	server.lastResolveOK.Store(time.Now().UnixNano())
	resolver := &busyTenantResolver{stubTenantResolver: &stubTenantResolver{}}
	resolver.setTenants("dmitrii", []string{"globex"})
	resolver.setBusy(true)
	server.TenantResolver = resolver
	time.AfterFunc(50*time.Millisecond, func() { resolver.setBusy(false) })

	if groups := server.groupsForSession("dmitrii", []string{"acme"}); !slices.Equal(groups, []string{"acme"}) {
		t.Fatalf("expected the session's tenant groups while busy within grace, got %v", groups)
	}
}

// Login bypasses the negative cache: a failure memoized a moment ago must
// not become the refresh-token snapshot. Fails if ResolveGroups honours
// recentResolverFailure.
func TestResolveGroupsAtLoginSkipsNegativeCache(t *testing.T) {
	server := newTestOAuthServer(t)
	resolver := &stubTenantResolver{}
	resolver.setTenants("dmitrii", []string{"acme"})
	server.TenantResolver = resolver
	server.noteResolverFailure(errors.New("transient"))

	if groups := server.ResolveGroups("dmitrii"); !slices.Equal(groups, []string{"acme"}) {
		t.Fatalf("expected login to bypass the negative cache, got %v", groups)
	}
	if _, err := server.resolveGroupsChecked("bob"); err == nil {
		t.Fatalf("expected the per-request path to still honour the negative cache")
	}
}

// Login waits out a busy resolver instead of recording admins-only groups
// as the refresh-token snapshot. Fails if ResolveGroups takes the
// non-blocking path.
func TestResolveGroupsAtLoginWaitsOutBusyResolver(t *testing.T) {
	server := newTestOAuthServer(t)
	resolver := &busyTenantResolver{stubTenantResolver: &stubTenantResolver{}}
	resolver.setTenants("dmitrii", []string{"acme"})
	resolver.setBusy(true)
	server.TenantResolver = resolver

	if groups := server.ResolveGroups("dmitrii"); !slices.Equal(groups, []string{"acme"}) {
		t.Fatalf("expected login to resolve through the blocking lookup, got %v", groups)
	}
}

// On the in-memory path a fail-closed refresh must not overwrite the
// successor's snapshot, or the next outage has nothing to fall back on.
// Fails if the degraded result is persisted.
func TestInMemoryRefreshKeepsSnapshotOnFailClosed(t *testing.T) {
	server := newTestOAuthServer(t)
	server.GroupsDegradedGrace = time.Minute
	resolver := &stubTenantResolver{}
	resolver.setErr(errors.New("gitops checkout unreachable"))
	server.TenantResolver = resolver
	server.lastResolveOK.Store(time.Now().Add(-time.Hour).UnixNano())

	raw, err := server.IssueRefreshToken("dmitrii", []string{"acme"}, "client-1")
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}
	accessToken, next, err := server.RefreshAccessToken(raw, "client-1")
	if err != nil {
		t.Fatalf("RefreshAccessToken: %v", err)
	}
	if groups := mustIssuedGroups(t, server, accessToken); slices.Contains(groups, "acme") {
		t.Fatalf("expected fail-closed access token beyond grace, got %v", groups)
	}

	// Back within grace, still failing: the fallback must still find the
	// original snapshot on the successor row.
	server.lastResolveOK.Store(time.Now().UnixNano())
	accessToken, _, err = server.RefreshAccessToken(next, "client-1")
	if err != nil {
		t.Fatalf("RefreshAccessToken (second): %v", err)
	}
	if groups := mustIssuedGroups(t, server, accessToken); !slices.Contains(groups, "acme") {
		t.Fatalf("expected the original snapshot to survive a fail-closed rotation, got %v", groups)
	}
}

// The negative cache holds a failure for resolverFailureTTL, not the full
// groups-cache TTL, so recovery is noticed within seconds.
func TestResolverFailureTTLIsShort(t *testing.T) {
	server := newTestOAuthServer(t)
	server.GroupsCacheTTL = time.Minute
	server.noteResolverFailure(errors.New("boom"))
	server.resolverFailMu.Lock()
	left := time.Until(server.resolverFailUntil)
	server.resolverFailMu.Unlock()
	if left > resolverFailureTTL || left <= 0 {
		t.Fatalf("expected the failure cached for at most %v, got %v", resolverFailureTTL, left)
	}
}
