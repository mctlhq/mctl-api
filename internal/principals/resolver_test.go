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

package principals

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-api/internal/auth"
)

type fakeBackend struct {
	byIdentity map[string]*Principal // provider|issuer|subject
	byLogin    map[string]*Principal
	err        error
	provisions []auth.Identity
	logins     []string
}

func (f *fakeBackend) Provision(_ context.Context, id auth.Identity) (*Principal, error) {
	f.provisions = append(f.provisions, id)
	if f.err != nil {
		return nil, f.err
	}
	key := id.Provider + "|" + id.Issuer + "|" + id.Subject
	if p, ok := f.byIdentity[key]; ok {
		return p, nil
	}
	p := &Principal{ID: "prn_" + key, Status: StatusActive}
	if f.byIdentity == nil {
		f.byIdentity = map[string]*Principal{}
	}
	f.byIdentity[key] = p
	return p, nil
}

func (f *fakeBackend) ResolveGitHubLogin(_ context.Context, login string) (*Principal, error) {
	f.logins = append(f.logins, login)
	if f.err != nil {
		return nil, f.err
	}
	if p, ok := f.byLogin[login]; ok {
		return p, nil
	}
	return nil, ErrNotFound
}

var githubAlice = auth.Identity{Provider: auth.ProviderGitHub, Subject: "4242", Display: "alice", Kind: auth.KindHuman}

func TestResolverCachesForTheTTL(t *testing.T) {
	b := &fakeBackend{}
	r := newResolver(b, nil, false)
	now := time.Unix(1_800_000_000, 0)
	r.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if _, err := r.ResolvePrincipal(context.Background(), githubAlice); err != nil {
			t.Fatal(err)
		}
	}
	if len(b.provisions) != 1 {
		t.Fatalf("store asked %d times within the TTL, want 1", len(b.provisions))
	}
	now = now.Add(CacheTTL)
	if _, err := r.ResolvePrincipal(context.Background(), githubAlice); err != nil {
		t.Fatal(err)
	}
	if len(b.provisions) != 2 {
		t.Fatalf("store asked %d times after the TTL, want 2", len(b.provisions))
	}
}

// Store unavailable: the resolver answers ErrUnresolved, counts it, and does
// not cache the failure, so the next request tries again.
// Expired entries are swept, so the cache holds recent identities only.
func TestResolverCacheEvictsExpiredEntries(t *testing.T) {
	b := &fakeBackend{}
	r := newResolver(b, nil, false)
	now := time.Unix(1_800_000_000, 0)
	r.now = func() time.Time { return now }
	for i := 0; i < 50; i++ {
		id := auth.Identity{Provider: auth.ProviderGitHub, Subject: strconv.Itoa(i + 1), Display: "u" + strconv.Itoa(i), Kind: auth.KindHuman}
		if _, err := r.ResolvePrincipal(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(2 * CacheTTL)
	if _, err := r.ResolvePrincipal(context.Background(), githubAlice); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	size := len(r.cache)
	r.mu.Unlock()
	if size != 1 {
		t.Fatalf("cache holds %d entries after the TTL, want 1", size)
	}
}

func TestResolverDegradesAndCountsWhenTheStoreIsDown(t *testing.T) {
	b := &fakeBackend{err: errors.New("dial tcp: connection refused")}
	r := newResolver(b, nil, false)
	now := time.Unix(1_800_000_000, 0)
	r.now = func() time.Time { return now }
	before := testutil.ToFloat64(resolutionFailed)
	for i := 0; i < 2; i++ {
		// Past the short failure window: a failure is never kept like an
		// answer.
		now = now.Add(FailureTTL)
		_, err := r.ResolvePrincipal(context.Background(), githubAlice)
		if !errors.Is(err, ErrUnresolved) {
			t.Fatalf("err = %v, want ErrUnresolved", err)
		}
		if errors.Is(err, auth.ErrPrincipalDisabled) || errors.Is(err, auth.ErrIdentityRefused) {
			t.Fatalf("an outage must not read as a refusal: %v", err)
		}
	}
	if got := testutil.ToFloat64(resolutionFailed) - before; got != 2 {
		t.Fatalf("principal_resolution_failed_total rose by %v, want 2", got)
	}
	if len(b.provisions) != 2 {
		t.Fatalf("a failure was cached: store asked %d times", len(b.provisions))
	}
}

func TestResolverRefusesADisabledPrincipal(t *testing.T) {
	b := &fakeBackend{byIdentity: map[string]*Principal{"github||4242": {ID: "prn_A", Status: StatusDisabled}}}
	r := newResolver(b, nil, false)
	if _, err := r.ResolvePrincipal(context.Background(), githubAlice); !errors.Is(err, auth.ErrPrincipalDisabled) {
		t.Fatalf("err = %v, want ErrPrincipalDisabled", err)
	}
	// And still refused from the cache.
	if _, err := r.ResolvePrincipal(context.Background(), githubAlice); !errors.Is(err, auth.ErrPrincipalDisabled) {
		t.Fatalf("cached err = %v", err)
	}
}

func TestResolverRefusesTheDevIdentityUnlessDevModeIsOn(t *testing.T) {
	dev := auth.Identity{Provider: auth.ProviderDev, Subject: "dev-user", Kind: auth.KindHuman}
	b := &fakeBackend{}
	if _, err := newResolver(b, nil, false).ResolvePrincipal(context.Background(), dev); !errors.Is(err, auth.ErrIdentityRefused) {
		t.Fatalf("err = %v, want ErrIdentityRefused", err)
	}
	if len(b.provisions) != 0 {
		t.Fatal("a refused dev identity reached the store")
	}
	if _, err := newResolver(b, nil, true).ResolvePrincipal(context.Background(), dev); err != nil {
		t.Fatalf("dev mode: %v", err)
	}
}

// A login-only GitHub caller maps through the identity that currently holds
// the login; only an unknown login costs a GitHub call, which yields the
// numeric id the new identity is keyed on.
func TestResolverMapsALoginOnlyCallerThroughItsGitHubID(t *testing.T) {
	loginOnly := auth.Identity{Provider: auth.ProviderGitHub, Display: "bob", Kind: auth.KindHuman}
	known := &fakeBackend{byLogin: map[string]*Principal{"bob": {ID: "prn_BOB", Status: StatusActive}}}
	calls := 0
	lookup := func(context.Context, string) (int64, error) { calls++; return 77, nil }

	got, err := newResolver(known, lookup, false).ResolvePrincipal(context.Background(), loginOnly)
	if err != nil || got != "prn_BOB" || calls != 0 {
		t.Fatalf("known login: %q, %v, %d lookups", got, err, calls)
	}

	unknown := &fakeBackend{}
	if _, err := newResolver(unknown, lookup, false).ResolvePrincipal(context.Background(), loginOnly); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(unknown.provisions) != 1 || unknown.provisions[0].Subject != "77" || unknown.provisions[0].Display != "bob" {
		t.Fatalf("unknown login: %d lookups, provisions %+v", calls, unknown.provisions)
	}

	if _, err := newResolver(&fakeBackend{}, nil, false).ResolvePrincipal(context.Background(), loginOnly); !errors.Is(err, ErrUnresolved) {
		t.Fatalf("no lookup: err = %v, want ErrUnresolved", err)
	}
}

func TestGitHubIDLookup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/users/alice":
			if r.Header.Get("Authorization") != "Bearer tok" {
				t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"login":"Alice","id":4242}`))
		case "/users/renamed":
			_, _ = w.Write([]byte(`{"login":"someone-else","id":9}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	lookup := NewGitHubIDLookup(srv.Client(), srv.URL, func() (string, error) { return "tok", nil })
	if id, err := lookup(context.Background(), "alice"); err != nil || id != 4242 {
		t.Fatalf("alice: %d, %v", id, err)
	}
	if _, err := lookup(context.Background(), "renamed"); err == nil {
		t.Fatal("an answer for another login was accepted")
	}
	if _, err := lookup(context.Background(), "ghost"); err == nil {
		t.Fatal("a 404 was accepted")
	}
}

func TestULIDShape(t *testing.T) {
	re := regexp.MustCompile(`^prn_[0-9A-HJKMNP-TV-Z]{26}$`)
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id, err := newPrefixedID(PrincipalIDPrefix, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if !re.MatchString(id) || seen[id] {
			t.Fatalf("bad or repeated id %q", id)
		}
		seen[id] = true
	}
	a, _ := newULID(time.UnixMilli(1000))
	b, _ := newULID(time.UnixMilli(2000))
	if a >= b {
		t.Fatalf("ULIDs do not sort by time: %s !< %s", a, b)
	}
}

// blockingBackend never answers until the test ends: a store that is up but
// stalled, or a caller parked on a lock.
type blockingBackend struct {
	fakeBackend
	release chan struct{}
}

func (b *blockingBackend) Provision(ctx context.Context, _ auth.Identity) (*Principal, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-b.release:
		return nil, errors.New("released")
	}
}

// A stalled store degrades within the resolution deadline instead of holding
// the request.
func TestResolverDegradesWhenTheStoreStalls(t *testing.T) {
	b := &blockingBackend{release: make(chan struct{})}
	t.Cleanup(func() { close(b.release) })
	r := newResolver(b, nil, false)
	r.timeout = 50 * time.Millisecond
	done := make(chan error, 1)
	go func() {
		_, err := r.ResolvePrincipal(context.Background(), githubAlice)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrUnresolved) {
			t.Fatalf("stalled store = %v, want ErrUnresolved", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("resolution is not bounded: a stalled store holds the request")
	}
}

// A failure is remembered for FailureTTL only: within it the store is not
// asked again (a stalled store would otherwise cost every request the full
// ResolveTimeout), after it the store is used again.
func TestResolverRemembersAFailureBriefly(t *testing.T) {
	b := &fakeBackend{err: errors.New("dial tcp: i/o timeout")}
	r := newResolver(b, nil, false)
	now := time.Unix(1_800_000_000, 0)
	r.now = func() time.Time { return now }
	before := testutil.ToFloat64(resolutionFailed)
	for i := 0; i < 3; i++ {
		if _, err := r.ResolvePrincipal(context.Background(), githubAlice); !errors.Is(err, ErrUnresolved) {
			t.Fatalf("attempt %d = %v", i, err)
		}
	}
	if len(b.provisions) != 1 {
		t.Fatalf("the store was asked %d times inside the failure window, want 1", len(b.provisions))
	}
	if got := testutil.ToFloat64(resolutionFailed) - before; got != 3 {
		t.Fatalf("counted %v degraded requests, want 3", got)
	}
	b.err = nil
	now = now.Add(FailureTTL)
	if p, err := r.ResolvePrincipal(context.Background(), githubAlice); err != nil || p == "" {
		t.Fatalf("after the window = %q, %v", p, err)
	}
	if len(b.provisions) != 2 {
		t.Fatalf("the store was not asked again after the window")
	}
}
