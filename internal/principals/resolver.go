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
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// CacheTTL is how long a resolved principal is reused without asking the
// store, like the GitHub login cache. A principal disabled meanwhile is
// refused once its entry expires.
const CacheTTL = 5 * time.Minute

// resolutionFailed counts requests that proceeded without a principal id
// because it could not be resolved (mctl-api#373 D2): phase 1 degrades
// instead of failing authentication.
var resolutionFailed = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "principal_resolution_failed_total",
	Help: "Authenticated requests whose canonical principal could not be resolved and that proceeded without one.",
})

func init() { prometheus.MustRegister(resolutionFailed) }

// ErrUnresolved wraps every failure that is not a refusal: the store did
// not answer, GitHub did not answer. The caller proceeds without a
// principal id.
var ErrUnresolved = errors.New("principal could not be resolved")

// backend is the part of Store the resolver uses.
type backend interface {
	Provision(ctx context.Context, id auth.Identity) (*Principal, error)
	ResolveGitHubLogin(ctx context.Context, login string) (*Principal, error)
}

// Resolver implements auth.PrincipalResolver over a Store, with a cache.
//
// Rules (mctl-api#373 phase 1):
//   - every proven identity is provisioned on first sight: a new human for
//     a new GitHub id or Dex (issuer, sub), a service principal for
//     mctl-agent or a surface; never by matching a login's spelling;
//   - a GitHub login proven without its id (a local OAuth JWT, a relayed
//     human) maps through the live GitHub identity that currently holds
//     that login, or asks GitHub for the id;
//   - the dev identity is refused unless dev mode is on;
//   - a disabled principal is refused;
//   - anything else that fails is ErrUnresolved, counted, and not cached.
type Resolver struct {
	store    backend
	lookup   GitHubIDLookup
	allowDev bool
	ttl      time.Duration
	now      func() time.Time

	mu        sync.Mutex
	cache     map[string]cached
	lastSweep time.Time
}

type cached struct {
	principal string
	disabled  bool
	at        time.Time
}

// NewResolver builds a resolver. lookup may be nil (a login-only caller whose
// identity is unknown then stays unresolved). allowDev must be true only when
// AUTH_REQUIRED=false.
func NewResolver(store *Store, lookup GitHubIDLookup, allowDev bool) *Resolver {
	return newResolver(store, lookup, allowDev)
}

func newResolver(store backend, lookup GitHubIDLookup, allowDev bool) *Resolver {
	return &Resolver{
		store: store, lookup: lookup, allowDev: allowDev, ttl: CacheTTL,
		now: time.Now, cache: map[string]cached{},
	}
}

func cacheKey(id auth.Identity) string {
	if id.GitHubLoginOnly() {
		return "github-login|" + strings.ToLower(id.Display)
	}
	return id.Provider + "|" + id.Issuer + "|" + id.Subject
}

// ResolvePrincipal implements auth.PrincipalResolver.
func (r *Resolver) ResolvePrincipal(ctx context.Context, id auth.Identity) (string, error) {
	if id.Provider == auth.ProviderDev && !r.allowDev {
		return "", fmt.Errorf("%w: the dev identity is only accepted when authentication is not required", auth.ErrIdentityRefused)
	}
	key := cacheKey(id)
	now := r.now()
	r.mu.Lock()
	c, ok := r.cache[key]
	r.mu.Unlock()
	if ok && now.Sub(c.at) < r.ttl {
		return answer(c)
	}
	p, err := r.resolve(ctx, id)
	if err != nil {
		if errors.Is(err, auth.ErrIdentityRefused) {
			return "", err
		}
		resolutionFailed.Inc()
		slog.Warn("principal resolution failed", "provider", id.Provider, "error", err)
		return "", fmt.Errorf("%w: %v", ErrUnresolved, err)
	}
	c = cached{principal: p.ID, disabled: p.Status == StatusDisabled, at: now}
	r.mu.Lock()
	r.cache[key] = c
	r.sweepLocked(now)
	r.mu.Unlock()
	return answer(c)
}

// sweepLocked drops expired entries, at most once per TTL, so the cache
// holds only the identities seen within the last TTL or two instead of every
// identity ever seen.
func (r *Resolver) sweepLocked(now time.Time) {
	if now.Sub(r.lastSweep) < r.ttl {
		return
	}
	r.lastSweep = now
	for k, c := range r.cache {
		if now.Sub(c.at) >= r.ttl {
			delete(r.cache, k)
		}
	}
}

func answer(c cached) (string, error) {
	if c.disabled {
		return "", auth.ErrPrincipalDisabled
	}
	return c.principal, nil
}

func (r *Resolver) resolve(ctx context.Context, id auth.Identity) (*Principal, error) {
	if !id.GitHubLoginOnly() {
		return r.store.Provision(ctx, id)
	}
	p, err := r.store.ResolveGitHubLogin(ctx, id.Display)
	if err == nil || !errors.Is(err, ErrNotFound) {
		return p, err
	}
	if r.lookup == nil {
		return nil, fmt.Errorf("no GitHub identity holds login %q and no GitHub lookup is configured", id.Display)
	}
	gid, err := r.lookup(ctx, id.Display)
	if err != nil {
		return nil, err
	}
	return r.store.Provision(ctx, auth.Identity{
		Provider: auth.ProviderGitHub, Subject: strconv.FormatInt(gid, 10), Display: id.Display, Kind: auth.KindHuman,
	})
}
