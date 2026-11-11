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

package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Synthetic values only. Every token in this package's tests starts with
// SYNTH- so a leak scan can look for the prefix.
const synthPrefix = "SYNTH-"

var testKey = Key{TenantID: "ten_a", PrincipalID: "prn_a", ConnectionID: "gcn_a"}

func testRing(t *testing.T) *Keyring {
	t.Helper()
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	r, err := NewKeyring("k1", map[string][]byte{"k1": k})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func expired() Tokens {
	return Tokens{Access: "SYNTH-ACCESS-0", Refresh: "SYNTH-REFRESH-0", AccessExpiresAt: time.Now().Add(-time.Minute)}
}

func pgPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DB_URL")
	if url == "" {
		t.Skip("TEST_DB_URL not set; skipping Postgres-backed session test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS glovo`); err != nil {
		t.Fatal(err)
	}
	if err := ApplySchema(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE glovo.glovo_provider_sessions`); err != nil {
		t.Fatal(err)
	}
	return pool
}

// stores runs fn against the in-memory fake and, when TEST_DB_URL is set,
// against Postgres: both must satisfy the same contract.
func stores(t *testing.T, fn func(t *testing.T, s Store)) {
	t.Run("memory", func(t *testing.T) { fn(t, NewMemory(nil)) })
	t.Run("postgres", func(t *testing.T) { fn(t, NewPostgres(pgPool(t), testRing(t))) })
}

// strictRefresher models a provider with ROTATING refresh tokens: a refresh
// token works exactly once. With grace, the previous token also works once
// more (a provider-side tolerance the real Glovo may or may not have).
type strictRefresher struct {
	mu      sync.Mutex
	current string
	prev    string
	grace   bool
	n       int
	calls   atomic.Int32
	delay   time.Duration
	// after runs once the response is built, before it is returned.
	after func()
	err   error
}

func newStrict(initial string) *strictRefresher { return &strictRefresher{current: initial} }

func (r *strictRefresher) Refresh(ctx context.Context, refresh Secret) (Tokens, error) {
	r.calls.Add(1)
	if r.delay > 0 {
		time.Sleep(r.delay)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return Tokens{}, r.err
	}
	got := refresh.Reveal()
	ok := got == r.current || (r.grace && got == r.prev && r.prev != "")
	if !ok {
		return Tokens{}, ErrRefreshRejected
	}
	r.n++
	r.prev, r.current = r.current, fmt.Sprintf("SYNTH-REFRESH-%d", r.n)
	out := Tokens{Access: Secret(fmt.Sprintf("SYNTH-ACCESS-%d", r.n)), Refresh: Secret(r.current), AccessExpiresAt: time.Now().Add(time.Hour)}
	if r.after != nil {
		r.after()
	}
	return out, nil
}

type recAudit struct {
	mu sync.Mutex
	ev []Event
}

func (a *recAudit) Record(e Event) { a.mu.Lock(); a.ev = append(a.ev, e); a.mu.Unlock() }
func (a *recAudit) kinds() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var k []string
	for _, e := range a.ev {
		k = append(k, e.Kind)
	}
	return strings.Join(k, ",")
}

func mgr(s Store, r Refresher, holder string, a Auditor) *Manager {
	return NewManager(Config{
		Store: s, Refresher: r, Auditor: a, Enabled: true, HolderID: holder,
		LeaseTTL: 5 * time.Second, WaitMax: 5 * time.Second, PollInterval: 10 * time.Millisecond,
		PersistAttempts: 5, PersistBackoff: 5 * time.Millisecond,
	})
}

// flaky wraps a Store and fails Commit on demand.
type flaky struct {
	Store
	failCommits atomic.Int32 // transient failures left
	dead        atomic.Bool  // every Commit fails (process "crashed" before persisting)
}

func (f *flaky) Commit(ctx context.Context, k Key, h string, e int64, t Tokens) (Record, error) {
	if f.dead.Load() {
		return Record{}, fmt.Errorf("%w: injected", ErrUnavailable)
	}
	if f.failCommits.Add(-1) >= 0 {
		return Record{}, fmt.Errorf("%w: injected", ErrUnavailable)
	}
	return f.Store.Commit(ctx, k, h, e, t)
}

func mustIs(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

// hookStore runs a hook once, just before the first AcquireLease.
type hookStore struct {
	Store
	beforeAcquire func()
	once          sync.Once
}

func (h *hookStore) AcquireLease(ctx context.Context, k Key, holder string, ttl time.Duration) (Record, error) {
	h.once.Do(func() {
		if h.beforeAcquire != nil {
			h.beforeAcquire()
		}
	})
	return h.Store.AcquireLease(ctx, k, holder, ttl)
}
