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
	"strings"
	"sync"
	"testing"
	"time"
)

func TestStoreContract(t *testing.T) {
	stores(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		rec, err := s.Put(ctx, testKey, expired())
		if err != nil || rec.Generation != 1 || rec.State != StateActive {
			t.Fatalf("Put = %+v, %v", rec, err)
		}
		got, err := s.Get(ctx, testKey)
		if err != nil || got.Tokens.Refresh.Reveal() != "SYNTH-REFRESH-0" {
			t.Fatalf("Get = %+v, %v", got, err)
		}

		// Binding: any of the three ids wrong reads as not found.
		for _, k := range []Key{
			{"ten_b", "prn_a", "gcn_a"}, {"ten_a", "prn_b", "gcn_a"}, {"ten_a", "prn_a", "gcn_b"},
		} {
			if _, err := s.Get(ctx, k); !errors.Is(err, ErrNotFound) {
				t.Errorf("Get(%+v) = %v, want ErrNotFound", k, err)
			}
		}
		// Another owner cannot overwrite the connection id.
		if _, err := s.Put(ctx, Key{"ten_b", "prn_b", "gcn_a"}, expired()); !errors.Is(err, ErrNotFound) {
			t.Errorf("cross-owner Put = %v, want ErrNotFound", err)
		}

		// Lease: exclusive until released; the holder may re-acquire.
		if _, err := s.AcquireLease(ctx, testKey, "h1", time.Minute); err != nil {
			t.Fatal(err)
		}
		if _, err := s.AcquireLease(ctx, testKey, "h2", time.Minute); !errors.Is(err, ErrLeaseHeld) {
			t.Fatalf("second holder = %v, want ErrLeaseHeld", err)
		}
		if _, err := s.AcquireLease(ctx, testKey, "h1", time.Minute); err != nil {
			t.Fatalf("re-acquire by holder: %v", err)
		}
		// Commit needs the lease and the generation.
		if _, err := s.Commit(ctx, testKey, "h2", 1, expired()); err == nil {
			t.Fatal("commit without the lease succeeded")
		}
		if _, err := s.Commit(ctx, testKey, "h1", 7, expired()); !errors.Is(err, ErrStale) {
			t.Fatalf("commit with a stale generation = %v, want ErrStale", err)
		}
		nt := Tokens{Access: "SYNTH-ACCESS-9", Refresh: "SYNTH-REFRESH-9", AccessExpiresAt: time.Now().Add(time.Hour)}
		rec, err = s.Commit(ctx, testKey, "h1", 1, nt)
		if err != nil || rec.Generation != 2 || !rec.FromRefresh || rec.Tokens.Refresh.Reveal() != "SYNTH-REFRESH-9" {
			t.Fatalf("Commit = %+v, %v", rec, err)
		}
		// The lease is gone after a commit.
		if _, err := s.AcquireLease(ctx, testKey, "h2", time.Minute); err != nil {
			t.Fatalf("lease after commit: %v", err)
		}
		// An owner load while h2 refreshes invalidates h2's commit.
		if _, err := s.Put(ctx, testKey, expired()); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Commit(ctx, testKey, "h2", 2, nt); !errors.Is(err, ErrStale) {
			t.Fatalf("commit after owner load = %v, want ErrStale", err)
		}

		// Revoke wipes; nothing resurrects it.
		if err := s.Revoke(ctx, testKey); err != nil {
			t.Fatal(err)
		}
		got, _ = s.Get(ctx, testKey)
		if got.State != StateRevoked || got.Tokens.Refresh != "" {
			t.Fatalf("after revoke: %+v", got)
		}
		if _, err := s.Commit(ctx, testKey, "h2", got.Generation, nt); err == nil {
			t.Fatal("commit after revoke succeeded")
		}
		// Only an explicit owner load re-enables.
		if rec, err := s.Put(ctx, testKey, expired()); err != nil || rec.State != StateActive {
			t.Fatalf("reload after revoke: %+v, %v", rec, err)
		}
	})
}

func TestConcurrentRefreshTwoReplicas(t *testing.T) {
	pool := pgPool(t)
	ring := testRing(t)
	ref := newStrict("SYNTH-REFRESH-0")
	ref.delay = 300 * time.Millisecond // widen the overlap window
	audit := &recAudit{}
	a := mgr(NewPostgres(pool, ring), ref, "replica-a", audit)
	b := mgr(NewPostgres(pool, ring), ref, "replica-b", audit)
	ctx := context.Background()
	if _, err := a.Load(ctx, testKey, expired()); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	res := make(chan AccessToken, 16)
	errs := make(chan error, 16)
	for i := 0; i < 8; i++ {
		for _, m := range []*Manager{a, b} {
			wg.Add(1)
			go func(m *Manager) {
				defer wg.Done()
				tok, err := m.AccessToken(ctx, testKey)
				if err != nil {
					errs <- err
					return
				}
				res <- tok
			}(m)
		}
	}
	wg.Wait()
	close(res)
	close(errs)
	for err := range errs {
		t.Errorf("AccessToken: %v", err)
	}
	if n := ref.calls.Load(); n != 1 {
		t.Fatalf("provider refresh calls = %d, want exactly 1", n)
	}
	for tok := range res {
		if tok.Value.Reveal() != "SYNTH-ACCESS-1" || tok.Generation != 2 {
			t.Errorf("token = %v gen %d, want SYNTH-ACCESS-1 gen 2", tok.Value.Reveal(), tok.Generation)
		}
	}
	rec, err := NewPostgres(pool, ring).Get(ctx, testKey)
	if err != nil || rec.Generation != 2 || rec.Tokens.Refresh.Reveal() != "SYNTH-REFRESH-1" || rec.RefreshIntent {
		t.Fatalf("persisted = %+v, %v; the rotated token must be stored and the intent cleared", rec, err)
	}
}

// A refresh whose response arrives but whose persist fails transiently must
// not lose the rotated token.
func TestRotatedTokenSurvivesTransientPersistFailure(t *testing.T) {
	pool := pgPool(t)
	ring := testRing(t)
	st := &flaky{Store: NewPostgres(pool, ring)}
	st.failCommits.Store(2)
	ref := newStrict("SYNTH-REFRESH-0")
	m := mgr(st, ref, "replica-a", nil)
	ctx := context.Background()
	_, _ = m.Load(ctx, testKey, expired())
	tok, err := m.AccessToken(ctx, testKey)
	if err != nil || tok.Generation != 2 {
		t.Fatalf("AccessToken = %+v, %v", tok, err)
	}
	rec, _ := NewPostgres(pool, ring).Get(ctx, testKey)
	if rec.Tokens.Refresh.Reveal() != "SYNTH-REFRESH-1" {
		t.Fatalf("stored refresh = %q, the rotated token was lost", rec.Tokens.Refresh.Reveal())
	}
}

// The caller that triggered the refresh gives up the moment the provider
// answers. The rotated token must still be persisted.
func TestRotatedTokenSurvivesCallerCancellation(t *testing.T) {
	pool := pgPool(t)
	ring := testRing(t)
	ctx, cancel := context.WithCancel(context.Background())
	ref := newStrict("SYNTH-REFRESH-0")
	ref.after = cancel
	m := mgr(NewPostgres(pool, ring), ref, "replica-a", nil)
	_, _ = m.Load(context.Background(), testKey, expired())
	_, err := m.AccessToken(ctx, testKey)
	_ = err // the caller may see either outcome; the store must hold the rotation
	deadline := time.Now().Add(3 * time.Second)
	for {
		rec, _ := NewPostgres(pool, ring).Get(context.Background(), testKey)
		if rec.Tokens.Refresh.Reveal() == "SYNTH-REFRESH-1" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("rotated token not persisted after caller cancellation: %+v", rec)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Crash between the provider response and the persist: the new token exists
// nowhere. The recovery is bounded and explicit.
func TestCrashBetweenResponseAndPersist(t *testing.T) {
	for _, tc := range []struct {
		name      string
		grace     bool
		wantRelog bool
	}{
		{"provider tolerates the old token once: recovered", true, false},
		{"provider rejects the old token: explicit relogin_required", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := pgPool(t)
			ring := testRing(t)
			ctx := context.Background()
			ref := newStrict("SYNTH-REFRESH-0")
			ref.grace = tc.grace

			// Replica A: gets the response, then "dies" before any persist.
			dead := &flaky{Store: NewPostgres(pool, ring)}
			dead.dead.Store(true)
			a := NewManager(Config{Store: dead, Refresher: ref, Enabled: true, HolderID: "replica-a",
				LeaseTTL: 300 * time.Millisecond, PersistAttempts: 2, PersistBackoff: time.Millisecond,
				WaitMax: 5 * time.Second, PollInterval: 10 * time.Millisecond})
			_, _ = a.Load(ctx, testKey, expired())
			if _, err := a.AccessToken(ctx, testKey); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("A: %v, want ErrUnavailable", err)
			}
			// Nothing partial: same generation, intent recorded, lease still A's.
			rec, _ := NewPostgres(pool, ring).Get(ctx, testKey)
			if rec.Generation != 1 || !rec.RefreshIntent || rec.State != StateActive {
				t.Fatalf("after crash: %+v", rec)
			}

			// Replica B waits out A's lease, then recovers with the old token.
			audit := &recAudit{}
			b := mgr(NewPostgres(pool, ring), ref, "replica-b", audit)
			tok, err := b.AccessToken(ctx, testKey)
			if tc.wantRelog {
				mustIs(t, err, ErrReloginRequired)
				var re *ReloginError
				if !errors.As(err, &re) || re.Reason != ReasonRefreshOutcomeLost {
					t.Fatalf("reason = %v, want %s", err, ReasonRefreshOutcomeLost)
				}
				st, _ := b.Status(ctx, testKey)
				if st.State != StateReloginRequired {
					t.Fatalf("state = %s", st.State)
				}
				// Bounded: asking again never reaches the provider.
				calls := ref.calls.Load()
				_, err = b.AccessToken(ctx, testKey)
				mustIs(t, err, ErrReloginRequired)
				if ref.calls.Load() != calls {
					t.Fatal("provider called again after relogin_required")
				}
				// The owner's reload restores service.
				ref.mu.Lock()
				ref.current = "SYNTH-REFRESH-0"
				ref.mu.Unlock()
				if _, err := b.Load(ctx, testKey, expired()); err != nil {
					t.Fatal(err)
				}
				if _, err := b.AccessToken(ctx, testKey); err != nil {
					t.Fatalf("after reload: %v", err)
				}
				return
			}
			if err != nil || tok.Generation != 2 {
				t.Fatalf("B recovery = %+v, %v", tok, err)
			}
			rec, _ = NewPostgres(pool, ring).Get(ctx, testKey)
			if rec.RefreshIntent || rec.Tokens.Refresh.Reveal() != "SYNTH-REFRESH-2" {
				t.Fatalf("after recovery: %+v", rec)
			}
		})
	}
}

func TestReloginAndRevokeAreExplicitErrors(t *testing.T) {
	stores(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		ref := newStrict("SYNTH-OTHER") // does not match the stored token: rejected
		m := mgr(s, ref, "replica-a", &recAudit{})
		_, _ = m.Load(ctx, testKey, expired())

		tok, err := m.AccessToken(ctx, testKey)
		if tok.Value != "" || tok.Generation != 0 {
			t.Fatalf("a failed call returned data: %+v", tok)
		}
		mustIs(t, err, ErrReloginRequired)
		st, _ := m.Status(ctx, testKey)
		if st.State != StateReloginRequired || st.ReloginReason != ReasonRefreshRejected {
			t.Fatalf("status = %+v", st)
		}
		rec, _ := s.Get(ctx, testKey)
		if rec.Tokens.Refresh != "" || rec.Tokens.Access != "" {
			t.Fatal("tokens kept after relogin_required")
		}
		calls := ref.calls.Load()
		_, err = m.AccessToken(ctx, testKey)
		mustIs(t, err, ErrReloginRequired)
		if ref.calls.Load() != calls {
			t.Fatal("provider called again after relogin_required")
		}

		// Revoked is its own explicit state.
		_, _ = m.Load(ctx, testKey, expired())
		if err := m.Revoke(ctx, testKey); err != nil {
			t.Fatal(err)
		}
		_, err = m.AccessToken(ctx, testKey)
		mustIs(t, err, ErrRevoked)
	})
}

// A provider outage is not a relogin: the session stays as it was.
func TestTransientProviderFailureIsUnavailableNotRelogin(t *testing.T) {
	stores(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		ref := newStrict("SYNTH-REFRESH-0")
		ref.err = errors.New("connection reset")
		m := mgr(s, ref, "replica-a", nil)
		_, _ = m.Load(ctx, testKey, expired())
		_, err := m.AccessToken(ctx, testKey)
		mustIs(t, err, ErrUnavailable)
		st, _ := m.Status(ctx, testKey)
		if st.State != StateActive || st.Generation != 1 {
			t.Fatalf("status after outage = %+v", st)
		}
		// The request may have rotated the token: the intent must stay set so
		// the next holder knows the outcome is unknown.
		if rec, _ := s.Get(ctx, testKey); !rec.RefreshIntent {
			t.Fatal("unknown refresh outcome did not leave the intent set")
		}
	})
}

// Revoke lands while a refresh is in flight: the commit must not resurrect.
func TestRevokeDuringRefreshIsNotResurrected(t *testing.T) {
	stores(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		ref := newStrict("SYNTH-REFRESH-0")
		m := mgr(s, ref, "replica-a", nil)
		_, _ = m.Load(ctx, testKey, expired())
		ref.after = func() { _ = s.Revoke(ctx, testKey) }
		_, err := m.AccessToken(ctx, testKey)
		if err == nil {
			t.Fatal("a revoked session produced a token")
		}
		rec, _ := s.Get(ctx, testKey)
		if rec.State != StateRevoked || rec.Tokens.Refresh != "" {
			t.Fatalf("after revoke during refresh: %+v", rec)
		}
	})
}

// An owner load during a refresh wins: the old lineage's rotation is dropped.
func TestOwnerLoadDuringRefreshWinsCAS(t *testing.T) {
	stores(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		ref := newStrict("SYNTH-REFRESH-0")
		m := mgr(s, ref, "replica-a", nil)
		_, _ = m.Load(ctx, testKey, expired())
		fresh := Tokens{Access: "SYNTH-ACCESS-OWNER", Refresh: "SYNTH-REFRESH-OWNER", AccessExpiresAt: time.Now().Add(time.Hour)}
		ref.after = func() { _, _ = s.Put(ctx, testKey, fresh) }
		_, err := m.AccessToken(ctx, testKey)
		mustIs(t, err, ErrStale)
		rec, _ := s.Get(ctx, testKey)
		if rec.Tokens.Refresh.Reveal() != "SYNTH-REFRESH-OWNER" {
			t.Fatalf("the stale lineage overwrote the owner load: %+v", rec)
		}
	})
}

// Upstream recursed forever on a persistent 401/403. Here a token that came
// from a refresh and is rejected again ends in relogin_required.
func TestRejectedIsBounded(t *testing.T) {
	stores(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		ref := newStrict("SYNTH-REFRESH-0")
		m := mgr(s, ref, "replica-a", nil)
		live := Tokens{Access: "SYNTH-ACCESS-0", Refresh: "SYNTH-REFRESH-0", AccessExpiresAt: time.Now().Add(time.Hour)}
		_, _ = m.Load(ctx, testKey, live)

		tok, err := m.AccessToken(ctx, testKey) // valid, no refresh
		if err != nil || tok.Generation != 1 || ref.calls.Load() != 0 {
			t.Fatalf("%+v %v calls=%d", tok, err, ref.calls.Load())
		}
		tok2, err := m.Rejected(ctx, testKey, tok.Generation) // one forced refresh
		if err != nil || tok2.Generation != 2 || ref.calls.Load() != 1 {
			t.Fatalf("%+v %v calls=%d", tok2, err, ref.calls.Load())
		}
		// Another caller reports the same stale generation: no second refresh.
		tok3, err := m.Rejected(ctx, testKey, tok.Generation)
		if err != nil || tok3.Generation != 2 || ref.calls.Load() != 1 {
			t.Fatalf("%+v %v calls=%d", tok3, err, ref.calls.Load())
		}
		// The refreshed token is rejected too: stop.
		_, err = m.Rejected(ctx, testKey, tok2.Generation)
		mustIs(t, err, ErrReloginRequired)
		if ref.calls.Load() != 1 {
			t.Fatal("refreshed again after a rejected refreshed token")
		}
	})
}

func TestDisabledAndKillSwitch(t *testing.T) {
	s := NewMemory(nil)
	ref := newStrict("SYNTH-REFRESH-0")
	_, _ = s.Put(context.Background(), testKey, expired())

	off := NewManager(Config{Store: s, Refresher: ref}) // zero Enabled
	if _, err := off.AccessToken(context.Background(), testKey); !errors.Is(err, ErrDisabled) {
		t.Fatalf("default-off = %v", err)
	}
	killed := false
	on := NewManager(Config{Store: s, Refresher: ref, Enabled: true, HolderID: "a", Kill: func() bool { return killed }})
	if _, err := on.AccessToken(context.Background(), testKey); err != nil {
		t.Fatal(err)
	}
	killed = true
	if _, err := on.AccessToken(context.Background(), testKey); !errors.Is(err, ErrDisabled) {
		t.Fatalf("kill switch = %v", err)
	}
	if ref.calls.Load() != 1 {
		t.Fatal("provider reached while killed")
	}
}

func TestBindingIsAuthenticated(t *testing.T) {
	pool := pgPool(t)
	ring := testRing(t)
	st := NewPostgres(pool, ring)
	ctx := context.Background()
	// Each victim differs from testKey in exactly one component.
	victims := map[string]Key{
		"tenant":     {"ten_b", "prn_a", "gcn_v1"},
		"principal":  {"ten_a", "prn_b", "gcn_v2"},
		"connection": {"ten_a", "prn_a", "gcn_v3"},
	}
	_, _ = st.Put(ctx, testKey, expired())
	for _, k := range victims {
		_, _ = st.Put(ctx, k, expired())
	}
	for name, k := range victims {
		// An attacker with write access to the table moves A's ciphertext to the victim row.
		if _, err := pool.Exec(ctx, `UPDATE glovo.glovo_provider_sessions v
		  SET ciphertext = a.ciphertext, key_id = a.key_id
		  FROM glovo.glovo_provider_sessions a WHERE a.connection_id='gcn_a' AND v.connection_id=$1`, k.ConnectionID); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Get(ctx, k); !errors.Is(err, ErrCorrupt) {
			t.Errorf("ciphertext moved across %s = %v, want ErrCorrupt", name, err)
		}
	}
	// Reassigning the owner columns of a row must not make it readable by the
	// new owner: tenant and principal are authenticated, not just filtered.
	for _, col := range []string{"tenant_id", "principal_id"} {
		if _, err := pool.Exec(ctx, `UPDATE glovo.glovo_provider_sessions SET `+col+`='mallory' WHERE connection_id='gcn_a'`); err != nil {
			t.Fatal(err)
		}
		k := testKey
		if col == "tenant_id" {
			k.TenantID = "mallory"
		} else {
			k.PrincipalID = "mallory"
		}
		if _, err := st.Get(ctx, k); !errors.Is(err, ErrCorrupt) {
			t.Errorf("row reassigned via %s = %v, want ErrCorrupt", col, err)
		}
		if _, err := pool.Exec(ctx, `UPDATE glovo.glovo_provider_sessions SET `+col+`=$1 WHERE connection_id='gcn_a'`, map[string]string{"tenant_id": testKey.TenantID, "principal_id": testKey.PrincipalID}[col]); err != nil {
			t.Fatal(err)
		}
	}
	// Rollback: an older ciphertext replayed onto a newer generation.
	var old []byte
	_ = pool.QueryRow(ctx, `SELECT ciphertext FROM glovo.glovo_provider_sessions WHERE connection_id='gcn_a'`).Scan(&old)
	_, _ = st.AcquireLease(ctx, testKey, "h", time.Minute)
	_, _ = st.Commit(ctx, testKey, "h", 1, Tokens{Access: "SYNTH-ACCESS-2", Refresh: "SYNTH-REFRESH-2", AccessExpiresAt: time.Now().Add(time.Hour)})
	if _, err := pool.Exec(ctx, `UPDATE glovo.glovo_provider_sessions SET ciphertext=$1 WHERE connection_id='gcn_a'`, old); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get(ctx, testKey); !errors.Is(err, ErrCorrupt) {
		t.Errorf("replayed old generation = %v, want ErrCorrupt", err)
	}
	// A wrong key never decrypts either.
	r2, _ := NewKeyring("k1", map[string][]byte{"k1": make([]byte, 32)})
	_, _ = st.Put(ctx, testKey, expired())
	if _, err := NewPostgres(pool, r2).Get(ctx, testKey); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("wrong key = %v, want ErrCorrupt", err)
	}
}

// Replica B read the stale token, then replica A completed a refresh before B
// got the lease. B must see the new generation under the lease and not call
// the provider (whose refresh tokens work once).
func TestSecondReplicaDoesNotRefreshAfterFirstCommitted(t *testing.T) {
	pool := pgPool(t)
	ring := testRing(t)
	ctx := context.Background()
	ref := newStrict("SYNTH-REFRESH-0")
	a := mgr(NewPostgres(pool, ring), ref, "replica-a", nil)
	_, _ = a.Load(ctx, testKey, expired())
	hs := &hookStore{Store: NewPostgres(pool, ring)}
	hs.beforeAcquire = func() {
		if _, err := a.AccessToken(ctx, testKey); err != nil {
			t.Errorf("A: %v", err)
		}
	}
	b := mgr(hs, ref, "replica-b", nil)
	tok, err := b.AccessToken(ctx, testKey)
	if err != nil || tok.Generation != 2 {
		t.Fatalf("B = %+v, %v", tok, err)
	}
	if n := ref.calls.Load(); n != 1 {
		t.Fatalf("provider calls = %d, want 1", n)
	}
}

func TestCiphertextAtRest(t *testing.T) {
	pool := pgPool(t)
	st := NewPostgres(pool, testRing(t))
	ctx := context.Background()
	_, _ = st.Put(ctx, testKey, expired())
	var blob []byte
	if err := pool.QueryRow(ctx, `SELECT ciphertext FROM glovo.glovo_provider_sessions`).Scan(&blob); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "SYNTH-") || strings.Contains(string(blob), "REFRESH") {
		t.Fatal("plaintext token found in the stored column")
	}
	// Wipe on revoke: the CHECK ties ciphertext to the active state.
	_ = st.Revoke(ctx, testKey)
	var n int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM glovo.glovo_provider_sessions WHERE ciphertext IS NOT NULL`).Scan(&n)
	if n != 0 {
		t.Fatal("ciphertext survived revoke")
	}
}

func TestNoSecretInErrorsAuditOrFormatting(t *testing.T) {
	audit := &recAudit{}
	s := NewMemory(nil)
	for _, refErr := range []error{nil, ErrRefreshRejected, errors.New("boom SYNTH-REFRESH-0 leaked by provider")} {
		ref := newStrict("SYNTH-REFRESH-0")
		ref.err = refErr
		m := mgr(s, ref, "a", audit)
		_, _ = m.Load(context.Background(), testKey, expired())
		tok, err := m.AccessToken(context.Background(), testKey)
		texts := []string{fmt.Sprint(err), fmt.Sprintf("%+v|%#v|%v|%s", tok, tok.Value, tok, tok.Value)}
		rec, _ := s.Get(context.Background(), testKey)
		texts = append(texts, fmt.Sprintf("%+v %#v", rec, rec))
		for _, tx := range texts {
			if strings.Contains(tx, synthPrefix) {
				t.Errorf("token leaked into %q", tx)
			}
		}
	}
	for _, e := range audit.ev {
		if strings.Contains(fmt.Sprintf("%+v", e), synthPrefix) {
			t.Errorf("token leaked into audit event %+v", e)
		}
	}
	if audit.kinds() == "" {
		t.Fatal("no audit events were recorded")
	}
}

func TestParseGlovoSessionFile(t *testing.T) {
	now := time.Now()
	in := `{"accessToken":"SYNTH-A","refreshToken":"SYNTH-R","expiresIn":3600,"createdAt":` +
		fmt.Sprint(now.UnixMilli()) + `,"customer":{"id":"1","name":"Synthetic Name","email":"x@example.invalid"},
		"location":{"latitude":1.5,"longitude":2.5},"deviceUrn":"d"}`
	tk, err := ParseGlovoSessionFile(strings.NewReader(in), now)
	if err != nil || tk.Access.Reveal() != "SYNTH-A" || tk.Refresh.Reveal() != "SYNTH-R" {
		t.Fatalf("%+v %v", tk, err)
	}
	if d := tk.AccessExpiresAt.Sub(now); d < 59*time.Minute || d > 61*time.Minute {
		t.Fatalf("expiry %v", d)
	}
	for _, bad := range []string{`{}`, `not json`, `{"accessToken":"x"}`, `{"refreshToken":"x"}`} {
		if _, err := ParseGlovoSessionFile(strings.NewReader(bad), now); !errors.Is(err, ErrSessionFile) {
			t.Errorf("%q = %v", bad, err)
		}
	}
}

func TestKeyringFromEnv(t *testing.T) {
	env := map[string]string{"ID": "k2", "KEYS": "k1=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=,k2=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}
	r, err := KeyringFromEnv(func(k string) string { return env[k] }, "ID", "KEYS")
	if err != nil || r.ActiveID() != "k2" {
		t.Fatalf("%v", err)
	}
	if _, err := KeyringFromEnv(func(string) string { return "" }, "ID", "KEYS"); err == nil || strings.Contains(err.Error(), "AAAA") {
		t.Fatalf("missing vars: %v", err)
	}
	env["KEYS"] = "k1=short"
	if _, err := KeyringFromEnv(func(k string) string { return env[k] }, "ID", "KEYS"); err == nil {
		t.Fatal("short key accepted")
	}
}
