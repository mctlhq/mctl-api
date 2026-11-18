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

package glovoconsent

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

const (
	pidA = "prn_01HZZZZZZZZZZZZZZZZZZZZZZA"
	pidB = "prn_01HZZZZZZZZZZZZZZZZZZZZZZB"
)

func newTestStore(t *testing.T) *PostgresStore {
	t.Helper()
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed Glovo consent test")
	}
	ctx := context.Background()
	s, err := NewStore(ctx, connStr)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	wipe := func() {
		if _, err := s.pool.Exec(ctx, "DELETE FROM glovo_link_consents"); err != nil {
			t.Fatal(err)
		}
	}
	wipe()
	t.Cleanup(func() { wipe(); s.Close() })
	return s
}

func TestPGRecordReadRevoke(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.Active(ctx, pidA); !errors.Is(err, ErrNoConsent) {
		t.Fatalf("before record: %v, want ErrNoConsent", err)
	}
	rec, created, err := s.Record(ctx, pidA, "github:alice", testCap)
	if err != nil || !created || rec.Version != Version || rec.PrincipalID != pidA || !rec.Active() {
		t.Fatalf("record = %+v %v %v", rec, created, err)
	}
	again, created, err := s.Record(ctx, pidA, "github:alice", testCap)
	if err != nil || created || again.ID != rec.ID {
		t.Fatalf("second record must return the active row: %+v %v %v", again, created, err)
	}
	got, err := s.Active(ctx, pidA)
	if err != nil || got.ID != rec.ID || got.Version != Version {
		t.Fatalf("active = %+v %v", got, err)
	}
	// Another principal sees nothing of A's.
	if _, err := s.Active(ctx, pidB); !errors.Is(err, ErrNoConsent) {
		t.Fatalf("B reads A's consent: %v", err)
	}
	if _, err := s.Revoke(ctx, pidB, "github:bob"); !errors.Is(err, ErrNoConsent) {
		t.Fatalf("B revoked A's consent: %v", err)
	}
	if _, err := s.Active(ctx, pidA); err != nil {
		t.Fatalf("A's consent gone after B's revoke: %v", err)
	}

	rv, err := s.Revoke(ctx, pidA, "github:alice")
	if err != nil || rv.RevokedAt == nil || rv.ID != rec.ID {
		t.Fatalf("revoke = %+v %v", rv, err)
	}
	if _, err := s.Active(ctx, pidA); !errors.Is(err, ErrNoConsent) {
		t.Fatalf("after revoke: %v, want ErrNoConsent", err)
	}
	if _, err := s.Revoke(ctx, pidA, "github:alice"); !errors.Is(err, ErrNoConsent) {
		t.Fatalf("second revoke: %v, want ErrNoConsent", err)
	}
	// Re-consent makes a new row; the revoked one stays as history.
	re, created, err := s.Record(ctx, pidA, "github:alice", testCap)
	if err != nil || !created || re.ID == rec.ID {
		t.Fatalf("re-record = %+v %v %v", re, created, err)
	}
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM glovo_link_consents WHERE principal_id = $1`, pidA).Scan(&n); err != nil || n != 2 {
		t.Fatalf("history rows = %d %v, want 2", n, err)
	}
}

// An active consent to an older text is superseded, not kept: the row that
// is active afterwards names Version.
func TestPGRecordSupersedesAnOlderVersion(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.pool.Exec(ctx, `INSERT INTO glovo_link_consents (consent_id, principal_id, consent_version, recorded_at, recorded_by)
		VALUES ('gcn_old', $1, 'c2-link-v1', now(), 'x')`, pidA); err != nil {
		t.Fatal(err)
	}
	rec, created, err := s.Record(ctx, pidA, "github:alice", testCap)
	if err != nil || !created || rec.Version != Version {
		t.Fatalf("record = %+v %v %v", rec, created, err)
	}
	var reason string
	if err := s.pool.QueryRow(ctx, `SELECT revoke_reason FROM glovo_link_consents WHERE consent_id = 'gcn_old'`).Scan(&reason); err != nil || reason != ReasonSuperseded {
		t.Fatalf("old row reason = %q %v", reason, err)
	}
}

// A read the database could not answer is an error, never ErrNoConsent and
// never a record.
func TestPGReadErrorIsNotAbsence(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, _, err := s.Record(ctx, pidA, "github:alice", testCap); err != nil {
		t.Fatal(err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	rec, err := s.Active(cctx, pidA)
	if err == nil || errors.Is(err, ErrNoConsent) || rec.Version != "" {
		t.Fatalf("cancelled read = %+v %v, want a read error", rec, err)
	}
}

// Concurrent records for one principal leave exactly one active row.
func TestPGConcurrentRecordsKeepOneActive(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := s.Record(ctx, pidA, "github:alice", testCap); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM glovo_link_consents WHERE principal_id = $1`, pidA).Scan(&n); err != nil || n != 1 {
		t.Fatalf("rows = %d %v, want 1", n, err)
	}
}

func TestStoreRefusesMalformedInput(t *testing.T) {
	s := &PostgresStore{}
	ctx := context.Background()
	if _, _, err := s.Record(ctx, "github:alice", "x", testCap); !errors.Is(err, ErrInvalid) {
		t.Fatalf("record bad pid: %v", err)
	}
	if _, _, err := s.Record(ctx, pidA, "", testCap); !errors.Is(err, ErrInvalid) {
		t.Fatalf("record no actor: %v", err)
	}
	if _, err := s.Active(ctx, "prn_short"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("active bad pid: %v", err)
	}
}

// testCap is a capacity no test outside the capacity tests reaches.
const testCap = 100

// pidN is the n-th well-formed test principal (n < 32).
func pidN(n int) string {
	const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	return "prn_01HZZZZZZZZZZZZZZZZZZZZZY" + string(crockford[n])
}

func activeCount(t *testing.T, s *PostgresStore) int {
	t.Helper()
	var n int
	if err := s.pool.QueryRow(context.Background(), `SELECT count(*) FROM glovo_link_consents WHERE revoked_at IS NULL`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Concurrent claims for the last slot: exactly one winner, the rest get
// ErrCapacityReached, and the cap is never exceeded.
func TestPGConcurrentClaimsForTheLastSlot(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const capacity = 3
	for i := 0; i < capacity-1; i++ {
		if _, _, err := s.Record(ctx, pidN(i), "github:x", capacity); err != nil {
			t.Fatalf("fill slot %d: %v", i, err)
		}
	}
	for round := 0; round < 5; round++ {
		const claimers = 12
		var wg sync.WaitGroup
		var mu sync.Mutex
		won, full, other := 0, 0, []error{}
		start := make(chan struct{})
		for i := 0; i < claimers; i++ {
			pid := pidN(10 + i)
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, created, err := s.Record(ctx, pid, "github:x", capacity)
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil && created:
					won++
				case errors.Is(err, ErrCapacityReached):
					full++
				default:
					other = append(other, err)
				}
			}()
		}
		close(start)
		wg.Wait()
		if won != 1 || full != claimers-1 || len(other) != 0 {
			t.Fatalf("round %d: won %d, full %d, other %v; want exactly one winner", round, won, full, other)
		}
		if n := activeCount(t, s); n != capacity {
			t.Fatalf("round %d: %d active, cap %d", round, n, capacity)
		}
		// Free the winner's slot for the next round.
		for i := 0; i < claimers; i++ {
			if _, err := s.Revoke(ctx, pidN(10+i), "github:x"); err != nil && !errors.Is(err, ErrNoConsent) {
				t.Fatal(err)
			}
		}
	}
}

// A revoke frees the slot; re-recording an active consent takes no second
// slot; a closed cap (0 or less) admits nobody new.
func TestPGCapacitySlots(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, _, err := s.Record(ctx, pidA, "github:a", 1); err != nil {
		t.Fatal(err)
	}
	// Re-record at a full cap: idempotent, no second slot, no refusal.
	for i := 0; i < 3; i++ {
		if _, created, err := s.Record(ctx, pidA, "github:a", 1); err != nil || created {
			t.Fatalf("re-record = %v %v", created, err)
		}
	}
	if n := activeCount(t, s); n != 1 {
		t.Fatalf("re-records took %d slots", n)
	}
	if _, _, err := s.Record(ctx, pidB, "github:b", 1); !errors.Is(err, ErrCapacityReached) {
		t.Fatalf("B at a full cap: %v, want ErrCapacityReached", err)
	}
	if _, err := s.Revoke(ctx, pidA, "github:a"); err != nil {
		t.Fatal(err)
	}
	if _, created, err := s.Record(ctx, pidB, "github:b", 1); err != nil || !created {
		t.Fatalf("B after A's revoke freed the slot: %v %v", created, err)
	}
	for _, closed := range []int{0, -1} {
		if _, _, err := s.Record(ctx, pidA, "github:a", closed); !errors.Is(err, ErrCapacityReached) {
			t.Fatalf("cap %d admitted A: %v", closed, err)
		}
	}
	if n := activeCount(t, s); n != 1 {
		t.Fatalf("%d active after the closed cap", n)
	}
	// An older-version holder keeps its slot when it re-consents, even at
	// a full cap.
	if _, err := s.pool.Exec(ctx, `UPDATE glovo_link_consents SET consent_version = 'c2-link-v0' WHERE principal_id = $1 AND revoked_at IS NULL`, pidB); err != nil {
		t.Fatal(err)
	}
	if rec, created, err := s.Record(ctx, pidB, "github:b", 1); err != nil || !created || rec.Version != Version {
		t.Fatalf("supersede at a full cap = %+v %v %v", rec, created, err)
	}
}

type failingStore struct{ err error }

func (f failingStore) Record(context.Context, string, string, int) (Record, bool, error) {
	return Record{}, false, f.err
}
func (f failingStore) Revoke(context.Context, string, string) (Record, error) { return Record{}, f.err }
func (f failingStore) Active(context.Context, string) (Record, error)         { return Record{}, f.err }

type rowStore struct {
	failingStore
	rec Record
}

func (r rowStore) Active(context.Context, string) (Record, error) { return r.rec, nil }

// The grant is the active consent; a store error is never a grant.
func TestConsentGrants(t *testing.T) {
	ctx := context.Background()
	if ok, err := (ConsentGrants{Store: failingStore{errors.New("db down")}}).HasGrant(ctx, pidA, GrantC2); ok || err == nil {
		t.Fatalf("db error = %v %v, want an error and no grant", ok, err)
	}
	if ok, err := (ConsentGrants{Store: failingStore{ErrNoConsent}}).HasGrant(ctx, pidA, GrantC2); ok || err != nil {
		t.Fatalf("no consent = %v %v, want no grant", ok, err)
	}
	if ok, err := (ConsentGrants{}).HasGrant(ctx, pidA, GrantC2); ok || err == nil {
		t.Fatalf("no store = %v %v", ok, err)
	}
	now := time.Now()
	good := Record{ID: "gcn_1", PrincipalID: pidA, Version: Version, RecordedAt: now}
	if ok, err := (ConsentGrants{Store: rowStore{rec: good}}).HasGrant(ctx, pidA, GrantC2); !ok || err != nil {
		t.Fatalf("active consent = %v %v, want the grant", ok, err)
	}
	if ok, _ := (ConsentGrants{Store: rowStore{rec: good}}).HasGrant(ctx, pidA, "glovo:c1"); ok {
		t.Fatal("consent grants something other than c2")
	}
	old := good
	old.Version = "c2-link-v0"
	if ok, err := (ConsentGrants{Store: rowStore{rec: old}}).HasGrant(ctx, pidA, GrantC2); ok || err != nil {
		t.Fatalf("older version = %v %v, want no grant", ok, err)
	}
	other := good
	other.PrincipalID = pidB
	revoked := good
	revoked.RevokedAt = &now
	for name, rec := range map[string]Record{"another principal": other, "revoked": revoked} {
		if ok, err := (ConsentGrants{Store: rowStore{rec: rec}}).HasGrant(ctx, pidA, GrantC2); ok || err == nil {
			t.Errorf("%s row = %v %v, want an error and no grant", name, ok, err)
		}
	}
}

// The store's timeout bounds the whole claim, the wait for the global
// capacity lock included: a transaction holding that lock stalls a claim
// for at most the timeout, and the stalled claim fails, never succeeds.
func TestPGClaimWaitIsBounded(t *testing.T) {
	s := newTestStore(t)
	s.timeout = 300 * time.Millisecond
	ctx := context.Background()
	holder, err := s.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(ctx) }()
	if _, err := holder.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('glovo-link-consent:capacity'))`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, _, err := s.Record(ctx, pidA, "github:a", testCap)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || errors.Is(err, ErrCapacityReached) {
			t.Fatalf("stalled claim = %v, want a timeout error", err)
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Fatalf("stalled claim took %v", d)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("the claim waited on the capacity lock past the store timeout")
	}
	_ = holder.Rollback(ctx)
	if _, err := s.Active(ctx, pidA); !errors.Is(err, ErrNoConsent) {
		t.Fatalf("a timed-out claim left a consent: %v", err)
	}
}

// HeldSince binds a personal grant to the consent it was created under: a
// consent recorded later (after a withdrawal) never revives the grant, and
// a failed read is an error, never a grant.
func TestConsentHeldSince(t *testing.T) {
	ctx := context.Background()
	at := time.Now()
	rec := Record{ID: "gcn_1", PrincipalID: pidA, Version: Version, RecordedAt: at.Add(-time.Minute)}
	if ok, err := (ConsentGrants{Store: rowStore{rec: rec}}).HeldSince(ctx, pidA, at); !ok || err != nil {
		t.Fatalf("consent before the grant = %v %v, want held", ok, err)
	}
	same := rec
	same.RecordedAt = at
	if ok, err := (ConsentGrants{Store: rowStore{rec: same}}).HeldSince(ctx, pidA, at); !ok || err != nil {
		t.Fatalf("consent at the grant = %v %v, want held", ok, err)
	}
	later := rec
	later.RecordedAt = at.Add(time.Second)
	if ok, err := (ConsentGrants{Store: rowStore{rec: later}}).HeldSince(ctx, pidA, at); ok || err != nil {
		t.Fatalf("consent recorded after the grant = %v %v, want not held", ok, err)
	}
	old := rec
	old.Version = "c2-link-v0"
	if ok, err := (ConsentGrants{Store: rowStore{rec: old}}).HeldSince(ctx, pidA, at); ok || err != nil {
		t.Fatalf("older version = %v %v, want not held", ok, err)
	}
	if ok, err := (ConsentGrants{Store: failingStore{ErrNoConsent}}).HeldSince(ctx, pidA, at); ok || err != nil {
		t.Fatalf("no consent = %v %v, want not held", ok, err)
	}
	if ok, err := (ConsentGrants{Store: failingStore{errors.New("db down")}}).HeldSince(ctx, pidA, at); ok || err == nil {
		t.Fatalf("db error = %v %v, want an error and not held", ok, err)
	}
	if ok, err := (ConsentGrants{}).HeldSince(ctx, pidA, at); ok || err == nil {
		t.Fatalf("no store = %v %v", ok, err)
	}
	other := rec
	other.PrincipalID = pidB
	revoked := rec
	revoked.RevokedAt = &at
	for name, r := range map[string]Record{"another principal": other, "revoked": revoked} {
		if ok, err := (ConsentGrants{Store: rowStore{rec: r}}).HeldSince(ctx, pidA, at); ok || err == nil {
			t.Errorf("%s row = %v %v, want an error and not held", name, ok, err)
		}
	}
}
