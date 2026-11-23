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
	"strings"
	"sync"
	"testing"
	"time"
)

// newAccessStore is newTestStore with the access tables wiped too and, when
// required is set, AccessRequired on. The clock is a settable fake.
func newAccessStore(t *testing.T, required bool) (*PostgresStore, *time.Time) {
	t.Helper()
	s := newTestStore(t)
	ctx := context.Background()
	wipe := func() {
		for _, q := range []string{"DELETE FROM glovo_access_requests", "DELETE FROM glovo_access_events"} {
			if _, err := s.pool.Exec(ctx, q); err != nil {
				t.Fatal(err)
			}
		}
	}
	wipe()
	t.Cleanup(wipe)
	s.accessRequired = required
	clock := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return clock }
	return s, &clock
}

func mustState(t *testing.T, s *PostgresStore, pid string, want AccessStatus) {
	t.Helper()
	got, err := s.AccessState(context.Background(), pid)
	if err != nil || got != want {
		t.Fatalf("state(%s) = %q %v, want %q", pid[len(pid)-2:], got, err, want)
	}
}

func eventCount(t *testing.T, s *PostgresStore, pid, event string) int {
	t.Helper()
	var n int
	if err := s.pool.QueryRow(context.Background(), `SELECT count(*) FROM glovo_access_events WHERE principal_id = $1 AND event = $2`, pid, event).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func approvedCount(t *testing.T, s *PostgresStore) int {
	t.Helper()
	var n int
	if err := s.pool.QueryRow(context.Background(), `SELECT count(*) FROM glovo_access_requests WHERE status = 'approved'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Every transition: the legal ones move the state and append one event, the
// illegal ones are refused and change nothing.
func TestPGAccessTransitionTable(t *testing.T) {
	type op struct {
		name string
		run  func(s *PostgresStore) error
	}
	ctx := context.Background()
	request := op{"request", func(s *PostgresStore) error { _, _, err := s.RequestAccess(ctx, pidA); return err }}
	approve := op{"approve", func(s *PostgresStore) error { _, err := s.ApproveAccess(ctx, pidA, "owner", "ok", testCap); return err }}
	reject := op{"reject", func(s *PostgresStore) error { _, err := s.RejectAccess(ctx, pidA, "owner", "no"); return err }}
	revoke := op{"revoke", func(s *PostgresStore) error { _, err := s.RevokeAccess(ctx, pidA, "owner", "stop"); return err }}

	// path reaches a state from none.
	paths := map[AccessStatus][]op{
		AccessNone:     nil,
		AccessPending:  {request},
		AccessApproved: {request, approve},
		AccessRejected: {request, reject},
		AccessRevoked:  {request, approve, revoke},
	}
	cases := []struct {
		from AccessStatus
		op   op
		want error // nil = legal
		to   AccessStatus
	}{
		{AccessNone, request, nil, AccessPending},
		{AccessNone, approve, ErrAccessNotPending, AccessNone},
		{AccessNone, reject, ErrAccessNotPending, AccessNone},
		{AccessNone, revoke, ErrAccessNotApproved, AccessNone},
		{AccessPending, request, nil, AccessPending},
		{AccessPending, approve, nil, AccessApproved},
		{AccessPending, reject, nil, AccessRejected},
		{AccessPending, revoke, ErrAccessNotApproved, AccessPending},
		{AccessApproved, request, ErrAccessApproved, AccessApproved},
		{AccessApproved, approve, ErrAccessNotPending, AccessApproved},
		{AccessApproved, reject, ErrAccessNotPending, AccessApproved},
		{AccessApproved, revoke, nil, AccessRevoked},
		{AccessRejected, request, nil, AccessPending},
		{AccessRejected, approve, ErrAccessNotPending, AccessRejected},
		{AccessRejected, reject, ErrAccessNotPending, AccessRejected},
		{AccessRejected, revoke, ErrAccessNotApproved, AccessRejected},
		{AccessRevoked, request, nil, AccessPending},
		{AccessRevoked, approve, ErrAccessNotPending, AccessRevoked},
		{AccessRevoked, reject, ErrAccessNotPending, AccessRevoked},
		{AccessRevoked, revoke, ErrAccessNotApproved, AccessRevoked},
	}
	for _, required := range []bool{false, true} {
		for _, tc := range cases {
			s, _ := newAccessStore(t, required)
			for _, p := range paths[tc.from] {
				if err := p.run(s); err != nil {
					t.Fatalf("setup %s via %s: %v", tc.from, p.name, err)
				}
			}
			var before int
			if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM glovo_access_events`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			err := tc.op.run(s)
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("required=%v %s -> %s: err %v, want %v", required, tc.from, tc.op.name, err, tc.want)
			}
			mustState(t, s, pidA, tc.to)
			var after int
			if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM glovo_access_events`).Scan(&after); err != nil {
				t.Fatal(err)
			}
			// A refused call, and an idempotent re-request, add no event.
			wantEvents := 0
			if tc.want == nil && (tc.from != AccessPending || tc.op.name != "request") {
				wantEvents = 1
			}
			if after-before != wantEvents {
				t.Errorf("required=%v %s -> %s: %d events added, want %d", required, tc.from, tc.op.name, after-before, wantEvents)
			}
		}
	}
}

func TestPGAccessActorAndReasonMandatory(t *testing.T) {
	s, _ := newAccessStore(t, false)
	ctx := context.Background()
	if _, _, err := s.RequestAccess(ctx, pidA); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("x", maxReasonLen+1)
	for name, f := range map[string]func() error{
		"approve no actor":  func() error { _, err := s.ApproveAccess(ctx, pidA, "", "ok", testCap); return err },
		"approve no reason": func() error { _, err := s.ApproveAccess(ctx, pidA, "owner", "", testCap); return err },
		"reject no actor":   func() error { _, err := s.RejectAccess(ctx, pidA, "", "no"); return err },
		"reject no reason":  func() error { _, err := s.RejectAccess(ctx, pidA, "owner", ""); return err },
		"revoke no actor":   func() error { _, err := s.RevokeAccess(ctx, pidA, "", "x"); return err },
		"revoke no reason":  func() error { _, err := s.RevokeAccess(ctx, pidA, "owner", ""); return err },
		"reason too long":   func() error { _, err := s.ApproveAccess(ctx, pidA, "owner", long, testCap); return err },
		"bad principal":     func() error { _, err := s.ApproveAccess(ctx, "github:x", "owner", "ok", testCap); return err },
	} {
		if err := f(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
	mustState(t, s, pidA, AccessPending)
	if _, _, err := s.RequestAccess(ctx, "prn_short"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("request bad pid: %v", err)
	}
	if _, err := s.AccessState(ctx, "prn_short"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("state bad pid: %v", err)
	}
}

// A pending request is live through exactly seven days and lapses after.
// The lapsed request reads as none, cannot be decided, is not listed, and
// can be asked for again.
func TestPGAccessLapseBoundary(t *testing.T) {
	s, clock := newAccessStore(t, false)
	ctx := context.Background()
	start := *clock
	a, created, err := s.RequestAccess(ctx, pidA)
	if err != nil || !created || !a.ExpiresAt.Equal(start.Add(7*24*time.Hour)) {
		t.Fatalf("request = %+v %v %v", a, created, err)
	}
	*clock = start.Add(7*24*time.Hour - time.Nanosecond)
	mustState(t, s, pidA, AccessPending)
	*clock = start.Add(7 * 24 * time.Hour)
	mustState(t, s, pidA, AccessPending)
	if l, err := s.ListPendingAccess(ctx); err != nil || len(l) != 1 {
		t.Fatalf("list at the boundary = %v %v", l, err)
	}
	*clock = start.Add(7*24*time.Hour + time.Microsecond)
	mustState(t, s, pidA, AccessNone)
	if l, err := s.ListPendingAccess(ctx); err != nil || len(l) != 0 {
		t.Fatalf("list after lapse = %v %v", l, err)
	}
	if _, err := s.ApproveAccess(ctx, pidA, "owner", "ok", testCap); !errors.Is(err, ErrAccessNotPending) {
		t.Fatalf("approve lapsed: %v", err)
	}
	if _, err := s.RejectAccess(ctx, pidA, "owner", "no"); !errors.Is(err, ErrAccessNotPending) {
		t.Fatalf("reject lapsed: %v", err)
	}
	// Ask again: a fresh request with a fresh expiry, the lapse on record.
	again, created, err := s.RequestAccess(ctx, pidA)
	if err != nil || !created || !again.ExpiresAt.After(a.ExpiresAt) {
		t.Fatalf("re-request = %+v %v %v", again, created, err)
	}
	mustState(t, s, pidA, AccessPending)
	if n := eventCount(t, s, pidA, "lapsed"); n != 1 {
		t.Fatalf("lapsed events = %d", n)
	}
}

func TestPGAccessRequestIdempotentWhilePending(t *testing.T) {
	s, clock := newAccessStore(t, false)
	ctx := context.Background()
	first, _, err := s.RequestAccess(ctx, pidA)
	if err != nil {
		t.Fatal(err)
	}
	*clock = clock.Add(time.Hour)
	second, created, err := s.RequestAccess(ctx, pidA)
	if err != nil || created || !second.ExpiresAt.Equal(first.ExpiresAt) {
		t.Fatalf("second request = %+v %v %v: must not extend the expiry", second, created, err)
	}
	if n := eventCount(t, s, pidA, "requested"); n != 1 {
		t.Fatalf("requested events = %d", n)
	}
}

func TestPGAccessListPendingOrdered(t *testing.T) {
	s, clock := newAccessStore(t, false)
	ctx := context.Background()
	for _, p := range []string{pidB, pidA} {
		if _, _, err := s.RequestAccess(ctx, p); err != nil {
			t.Fatal(err)
		}
		*clock = clock.Add(time.Minute)
	}
	if _, err := s.ApproveAccess(ctx, pidA, "owner", "ok", testCap); err != nil {
		t.Fatal(err)
	}
	l, err := s.ListPendingAccess(ctx)
	if err != nil || len(l) != 1 || l[0].PrincipalID != pidB {
		t.Fatalf("list = %v %v", l, err)
	}
}

// AccessRequired: Record claims no slot, approval does, revoke frees it.
func TestPGAccessRequiredSlotSemantics(t *testing.T) {
	s, _ := newAccessStore(t, true)
	ctx := context.Background()
	// Consent at a closed cap still records: a person consents before asking.
	if _, created, err := s.Record(ctx, pidA, "github:a", 0); err != nil || !created {
		t.Fatalf("record at closed cap in access mode = %v %v", created, err)
	}
	if _, _, err := s.RequestAccess(ctx, pidA); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveAccess(ctx, pidA, "owner", "ok", 0); !errors.Is(err, ErrCapacityReached) {
		t.Fatalf("approve at closed cap: %v", err)
	}
	if _, err := s.ApproveAccess(ctx, pidA, "owner", "ok", -1); !errors.Is(err, ErrCapacityReached) {
		t.Fatalf("approve at negative cap: %v", err)
	}
	mustState(t, s, pidA, AccessPending)

	// Cap 1: A takes it, B is refused, revoking A frees it for B.
	if _, err := s.ApproveAccess(ctx, pidA, "owner", "ok", 1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RequestAccess(ctx, pidB); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveAccess(ctx, pidB, "owner", "ok", 1); !errors.Is(err, ErrCapacityReached) {
		t.Fatalf("approve at cap: %v", err)
	}
	mustState(t, s, pidB, AccessPending)
	if _, err := s.RevokeAccess(ctx, pidA, "owner", "done"); err != nil {
		t.Fatal(err)
	}
	if n := approvedCount(t, s); n != 0 {
		t.Fatalf("approved after revoke = %d", n)
	}
	if _, err := s.ApproveAccess(ctx, pidB, "owner", "ok", 1); err != nil {
		t.Fatalf("approve after the slot was freed: %v", err)
	}
	// A principal cannot hold two slots: a second approval is illegal.
	if _, err := s.ApproveAccess(ctx, pidB, "owner", "again", 5); !errors.Is(err, ErrAccessNotPending) {
		t.Fatalf("second approve: %v", err)
	}
	if n := approvedCount(t, s); n != 1 {
		t.Fatalf("approved = %d", n)
	}
}

// Two approvals racing for the last slot: exactly one wins, every round.
func TestPGConcurrentApprovesForTheLastSlot(t *testing.T) {
	s, _ := newAccessStore(t, true)
	ctx := context.Background()
	const capacity = 3
	for i := 0; i < capacity-1; i++ {
		if _, _, err := s.RequestAccess(ctx, pidN(i)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ApproveAccess(ctx, pidN(i), "owner", "ok", capacity); err != nil {
			t.Fatal(err)
		}
	}
	for round := 0; round < 5; round++ {
		const claimers = 12
		for i := 0; i < claimers; i++ {
			if _, _, err := s.RequestAccess(ctx, pidN(10+i)); err != nil {
				t.Fatal(err)
			}
		}
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
				_, err := s.ApproveAccess(ctx, pid, "owner", "ok", capacity)
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
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
			t.Fatalf("round %d: won %d, full %d, other %v", round, won, full, other)
		}
		if n := approvedCount(t, s); n != capacity {
			t.Fatalf("round %d: %d approved, cap %d", round, n, capacity)
		}
		for i := 0; i < claimers; i++ {
			if _, err := s.RevokeAccess(ctx, pidN(10+i), "owner", "next round"); err != nil && !errors.Is(err, ErrAccessNotApproved) {
				t.Fatal(err)
			}
			if _, err := s.RejectAccess(ctx, pidN(10+i), "owner", "next round"); err != nil && !errors.Is(err, ErrAccessNotPending) {
				t.Fatal(err)
			}
		}
	}
}

// With AccessRequired off, the access methods never touch capacity.
func TestPGAccessDefaultModeIgnoresCapacity(t *testing.T) {
	s, _ := newAccessStore(t, false)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, _, err := s.RequestAccess(ctx, pidN(i)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ApproveAccess(ctx, pidN(i), "owner", "ok", 1); err != nil {
			t.Fatalf("approve %d in default mode: %v", i, err)
		}
	}
	// Record still claims against consents: cap 1 holds one.
	if _, _, err := s.Record(ctx, pidA, "github:a", 1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Record(ctx, pidB, "github:b", 1); !errors.Is(err, ErrCapacityReached) {
		t.Fatalf("default-mode record at cap: %v", err)
	}
}

func TestPGAccessBackfill(t *testing.T) {
	s, _ := newAccessStore(t, true)
	ctx := context.Background()
	// A has an active consent, B a revoked one, C an active consent and a
	// revoked access row (must stay revoked), D an active consent that
	// appears after the one-shot ran.
	for _, p := range []string{pidA, pidB, pidN(3)} {
		if _, _, err := s.Record(ctx, p, "github:x", testCap); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Revoke(ctx, pidB, "github:x"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RequestAccess(ctx, pidN(3)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveAccess(ctx, pidN(3), "owner", "ok", testCap); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeAccess(ctx, pidN(3), "owner", "gone"); err != nil {
		t.Fatal(err)
	}
	reset := func() {
		if _, err := s.pool.Exec(ctx, `DELETE FROM glovo_access_meta`); err != nil {
			t.Fatal(err)
		}
	}
	reset()
	for run := 0; run < 3; run++ {
		if run > 0 {
			reset() // re-running the whole migration, not only the marker
		}
		if err := s.backfillAccess(ctx); err != nil {
			t.Fatal(err)
		}
		mustState(t, s, pidA, AccessApproved)
		mustState(t, s, pidB, AccessNone)
		mustState(t, s, pidN(3), AccessRevoked)
		if n := approvedCount(t, s); n != 1 {
			t.Fatalf("run %d: approved = %d, want 1", run, n)
		}
		if n := eventCount(t, s, pidA, "approved"); n != 1 {
			t.Fatalf("run %d: approved events = %d", run, n)
		}
	}
	var by string
	if err := s.pool.QueryRow(ctx, `SELECT decided_by FROM glovo_access_requests WHERE principal_id = $1`, pidA).Scan(&by); err != nil || by != ActorBackfill {
		t.Fatalf("decided_by = %q %v", by, err)
	}
	// The marker makes it one-shot: a consent recorded later is not
	// approved by a later start.
	if _, _, err := s.Record(ctx, pidN(4), "github:x", testCap); err != nil {
		t.Fatal(err)
	}
	if err := s.backfillAccess(ctx); err != nil {
		t.Fatal(err)
	}
	mustState(t, s, pidN(4), AccessNone)
	// Backfilled access counts once against the cap, and is revocable.
	if _, err := s.RevokeAccess(ctx, pidA, "owner", "x"); err != nil {
		t.Fatal(err)
	}
}

// A read the database cannot answer is an error, never none or an empty list.
func TestPGAccessReadFailureIsNotAbsence(t *testing.T) {
	s, _ := newAccessStore(t, false)
	ctx := context.Background()
	if _, _, err := s.RequestAccess(ctx, pidA); err != nil {
		t.Fatal(err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if st, err := s.AccessState(cctx, pidA); err == nil || st != "" || st == AccessNone {
		t.Fatalf("cancelled state read = %q %v", st, err)
	}
	if l, err := s.ListPendingAccess(cctx); err == nil || l != nil {
		t.Fatalf("cancelled list = %v %v", l, err)
	}
	if _, _, err := s.RequestAccess(cctx, pidB); err == nil {
		t.Fatal("cancelled request succeeded")
	}
	// An unknown status in the row is a read error too.
	if _, err := s.pool.Exec(ctx, `ALTER TABLE glovo_access_requests DROP CONSTRAINT glovo_access_requests_status_check`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = s.pool.Exec(ctx, `DELETE FROM glovo_access_requests`)
		_, _ = s.pool.Exec(ctx, `ALTER TABLE glovo_access_requests ADD CONSTRAINT glovo_access_requests_status_check CHECK (status IN ('pending','approved','rejected','revoked'))`)
	}()
	if _, err := s.pool.Exec(ctx, `UPDATE glovo_access_requests SET status = 'bogus'`); err != nil {
		t.Fatal(err)
	}
	if st, err := s.AccessState(ctx, pidA); err == nil || st == AccessNone {
		t.Fatalf("unknown status = %q %v, want an error", st, err)
	}
}

// The capacity lock bounds an access decision like a claim: a holder of the
// lock stalls an approval for at most the store timeout, and the stalled
// approval fails.
func TestPGAccessApproveWaitIsBounded(t *testing.T) {
	s, _ := newAccessStore(t, true)
	ctx := context.Background()
	if _, _, err := s.RequestAccess(ctx, pidA); err != nil {
		t.Fatal(err)
	}
	s.timeout = 300 * time.Millisecond
	holder, err := s.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(ctx) }()
	if _, err := holder.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('glovo-link-consent:capacity'))`); err != nil {
		t.Fatal(err)
	}
	_, err = s.ApproveAccess(ctx, pidA, "owner", "ok", testCap)
	if err == nil || errors.Is(err, ErrCapacityReached) {
		t.Fatalf("stalled approve = %v, want a timeout error", err)
	}
	_ = holder.Rollback(ctx)
	s.timeout = dbTimeout
	mustState(t, s, pidA, AccessPending)
}

// In default mode Record creates no access rows, so a backfill that ran there
// would burn its one-shot marker and miss everyone who consents before the
// switch. NewStore therefore runs it only with AccessRequired, and a store
// opened later with the flag on takes the snapshot then.
func TestPGBackfillRunsOnlyWhenAccessRequired(t *testing.T) {
	s, _ := newAccessStore(t, false)
	ctx := context.Background()
	if _, err := s.pool.Exec(ctx, `DELETE FROM glovo_access_meta`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Record(ctx, pidA, "github:x", testCap); err != nil {
		t.Fatal(err)
	}
	connStr := os.Getenv("TEST_DATABASE_URL")
	def, err := NewStore(ctx, connStr)
	if err != nil {
		t.Fatal(err)
	}
	defer def.Close()
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM glovo_access_meta`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("default-mode NewStore wrote the backfill marker (%d rows, %v)", n, err)
	}
	mustState(t, s, pidA, AccessNone)

	on, err := NewStore(ctx, connStr, WithAccessRequired(true))
	if err != nil {
		t.Fatal(err)
	}
	defer on.Close()
	mustState(t, s, pidA, AccessApproved)
}

// GetAccess answers the effective state with the row's times, and a failed
// read is an error, never none.
func TestPGGetAccess(t *testing.T) {
	s, clock := newAccessStore(t, false)
	ctx := context.Background()
	if a, err := s.GetAccess(ctx, pidA); err != nil || a.Status != AccessNone || !a.RequestedAt.IsZero() {
		t.Fatalf("no row = %+v %v", a, err)
	}
	req, _, err := s.RequestAccess(ctx, pidA)
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.GetAccess(ctx, pidA)
	if err != nil || a.Status != AccessPending || !a.RequestedAt.Equal(req.RequestedAt) || !a.ExpiresAt.Equal(req.ExpiresAt) {
		t.Fatalf("pending = %+v %v", a, err)
	}
	*clock = req.ExpiresAt.Add(time.Second)
	if a, err := s.GetAccess(ctx, pidA); err != nil || a.Status != AccessNone {
		t.Fatalf("lapsed = %+v %v, want none", a, err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if a, err := s.GetAccess(cctx, pidA); err == nil || a.Status == AccessNone {
		t.Fatalf("cancelled read = %+v %v", a, err)
	}
	if _, err := s.GetAccess(ctx, "bad"); err == nil {
		t.Fatal("invalid principal accepted")
	}
}
