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

package bridge

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// pgIsolatedStore opens a Store on a throwaway schema. bridge_signal_outbox is
// tenant-agnostic and LeaseSignals scans the whole table, so exact assertions
// need a private table. Setup fails (it never falls back to the shared
// schema) when isolation cannot be proven.
func pgIsolatedStore(t *testing.T) *Store {
	t.Helper()
	conn := os.Getenv("TEST_DATABASE_URL")
	if conn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed bridge outbox test")
	}
	ctx := context.Background()
	schema := fmt.Sprintf("bridge_t_%d", time.Now().UnixNano())
	admin, err := pgx.Connect(ctx, conn)
	if err != nil {
		t.Fatalf("isolation setup: connect: %v", err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("isolation setup: create schema: %v", err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+schema+" CASCADE") })

	u, err := url.Parse(conn)
	if err != nil {
		t.Fatalf("isolation setup: parse TEST_DATABASE_URL: %v", err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	s, err := NewStore(ctx, u.String())
	if err != nil {
		t.Fatalf("isolation setup: store: %v", err)
	}
	t.Cleanup(s.Close)

	var got, version string
	if err := s.pool.QueryRow(ctx, "SELECT current_schema(), version()").Scan(&got, &version); err != nil {
		t.Fatalf("isolation setup: current_schema: %v", err)
	}
	if got != schema {
		t.Fatalf("isolation not established: current_schema=%q want %q", got, schema)
	}
	var n int
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM bridge_signal_outbox").Scan(&n); err != nil || n != 0 {
		t.Fatalf("isolation setup: outbox not empty in test schema: n=%d err=%v", n, err)
	}
	t.Logf("PostgreSQL: %s (schema %s)", version, schema)
	return s
}

// outboxRow is a full-row snapshot used to prove a row did not change.
type outboxRow struct {
	Status, LastErr string
	Attempts        int
	Next            time.Time
	SentAt          *time.Time
}

func snapshot(t *testing.T, s *Store, id string) outboxRow {
	t.Helper()
	var r outboxRow
	if err := s.pool.QueryRow(context.Background(), `SELECT status, last_error_code, attempts, next_attempt_at, sent_at
		FROM bridge_signal_outbox WHERE command_id=$1`, id).Scan(&r.Status, &r.LastErr, &r.Attempts, &r.Next, &r.SentAt); err != nil {
		t.Fatalf("snapshot %s: %v", id, err)
	}
	return r
}

// insertOutbox inserts a row with an explicit status and due offset.
func insertOutbox(t *testing.T, s *Store, id, status string, dueIn time.Duration) {
	t.Helper()
	if _, err := s.pool.Exec(context.Background(), `INSERT INTO bridge_signal_outbox (command_id, workflow_id, run_id, result_digest, status, next_attempt_at)
		VALUES ($1, 'wf-'||$1, 'run-'||$1, 'sha256:x', $2, now() + ($3 * interval '1 second'))`,
		id, status, int(dueIn/time.Second)); err != nil {
		t.Fatal(err)
	}
}

func ids(sigs []Signal) []string {
	out := make([]string, 0, len(sigs))
	for _, sg := range sigs {
		out = append(out, sg.CommandID)
	}
	sort.Strings(out)
	return out
}

func equalIDs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestPGOutboxLeaseDueOrderLimit(t *testing.T) {
	s := pgIsolatedStore(t)
	ctx := context.Background()
	// Due rows, oldest first: d1 < d2 < d3 < d4.
	insertOutbox(t, s, "d1", "pending", -4*time.Hour)
	insertOutbox(t, s, "d2", "pending", -3*time.Hour)
	insertOutbox(t, s, "d3", "pending", -2*time.Hour)
	insertOutbox(t, s, "d4", "pending", -1*time.Hour)
	insertOutbox(t, s, "future", "pending", time.Hour)
	insertOutbox(t, s, "sent", "sent", -5*time.Hour)
	insertOutbox(t, s, "unknown", "unknown", -5*time.Hour)

	got, err := s.LeaseSignals(ctx, 2, 90*time.Second)
	if err != nil {
		t.Fatalf("LeaseSignals (verbatim error): %v", err)
	}
	// Selection priority is oldest next_attempt_at; RETURNING order is unspecified.
	if want := []string{"d1", "d2"}; !equalIDs(ids(got), want) {
		t.Fatalf("leased %v, want %v", ids(got), want)
	}
	for _, sg := range got {
		if sg.WorkflowID != "wf-"+sg.CommandID || sg.RunID != "run-"+sg.CommandID || sg.ResultDigest != "sha256:x" || sg.Attempts != 0 {
			t.Fatalf("unexpected signal %+v", sg)
		}
		var secs float64
		if err := s.pool.QueryRow(ctx, `SELECT extract(epoch FROM next_attempt_at - now()) FROM bridge_signal_outbox WHERE command_id=$1`, sg.CommandID).Scan(&secs); err != nil {
			t.Fatal(err)
		}
		if secs < 60 || secs > 91 {
			t.Fatalf("%s next_attempt_at is %.0fs ahead, want about 90", sg.CommandID, secs)
		}
	}
	got, err = s.LeaseSignals(ctx, 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"d3", "d4"}; !equalIDs(ids(got), want) {
		t.Fatalf("second lease %v, want %v (future/terminal/leased rows must be excluded)", ids(got), want)
	}
	if got, err = s.LeaseSignals(ctx, 10, time.Minute); err != nil || len(got) != 0 {
		t.Fatalf("immediate re-lease = %v, %v; want nothing", ids(got), err)
	}
}

func TestPGOutboxVisibilityTimeoutReleases(t *testing.T) {
	s := pgIsolatedStore(t)
	ctx := context.Background()
	insertOutbox(t, s, "v1", "pending", -time.Minute)
	if got, err := s.LeaseSignals(ctx, 5, time.Second); err != nil || len(got) != 1 {
		t.Fatalf("first lease: %v %v", got, err)
	}
	if got, _ := s.LeaseSignals(ctx, 5, time.Second); len(got) != 0 {
		t.Fatal("row leasable while invisible")
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		got, err := s.LeaseSignals(ctx, 5, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("row not leasable again after the visibility timeout")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func TestPGOutboxSkipLockedDoesNotBlock(t *testing.T) {
	s := pgIsolatedStore(t)
	for i := 0; i < 6; i++ {
		insertOutbox(t, s, fmt.Sprintf("k%d", i), "pending", -time.Hour+time.Duration(i)*time.Minute)
	}
	bg := context.Background()
	tx, err := s.pool.Begin(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(bg) }()
	rows, err := tx.Query(bg, `SELECT command_id FROM bridge_signal_outbox WHERE status='pending' ORDER BY next_attempt_at LIMIT 3 FOR UPDATE`)
	if err != nil {
		t.Fatal(err)
	}
	locked := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		locked[id] = true
	}
	rows.Close()
	if len(locked) != 3 {
		t.Fatalf("locked %d rows, want 3", len(locked))
	}

	ctx, cancel := context.WithTimeout(bg, 5*time.Second)
	defer cancel()
	got, err := s.LeaseSignals(ctx, 10, time.Minute)
	if err != nil {
		t.Fatalf("LeaseSignals while rows locked (verbatim error): %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("leased %v, want the 3 unlocked rows", ids(got))
	}
	for _, sg := range got {
		if locked[sg.CommandID] {
			t.Fatalf("leased row %s that another transaction holds locked", sg.CommandID)
		}
	}
}

func TestPGOutboxConcurrentLeasersDisjoint(t *testing.T) {
	s := pgIsolatedStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	const workers, rowsN, rounds = 4, 40, 20
	for round := 0; round < rounds; round++ {
		if _, err := s.pool.Exec(ctx, `DELETE FROM bridge_signal_outbox`); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < rowsN; i++ {
			insertOutbox(t, s, fmt.Sprintf("r%d-%d", round, i), "pending", -time.Hour)
		}
		start := make(chan struct{})
		results := make([][]string, workers)
		errs := make([]error, workers)
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				<-start
				var sigs []Signal
				sigs, errs[w] = s.LeaseSignals(ctx, 15, time.Minute)
				results[w] = ids(sigs)
			}(w)
		}
		close(start)
		wg.Wait()
		seen := map[string]int{}
		for w := 0; w < workers; w++ {
			if errs[w] != nil {
				t.Fatalf("round %d worker %d (verbatim error): %v", round, w, errs[w])
			}
			if len(results[w]) > 15 {
				t.Fatalf("worker %d leased %d > limit", w, len(results[w]))
			}
			for _, id := range results[w] {
				seen[id]++
			}
		}
		total := 0
		for id, n := range seen {
			total += n
			if n != 1 {
				t.Fatalf("round %d: %s leased %d times", round, id, n)
			}
		}
		if total > rowsN {
			t.Fatalf("round %d: leased %d > %d rows", round, total, rowsN)
		}
	}
}

func TestPGOutboxRetrySignal(t *testing.T) {
	s := pgIsolatedStore(t)
	ctx := context.Background()
	insertOutbox(t, s, "rt", "pending", -time.Minute)
	if err := s.RetrySignal(ctx, "rt", "signal_error", time.Hour); err != nil {
		t.Fatal(err)
	}
	r := snapshot(t, s, "rt")
	if r.Status != "pending" || r.Attempts != 1 || r.LastErr != "signal_error" {
		t.Fatalf("after retry: %+v", r)
	}
	var secs float64
	if err := s.pool.QueryRow(ctx, `SELECT extract(epoch FROM next_attempt_at - now()) FROM bridge_signal_outbox WHERE command_id='rt'`).Scan(&secs); err != nil {
		t.Fatal(err)
	}
	if secs < 3500 || secs > 3601 {
		t.Fatalf("next_attempt_at is %.0fs ahead, want about 3600", secs)
	}
	if got, _ := s.LeaseSignals(ctx, 5, time.Minute); len(got) != 0 {
		t.Fatal("row leasable before its retry time")
	}
	if _, err := s.pool.Exec(ctx, `UPDATE bridge_signal_outbox SET next_attempt_at = now() - interval '1 second' WHERE command_id='rt'`); err != nil {
		t.Fatal(err)
	}
	if got, err := s.LeaseSignals(ctx, 5, time.Minute); err != nil || len(got) != 1 || got[0].Attempts != 1 {
		t.Fatalf("lease after retry time: %+v %v", got, err)
	}
}

func TestPGOutboxTerminalStatesImmutable(t *testing.T) {
	s := pgIsolatedStore(t)
	ctx := context.Background()
	insertOutbox(t, s, "s1", "pending", -time.Minute)
	insertOutbox(t, s, "u1", "pending", -time.Minute)
	if err := s.MarkSignalSent(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkSignalUnknown(ctx, "u1", ErrSignalTargetNotFound.Error()); err != nil {
		t.Fatal(err)
	}
	sent, unk := snapshot(t, s, "s1"), snapshot(t, s, "u1")
	if sent.Status != "sent" || sent.SentAt == nil || sent.Attempts != 1 || sent.LastErr != "" {
		t.Fatalf("sent row: %+v", sent)
	}
	if unk.Status != "unknown" || unk.Attempts != 1 || unk.LastErr != ErrSignalTargetNotFound.Error() || unk.SentAt != nil {
		t.Fatalf("unknown row: %+v", unk)
	}
	for _, id := range []string{"s1", "u1"} {
		before := snapshot(t, s, id)
		if err := s.MarkSignalSent(ctx, id); err != nil {
			t.Fatal(err)
		}
		if err := s.MarkSignalUnknown(ctx, id, "late"); err != nil {
			t.Fatal(err)
		}
		if err := s.RetrySignal(ctx, id, "late", time.Hour); err != nil {
			t.Fatal(err)
		}
		after := snapshot(t, s, id)
		if fmt.Sprintf("%+v", before) != fmt.Sprintf("%+v", after) {
			t.Fatalf("%s changed by late calls: before %+v after %+v", id, before, after)
		}
	}
	if got, err := s.LeaseSignals(ctx, 10, time.Minute); err != nil || len(got) != 0 {
		t.Fatalf("terminal rows leased: %v %v", ids(got), err)
	}
}

func TestPGOutboxFromSubmitResult(t *testing.T) {
	s := pgIsolatedStore(t)
	ctx := context.Background()
	tenant := fmt.Sprintf("t-%d", time.Now().UnixNano())
	c := Caller{ProviderRef: "glovo", Actor: "a", Tenants: []string{tenant}}
	id := enqueue(t, s, tenant, KindQuote)
	cmd := claimOne(t, s, c, id)
	if _, err := s.SubmitResult(ctx, c, id, resultBody(id, cmd)); err != nil {
		t.Fatal(err)
	}
	got, err := s.LeaseSignals(ctx, 5, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].CommandID != id || got[0].ResultDigest == "" {
		t.Fatalf("leased %+v, want the submitted command", got)
	}
	if err := s.MarkSignalSent(ctx, id); err != nil {
		t.Fatal(err)
	}
	if r := snapshot(t, s, id); r.Status != "sent" || r.SentAt == nil {
		t.Fatalf("row after sent: %+v", r)
	}
}

type outboxSignaler struct{ errs map[string]error }

func (f outboxSignaler) SignalBridgeResult(_ context.Context, _, _, commandID, _ string) error {
	return f.errs[commandID]
}

func TestPGOutboxDispatcherRunOnce(t *testing.T) {
	s := pgIsolatedStore(t)
	ctx := context.Background()
	for _, id := range []string{"ok", "gone", "flaky"} {
		insertOutbox(t, s, id, "pending", -time.Minute)
	}
	d := &Dispatcher{Outbox: s, Batch: 10, Backoff: func(int) time.Duration { return time.Hour },
		Signaler: outboxSignaler{errs: map[string]error{
			"gone":  fmt.Errorf("wrapped: %w", ErrSignalTargetNotFound),
			"flaky": errors.New("transient"),
		}}}
	sent, err := d.RunOnce(ctx)
	if err != nil || sent != 1 {
		t.Fatalf("RunOnce = %d, %v", sent, err)
	}
	if r := snapshot(t, s, "ok"); r.Status != "sent" || r.Attempts != 1 {
		t.Fatalf("ok: %+v", r)
	}
	if r := snapshot(t, s, "gone"); r.Status != "unknown" || r.Attempts != 1 {
		t.Fatalf("gone: %+v", r)
	}
	if r := snapshot(t, s, "flaky"); r.Status != "pending" || r.Attempts != 1 || r.LastErr != "signal_error" {
		t.Fatalf("flaky: %+v", r)
	}
}

func TestPGOutboxLeaseError(t *testing.T) {
	s := pgIsolatedStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.LeaseSignals(ctx, 5, time.Minute)
	if err == nil || err.Error()[:len("bridge: lease signals:")] != "bridge: lease signals:" {
		t.Fatalf("err = %v, want wrapped bridge: lease signals", err)
	}
	if err := s.MarkSignalSent(context.Background(), "absent"); err != nil {
		t.Fatalf("mark on unknown id: %v", err)
	}
}
