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

package glovojoin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

type fakeStarter struct {
	mu    sync.Mutex
	calls []string
	got   map[string][]byte
	err   error
	run   string
	delay time.Duration
}

func (f *fakeStarter) Start(_ context.Context, wf string, input []byte) (string, error) {
	f.mu.Lock()
	f.calls = append(f.calls, wf)
	if f.got == nil {
		f.got = map[string][]byte{}
	}
	f.got[wf] = append([]byte(nil), input...)
	err, run, delay := f.err, f.run, f.delay
	f.mu.Unlock()
	time.Sleep(delay)
	return run, err
}

func (s *stack) dispatcher(st WorkflowStarter, enabled bool) *ControlStartDispatcher {
	return &ControlStartDispatcher{Enabled: enabled, DB: s.rp, Starter: st}
}

func (s *stack) startRow(orderRef string) (state, run string, attempts int) {
	s.t.Helper()
	if err := s.mp.QueryRow(context.Background(), `SELECT state, started_run_id, attempts FROM glovo.control_starts WHERE order_ref=$1`, orderRef).Scan(&state, &run, &attempts); err != nil {
		s.t.Fatal(err)
	}
	return
}

func (s *stack) prepared(key string) (orderRef string, input []byte) {
	s.t.Helper()
	p := s.preview(stackBasket)
	res, rf := s.prepare.Prepare(context.Background(), s.req(p, key))
	if rf != nil {
		s.t.Fatal(rf)
	}
	if err := s.mp.QueryRow(context.Background(), `SELECT input FROM glovo.control_starts WHERE order_ref=$1`, res.OrderID).Scan(&input); err != nil {
		s.t.Fatal(err)
	}
	return res.OrderID, input
}

// Crash recovery: after commit, the workflow starts from the stored row alone.
// The dispatcher holds no order, join-ref or connection store at all.
func TestDispatcherStartsFromTheStoredRowAlone(t *testing.T) {
	s := newStack(t)
	s.activate("k-disp")
	ref, input := s.prepared("key-d")
	st := &fakeStarter{run: "run-1"}
	n, err := s.dispatcher(st, true).RunOnce(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("RunOnce = %d, %v", n, err)
	}
	if len(st.calls) != 1 || !bytes.Equal(st.got[st.calls[0]], input) {
		t.Fatalf("starter got %v, want the stored input verbatim", st.calls)
	}
	if state, run, _ := s.startRow(ref); state != "started" || run != "run-1" {
		t.Fatalf("row = %s %s", state, run)
	}
	// A started row is never started again.
	if n, _ := s.dispatcher(st, true).RunOnce(context.Background()); n != 0 || len(st.calls) != 1 {
		t.Fatalf("second pass started again: %d %v", n, st.calls)
	}
}

func TestDispatcherOffLeavesRowsPending(t *testing.T) {
	s := newStack(t)
	s.activate("k-off")
	ref, _ := s.prepared("key-o")
	st := &fakeStarter{run: "run-1"}
	if n, err := s.dispatcher(st, false).RunOnce(context.Background()); n != 0 || err != nil || len(st.calls) != 0 {
		t.Fatalf("disabled dispatcher ran: %d %v %v", n, err, st.calls)
	}
	if state, _, attempts := s.startRow(ref); state != "pending" || attempts != 0 {
		t.Fatalf("row = %s/%d", state, attempts)
	}
}

func TestDispatcherAlreadyStartedIsSuccess(t *testing.T) {
	s := newStack(t)
	s.activate("k-dup")
	ref, _ := s.prepared("key-dup")
	st := &fakeStarter{run: "run-existing", err: fmt.Errorf("%w: run-existing", ErrAlreadyStarted)}
	if n, err := s.dispatcher(st, true).RunOnce(context.Background()); n != 1 || err != nil {
		t.Fatalf("RunOnce = %d %v", n, err)
	}
	if state, run, _ := s.startRow(ref); state != "started" || run != "run-existing" {
		t.Fatalf("row = %s %s", state, run)
	}
}

func TestDispatcherBacksOffAndGivesUp(t *testing.T) {
	s := newStack(t)
	s.activate("k-retry")
	ref, _ := s.prepared("key-retry")
	st := &fakeStarter{err: errors.New("temporal down")}
	now := time.Now().UTC()
	d := s.dispatcher(st, true)
	var events []DispatchEvent
	d.Audit = func(e DispatchEvent) { events = append(events, e) }
	for i := 1; i < MaxStartAttempts; i++ {
		d.Now = func() time.Time { return now }
		if n, err := d.RunOnce(context.Background()); n != 0 || err != nil {
			t.Fatalf("pass %d = %d %v", i, n, err)
		}
		if state, _, attempts := s.startRow(ref); state != "pending" || attempts != i {
			t.Fatalf("pass %d: %s/%d", i, state, attempts)
		}
		// Not due yet: the same instant claims nothing.
		if n, _ := d.RunOnce(context.Background()); n != 0 || len(st.calls) != i {
			t.Fatalf("pass %d re-ran before the back-off: %v", i, st.calls)
		}
		now = now.Add(time.Hour)
	}
	d.Now = func() time.Time { return now }
	if n, err := d.RunOnce(context.Background()); n != 1 || err != nil {
		t.Fatalf("final pass = %d %v", n, err)
	}
	if state, run, attempts := s.startRow(ref); state != "failed_terminal" || run != "" || attempts != MaxStartAttempts {
		t.Fatalf("row = %s %q %d", state, run, attempts)
	}
	if last := events[len(events)-1]; last.Event != "failed_terminal" || last.OrderRef != ref {
		t.Fatalf("audit = %+v", last)
	}
}

// A stored input whose digest no longer matches is never sent and never rebuilt.
func TestDispatcherRefusesADigestMismatch(t *testing.T) {
	s := newStack(t)
	s.activate("k-digest")
	ref, _ := s.prepared("key-digest")
	var cons string
	if err := s.mp.QueryRow(context.Background(), `SELECT conname FROM pg_constraint WHERE conrelid='glovo.control_starts'::regclass AND pg_get_constraintdef(oid) LIKE '%input_digest%' AND contype='c'`).Scan(&cons); err != nil {
		t.Fatal(err)
	}
	if _, err := s.mp.Exec(context.Background(), fmt.Sprintf(`ALTER TABLE glovo.control_starts DROP CONSTRAINT %q`, cons)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.mp.Exec(context.Background(), `UPDATE glovo.control_starts SET input_digest='sha256:'||repeat('0',64) WHERE order_ref=$1`, ref); err != nil {
		t.Fatal(err)
	}
	st := &fakeStarter{run: "run-1"}
	d := s.dispatcher(st, true)
	var events []DispatchEvent
	d.Audit = func(e DispatchEvent) { events = append(events, e) }
	if n, err := d.RunOnce(context.Background()); n != 1 || err != nil {
		t.Fatalf("RunOnce = %d %v", n, err)
	}
	if len(st.calls) != 0 {
		t.Fatalf("a mismatched input was sent: %v", st.calls)
	}
	if state, _, _ := s.startRow(ref); state != "failed_terminal" {
		t.Fatalf("state = %s", state)
	}
	if len(events) != 1 || events[0].Event != "digest_mismatch" {
		t.Fatalf("audit = %+v", events)
	}
}

// Two dispatchers racing for one row start it once (FOR UPDATE SKIP LOCKED).
func TestDispatcherConcurrentClaimStartsOnce(t *testing.T) {
	s := newStack(t)
	s.activate("k-skip")
	ref, _ := s.prepared("key-skip")
	st := &fakeStarter{run: "run-1", delay: 300 * time.Millisecond}
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = s.dispatcher(st, true).RunOnce(context.Background())
		}()
	}
	wg.Wait()
	if len(st.calls) != 1 {
		t.Fatalf("workflow started %d times, want once", len(st.calls))
	}
	if state, _, _ := s.startRow(ref); state != "started" {
		t.Fatalf("state = %s", state)
	}
}
