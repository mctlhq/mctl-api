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
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/orders"
)

var errInjected = errors.New("injected statement failure")

// faultState counts the statements a prepare sends and fails the failAt-th
// (1-based) before it runs, so the database holds exactly the effects of the
// statements before it. commitAt fails the commit instead.
type faultState struct {
	n        int
	failAt   int
	commitAt bool
}

func (f *faultState) step() error {
	f.n++
	if f.failAt > 0 && f.n == f.failAt {
		return errInjected
	}
	return nil
}

type faultDB struct {
	inner TxBeginner
	st    *faultState
}

func (d faultDB) BeginTx(ctx context.Context, o pgx.TxOptions) (pgx.Tx, error) {
	tx, err := d.inner.BeginTx(ctx, o)
	if err != nil {
		return nil, err
	}
	return faultTx{Tx: tx, st: d.st}, nil
}

type faultTx struct {
	pgx.Tx
	st *faultState
}

func (t faultTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if err := t.st.step(); err != nil {
		return pgconn.CommandTag{}, err
	}
	return t.Tx.Exec(ctx, sql, args...)
}

func (t faultTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if err := t.st.step(); err != nil {
		return nil, err
	}
	return t.Tx.Query(ctx, sql, args...)
}

type failRow struct{ err error }

func (r failRow) Scan(...any) error { return r.err }

func (t faultTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if err := t.st.step(); err != nil {
		return failRow{err}
	}
	return t.Tx.QueryRow(ctx, sql, args...)
}

func (t faultTx) Begin(ctx context.Context) (pgx.Tx, error) {
	if err := t.st.step(); err != nil {
		return nil, err
	}
	inner, err := t.Tx.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return faultTx{Tx: inner, st: t.st}, nil
}

func (t faultTx) Commit(ctx context.Context) error {
	if t.st.commitAt {
		_ = t.Tx.Rollback(ctx)
		return errInjected
	}
	return t.Tx.Commit(ctx)
}

func (s *stack) allRows() [8]int {
	w := s.writes()
	return [8]int{w[0], w[1], w[2], w[3], w[4], w[5],
		s.count(`SELECT count(*) FROM public.action_approval_requests`),
		s.count(`SELECT count(*) FROM glovo.order_snapshots`)}
}

// A2/T11: a failure after ANY statement of a prepare leaves no row behind
// (one transaction, nothing committed early), the preview is still unspent,
// and an immediate retry with the same key completes once.
func TestPrepareLeavesNothingAfterAFailureAtAnyStatement(t *testing.T) {
	// First a clean run counts the statements, so the loop below covers all of
	// them rather than a number someone typed.
	count := &faultState{}
	s := newStack(t)
	s.activate("k-fault-count")
	s.prepare.DB = faultDB{inner: s.rp, st: count}
	if _, rf := s.prepare.Prepare(context.Background(), s.req(s.preview(stackBasket), "key-count")); rf != nil {
		t.Fatal(rf)
	}
	total := count.n
	if total < 20 {
		t.Fatalf("a prepare sent %d statements; the instrumentation is not seeing the store calls", total)
	}
	full := s.allRows()

	for at := 1; at <= total+1; at++ {
		s := newStack(t)
		s.activate("k-fault")
		base := s.allRows()
		st := &faultState{failAt: at}
		commit := at == total+1
		if commit {
			st = &faultState{commitAt: true}
		}
		s.prepare.DB = faultDB{inner: s.rp, st: st}
		p := s.preview(stackBasket)
		res, rf := s.prepare.Prepare(context.Background(), s.req(p, "key-fault"))
		if rf == nil || res != nil {
			t.Fatalf("failure at statement %d (commit=%v) was reported as success", at, commit)
		}
		if got := s.allRows(); got != base {
			t.Fatalf("failure at statement %d (commit=%v) left rows: %v, want %v", at, commit, got, base)
		}
		s.prepare.DB = s.rp
		again, rf := s.prepare.Prepare(context.Background(), s.req(p, "key-fault"))
		if rf != nil || again.Replayed {
			t.Fatalf("retry after a failure at statement %d: %+v, %v", at, again, rf)
		}
		if got := s.allRows(); got != full {
			t.Fatalf("retry after statement %d wrote %v, want %v", at, got, full)
		}
	}
}

// The #985 Enqueue and its shared pgx.Tx contract are not part of this slice:
// prepare writes the workflow-start outbox row and never a bridge command, so
// there is no Enqueue call to hold to one transaction (the bridge package is
// imported only for its read client). This pins that fact; if a join file
// starts to name Enqueue, this fails and the shared-tx
// proof becomes owed.
func TestJoinSliceNeverCallsTheBridgeEnqueue(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatal(files, err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f) //nolint:gosec // a package source file
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(src), "Enqueue") {
			t.Errorf("%s mentions Enqueue", f)
		}
	}
}

// replayOnceOrders makes the first order Create report a replay, as it does
// when a concurrent prepare of the same key committed between the lookup and
// the insert.
type replayOnceOrders struct {
	PrepareOrders
	creates int
}

func (r *replayOnceOrders) Create(ctx context.Context, tx pgx.Tx, in orders.CreateInput) (*orders.Order, bool, error) {
	r.creates++
	if r.creates == 1 {
		return &orders.Order{OrderRef: in.OrderRef, Version: 1}, true, nil
	}
	return r.PrepareOrders.Create(ctx, tx, in)
}

// A replayed Create restarts the flow from step 1 and rolls the first attempt
// back: the claim, execution and ids of attempt one are not left behind, and
// the second attempt completes once.
func TestPrepareRestartsWhenCreateReportsAReplay(t *testing.T) {
	s := newStack(t)
	s.activate("k-replay-create")
	ro := &replayOnceOrders{PrepareOrders: s.orders}
	s.prepare.Order = ro
	p := s.preview(stackBasket)
	res, rf := s.prepare.Prepare(context.Background(), s.req(p, "key-rc"))
	if rf != nil || res.Replayed {
		t.Fatalf("prepare = %+v, %v", res, rf)
	}
	if ro.creates != 2 {
		t.Fatalf("Create ran %d times, want 2 (one restart)", ro.creates)
	}
	if w := s.writes(); w != [6]int{1, 1, 1, 1, 1, 0} {
		t.Fatalf("writes = %v after a restart, want exactly one of each", w)
	}
}

// Two different previews under one key race: the loser's Create waits for the
// winner's commit, restarts, and is refused as a reused key. One order exists
// and the loser's preview is not spent.
func TestPrepareSameKeyTwoPreviewsRace(t *testing.T) {
	s := newStack(t)
	s.activate("k-race2")
	pa, pb := s.preview(stackBasket), s.preview(stackBasket)
	var wg sync.WaitGroup
	got := make([]*Refusal, 2)
	for i, p := range []Preview{pa, pb} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, got[i] = s.prepare.Prepare(context.Background(), s.req(p, "same-key"))
		}()
	}
	wg.Wait()
	ok := 0
	for _, rf := range got {
		switch {
		case rf == nil:
			ok++
		case !errors.Is(rf, glovo.Refuse(glovo.CodeIdempotencyReused)) && !errors.Is(rf, glovo.Refuse(glovo.CodeFingerprintChanged)):
			t.Fatalf("loser refused with %v", rf)
		}
	}
	if ok != 1 {
		t.Fatalf("%d of 2 prepares of one key succeeded: %v", ok, got)
	}
	if w := s.writes(); w != [6]int{1, 1, 1, 1, 1, 0} {
		t.Fatalf("writes = %v, want exactly one order", w)
	}
}

// 55P03 (lock_timeout) is tenant_busy however it is wrapped; any other error
// without a Glovo code is unavailable.
func TestToRefusalLockTimeoutIsTenantBusy(t *testing.T) {
	pg := &pgconn.PgError{Code: "55P03"}
	for name, err := range map[string]error{
		"bare":    pg,
		"wrapped": fmt.Errorf("lock owner: %w", pg),
	} {
		rf := toRefusal(err, "lock")
		wantCode(t, rf, glovo.CodeTenantBusy, "lock_timeout")
		_ = name
	}
	wantCode(t, toRefusal(&pgconn.PgError{Code: "40001"}, "x"), glovo.CodeUnavailable, "")
	wantCode(t, toRefusal(errors.New("boom"), "x"), glovo.CodeUnavailable, "")
}
