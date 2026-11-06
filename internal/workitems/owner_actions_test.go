package workitems

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Owner-action store tests (mctl-api#900, tasks.md task 1 and T10). They run
// against Postgres like the rest of the store tests and only touch rows of
// their own workflow-id prefix, since the api tests share the database.

func newOwnerActionStoreForTest(t *testing.T) (*Store, string) {
	t.Helper()
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed owner-action store test")
	}
	ctx := context.Background()
	s, err := NewStore(ctx, connStr)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	prefix := fmt.Sprintf("oa-test-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = s.pool.Exec(ctx, `DELETE FROM dev_loop_owner_actions WHERE workflow_id LIKE $1`, prefix+"%")
		s.Close()
	})
	return s, prefix
}

func cancelInput(wf, run, by, key, digest string) OwnerActionInput {
	return OwnerActionInput{
		WorkflowID: wf, RunID: run, Action: OwnerActionRequestCancel, RequestedBy: by,
		IdempotencyKey: key, ContentDigest: digest, State: OwnerActionRequested,
	}
}

func deferInput(wf, grant, by, key, digest string) OwnerActionInput {
	return OwnerActionInput{
		WorkflowID: wf, ApprovalRef: grant, Action: OwnerActionDefer, RequestedBy: by,
		IdempotencyKey: key, ContentDigest: digest, State: OwnerActionRecorded, Outcome: "deferred",
	}
}

func mustCreateOwnerAction(t *testing.T, s *Store, in OwnerActionInput) (*OwnerAction, bool) {
	t.Helper()
	o, replayed, err := s.CreateOwnerAction(context.Background(), in)
	if err != nil {
		t.Fatalf("CreateOwnerAction: %v", err)
	}
	return o, replayed
}

func countOwnerActions(t *testing.T, s *Store, wf string) int {
	t.Helper()
	var n int
	if err := s.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM dev_loop_owner_actions WHERE workflow_id=$1`, wf).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// T10: the same key with the same content is a replay of one row; the same
// key with other content is a conflict.
func TestCreateOwnerAction_KeyReplayAndConflict(t *testing.T) {
	s, p := newOwnerActionStoreForTest(t)
	wf := p + "-wf"
	first, replayed := mustCreateOwnerAction(t, s, deferInput(wf, "aar_1", "github:alice", "k1", "sha256:a"))
	if replayed || !strings.HasPrefix(first.ID, OwnerActionIDPrefix) || first.State != OwnerActionRecorded ||
		first.Outcome != "deferred" || first.SchemaVersion != OwnerActionSchemaVersion {
		t.Fatalf("first = %+v replayed=%v", first, replayed)
	}
	again, replayed := mustCreateOwnerAction(t, s, deferInput(wf, "aar_1", "github:alice", "k1", "sha256:a"))
	if !replayed || again.ID != first.ID {
		t.Fatalf("same key, same content: %s replayed=%v, want %s replayed", again.ID, replayed, first.ID)
	}
	if _, _, err := s.CreateOwnerAction(context.Background(), deferInput(wf, "aar_1", "github:alice", "k1", "sha256:b")); !errors.Is(err, ErrOwnerActionIdempotencyConflict) {
		t.Fatalf("same key, other content: err = %v, want ErrOwnerActionIdempotencyConflict", err)
	}
	// The key is per principal: another principal's identical key is its own.
	other, replayed := mustCreateOwnerAction(t, s, cancelInput(wf, "run-1", "github:bob", "k1", "sha256:c"))
	if replayed || other.ID == first.ID {
		t.Fatalf("another principal's key replayed %s", other.ID)
	}
	if n := countOwnerActions(t, s, wf); n != 2 {
		t.Fatalf("rows = %d, want 2", n)
	}
}

// T10: one cancel per (workflow, run) under any key or principal; a cancel
// of another run of the same workflow is a new row.
func TestCreateOwnerAction_OneCancelPerRun(t *testing.T) {
	s, p := newOwnerActionStoreForTest(t)
	wf := p + "-wf"
	first, _ := mustCreateOwnerAction(t, s, cancelInput(wf, "run-1", "github:alice", "k1", "sha256:a"))
	dup, replayed := mustCreateOwnerAction(t, s, cancelInput(wf, "run-1", "github:bob", "k2", "sha256:b"))
	if !replayed || dup.ID != first.ID {
		t.Fatalf("second cancel of run-1: %s replayed=%v, want %s replayed", dup.ID, replayed, first.ID)
	}
	next, replayed := mustCreateOwnerAction(t, s, cancelInput(wf, "run-2", "github:alice", "k3", "sha256:a"))
	if replayed || next.ID == first.ID {
		t.Fatalf("cancel of run-2 replayed %s", next.ID)
	}
	if n := countOwnerActions(t, s, wf); n != 2 {
		t.Fatalf("rows = %d, want 2", n)
	}
}

// T10: one request_changes and one defer per grant; the two kinds do not
// replay each other.
func TestCreateOwnerAction_OneActionPerGrant(t *testing.T) {
	s, p := newOwnerActionStoreForTest(t)
	wf := p + "-wf"
	first, _ := mustCreateOwnerAction(t, s, deferInput(wf, "aar_1", "github:alice", "k1", "sha256:a"))
	dup, replayed := mustCreateOwnerAction(t, s, deferInput(wf, "aar_1", "github:bob", "k2", "sha256:b"))
	if !replayed || dup.ID != first.ID {
		t.Fatalf("second defer of aar_1: %s replayed=%v, want %s replayed", dup.ID, replayed, first.ID)
	}
	changes := deferInput(wf, "aar_1", "github:alice", "k3", "sha256:c")
	changes.Action, changes.Outcome = OwnerActionRequestChanges, "changes_requested"
	rc, replayed := mustCreateOwnerAction(t, s, changes)
	if replayed || rc.ID == first.ID || rc.Action != OwnerActionRequestChanges {
		t.Fatalf("request_changes on a deferred grant = %+v replayed=%v", rc, replayed)
	}
	newer, replayed := mustCreateOwnerAction(t, s, deferInput(wf, "aar_2", "github:alice", "k4", "sha256:d"))
	if replayed || newer.ID == first.ID {
		t.Fatalf("defer of a newer grant replayed %s", newer.ID)
	}
}

// The input is refused before any write when it is not a well-formed
// record: a cancel names its run, the other kinds the grant they observed.
func TestCreateOwnerAction_RefusesIncompleteInput(t *testing.T) {
	s, p := newOwnerActionStoreForTest(t)
	wf := p + "-wf"
	for name, in := range map[string]OwnerActionInput{
		"cancel without run":      cancelInput(wf, "", "github:alice", "k1", "sha256:a"),
		"defer without grant":     deferInput(wf, "", "github:alice", "k2", "sha256:a"),
		"unknown action":          {WorkflowID: wf, Action: "approve", RequestedBy: "a", IdempotencyKey: "k", ContentDigest: "d", State: OwnerActionRecorded},
		"initial state signalled": {WorkflowID: wf, RunID: "r", Action: OwnerActionRequestCancel, RequestedBy: "a", IdempotencyKey: "k", ContentDigest: "d", State: OwnerActionSignalled},
		"no key":                  cancelInput(wf, "run-1", "github:alice", "", "sha256:a"),
	} {
		if _, _, err := s.CreateOwnerAction(context.Background(), in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if n := countOwnerActions(t, s, wf); n != 0 {
		t.Fatalf("rows = %d, want 0", n)
	}
}

// P3 (review of mctl-api#930): the advisory lock is per workflow but the key
// is unique per principal across workflows. A request that passed the key
// lookup while another workflow's insert of the same key was still
// uncommitted must answer the idempotency conflict, not a store failure.
func TestCreateOwnerAction_CrossWorkflowKeyRaceIsAConflict(t *testing.T) {
	s, p := newOwnerActionStoreForTest(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	// The concurrent request on workflow A: inserted, not yet committed.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `INSERT INTO dev_loop_owner_actions (id, workflow_id, run_id, action, requested_by,
		idempotency_key, content_digest, state, created_at, updated_at, schema_version)
		VALUES ('oa_race', $1, 'run-a', 'request_cancel', 'github:alice', 'shared', 'sha256:a', 'requested', now(), now(), $2)`,
		p+"-a", OwnerActionSchemaVersion); err != nil {
		t.Fatal(err)
	}

	// This request on workflow B takes another advisory lock, so it passes
	// its lookups and blocks on the unique key until A commits.
	type result struct {
		err error
	}
	done := make(chan result, 1)
	go func() {
		_, _, err := s.CreateOwnerAction(ctx, cancelInput(p+"-b", "run-b", "github:alice", "shared", "sha256:b"))
		done <- result{err}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
			WHERE wait_event_type = 'Lock' AND query LIKE 'INSERT INTO dev_loop_owner_actions%'`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		select {
		case r := <-done:
			t.Fatalf("the insert on B did not wait for A: err = %v", r.err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the insert on B never blocked on A's uncommitted key")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if !errors.Is(r.err, ErrOwnerActionIdempotencyConflict) {
		t.Fatalf("cross-workflow key race: err = %v, want ErrOwnerActionIdempotencyConflict", r.err)
	}
	if n := countOwnerActions(t, s, p+"-b"); n != 0 {
		t.Fatalf("workflow B rows = %d, want 0", n)
	}
}

// MarkOwnerActionOutcome is a compare-and-set on state: only the first of
// two movers from the same state wins, and a missing row is not "moved".
func TestMarkOwnerActionOutcome_CompareAndSet(t *testing.T) {
	s, p := newOwnerActionStoreForTest(t)
	ctx := context.Background()
	o, _ := mustCreateOwnerAction(t, s, cancelInput(p+"-wf", "run-1", "github:alice", "k1", "sha256:a"))

	marked, err := s.MarkOwnerActionOutcome(ctx, o.ID, OwnerActionRequested, OwnerActionSignalled, "cancellation_pending")
	if err != nil || marked.State != OwnerActionSignalled || marked.Outcome != "cancellation_pending" {
		t.Fatalf("first mark = %+v, %v", marked, err)
	}
	if !marked.UpdatedAt.After(o.UpdatedAt) && !marked.UpdatedAt.Equal(o.UpdatedAt) {
		t.Fatalf("updated_at went back: %v -> %v", o.UpdatedAt, marked.UpdatedAt)
	}
	if _, err := s.MarkOwnerActionOutcome(ctx, o.ID, OwnerActionRequested, OwnerActionFinished, "cancelled"); !errors.Is(err, ErrOwnerActionStateChanged) {
		t.Fatalf("stale mark: err = %v, want ErrOwnerActionStateChanged", err)
	}
	got, err := s.GetOwnerAction(ctx, o.ID)
	if err != nil || got.State != OwnerActionSignalled || got.Outcome != "cancellation_pending" {
		t.Fatalf("after the stale mark = %+v, %v", got, err)
	}
	if _, err := s.MarkOwnerActionOutcome(ctx, "oa_missing", OwnerActionRequested, OwnerActionSignalled, "x"); !errors.Is(err, ErrOwnerActionStateChanged) {
		t.Fatalf("missing row: err = %v, want ErrOwnerActionStateChanged", err)
	}
}

// GetOwnerAction answers ErrOwnerActionNotFound for an unknown id; the
// listing is per workflow, newest first, and bounded.
func TestGetAndListOwnerActions(t *testing.T) {
	s, p := newOwnerActionStoreForTest(t)
	ctx := context.Background()
	if _, err := s.GetOwnerAction(ctx, "oa_missing"); !errors.Is(err, ErrOwnerActionNotFound) {
		t.Fatalf("unknown id: err = %v", err)
	}
	wf := p + "-wf"
	base := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	var ids []string
	for i := 0; i < 3; i++ {
		at := base.Add(time.Duration(i) * time.Minute)
		s.now = func() time.Time { return at }
		o, _ := mustCreateOwnerAction(t, s, cancelInput(wf, fmt.Sprintf("run-%d", i), "github:alice", fmt.Sprintf("k%d", i), "sha256:a"))
		ids = append(ids, o.ID)
	}
	mustCreateOwnerAction(t, s, cancelInput(p+"-other", "run-x", "github:alice", "kx", "sha256:a"))

	got, err := s.GetOwnerAction(ctx, ids[1])
	if err != nil || got.ID != ids[1] || got.WorkflowID != wf || got.RunID != "run-1" || got.IdempotencyKey != "k1" {
		t.Fatalf("get = %+v, %v", got, err)
	}
	list, err := s.ListOwnerActions(ctx, wf, 0)
	if err != nil || len(list) != 3 {
		t.Fatalf("list = %d rows, %v; want 3", len(list), err)
	}
	if list[0].ID != ids[2] || list[2].ID != ids[0] {
		t.Fatalf("list order = %s,%s,%s; want newest first", list[0].ID, list[1].ID, list[2].ID)
	}
	limited, err := s.ListOwnerActions(ctx, wf, 2)
	if err != nil || len(limited) != 2 || limited[0].ID != ids[2] {
		t.Fatalf("limited list = %+v, %v", limited, err)
	}
	empty, err := s.ListOwnerActions(ctx, p+"-none", 0)
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("empty list = %#v, %v; want a non-nil empty slice", empty, err)
	}
}

// Task 1 DoD: the table holds ids, digests, codes and states only.
func TestOwnerActionSchema_HasNoFreeTextColumn(t *testing.T) {
	s, _ := newOwnerActionStoreForTest(t)
	rows, err := s.pool.Query(context.Background(),
		`SELECT column_name FROM information_schema.columns WHERE table_name = 'dev_loop_owner_actions' ORDER BY ordinal_position`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	allowed := map[string]bool{
		"id": true, "workflow_id": true, "run_id": true, "execution_id": true, "approval_ref": true, "action": true,
		"reason_code": true, "requested_by": true, "principal_id": true, "idempotency_key": true, "content_digest": true,
		"state": true, "outcome": true, "created_at": true, "updated_at": true, "schema_version": true,
	}
	n := 0
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			t.Fatal(err)
		}
		n++
		if !allowed[col] {
			t.Errorf("unexpected column %q: the owner-action row carries no free text", col)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if n != len(allowed) {
		t.Fatalf("columns = %d, want %d", n, len(allowed))
	}
}
