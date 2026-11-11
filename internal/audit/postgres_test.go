package audit

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The refusal code is persisted in its own column and read back by every read
// path, independent of a submitted "code" parameter; a row with no refusal
// code (including one inserted before the column existed) reads back empty.
// Needs TEST_DATABASE_URL; skipped without it.
func TestPostgresLogger_RefusalCodeRoundTrip(t *testing.T) {
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed audit test")
	}
	ctx := context.Background()
	p, err := NewPostgresLogger(ctx, connStr)
	if err != nil {
		t.Fatal(err)
	}
	refused, plain, legacy := uuid.NewString(), uuid.NewString(), uuid.NewString()
	wf := "refusal-" + refused[:8]
	t.Cleanup(func() {
		_, _ = p.pool.Exec(ctx, `DELETE FROM audit_events WHERE id = ANY($1)`, []string{refused, plain, legacy})
		p.pool.Close()
	})
	p.Log(Entry{ID: refused, UserID: "alice", Operation: "op", Status: "denied", WorkflowName: wf,
		Parameters: map[string]string{"code": "user-value"}, RefusalCode: "validation_failed"})
	p.Log(Entry{ID: plain, UserID: "alice", Operation: "op", Status: "succeeded"})
	// A row written before the column existed has no value for it at all.
	if _, err := p.pool.Exec(ctx, `INSERT INTO audit_events (id, timestamp, user_id, operation, status) VALUES ($1, now(), 'alice', 'op', 'succeeded')`, legacy); err != nil {
		t.Fatal(err)
	}

	e, err := p.LookupByWorkflow(ctx, wf)
	if err != nil || e == nil || e.RefusalCode != "validation_failed" || e.Parameters["code"] != "user-value" {
		t.Fatalf("lookup: %+v %v", e, err)
	}
	byID := map[string]Entry{}
	for _, x := range p.List(1000) {
		byID[x.ID] = x
	}
	if x := byID[refused]; x.RefusalCode != "validation_failed" || x.Parameters["code"] != "user-value" {
		t.Errorf("List: %+v", x)
	}
	for _, id := range []string{plain, legacy} {
		if x, ok := byID[id]; !ok || x.RefusalCode != "" {
			t.Errorf("row %s: %+v (present=%v), want empty refusal code", id, x, ok)
		}
	}
	listed, err := p.ListByStatus("denied", time.Hour, 1000, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, x := range listed {
		if x.ID == refused {
			found = x.RefusalCode == "validation_failed" && x.Parameters["code"] == "user-value"
		}
	}
	if !found {
		t.Errorf("ListByStatus did not return the refusal code intact")
	}
}

// mctl-api#373 phase 1: an audit row records the caller's canonical principal
// id and the relaying surface's next to user_id.
func TestPostgresLogger_RecordsPrincipalIDs(t *testing.T) {
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed audit test")
	}
	ctx := context.Background()
	p, err := NewPostgresLogger(ctx, connStr)
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.NewString()
	t.Cleanup(func() {
		_, _ = p.pool.Exec(ctx, `DELETE FROM audit_events WHERE id=$1`, id)
		p.pool.Close()
	})
	p.Log(Entry{ID: id, UserID: "alice", Operation: "work_item.create", Status: "succeeded",
		PrincipalID: "prn_ALICE", ViaPrincipalID: "prn_TELEGRAM"})
	var principal, via string
	if err := p.pool.QueryRow(ctx, `SELECT user_principal_id, via_principal_id FROM audit_events WHERE id=$1`, id).
		Scan(&principal, &via); err != nil {
		t.Fatal(err)
	}
	if principal != "prn_ALICE" || via != "prn_TELEGRAM" {
		t.Fatalf("recorded %q / %q", principal, via)
	}
}
