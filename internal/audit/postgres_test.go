package audit

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
)

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
