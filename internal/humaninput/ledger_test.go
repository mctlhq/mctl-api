package humaninput

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

func newPostgresLedgerForTest(t *testing.T) *PostgresLedger {
	t.Helper()
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed human-input ledger test")
	}
	ctx := context.Background()
	l, err := NewPostgresLedger(ctx, connStr)
	if err != nil {
		t.Fatalf("NewPostgresLedger: %v", err)
	}
	if _, err := l.pool.Exec(ctx, "DELETE FROM human_input_deliveries"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = l.pool.Exec(ctx, "DELETE FROM human_input_deliveries")
		l.Close()
	})
	return l
}

func ledgers(t *testing.T) map[string]func(t *testing.T) Ledger {
	return map[string]func(t *testing.T) Ledger{
		"memory":   func(t *testing.T) Ledger { return NewMemoryLedger() },
		"postgres": func(t *testing.T) Ledger { return newPostgresLedgerForTest(t) },
	}
}

func delivery(respondent, value string) Delivery {
	return Delivery{
		RequestID: "hir-0123456789abcdef", RequestHash: "sha256:aa", WorkflowID: "wf", RunID: "run-1",
		Respondent: respondent, Surface: "api", ValueHash: "sha256:" + value, Value: []byte(`"` + value + `"`),
		ReceivedAt: time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC), BaselineResumeCount: 2,
		ExpiresAt: time.Date(2026, 9, 24, 2, 0, 0, 0, time.UTC),
	}
}

func TestLedger_FirstClaimWinsAndTerminalStatesHold(t *testing.T) {
	for name, mk := range ledgers(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			l := mk(t)
			if d, _ := l.Get(ctx, "hir-0123456789abcdef"); d != nil {
				t.Fatal("empty ledger returned a row")
			}
			alice, bob := delivery("github:alice", "A"), delivery("github:bob", "B")

			cur, won, err := l.Claim(ctx, alice)
			if err != nil || !won || cur.State != DeliveryPending || string(cur.Value) != `"A"` || cur.BaselineResumeCount != 2 {
				t.Fatalf("first claim: %+v won=%v err=%v", cur, won, err)
			}
			cur, won, err = l.Claim(ctx, bob)
			if err != nil || won || cur.Respondent != "github:alice" {
				t.Fatalf("competing claim over a pending row: %+v won=%v err=%v", cur, won, err)
			}
			if err := l.NoteAttempt(ctx, alice.RequestID); err != nil {
				t.Fatal(err)
			}
			if err := l.Resolve(ctx, bob, DeliveryAccepted); !errors.Is(err, ErrDeliveryNotPending) {
				t.Fatalf("resolve by a different submission: %v", err)
			}
			if err := l.Resolve(ctx, alice, DeliveryAccepted); err != nil {
				t.Fatal(err)
			}
			got, _ := l.Get(ctx, alice.RequestID)
			if got.State != DeliveryAccepted || got.Value != nil || got.Attempts != 1 {
				t.Fatalf("accepted row: %+v (value must be cleared)", got)
			}
			if _, won, _ := l.Claim(ctx, bob); won {
				t.Fatal("an accepted row was replaced")
			}
			if err := l.Resolve(ctx, alice, DeliveryRejected); !errors.Is(err, ErrDeliveryNotPending) {
				t.Fatalf("a terminal row was resolved again: %v", err)
			}
		})
	}
}

func TestLedger_RejectedRowFreesTheSlot(t *testing.T) {
	for name, mk := range ledgers(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			l := mk(t)
			alice, bob := delivery("github:alice", "A"), delivery("github:bob", "B")
			if _, won, _ := l.Claim(ctx, alice); !won {
				t.Fatal("claim")
			}
			if err := l.Resolve(ctx, alice, DeliveryRejected); err != nil {
				t.Fatal(err)
			}
			cur, won, err := l.Claim(ctx, bob)
			if err != nil || !won || cur.Respondent != "github:bob" || cur.State != DeliveryPending || cur.Attempts != 0 {
				t.Fatalf("claim over a rejected row: %+v won=%v err=%v", cur, won, err)
			}
		})
	}
}

func TestLedger_ConcurrentClaimsHaveOneWinner(t *testing.T) {
	for name, mk := range ledgers(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			l := mk(t)
			var wg sync.WaitGroup
			var mu sync.Mutex
			wins := 0
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					d := delivery("github:alice", fmt.Sprintf("v%d", i))
					if _, won, err := l.Claim(ctx, d); err == nil && won {
						mu.Lock()
						wins++
						mu.Unlock()
					}
				}(i)
			}
			wg.Wait()
			if wins != 1 {
				t.Fatalf("%d concurrent claims won, want exactly 1", wins)
			}
		})
	}
}

func TestLedger_ClearExpiredValuesDropsOnlyUndeliverableAnswers(t *testing.T) {
	for name, mk := range ledgers(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			l := mk(t)
			d := delivery("github:alice", "A")
			if _, won, _ := l.Claim(ctx, d); !won {
				t.Fatal("claim")
			}
			if n, err := l.ClearExpiredValues(ctx, d.ExpiresAt.Add(-time.Second)); err != nil || n != 0 {
				t.Fatalf("before expiry: cleared %d, %v", n, err)
			}
			if got, _ := l.Get(ctx, d.RequestID); string(got.Value) != `"A"` {
				t.Fatalf("value dropped before expiry: %+v", got)
			}
			if n, err := l.ClearExpiredValues(ctx, d.ExpiresAt); err != nil || n != 1 {
				t.Fatalf("at expiry: cleared %d, %v", n, err)
			}
			got, _ := l.Get(ctx, d.RequestID)
			if got.Value != nil || got.State != DeliveryPending || !got.ExpiresAt.Equal(d.ExpiresAt) {
				t.Fatalf("after expiry: %+v (value cleared, state kept)", got)
			}
		})
	}
}

// mctl-api#373 phase 1: the respondent's canonical principal id and the
// relaying surface's are recorded, including when a new answer takes over a
// rejected row.
func TestPostgresLedger_RecordsPrincipalIDs(t *testing.T) {
	l := newPostgresLedgerForTest(t)
	ctx := context.Background()
	principals := func() string {
		t.Helper()
		var p, v string
		if err := l.pool.QueryRow(ctx, `SELECT respondent_principal_id, via_principal_id FROM human_input_deliveries
			WHERE request_id='hir-0123456789abcdef'`).Scan(&p, &v); err != nil {
			t.Fatal(err)
		}
		return p + "/" + v
	}
	d := delivery("user:alice", "yes")
	d.RespondentPrincipalID, d.ViaPrincipalID = "prn_ALICE", "prn_TELEGRAM"
	if _, ok, err := l.Claim(ctx, d); err != nil || !ok {
		t.Fatalf("claim = %v %v", ok, err)
	}
	if got := principals(); got != "prn_ALICE/prn_TELEGRAM" {
		t.Fatalf("recorded %s", got)
	}
	if err := l.Resolve(ctx, d, DeliveryRejected); err != nil {
		t.Fatal(err)
	}
	next := delivery("user:bob", "no")
	next.RespondentPrincipalID = "prn_BOB"
	if _, ok, err := l.Claim(ctx, next); err != nil || !ok {
		t.Fatalf("takeover = %v %v", ok, err)
	}
	if got := principals(); got != "prn_BOB/" {
		t.Fatalf("after takeover recorded %s", got)
	}
}
