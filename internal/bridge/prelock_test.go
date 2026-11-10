package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type hookFence struct {
	pre      func(tx pgx.Tx) error
	preSeen  chan struct{}
	checkTx  pgx.Tx
	preTx    pgx.Tx
	checkRan bool
}

func (h *hookFence) PreLock(_ context.Context, tx pgx.Tx, _ Caller, _ string) error {
	h.preTx = tx
	if h.preSeen != nil {
		close(h.preSeen)
	}
	if h.pre != nil {
		return h.pre(tx)
	}
	return nil
}

func (h *hookFence) Check(_ context.Context, tx pgx.Tx, _ FenceBinding) (string, error) {
	h.checkRan = true
	h.checkTx = tx
	return "fence_hook", nil
}

// mctl-api#989 task 7: PreLock runs in the permit transaction before the
// command row lock, and Check runs in the same transaction.
func TestPGPreLockRunsBeforeTheCommandLock(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()
	tenant := fmt.Sprintf("t-%d", time.Now().UnixNano())
	c := Caller{ProviderRef: "glovo", Actor: "a", Tenants: []string{tenant}}
	id := enqueue(t, s, tenant, KindPlaceOrderFake)
	cmd := claimOne(t, s, c, id)
	var d map[string]any
	_ = json.Unmarshal(cmd, &d)
	tok := d["lease_token"].(string)

	h := &hookFence{preSeen: make(chan struct{})}
	s.SetFence(h)
	holder, err := s.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(ctx) }()
	if _, err := holder.Exec(ctx, `SELECT 1 FROM bridge_commands WHERE command_id=$1 FOR UPDATE`, id); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := s.IssueWritePermit(ctx, c, id, tok); done <- err }()
	select {
	case <-h.preSeen:
	case <-time.After(10 * time.Second):
		t.Fatal("PreLock was not reached while the command row was locked by another transaction")
	}
	select {
	case err := <-done:
		t.Fatalf("permit finished while the row was held: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if err := holder.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("permit: %v", err)
	}
	if !h.checkRan || h.checkTx != h.preTx {
		t.Fatal("Check must run in the transaction PreLock ran in")
	}
}

func TestPGPreLockErrorMapping(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()
	tenant := fmt.Sprintf("t-%d", time.Now().UnixNano())
	c := Caller{ProviderRef: "glovo", Actor: "a", Tenants: []string{tenant}}
	id := enqueue(t, s, tenant, KindPlaceOrderFake)
	cmd := claimOne(t, s, c, id)
	var d map[string]any
	_ = json.Unmarshal(cmd, &d)
	tok := d["lease_token"].(string)
	for name, tc := range map[string]struct {
		err  error
		want func(error) bool
	}{
		"not found passes through": {ErrCommandNotFound, func(e error) bool { return errors.Is(e, ErrCommandNotFound) }},
		"refusal passes through":   {ErrWriteFenceRefused, func(e error) bool { return Code(e) == "write_fence_refused" }},
		"unavailable passes":       {ErrWriteFenceUnavailable, func(e error) bool { return Code(e) == "write_fence_unavailable" }},
		"other error is a refusal": {errors.New("boom"), func(e error) bool { return errors.Is(e, ErrWriteFenceRefused) }},
	} {
		t.Run(name, func(t *testing.T) {
			s.SetFence(&hookFence{pre: func(pgx.Tx) error { return tc.err }})
			_, err := s.IssueWritePermit(ctx, c, id, tok)
			if err == nil || !tc.want(err) {
				t.Fatalf("err = %v", err)
			}
			var n int
			_ = s.pool.QueryRow(ctx, `SELECT count(*) FROM bridge_write_permits WHERE command_id=$1`, id).Scan(&n)
			if n != 0 {
				t.Fatal("permit row written when PreLock refused")
			}
		})
	}
}
