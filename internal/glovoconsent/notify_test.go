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
	"strings"
	"testing"
	"time"
)

const (
	notifyPRN   = "prn_01HZZZZZZZZZZZZZZZZZZZZZN1"
	notifyPRN2  = "prn_01HZZZZZZZZZZZZZZZZZZZZZN2"
	notifyOwner = "prn_01HZZZZZZZZZZZZZZZZZZZZZNW"
)

// newNotifyStore is newAccessStore with the outbox and token tables wiped
// and both switches, the owner card and the emails, set as asked.
func newNotifyStore(t *testing.T, on bool) (*PostgresStore, *time.Time) {
	t.Helper()
	s, clock := newAccessStore(t, false)
	wipe := func() {
		for _, q := range []string{"DELETE FROM glovo_access_notifications", "DELETE FROM glovo_access_decide_tokens"} {
			if _, err := s.pool.Exec(context.Background(), q); err != nil {
				t.Fatal(err)
			}
		}
	}
	wipe()
	t.Cleanup(wipe)
	s.SetAccessNotify(on)
	s.SetAccessEmail(on)
	return s, clock
}

func notifyKinds(t *testing.T, s *PostgresStore, pid string) string {
	t.Helper()
	rows, err := s.pool.Query(context.Background(), `SELECT kind FROM glovo_access_notifications WHERE principal_id = $1 ORDER BY notification_id`, pid)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			t.Fatal(err)
		}
		out = append(out, k)
	}
	if rows.Err() != nil {
		t.Fatal(rows.Err())
	}
	return strings.Join(out, ",")
}

func tableCount(t *testing.T, s *PostgresStore, table string) int {
	t.Helper()
	var n int
	if err := s.pool.QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func mustRequest(t *testing.T, s *PostgresStore, pid string) Access {
	t.Helper()
	a, _, err := s.RequestAccess(context.Background(), pid)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func mustMint(t *testing.T, s *PostgresStore, a Access) string {
	t.Helper()
	raw, err := s.MintDecideToken(context.Background(), a.PrincipalID, a.RequestedAt)
	if err != nil || HashDecideToken(raw) == "" {
		t.Fatalf("mint = %q %v", raw, err)
	}
	return raw
}

func mustLive(t *testing.T, s *PostgresStore, pid, raw string, want bool) {
	t.Helper()
	got, err := s.CheckDecideToken(context.Background(), pid, HashDecideToken(raw))
	if err != nil || got != want {
		t.Fatalf("token live = %v %v, want %v", got, err, want)
	}
}

// Off, which is the default, the store behaves as before stage C: no outbox
// row from any transition and none from the lapse sweep.
func TestPGNotifyOffWritesNothing(t *testing.T) {
	s, clock := newNotifyStore(t, false)
	ctx := context.Background()
	if s.AccessNotify() || s.AccessEmail() {
		t.Fatal("a notification switch is on by default")
	}
	mustRequest(t, s, notifyPRN)
	if _, err := s.ApproveAccess(ctx, notifyPRN, notifyOwner, "ok", 0); err != nil {
		t.Fatal(err)
	}
	mustRequest(t, s, notifyPRN2)
	if _, err := s.RejectAccess(ctx, notifyPRN2, notifyOwner, "no"); err != nil {
		t.Fatal(err)
	}
	mustRequest(t, s, notifyPRN2)
	*clock = clock.Add(AccessRequestTTL + time.Hour)
	if n, err := s.EnqueueLapsed(ctx); err != nil || n != 0 {
		t.Fatalf("lapsed sweep = %d %v", n, err)
	}
	if n := tableCount(t, s, "glovo_access_notifications"); n != 0 {
		t.Fatalf("%d outbox rows with the switch off", n)
	}
}

// The owner card and the emails have a switch each. With only the card on,
// no email row is ever queued, by a decision or by the lapse sweep; with
// only the emails on, no card is.
func TestPGNotifyCardAndEmailSwitchSeparately(t *testing.T) {
	s, clock := newNotifyStore(t, false)
	ctx := context.Background()
	run := func() {
		t.Helper()
		mustRequest(t, s, notifyPRN)
		if _, err := s.ApproveAccess(ctx, notifyPRN, notifyOwner, "ok", 0); err != nil {
			t.Fatal(err)
		}
		mustRequest(t, s, notifyPRN2)
		if _, err := s.RejectAccess(ctx, notifyPRN2, notifyOwner, "no"); err != nil {
			t.Fatal(err)
		}
	}
	s.SetAccessNotify(true)
	run()
	if got := notifyKinds(t, s, notifyPRN) + "|" + notifyKinds(t, s, notifyPRN2); got != "owner_card|owner_card" {
		t.Fatalf("card only: rows %q", got)
	}
	mustRequest(t, s, notifyPRN2)
	start := *clock
	*clock = start.Add(AccessRequestTTL + time.Hour)
	if n, err := s.EnqueueLapsed(ctx); err != nil || n != 0 {
		t.Fatalf("card only: lapsed sweep = %d %v", n, err)
	}
	s.SetAccessEmail(true)
	if n, err := s.EnqueueLapsed(ctx); err != nil || n != 1 {
		t.Fatalf("emails on: lapsed sweep = %d %v", n, err)
	}

	*clock = start
	for _, q := range []string{"DELETE FROM glovo_access_notifications", "DELETE FROM glovo_access_requests WHERE principal_id IN ($1, $2)"} {
		args := []any{}
		if strings.Contains(q, "$1") {
			args = []any{notifyPRN, notifyPRN2}
		}
		if _, err := s.pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	s.SetAccessNotify(false)
	run()
	if got := notifyKinds(t, s, notifyPRN) + "|" + notifyKinds(t, s, notifyPRN2); got != "approved|rejected" {
		t.Fatalf("emails only: rows %q", got)
	}
}

// Each trigger appends exactly one row of its kind; a withdrawal and a
// revocation append none.
func TestPGNotifyOneRowPerTrigger(t *testing.T) {
	s, _ := newNotifyStore(t, true)
	ctx := context.Background()

	mustRequest(t, s, notifyPRN)
	mustRequest(t, s, notifyPRN) // idempotent while pending
	if got := notifyKinds(t, s, notifyPRN); got != "owner_card" {
		t.Fatalf("after request: %q", got)
	}
	if _, err := s.ApproveAccess(ctx, notifyPRN, notifyOwner, "ok", 0); err != nil {
		t.Fatal(err)
	}
	if got := notifyKinds(t, s, notifyPRN); got != "owner_card,approved" {
		t.Fatalf("after approve: %q", got)
	}
	if _, err := s.RevokeAccess(ctx, notifyPRN, notifyOwner, "left"); err != nil {
		t.Fatal(err)
	}
	if got := notifyKinds(t, s, notifyPRN); got != "owner_card,approved" {
		t.Fatalf("revoke queued something: %q", got)
	}

	mustRequest(t, s, notifyPRN2)
	if _, err := s.RejectAccess(ctx, notifyPRN2, notifyOwner, "no"); err != nil {
		t.Fatal(err)
	}
	if got := notifyKinds(t, s, notifyPRN2); got != "owner_card,rejected" {
		t.Fatalf("after reject: %q", got)
	}
}

func TestPGNotifyWithdrawalQueuesNoEmail(t *testing.T) {
	s, _ := newNotifyStore(t, true)
	mustRequest(t, s, notifyPRN)
	// A withdrawal is a rejection decided by the requester.
	if _, err := s.RejectAccess(context.Background(), notifyPRN, notifyPRN, "withdrawn"); err != nil {
		t.Fatal(err)
	}
	if got := notifyKinds(t, s, notifyPRN); got != "owner_card" {
		t.Fatalf("withdrawal queued: %q", got)
	}
}

// A refused decision queues nothing: the row is written with the decision or
// not at all.
func TestPGNotifyRefusedDecisionQueuesNothing(t *testing.T) {
	s, _ := newNotifyStore(t, true)
	ctx := context.Background()
	if _, err := s.ApproveAccess(ctx, notifyPRN, notifyOwner, "ok", 0); !errors.Is(err, ErrAccessNotPending) {
		t.Fatalf("approve of nothing = %v", err)
	}
	mustRequest(t, s, notifyPRN)
	if _, err := s.ApproveAccess(ctx, notifyPRN, notifyOwner, "", 0); err == nil {
		t.Fatal("approve without a reason accepted")
	}
	if got := notifyKinds(t, s, notifyPRN); got != "owner_card" {
		t.Fatalf("refused decisions queued: %q", got)
	}
}

func TestPGNotifyLapsedOnceWithinTheWindow(t *testing.T) {
	s, clock := newNotifyStore(t, true)
	ctx := context.Background()
	a := mustRequest(t, s, notifyPRN)
	if n, err := s.EnqueueLapsed(ctx); err != nil || n != 0 {
		t.Fatalf("live request lapsed: %d %v", n, err)
	}
	*clock = a.ExpiresAt // the boundary itself is still pending
	if n, err := s.EnqueueLapsed(ctx); err != nil || n != 0 {
		t.Fatalf("lapsed at the boundary: %d %v", n, err)
	}
	*clock = a.ExpiresAt.Add(time.Second)
	if n, err := s.EnqueueLapsed(ctx); err != nil || n != 1 {
		t.Fatalf("first sweep = %d %v", n, err)
	}
	if n, err := s.EnqueueLapsed(ctx); err != nil || n != 0 {
		t.Fatalf("second sweep = %d %v", n, err)
	}
	if got := notifyKinds(t, s, notifyPRN); got != "owner_card,lapsed" {
		t.Fatalf("rows: %q", got)
	}
	// A request that lapsed longer ago than the window is not mailed late.
	b := mustRequest(t, s, notifyPRN2)
	*clock = b.ExpiresAt.Add(NotifyWindow + time.Second)
	if n, err := s.EnqueueLapsed(ctx); err != nil || n != 0 {
		t.Fatalf("stale lapse queued: %d %v", n, err)
	}
}

func TestPGDecideTokenSingleUse(t *testing.T) {
	s, _ := newNotifyStore(t, true)
	ctx := context.Background()
	a := mustRequest(t, s, notifyPRN)
	raw := mustMint(t, s, a)
	// Only the hash is stored.
	var stored string
	if err := s.pool.QueryRow(ctx, `SELECT token_hash FROM glovo_access_decide_tokens`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != HashDecideToken(raw) || stored == raw {
		t.Fatalf("stored %q", stored)
	}
	mustLive(t, s, notifyPRN, raw, true)
	mustLive(t, s, notifyPRN, raw, true) // a check spends nothing
	if _, err := s.ApproveAccessByLink(ctx, notifyPRN, notifyOwner, "ok", 0, HashDecideToken(raw)); err != nil {
		t.Fatal(err)
	}
	mustState(t, s, notifyPRN, AccessApproved)
	mustLive(t, s, notifyPRN, raw, false)

	// Replay: nothing is decided, even where the state would allow it.
	if _, err := s.RevokeAccess(ctx, notifyPRN, notifyOwner, "undo"); err != nil {
		t.Fatal(err)
	}
	b := mustRequest(t, s, notifyPRN)
	if !b.RequestedAt.Equal(a.RequestedAt) {
		t.Skip("clock moved") // the fake clock is fixed; same instant is the hard case
	}
	for _, try := range []func() error{
		func() error {
			_, err := s.ApproveAccessByLink(ctx, notifyPRN, notifyOwner, "again", 0, HashDecideToken(raw))
			return err
		},
		func() error {
			_, err := s.RejectAccessByLink(ctx, notifyPRN, notifyOwner, "again", HashDecideToken(raw))
			return err
		},
	} {
		if err := try(); !errors.Is(err, ErrDecideTokenInvalid) {
			t.Fatalf("replay = %v", err)
		}
	}
	mustState(t, s, notifyPRN, AccessPending)
	if n := eventCount(t, s, notifyPRN, "approved"); n != 1 {
		t.Fatalf("%d approved events", n)
	}
}

// The decide link names its request by the token alone: the token resolves
// to its principal exactly while CheckDecideToken would call it live.
func TestPGDecideTokenPrincipal(t *testing.T) {
	s, clock := newNotifyStore(t, true)
	ctx := context.Background()
	resolve := func(raw, want string) {
		t.Helper()
		pid, found, err := s.DecideTokenPrincipal(ctx, HashDecideToken(raw))
		if err != nil || found != (want != "") || pid != want {
			t.Fatalf("resolve = %q %v %v, want %q", pid, found, err, want)
		}
	}
	a := mustRequest(t, s, notifyPRN)
	b := mustRequest(t, s, notifyPRN2)
	rawA, rawB := mustMint(t, s, a), mustMint(t, s, b)
	resolve(rawA, notifyPRN)
	resolve(rawB, notifyPRN2)
	resolve("short", "")
	resolve(strings.Repeat("z", 43), "")
	if _, _, err := s.DecideTokenPrincipal(ctx, "not-a-hash"); err != nil {
		t.Fatalf("malformed hash = %v", err)
	}
	// Decided: the token names nothing, the other request's still does.
	if _, err := s.RejectAccessByLink(ctx, notifyPRN, notifyOwner, "no", HashDecideToken(rawA)); err != nil {
		t.Fatal(err)
	}
	resolve(rawA, "")
	resolve(rawB, notifyPRN2)
	// The request itself must be pending, whatever the token row says: an
	// unused token of a decided request names nothing.
	if _, err := s.pool.Exec(ctx, `UPDATE glovo_access_decide_tokens SET used_at = NULL WHERE principal_id = $1`, notifyPRN); err != nil {
		t.Fatal(err)
	}
	resolve(rawA, "")
	if _, err := s.pool.Exec(ctx, `UPDATE glovo_access_decide_tokens SET used_at = $2 WHERE principal_id = $1`, notifyPRN, *clock); err != nil {
		t.Fatal(err)
	}
	// So does a token of a request whose own expiry passed.
	if _, err := s.pool.Exec(ctx, `UPDATE glovo_access_requests SET expires_at = $2 WHERE principal_id = $1`, notifyPRN2, b.RequestedAt); err != nil {
		t.Fatal(err)
	}
	*clock = b.RequestedAt.Add(time.Second)
	resolve(rawB, "")
	*clock = b.RequestedAt
	if _, err := s.pool.Exec(ctx, `UPDATE glovo_access_requests SET expires_at = $2 WHERE principal_id = $1`, notifyPRN2, b.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	resolve(rawB, notifyPRN2)
	// A used token on a request that is pending again names nothing.
	c := mustRequest(t, s, notifyPRN)
	if c.RequestedAt.Equal(a.RequestedAt) {
		resolve(rawA, "")
	}
	// Past the expiry it names nothing; so does a token past its own expiry
	// on a request that is still live.
	*clock = b.ExpiresAt.Add(time.Second)
	resolve(rawB, "")
	*clock = b.RequestedAt
	resolve(rawB, notifyPRN2)
	if _, err := s.pool.Exec(ctx, `UPDATE glovo_access_decide_tokens SET expires_at = $1 WHERE principal_id = $2`,
		b.RequestedAt.Add(-time.Second), notifyPRN2); err != nil {
		t.Fatal(err)
	}
	resolve(rawB, "")
	// A token left unretired from an earlier request of the same principal
	// names nothing: it is bound to requested_at, not only to the principal.
	if _, err := s.pool.Exec(ctx, `UPDATE glovo_access_decide_tokens SET expires_at = $1, used_at = NULL, requested_at = $2 WHERE principal_id = $3`,
		b.ExpiresAt, b.RequestedAt.Add(-time.Hour), notifyPRN2); err != nil {
		t.Fatal(err)
	}
	resolve(rawB, "")
	// A failed read is an error, never "names nothing".
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, found, err := s.DecideTokenPrincipal(cctx, HashDecideToken(rawB)); err == nil || found {
		t.Fatalf("failed read = %v %v", found, err)
	}
}

func TestPGDecideTokenExpiry(t *testing.T) {
	s, clock := newNotifyStore(t, true)
	ctx := context.Background()
	a := mustRequest(t, s, notifyPRN)
	raw := mustMint(t, s, a)
	*clock = a.ExpiresAt.Add(time.Second)
	mustLive(t, s, notifyPRN, raw, false)
	if _, err := s.ApproveAccessByLink(ctx, notifyPRN, notifyOwner, "late", 0, HashDecideToken(raw)); !errors.Is(err, ErrDecideTokenInvalid) {
		t.Fatalf("expired token = %v", err)
	}
	// A token whose own expiry passed is refused even if the request row
	// were still pending: move only the token's expiry.
	*clock = a.RequestedAt
	if _, err := s.pool.Exec(ctx, `UPDATE glovo_access_decide_tokens SET expires_at = $1`, a.RequestedAt.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	mustLive(t, s, notifyPRN, raw, false)
	if _, err := s.RejectAccessByLink(ctx, notifyPRN, notifyOwner, "late", HashDecideToken(raw)); !errors.Is(err, ErrDecideTokenInvalid) {
		t.Fatalf("expired token on a live request = %v", err)
	}
	mustState(t, s, notifyPRN, AccessPending)
	// No token for a request that is not live.
	*clock = a.ExpiresAt.Add(time.Second)
	if _, err := s.MintDecideToken(ctx, notifyPRN, a.RequestedAt); !errors.Is(err, ErrAccessNotPending) {
		t.Fatalf("mint for a lapsed request = %v", err)
	}
}

func TestPGDecideTokenWrongRequest(t *testing.T) {
	s, clock := newNotifyStore(t, true)
	ctx := context.Background()
	a := mustRequest(t, s, notifyPRN)
	raw := mustMint(t, s, a)
	other := mustRequest(t, s, notifyPRN2)
	otherRaw := mustMint(t, s, other)

	// Another principal's token decides nothing here.
	mustLive(t, s, notifyPRN, otherRaw, false)
	if _, err := s.ApproveAccessByLink(ctx, notifyPRN, notifyOwner, "x", 0, HashDecideToken(otherRaw)); !errors.Is(err, ErrDecideTokenInvalid) {
		t.Fatalf("foreign token = %v", err)
	}
	mustState(t, s, notifyPRN, AccessPending)
	mustLive(t, s, notifyPRN2, otherRaw, true) // and it was not spent

	// The request is withdrawn and asked again: the old link is dead.
	if _, err := s.RejectAccess(ctx, notifyPRN, notifyPRN, "withdrawn"); err != nil {
		t.Fatal(err)
	}
	mustLive(t, s, notifyPRN, raw, false)
	*clock = clock.Add(time.Hour)
	b := mustRequest(t, s, notifyPRN)
	if b.RequestedAt.Equal(a.RequestedAt) {
		t.Fatal("the second request has the first one's time")
	}
	mustLive(t, s, notifyPRN, raw, false)
	if _, err := s.ApproveAccessByLink(ctx, notifyPRN, notifyOwner, "x", 0, HashDecideToken(raw)); !errors.Is(err, ErrDecideTokenInvalid) {
		t.Fatalf("earlier request's token = %v", err)
	}
	mustState(t, s, notifyPRN, AccessPending)
	// Retiring is not the only thing between an earlier request's token and
	// a decision: a token row that was never retired is still bound to its
	// own request.
	stale := strings.Repeat("s", 43)
	if _, err := s.pool.Exec(ctx, `INSERT INTO glovo_access_decide_tokens (token_hash, principal_id, requested_at, created_at, expires_at)
		VALUES ($1, $2, $3, $3, $4)`, HashDecideToken(stale), notifyPRN, a.RequestedAt, b.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	mustLive(t, s, notifyPRN, stale, false)
	if _, err := s.RejectAccessByLink(ctx, notifyPRN, notifyOwner, "x", HashDecideToken(stale)); !errors.Is(err, ErrDecideTokenInvalid) {
		t.Fatalf("unretired token of an earlier request = %v", err)
	}
	mustState(t, s, notifyPRN, AccessPending)
	// Minting for the earlier request is refused too.
	if _, err := s.MintDecideToken(ctx, notifyPRN, a.RequestedAt); !errors.Is(err, ErrAccessNotPending) {
		t.Fatalf("mint for an earlier request = %v", err)
	}

	// Malformed and unknown tokens.
	for _, h := range []string{"", "zz", strings.Repeat("0", 64), strings.Repeat("G", 64)} {
		if _, err := s.RejectAccessByLink(ctx, notifyPRN, notifyOwner, "x", h); !errors.Is(err, ErrDecideTokenInvalid) {
			t.Fatalf("token %q = %v", h, err)
		}
	}
	if HashDecideToken("short") != "" || HashDecideToken(strings.Repeat("a", 44)) != "" || HashDecideToken(strings.Repeat("a", 42)+"=") != "" {
		t.Fatal("a malformed token hashed")
	}
	mustState(t, s, notifyPRN, AccessPending)
}

// A decision made without the link retires the link, and a refused decision
// leaves the token for the next try.
func TestPGDecideTokenRetiredAndKept(t *testing.T) {
	s, _ := newNotifyStore(t, true)
	ctx := context.Background()
	s.accessRequired = true
	a := mustRequest(t, s, notifyPRN)
	raw := mustMint(t, s, a)
	// Capacity 0 with access required refuses the approval.
	if _, err := s.ApproveAccessByLink(ctx, notifyPRN, notifyOwner, "ok", 0, HashDecideToken(raw)); err == nil || errors.Is(err, ErrDecideTokenInvalid) {
		t.Fatalf("approve at zero capacity = %v", err)
	}
	mustLive(t, s, notifyPRN, raw, true)
	mustState(t, s, notifyPRN, AccessPending)
	second := mustMint(t, s, a)
	if _, err := s.ApproveAccess(ctx, notifyPRN, notifyOwner, "ok", 5); err != nil {
		t.Fatal(err)
	}
	mustLive(t, s, notifyPRN, raw, false)
	mustLive(t, s, notifyPRN, second, false)
}

func TestPGNotifyLeaseAckAbandon(t *testing.T) {
	s, clock := newNotifyStore(t, true)
	ctx := context.Background()
	a := mustRequest(t, s, notifyPRN)

	if _, _, err := s.LeaseNotification(ctx, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty lease = %v", err)
	}
	n, found, err := s.LeaseNotification(ctx, "lease-1")
	if err != nil || !found || n.Kind != NotifyOwnerCard || n.PrincipalID != notifyPRN || n.Attempts != 1 ||
		!n.RequestedAt.Equal(a.RequestedAt) || !n.ExpiresAt.Equal(a.ExpiresAt) {
		t.Fatalf("lease = %+v %v %v", n, found, err)
	}
	// Held: a second worker gets nothing.
	if _, found, err := s.LeaseNotification(ctx, "lease-2"); err != nil || found {
		t.Fatalf("second lease = %v %v", found, err)
	}
	// Another lease cannot finish it.
	if err := s.AckNotification(ctx, n.ID, "lease-2", "d-1"); !errors.Is(err, ErrNotifyLeaseLost) {
		t.Fatalf("foreign ack = %v", err)
	}
	// The lease runs out: the row is retried with the same key, and the old
	// lease can no longer finish it.
	*clock = clock.Add(notifyLease + time.Second)
	if err := s.AckNotification(ctx, n.ID, "lease-1", "d-1"); !errors.Is(err, ErrNotifyLeaseLost) {
		t.Fatalf("ack after the lease ran out = %v", err)
	}
	again, found, err := s.LeaseNotification(ctx, "lease-3")
	if err != nil || !found || again.ID != n.ID || again.Attempts != 2 || again.DeliveryKey() != n.DeliveryKey() {
		t.Fatalf("retry lease = %+v %v %v", again, found, err)
	}
	if err := s.AckNotification(ctx, n.ID, "lease-3", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ack without a delivery id = %v", err)
	}
	if err := s.AckNotification(ctx, n.ID, "lease-3", "d-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.AckNotification(ctx, n.ID, "lease-3", "d-1"); !errors.Is(err, ErrNotifyLeaseLost) {
		t.Fatalf("second ack = %v", err)
	}
	if _, found, _ := s.LeaseNotification(ctx, "lease-4"); found {
		t.Fatal("a sent row was leased again")
	}

	// Abandon closes the next row for good.
	if _, err := s.RejectAccess(ctx, notifyPRN, notifyOwner, "no"); err != nil {
		t.Fatal(err)
	}
	r, found, err := s.LeaseNotification(ctx, "lease-5")
	if err != nil || !found || r.Kind != NotifyRejected || r.DeliveryKey() == n.DeliveryKey() {
		t.Fatalf("rejected lease = %+v %v %v", r, found, err)
	}
	if err := s.AbandonNotification(ctx, r.ID, "lease-5", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("abandon without a reason = %v", err)
	}
	if err := s.AbandonNotification(ctx, r.ID, "lease-5", "no_recipient"); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := s.LeaseNotification(ctx, "lease-6"); found {
		t.Fatal("an abandoned row was leased again")
	}
}

func TestPGNotifyWindow(t *testing.T) {
	s, clock := newNotifyStore(t, true)
	ctx := context.Background()
	mustRequest(t, s, notifyPRN)
	*clock = clock.Add(NotifyWindow)
	if _, found, err := s.LeaseNotification(ctx, "l"); err != nil || found {
		t.Fatalf("lease past the window = %v %v", found, err)
	}
	if n, err := s.ExpireNotifications(ctx); err != nil || n != 1 {
		t.Fatalf("expire = %d %v", n, err)
	}
	if n, err := s.ExpireNotifications(ctx); err != nil || n != 0 {
		t.Fatalf("second expire = %d %v", n, err)
	}
	var state, outcome string
	if err := s.pool.QueryRow(ctx, `SELECT state, outcome FROM glovo_access_notifications`).Scan(&state, &outcome); err != nil {
		t.Fatal(err)
	}
	if state != "abandoned" || outcome != NotifyOutcomeExpired {
		t.Fatalf("row %s %s", state, outcome)
	}
}

// Dead decide tokens are dropped a window after they died; a live one, and
// one that died less than a window ago, are kept.
func TestPGDecideTokensPruned(t *testing.T) {
	s, clock := newNotifyStore(t, true)
	ctx := context.Background()
	a := mustRequest(t, s, notifyPRN)
	spent, spare := mustMint(t, s, a), mustMint(t, s, a)
	b := mustRequest(t, s, notifyPRN2)
	live := mustMint(t, s, b)
	if _, err := s.RejectAccessByLink(ctx, notifyPRN, notifyOwner, "no", HashDecideToken(spent)); err != nil {
		t.Fatal(err)
	}
	_ = spare // retired by the decision
	prune := func(want int) {
		t.Helper()
		if _, err := s.ExpireNotifications(ctx); err != nil {
			t.Fatal(err)
		}
		if n := tableCount(t, s, "glovo_access_decide_tokens"); n != want {
			t.Fatalf("%d tokens, want %d", n, want)
		}
	}
	prune(3)
	*clock = clock.Add(NotifyWindow - time.Minute)
	prune(3)
	*clock = clock.Add(2 * time.Minute)
	prune(1) // the spent and the retired one are gone, the live one stays
	mustLive(t, s, notifyPRN2, live, true)
	mustLive(t, s, notifyPRN, spent, false)
	*clock = b.ExpiresAt.Add(NotifyWindow - time.Minute)
	prune(1)
	*clock = b.ExpiresAt.Add(NotifyWindow + time.Minute)
	prune(0)
}

func TestNotifyDeliveryKeyStableAndDistinct(t *testing.T) {
	at := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	base := Notification{PrincipalID: notifyPRN, Kind: NotifyApproved, RequestedAt: at}
	same := Notification{ID: 9, PrincipalID: notifyPRN, Kind: NotifyApproved, RequestedAt: at.In(time.FixedZone("x", 3600)), Attempts: 4}
	if base.DeliveryKey() != same.DeliveryKey() || len(base.DeliveryKey()) != 64 {
		t.Fatal("key not stable")
	}
	if strings.Contains(base.DeliveryKey(), notifyPRN) {
		t.Fatal("key holds the principal id")
	}
	for _, other := range []Notification{
		{PrincipalID: notifyPRN2, Kind: NotifyApproved, RequestedAt: at},
		{PrincipalID: notifyPRN, Kind: NotifyRejected, RequestedAt: at},
		{PrincipalID: notifyPRN, Kind: NotifyApproved, RequestedAt: at.Add(time.Microsecond)},
	} {
		if other.DeliveryKey() == base.DeliveryKey() {
			t.Fatalf("key collides for %+v", other)
		}
	}
}
