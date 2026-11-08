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
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestRedactedResultOmitsLeaseTokenAndDigestIsStable(t *testing.T) {
	raw := fixture(t, "result.valid.json")
	res, err := ParseResult(raw)
	if err != nil {
		t.Fatal(err)
	}
	if res.LeaseToken == "" {
		t.Fatal("fixture has no lease_token")
	}
	red, err := res.redacted()
	if err != nil {
		t.Fatal(err)
	}
	var got, full map[string]any
	_ = json.Unmarshal(red, &got)
	_ = json.Unmarshal(raw, &full)
	if _, ok := got["lease_token"]; ok {
		t.Fatal("redacted form still has lease_token")
	}
	for k, v := range full {
		if k == "lease_token" {
			continue
		}
		if fmt.Sprint(got[k]) != fmt.Sprint(v) {
			t.Errorf("field %s changed: %v vs %v", k, got[k], v)
		}
	}
	if strings.Contains(string(red), res.LeaseToken) {
		t.Fatal("token value leaked")
	}
	// Digest still covers the full projection, including the token.
	if d := res.Digest(); !strings.HasPrefix(d, "sha256:") {
		t.Fatalf("digest %q", d)
	}
	res2 := *res
	res2.LeaseToken = "lt_other"
	if res.Digest() == res2.Digest() {
		t.Fatal("digest must cover lease_token as before")
	}
}

type fakeSweeper struct {
	due            int
	calls          int
	failing        bool
	backlogFailing bool
	ticks          chan struct{}
}

func (f *fakeSweeper) ExpireDue(_ context.Context, limit int) (int, error) {
	f.calls++
	if f.ticks != nil {
		select {
		case f.ticks <- struct{}{}:
		default:
		}
	}
	if f.failing {
		return 0, errors.New("db down")
	}
	n := min(limit, f.due)
	f.due -= n
	return n, nil
}

func (f *fakeSweeper) ExpiryBacklog(context.Context) (int64, float64, error) {
	if f.backlogFailing {
		return 0, 0, errors.New("backlog query failed")
	}
	return int64(f.due), 0, nil
}

func TestExpirerHonorsBatchAndLoopCaps(t *testing.T) {
	f := &fakeSweeper{due: 1000}
	e := &Expirer{Store: f, Batch: 100, MaxBatches: 3}
	n, err := e.RunOnce(context.Background())
	if err != nil || n != 300 || f.calls != 3 {
		t.Fatalf("n=%d calls=%d err=%v", n, f.calls, err)
	}
	// The backlog continues over later ticks.
	for i := 0; i < 2; i++ {
		_, _ = e.RunOnce(context.Background())
	}
	if f.due != 100 {
		t.Fatalf("due=%d", f.due)
	}
	st := e.Stats()
	if st.Processed != 900 || st.Backlog != 100 || st.LastSuccess.IsZero() {
		t.Fatalf("stats %+v", st)
	}
}

func TestExpirerReportsErrors(t *testing.T) {
	f := &fakeSweeper{failing: true}
	e := &Expirer{Store: f}
	for i := 0; i < 3; i++ {
		if _, err := e.RunOnce(context.Background()); err == nil {
			t.Fatal("want error")
		}
	}
	if st := e.Stats(); st.Errors != 3 || st.ConsecutiveErrors != 3 {
		t.Fatalf("stats %+v", st)
	}
}

func TestExpirerBacklogErrorsAreVisible(t *testing.T) {
	f := &fakeSweeper{backlogFailing: true}
	e := &Expirer{Store: f}
	if _, err := e.RunOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "backlog query failed") {
		t.Fatalf("expected backlog failure, got %v", err)
	}
	st := e.Stats()
	if st.Errors != 1 || st.ConsecutiveErrors != 1 || !st.LastSuccess.IsZero() {
		t.Fatalf("backlog failure was reported as success: %+v", st)
	}
	// After a fully successful sweep the consecutive-error streak resets.
	f.backlogFailing = false
	if _, err := e.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := e.Stats(); st.ConsecutiveErrors != 0 || st.LastSuccess.IsZero() {
		t.Fatalf("successful retry did not clear consecutive errors: %+v", st)
	}
}

func TestExpirerRunTicksAndStopsCleanly(t *testing.T) {
	f := &fakeSweeper{ticks: make(chan struct{}, 4)}
	e := &Expirer{Store: f, Interval: 5 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.Run(ctx)
	}()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	// The first call is immediate; the second proves the ticker actually fires.
	for i := 0; i < 2; i++ {
		select {
		case <-f.ticks:
		case <-deadline.C:
			cancel()
			<-done
			t.Fatal("expirer did not run a scheduled sweep tick")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("expirer did not stop on context cancellation")
	}
	if f.calls < 2 {
		t.Fatalf("expirer executed %d sweep calls, need at least two", f.calls)
	}
	if st := e.Stats(); st.Errors != 0 || st.ConsecutiveErrors != 0 {
		t.Fatalf("clean shutdown counted as failure: %+v", st)
	}

	cancelled, cancelBefore := context.WithCancel(context.Background())
	cancelBefore()
	before := e.Stats()
	if _, err := e.RunOnce(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled RunOnce: %v", err)
	}
	if after := e.Stats(); after.Errors != before.Errors || after.ConsecutiveErrors != before.ConsecutiveErrors {
		t.Fatalf("cancelled RunOnce counted as failure: before=%+v after=%+v", before, after)
	}
}

func TestPGResultHasNoLeaseTokenAndLegacyScrub(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()
	tenant := fmt.Sprintf("t-%d", time.Now().UnixNano())
	c := Caller{ProviderRef: "glovo", Actor: "service:bridge-provider:glovo", Tenants: []string{tenant}}
	id := enqueue(t, s, tenant, KindQuote)
	cmd := claimOne(t, s, c, id)
	body := resultBody(id, cmd)
	res, err := ParseResult(body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SubmitResult(ctx, c, id, body); err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := s.pool.QueryRow(ctx, `SELECT result::text FROM bridge_commands WHERE command_id=$1`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "lease_token") || strings.Contains(raw, "lt_") {
		t.Fatalf("stored result leaks token: %s", raw)
	}
	var digest string
	if err := s.pool.QueryRow(ctx, `SELECT result_digest FROM bridge_commands WHERE command_id=$1`, id).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	if digest != res.Digest() {
		t.Fatalf("digest changed: %s", digest)
	}

	// Legacy row: token-bearing result reads clean and is scrubbed in batches.
	if _, err := s.pool.Exec(ctx, `UPDATE bridge_commands SET result = result || '{"lease_token":"lt_legacy"}'::jsonb WHERE command_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	out, err := s.ReadOutcome(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out.Result), "lease_token") {
		t.Fatalf("ReadOutcome leaks: %s", out.Result)
	}
	for i := 0; i < 1000; i++ {
		n, rem, err := s.ScrubLegacyResultBatch(ctx, 50)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 && rem == 0 {
			break
		}
	}
	var left int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM bridge_commands WHERE result ? 'lease_token'`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatalf("%d legacy rows remain", left)
	}
}

func TestPGExpireDueWithoutPollerAndAudit(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()
	tenant := fmt.Sprintf("t-%d", time.Now().UnixNano())
	id := enqueue(t, s, tenant, KindQuote)
	if _, err := s.pool.Exec(ctx, `UPDATE bridge_commands SET expires_at = now() - interval '1 minute' WHERE command_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExpireDue(ctx, 1000); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := s.pool.QueryRow(ctx, `SELECT status FROM bridge_commands WHERE command_id=$1`, id).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != StatusExpired {
		t.Fatalf("status %s", status)
	}
	var from, to, actor string
	if err := s.pool.QueryRow(ctx, `SELECT from_status, to_status, actor FROM bridge_command_transitions
		WHERE command_id=$1 ORDER BY id DESC LIMIT 1`, id).Scan(&from, &to, &actor); err != nil {
		t.Fatal(err)
	}
	if from != StatusPending || to != StatusExpired || actor != ExpireActor {
		t.Fatalf("transition %s -> %s by %s", from, to, actor)
	}
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM bridge_signal_outbox WHERE command_id=$1 AND result_digest='expired'`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("outbox rows %d", n)
	}
}

func TestPGLegacyScrubSkipsLockedWriterAndResumes(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()
	tenant := fmt.Sprintf("scrub-race-%d", time.Now().UnixNano())
	caller := Caller{ProviderRef: "glovo", Actor: "service:bridge-provider:glovo", Tenants: []string{tenant}}
	ids := make([]string, 0, 2)
	for i := 0; i < 2; i++ {
		// Claim and finish each command before enqueuing the next: Claim()
		// may lease the entire tenant batch in one call.
		id := enqueue(t, s, tenant, KindQuote)
		claimed := claimOne(t, s, caller, id)
		if _, err := s.SubmitResult(ctx, caller, id, resultBody(id, claimed)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.pool.Exec(ctx, `UPDATE bridge_commands
			SET result=result || '{"lease_token":"lt_legacy"}'::jsonb
			WHERE command_id=$1`, id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}

	// A concurrent legacy writer holds one result row while the scrub batch
	// runs. SKIP LOCKED must never block or overwrite the uncommitted write.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `UPDATE bridge_commands
		SET result=result || '{"lease_token":"lt_racing"}'::jsonb
		WHERE command_id=$1`, ids[0]); err != nil {
		t.Fatal(err)
	}
	n, _, err := s.ScrubLegacyResultBatch(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if n > 1 {
		t.Fatalf("batch updated %d rows, limit=1", n)
	}
	var stillLegacy bool
	if err := s.pool.QueryRow(ctx, `SELECT result ? 'lease_token' FROM bridge_commands WHERE command_id=$1`, ids[0]).Scan(&stillLegacy); err != nil {
		t.Fatal(err)
	}
	if !stillLegacy {
		t.Fatal("scrub modified a row locked by a concurrent writer")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	// Restartable: a subsequent bounded invocation must clean both rows.
	for attempt := 0; attempt < 20; attempt++ {
		if _, _, err := s.ScrubLegacyResultBatch(ctx, 100); err != nil {
			t.Fatal(err)
		}
		var count int
		if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM bridge_commands
			WHERE command_id = ANY($1) AND result ? 'lease_token'`, ids).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count == 0 {
			return
		}
	}
	t.Fatal("scrub could not clean previously locked legacy results")
}

func TestPGExpiredLeasedPermitIsUnknownAndAudited(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()
	s.SetFence(allowFence{})
	tenant := fmt.Sprintf("expiry-permit-%d", time.Now().UnixNano())
	caller := Caller{ProviderRef: "glovo", Actor: "service:bridge-provider:glovo", Tenants: []string{tenant}}
	id := enqueue(t, s, tenant, KindPlaceOrderFake)
	var claim struct {
		LeaseToken string `json:"lease_token"`
	}
	if err := json.Unmarshal(claimOne(t, s, caller, id), &claim); err != nil {
		t.Fatal(err)
	}
	if claim.LeaseToken == "" {
		t.Fatal("claim did not provide a lease token")
	}
	if _, err := s.IssueWritePermit(ctx, caller, id, claim.LeaseToken); err != nil {
		t.Fatalf("issue permit: %v", err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE bridge_commands SET expires_at = now() - interval '1 minute' WHERE command_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExpireDue(ctx, 1000); err != nil {
		t.Fatal(err)
	}
	var status, effect string
	if err := s.pool.QueryRow(ctx, `SELECT status, effect_state FROM bridge_commands WHERE command_id=$1`, id).Scan(&status, &effect); err != nil {
		t.Fatal(err)
	}
	if status != StatusExpired || effect != "unknown" {
		t.Fatalf("after expiry: status=%q effect_state=%q, want expired/unknown", status, effect)
	}
	var from, to, actor string
	if err := s.pool.QueryRow(ctx, `SELECT from_status, to_status, actor FROM bridge_command_transitions
		WHERE command_id=$1 ORDER BY id DESC LIMIT 1`, id).Scan(&from, &to, &actor); err != nil {
		t.Fatal(err)
	}
	if from != StatusLeased || to != StatusExpired || actor != ExpireActor {
		t.Fatalf("expiry audit: %q -> %q by %q", from, to, actor)
	}
	var transitions, outbox int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM bridge_command_transitions
		WHERE command_id=$1 AND from_status='leased' AND to_status='expired'`, id).Scan(&transitions); err != nil {
		t.Fatal(err)
	}
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM bridge_signal_outbox
		WHERE command_id=$1 AND result_digest='expired'`, id).Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	if transitions != 1 || outbox != 1 {
		t.Fatalf("expiry artifacts: transitions=%d outbox=%d; want 1 each", transitions, outbox)
	}
}

func TestPGReclaimAuditRecordsRealPriorStatus(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()
	tenant := fmt.Sprintf("t-%d", time.Now().UnixNano())
	c := Caller{ProviderRef: "glovo", Actor: "service:bridge-provider:glovo", Tenants: []string{tenant}}
	id := enqueue(t, s, tenant, KindQuote)
	claimOne(t, s, c, id)
	if _, err := s.pool.Exec(ctx, `UPDATE bridge_commands SET lease_expires_at = now() - interval '1 second' WHERE command_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	claimOne(t, s, c, id)
	rows, err := s.pool.Query(ctx, `SELECT from_status, to_status, lease_epoch FROM bridge_command_transitions WHERE command_id=$1 ORDER BY id`, id)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var f, to string
		var e int64
		if err := rows.Scan(&f, &to, &e); err != nil {
			t.Fatal(err)
		}
		got = append(got, fmt.Sprintf("%s>%s@%d", f, to, e))
	}
	want := ">pending@0,pending>leased@1,leased>leased@2"
	if strings.Join(got, ",") != want {
		t.Fatalf("transitions %v, want %s", got, want)
	}
}
