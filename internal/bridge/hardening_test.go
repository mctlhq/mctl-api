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
	due     int
	calls   int
	failing bool
}

func (f *fakeSweeper) ExpireDue(_ context.Context, limit int) (int, error) {
	f.calls++
	if f.failing {
		return 0, errors.New("db down")
	}
	n := min(limit, f.due)
	f.due -= n
	return n, nil
}

func (f *fakeSweeper) ExpiryBacklog(context.Context) (int64, float64, error) {
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

func TestPGResultHasNoLeaseTokenAndLegacyScrub(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()
	tenant := fmt.Sprintf("t-%d", time.Now().UnixNano())
	c := Caller{ProviderRef: "glovo", Actor: "service:bridge-provider:glovo", Tenants: []string{tenant}}
	id := enqueue(t, s, tenant, KindQuote)
	cmd := claimOne(t, s, c, id)
	body := resultBody(id, cmd)
	res, _ := ParseResult(body)
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
	_ = s.pool.QueryRow(ctx, `SELECT result_digest FROM bridge_commands WHERE command_id=$1`, id).Scan(&digest)
	if digest != res.Digest() {
		t.Fatalf("digest changed: %s", digest)
	}

	// Legacy row: token-bearing result reads clean and is scrubbed in batches.
	if _, err := s.pool.Exec(ctx, `UPDATE bridge_commands SET result = result || '{"lease_token":"lt_legacy"}'::jsonb WHERE command_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	out, err := s.ReadOutcome(ctx, id)
	if err != nil || strings.Contains(string(out.Result), "lease_token") {
		t.Fatalf("ReadOutcome leaks: %v %s", err, out.Result)
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
	_ = s.pool.QueryRow(ctx, `SELECT count(*) FROM bridge_commands WHERE result ? 'lease_token'`).Scan(&left)
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
	_ = s.pool.QueryRow(ctx, `SELECT status FROM bridge_commands WHERE command_id=$1`, id).Scan(&status)
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
	_ = s.pool.QueryRow(ctx, `SELECT count(*) FROM bridge_signal_outbox WHERE command_id=$1 AND result_digest='expired'`, id).Scan(&n)
	if n != 1 {
		t.Fatalf("outbox rows %d", n)
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
		_ = rows.Scan(&f, &to, &e)
		got = append(got, fmt.Sprintf("%s>%s@%d", f, to, e))
	}
	want := ">pending@0,pending>leased@1,leased>leased@2"
	if strings.Join(got, ",") != want {
		t.Fatalf("transitions %v, want %s", got, want)
	}
}
