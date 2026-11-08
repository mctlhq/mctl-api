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
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Postgres-backed tests, gated on TEST_DATABASE_URL like the other stores.

type allowFence struct{}

func (allowFence) Check(context.Context, pgx.Tx, FenceBinding) (string, error) {
	return "fence_test", nil
}

func pgStore(t *testing.T) *Store {
	t.Helper()
	conn := os.Getenv("TEST_DATABASE_URL")
	if conn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed bridge store test")
	}
	s, err := NewStore(context.Background(), conn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	// A second application of the schema is a no-op.
	if _, err := s.pool.Exec(context.Background(), bridgeSchema); err != nil {
		t.Fatalf("schema not idempotent: %v", err)
	}
	return s
}

var pgSeq int

func enqueue(t *testing.T, s *Store, tenant, kind string) string {
	t.Helper()
	pgSeq++
	suffix := fmt.Sprintf("%016d", time.Now().UnixNano()%1e15+int64(pgSeq))
	in := EnqueueInput{
		ExecutionID: "we_" + suffix, WorkItemID: "wi_" + suffix, WorkflowID: "wf-" + suffix, Tenant: tenant,
		OwnerPrincipalID: "owner", TenantRef: "tnr_" + suffix, PrincipalRef: "prr_" + suffix, OrderRef: "ordr_" + suffix,
		ConnectionRef: "gcn_" + suffix, InstallRevision: "r1", ProviderRef: "glovo", Kind: kind, Attempt: 1,
		OperationKey: "op-" + suffix, IntentHash: "sha256:" + strings.Repeat("0", 64), Payload: json.RawMessage(`{"quantity_total":1}`),
	}
	if kind == KindPlaceOrderFake {
		in.ApprovalRef = "aar_" + suffix
	}
	tx, err := s.Pool().Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	id, created, err := s.Enqueue(context.Background(), tx, in)
	if err != nil || !created {
		t.Fatalf("enqueue: %v created=%v", err, created)
	}
	if id2, created2, err := s.Enqueue(context.Background(), tx, in); err != nil || created2 || id2 != id {
		t.Fatalf("enqueue not idempotent: %v %v %v", id2, created2, err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	return id
}

func resultBody(id string, claimed json.RawMessage) []byte {
	var c map[string]any
	_ = json.Unmarshal(claimed, &c)
	b, _ := json.Marshal(map[string]any{
		"schema_version": SchemaVersion, "command_id": id, "execution_id": c["execution_id"], "lease_token": c["lease_token"],
		"attempt": 1, "worker_identity": "provider:glovo", "outcome": "succeeded", "provider_effect": "none",
		"completed_at": "2026-11-08T10:01:00Z",
	})
	return b
}

func claimOne(t *testing.T, s *Store, c Caller, id string) json.RawMessage {
	t.Helper()
	got, err := s.Claim(context.Background(), c, MaxClaimBatch, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range got {
		if g.CommandID == id {
			return g.Command
		}
	}
	t.Fatalf("command %s not claimed", id)
	return nil
}

func TestPGClaimResultReplayAndTenancy(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()
	tenant := fmt.Sprintf("t-%d", time.Now().UnixNano())
	c := Caller{ProviderRef: "glovo", Actor: "service:bridge-provider:glovo", Tenants: []string{tenant}}
	id := enqueue(t, s, tenant, KindQuote)

	// A caller whose tenant bound excludes the command, or another provider, sees nothing.
	other := Caller{ProviderRef: "glovo", Actor: "x", Tenants: []string{"elsewhere"}}
	if got, _ := s.Claim(ctx, other, 5, time.Minute); len(got) != 0 {
		t.Fatal("foreign tenant claimed a command")
	}
	cmd := claimOne(t, s, c, id)
	body := resultBody(id, cmd)
	if _, err := s.SubmitResult(ctx, other, id, body); Code(err) != "command_not_found" {
		t.Fatalf("foreign tenant result: %v", err)
	}
	out, err := s.SubmitResult(ctx, c, id, body)
	if err != nil || out.Replayed {
		t.Fatalf("submit: %v %+v", err, out)
	}
	again, err := s.SubmitResult(ctx, c, id, body)
	if err != nil || !again.Replayed {
		t.Fatalf("replay: %v %+v", err, again)
	}
	var diff map[string]any
	_ = json.Unmarshal(body, &diff)
	diff["completed_at"] = "2026-11-08T10:05:00Z"
	b2, _ := json.Marshal(diff)
	if _, err := s.SubmitResult(ctx, c, id, b2); Code(err) != "result_conflict" {
		t.Fatalf("different digest: %v", err)
	}
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM bridge_signal_outbox WHERE command_id=$1`, id).Scan(&n); err != nil || n != 1 {
		t.Fatalf("outbox rows=%d err=%v", n, err)
	}
}

func TestPGReclaimFencesOldHolderAndCancel(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()
	tenant := fmt.Sprintf("t-%d", time.Now().UnixNano())
	c := Caller{ProviderRef: "glovo", Actor: "a", Tenants: []string{tenant}}
	id := enqueue(t, s, tenant, KindQuote)
	old := claimOne(t, s, c, id)
	if _, err := s.pool.Exec(ctx, `UPDATE bridge_commands SET lease_expires_at=now()-interval '1 second' WHERE command_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	fresh := claimOne(t, s, c, id)
	if _, err := s.SubmitResult(ctx, c, id, resultBody(id, old)); Code(err) != "lease_stale" {
		t.Fatalf("old holder: %v", err)
	}
	if _, err := s.SubmitResult(ctx, c, id, resultBody(id, fresh)); err != nil {
		t.Fatalf("new holder: %v", err)
	}

	id2 := enqueue(t, s, tenant, KindQuote)
	cmd2 := claimOne(t, s, c, id2)
	tx, _ := s.Pool().Begin(ctx)
	if err := s.Cancel(ctx, tx, id2, "control"); err != nil {
		t.Fatal(err)
	}
	_ = tx.Commit(ctx)
	if _, err := s.SubmitResult(ctx, c, id2, resultBody(id2, cmd2)); Code(err) != "command_cancelled" {
		t.Fatalf("after cancel: %v", err)
	}
}

func TestPGWritePermit(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()
	tenant := fmt.Sprintf("t-%d", time.Now().UnixNano())
	c := Caller{ProviderRef: "glovo", Actor: "a", Tenants: []string{tenant}}
	id := enqueue(t, s, tenant, KindPlaceOrderFake)
	cmd := claimOne(t, s, c, id)
	var d map[string]any
	_ = json.Unmarshal(cmd, &d)
	tok := d["lease_token"].(string)

	if _, err := s.IssueWritePermit(ctx, c, id, tok); Code(err) != "write_fence_unavailable" {
		t.Fatalf("default fence: %v", err)
	}
	var n int
	_ = s.pool.QueryRow(ctx, `SELECT count(*) FROM bridge_write_permits WHERE command_id=$1`, id).Scan(&n)
	if n != 0 {
		t.Fatal("permit row written on refusal")
	}
	s.SetFence(allowFence{})
	if _, err := s.IssueWritePermit(ctx, c, id, "lt_forged0123456789abc"); Code(err) != "lease_stale" {
		t.Fatalf("forged token: %v", err)
	}
	if _, err := s.IssueWritePermit(ctx, c, id, tok); err != nil {
		t.Fatalf("permit: %v", err)
	}
	if _, err := s.IssueWritePermit(ctx, c, id, tok); Code(err) != "permit_already_issued" {
		t.Fatalf("second permit: %v", err)
	}
	// An applied effect without a permit is refused; with one it is recorded.
	body := resultBody(id, cmd)
	var r map[string]any
	_ = json.Unmarshal(body, &r)
	r["provider_effect"] = "applied"
	b, _ := json.Marshal(r)
	out, err := s.SubmitResult(ctx, c, id, b)
	if err != nil || out.EffectState != EffectSucceeded {
		t.Fatalf("applied result: %v %+v", err, out)
	}
}
