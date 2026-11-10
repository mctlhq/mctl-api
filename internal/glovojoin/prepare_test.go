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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/glovo"
)

func wantCode(t *testing.T, rf *Refusal, code glovo.Code, reason string) {
	t.Helper()
	if rf == nil {
		t.Fatalf("want %s (%s), got success", code, reason)
	}
	if !errors.Is(rf, glovo.Refuse(code)) {
		t.Fatalf("want %s (%s), got %v", code, reason, rf)
	}
	if reason != "" && rf.Reason != reason {
		t.Fatalf("want reason %q, got %q", reason, rf.Reason)
	}
}

// writes counts every row prepare may create, plus bridge_commands, which it
// must never touch.
func (s *stack) writes() [6]int {
	return [6]int{
		s.count(`SELECT count(*) FROM glovo.orders`),
		s.count(`SELECT count(*) FROM glovo.control_starts`),
		s.count(`SELECT count(*) FROM public.work_item_executions`),
		s.count(`SELECT count(*) FROM glovo.approval_bindings`),
		s.count(`SELECT count(*) FROM glovo.join_previews WHERE consumed_order_ref IS NOT NULL`),
		s.count(`SELECT count(*) FROM public.bridge_commands`),
	}
}

func TestPrepareCreatesOneOrderAndNoProviderEffect(t *testing.T) {
	s := newStack(t)
	s.activate("k-happy")
	p := s.preview(stackBasket)
	res, rf := s.prepare.Prepare(context.Background(), s.req(p, "key-1"))
	if rf != nil {
		t.Fatalf("prepare: %v", rf)
	}
	if res.Replayed || res.Fingerprint != p.Fingerprint || res.ConsentRequestID == "" || res.OrderID == "" {
		t.Fatalf("result = %+v", res)
	}
	w := s.writes()
	if w != [6]int{1, 1, 1, 1, 1, 0} {
		t.Fatalf("writes = %v, want one order/start/execution/binding/claim and zero bridge_commands (A8)", w)
	}
	if st := s.count(`SELECT count(*) FROM glovo.orders WHERE order_ref=$1 AND state='finalized' AND approval_ref=$2`, res.OrderID, res.ConsentRequestID); st != 1 {
		t.Fatalf("order is not finalized with its approval: %d", st)
	}
	if st := s.count(`SELECT count(*) FROM glovo.control_starts WHERE order_ref=$1 AND state='pending'`, res.OrderID); st != 1 {
		t.Fatalf("control start missing")
	}
}

func TestPrepareReplayIsByteIdenticalAndWritesNothing(t *testing.T) {
	s := newStack(t)
	s.activate("k-replay")
	p := s.preview(stackBasket)
	first, rf := s.prepare.Prepare(context.Background(), s.req(p, "key-r"))
	if rf != nil {
		t.Fatal(rf)
	}
	before := s.writes()
	again, rf := s.prepare.Prepare(context.Background(), s.req(p, "key-r"))
	if rf != nil {
		t.Fatal(rf)
	}
	if !again.Replayed || first.Replayed {
		t.Fatalf("replayed flags = %v %v", first.Replayed, again.Replayed)
	}
	if !bytes.Equal(first.WireBody(), again.WireBody()) {
		t.Fatalf("replay differs:\n%s\n%s", first.WireBody(), again.WireBody())
	}
	if after := s.writes(); after != before {
		t.Fatalf("replay wrote: %v -> %v", before, after)
	}
}

func TestPrepareSameKeyOtherPreviewIsReused(t *testing.T) {
	s := newStack(t)
	s.activate("k-reuse")
	p1, p2 := s.preview(stackBasket), s.preview(stackBasket)
	if _, rf := s.prepare.Prepare(context.Background(), s.req(p1, "key-x")); rf != nil {
		t.Fatal(rf)
	}
	_, rf := s.prepare.Prepare(context.Background(), s.req(p2, "key-x"))
	wantCode(t, rf, glovo.CodeIdempotencyReused, "idempotency_key_reused")
}

func TestPrepareConsumedPreviewUnderAnotherKey(t *testing.T) {
	s := newStack(t)
	s.activate("k-consumed")
	p := s.preview(stackBasket)
	if _, rf := s.prepare.Prepare(context.Background(), s.req(p, "key-a")); rf != nil {
		t.Fatal(rf)
	}
	before := s.writes()
	_, rf := s.prepare.Prepare(context.Background(), s.req(p, "key-b"))
	wantCode(t, rf, glovo.CodeFingerprintChanged, "preview_consumed")
	if after := s.writes(); after != before {
		t.Fatalf("refused prepare wrote: %v -> %v", before, after)
	}
}

// T16: two keys race for one preview; exactly one order exists afterwards.
func TestPrepareTwoKeyPreviewRace(t *testing.T) {
	s := newStack(t)
	s.activate("k-race")
	p := s.preview(stackBasket)
	var wg sync.WaitGroup
	results := make([]*Refusal, 2)
	for i, key := range []string{"race-a", "race-b"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, results[i] = s.prepare.Prepare(context.Background(), s.req(p, key))
		}()
	}
	wg.Wait()
	ok := 0
	for _, r := range results {
		switch {
		case r == nil:
			ok++
		case errors.Is(r, glovo.Refuse(glovo.CodeFingerprintChanged)):
		default:
			t.Fatalf("unexpected refusal %v", r)
		}
	}
	if ok != 1 {
		t.Fatalf("%d winners, want exactly 1 (%v)", ok, results)
	}
	if w := s.writes(); w != [6]int{1, 1, 1, 1, 1, 0} {
		t.Fatalf("writes = %v", w)
	}
}

func TestPrepareRefusals(t *testing.T) {
	s := newStack(t)
	s.activate("k-ref")
	empty := s.preview("")
	_, rf := s.prepare.Prepare(context.Background(), s.req(empty, "key-e"))
	wantCode(t, rf, glovo.CodeInvalidRequest, "basket_empty")

	_, rf = s.prepare.Prepare(context.Background(), PrepareRequest{Tenant: stackTenant, PrincipalID: stackOwner, PreviewID: "gpv_doesnotexist0000000000000", Key: "key-n", InstallID: s.installID, InstallRevision: s.installRev})
	wantCode(t, rf, glovo.CodeNotFound, "preview_not_found")

	foreign := s.preview(stackBasket)
	_, rf = s.prepare.Prepare(context.Background(), PrepareRequest{Tenant: stackTenant, PrincipalID: "prn_OTHER00000000000000000001", PreviewID: foreign.ID, Key: "key-f", InstallID: s.installID, InstallRevision: s.installRev})
	if rf == nil {
		t.Fatal("a foreign principal prepared the preview")
	}
	if w := s.writes(); w != [6]int{0, 0, 0, 0, 0, 0} {
		t.Fatalf("refusals wrote: %v", w)
	}
}

// T12: a revoked connection stops prepare before any write.
func TestPrepareReReadsTheConnection(t *testing.T) {
	s := newStack(t)
	s.activate("k-t12")
	p := s.preview(stackBasket)
	if _, err := s.conns.Revoke(context.Background(), stackOf, stackUser, s.connID, "user_revoked"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	_, rf := s.prepare.Prepare(context.Background(), s.req(p, "key-12"))
	wantCode(t, rf, glovo.CodeConnectionRevoked, "")
	if w := s.writes(); w != [6]int{0, 0, 0, 0, 0, 0} {
		t.Fatalf("wrote on a revoked connection: %v", w)
	}
}

const controlInputGolden = "contract/testdata/control-input.golden.json"

func goldenInput() ControlInput {
	return ControlInput{
		SchemaVersion: ControlInputSchemaVersion, TenantRef: "tnr_TENANT000000000000000001", PrincipalRef: "prr_PRINCIPAL00000000000000001",
		InstallRef: "gin_INSTALL0000000000000001", InstallRevision: 3, ConnectionRef: "gcn_CONN00000000000000000001",
		OrderRef: "ordr_ORDER0000000000000000001", ExecutionID: "we_EXEC00000000000000000001", WorkItemID: "wi_ITEM000000000000000000001",
		ApprovalRef: "aar_APPROVAL0000000000000001", Fingerprint: "sha256:" + strings.Repeat("ab", 32), Limits: ControlLimits,
	}
}

// The checked-in golden is the shape #1044's validator is asked to accept
// (OPEN-957-11): twelve members, RFC 8785 order and encoding.
func TestControlInputMatchesGolden(t *testing.T) {
	got, digest, err := goldenInput().Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(controlInputGolden, append(got, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(controlInputGolden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(want), got) {
		t.Fatalf("control input drifted from the golden:\n got %s\nwant %s", got, want)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(got, &m); err != nil || len(m) != 12 {
		t.Fatalf("control input has %d members, want twelve (%v)", len(m), err)
	}
	if sum := sha256.Sum256(got); digest != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("digest %s", digest)
	}
}

// A real prepare stores exactly the canonical input its own refs produce, and
// the stored digest is the row's CHECK.
func TestPrepareStoresTheCanonicalControlInput(t *testing.T) {
	s := newStack(t)
	s.activate("k-input")
	p := s.preview(stackBasket)
	res, rf := s.prepare.Prepare(context.Background(), s.req(p, "key-in"))
	if rf != nil {
		t.Fatal(rf)
	}
	var input []byte
	var digest, wf string
	if err := s.mp.QueryRow(context.Background(), `SELECT input, input_digest, workflow_id FROM glovo.control_starts WHERE order_ref=$1`, res.OrderID).Scan(&input, &digest, &wf); err != nil {
		t.Fatal(err)
	}
	var in ControlInput
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		t.Fatalf("stored input is not a ControlInput: %v", err)
	}
	if in.OrderRef != res.OrderID || in.ApprovalRef != res.ConsentRequestID || in.Fingerprint != p.Fingerprint ||
		in.InstallRef != s.installID || in.ConnectionRef != s.connID || in.InstallRevision != s.installRev {
		t.Fatalf("stored input = %+v", in)
	}
	if want := WorkflowID(in.TenantRef, in.PrincipalRef, in.InstallRef, in.OrderRef); wf != want {
		t.Fatalf("workflow id %q, want %q", wf, want)
	}
	again, d2, err := in.Canonical()
	if err != nil || !bytes.Equal(again, input) || d2 != digest {
		t.Fatalf("stored input is not canonical: %v", err)
	}
}

// lockOrder records the connection-store calls prepare makes, in order.
type lockOrder struct {
	PrepareConnections
	calls []string
}

func (l *lockOrder) LockOwnerShared(ctx context.Context, tx pgx.Tx, tenant, principal string) error {
	l.calls = append(l.calls, "lock")
	return l.PrepareConnections.LockOwnerShared(ctx, tx, tenant, principal)
}

func (l *lockOrder) LiveConnectionTx(ctx context.Context, tx pgx.Tx, o glovo.Owner) (*glovo.Connection, error) {
	l.calls = append(l.calls, "live")
	return l.PrepareConnections.LiveConnectionTx(ctx, tx, o)
}

// T12: prepare takes the shared owner locks before it re-reads the live
// connection, so a concurrent revoke or reconnect (which takes L2 exclusive)
// cannot slip between the read and the writes.
func TestPrepareLocksTheOwnerBeforeTheConnectionRead(t *testing.T) {
	s := newStack(t)
	s.activate("k-lock")
	rec := &lockOrder{PrepareConnections: s.conns}
	p := &Preparer{DB: s.rp, Conns: rec, Order: s.orders, Work: s.work}
	if _, rf := p.Prepare(context.Background(), s.req(s.preview(stackBasket), "key-lock")); rf != nil {
		t.Fatal(rf)
	}
	if len(rec.calls) < 2 || rec.calls[0] != "lock" || rec.calls[1] != "live" {
		t.Fatalf("connection-store calls = %v, want lock then live", rec.calls)
	}
}

// T12: a preview bound to another install revision than the live connection's
// is stale_install, and nothing is written.
func TestPrepareRefusesAPreviewOfAnotherInstallRevision(t *testing.T) {
	s := newStack(t)
	s.activate("k-rev")
	p := s.preview(stackBasket)
	if _, err := s.mp.Exec(context.Background(), `UPDATE glovo.join_previews SET install_revision = install_revision + 1 WHERE id = $1`, p.ID); err != nil {
		t.Fatal(err)
	}
	_, rf := s.prepare.Prepare(context.Background(), s.req(p, "key-rev"))
	wantCode(t, rf, glovo.CodeStaleInstall, "preview_connection_changed")
	if w := s.writes(); w != [6]int{0, 0, 0, 0, 0, 0} {
		t.Fatalf("wrote on a stale preview: %v", w)
	}
}
