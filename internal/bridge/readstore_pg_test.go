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

package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Postgres-backed tests of the v1alpha2 read path, gated on TEST_DATABASE_URL
// like the rest of the store tests. The connecting role owns the bridge tables.

type liveChecker struct {
	live LiveConnection
	err  error
}

func (l liveChecker) Live(context.Context, string, string) (LiveConnection, error) {
	return l.live, l.err
}

func applyRead(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	tx, err := s.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyReadSchemaTx(ctx, tx, ""); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// T16: the read schema applies twice, and the second run, inside its open
// transaction, holds no AccessExclusiveLock on any bridge object.
func TestApplyReadSchemaIdempotentTakesNoExclusiveLock(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()
	applyRead(t, s)
	tx, err := s.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := ApplyReadSchemaTx(ctx, tx, ""); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid = l.relation
		WHERE l.pid = pg_backend_pid() AND l.mode = 'AccessExclusiveLock' AND c.relname LIKE 'bridge\_%'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("second run holds %d AccessExclusiveLock(s) on bridge objects", n)
	}
	if err := CheckReadLevel(ctx, tx); err != nil {
		t.Fatal(err)
	}
}

type readHarness struct {
	s      *Store
	tenant string
	req    ReadRequest
}

func newReadHarness(t *testing.T, kind ReadKind) *readHarness {
	t.Helper()
	s := pgStore(t)
	applyRead(t, s)
	if err := s.EnableWireVersions(context.Background()); err != nil {
		t.Fatal(err)
	}
	pgSeq++
	suffix := fmt.Sprintf("%016d", time.Now().UnixNano()%1e15+int64(pgSeq))
	h := &readHarness{s: s, tenant: "readtenant-" + suffix}
	h.req = ReadRequest{
		Kind: kind, Tenant: h.tenant, OwnerPrincipalID: "prr-owner-" + suffix, TenantRef: "tnr_" + suffix, PrincipalRef: "prr_" + suffix,
		ConnectionRef: "gcn_" + suffix, InstallRevision: "7", InstallRevisionRef: "irv_" + suffix, Scopes: []string{ReadScope},
		Deadline: time.Now().Add(15 * time.Second),
	}
	s.SetConnectionChecker(liveChecker{live: LiveConnection{ConnectionRef: h.req.ConnectionRef, InstallRevision: "7"}})
	return h
}

func (h *readHarness) caller(versions ...string) Caller {
	return Caller{ProviderRef: "glovo", Actor: "provider-test", Tenants: []string{h.tenant}, Versions: versions}
}

// resultFor builds a read result for a claimed command from a vendored fixture.
func resultFor(t *testing.T, claimed json.RawMessage, fixtureName string) []byte {
	t.Helper()
	var cmd map[string]any
	if err := json.Unmarshal(claimed, &cmd); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(v2fixture(t, fixtureName)))
	dec.UseNumber()
	var res map[string]any
	if err := dec.Decode(&res); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"command_id", "request_id", "lease_token", "kind"} {
		res[k] = cmd[k]
	}
	out, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// provider claims one read command as a v1alpha2 provider and posts the
// fixture result, returning every body it posted.
func (h *readHarness) provider(t *testing.T, fixtureName string, done chan<- []byte) {
	go func() {
		ctx := context.Background()
		for i := 0; i < 300; i++ {
			got, err := h.s.Claim(ctx, h.caller(WireV1alpha1, WireV1alpha2), 1, 0)
			if err == nil && len(got) == 1 {
				body := resultFor(t, got[0].Command, fixtureName)
				if _, err := h.s.SubmitResult(ctx, h.caller(WireV1alpha1, WireV1alpha2), got[0].CommandID, body); err != nil {
					t.Errorf("provider submit: %v", err)
				}
				done <- body
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		done <- nil
	}()
}

// T5, T8, T9, T10, T10b, T12: a read round trip and its fetch scope.
func TestReadRoundTrip(t *testing.T) {
	h := newReadHarness(t, ReadBasket)
	ctx := context.Background()
	done := make(chan []byte, 1)
	h.provider(t, "read-result.basket.valid.json", done)
	client := &ReadClient{Store: h.s}
	res, err := client.Read(ctx, h.req)
	if err != nil {
		t.Fatal(err)
	}
	body := <-done
	if body == nil {
		t.Fatal("provider never claimed the read")
	}
	var posted struct {
		PayloadDigest string `json:"payload_digest"`
	}
	_ = json.Unmarshal(body, &posted)
	if res.Digest != posted.PayloadDigest || digestOf(res.Data) != res.Digest {
		t.Fatalf("digest %s, want %s", res.Digest, posted.PayloadDigest)
	}
	if !strings.HasPrefix(res.ResultRef, "res_") {
		t.Fatalf("result ref %q", res.ResultRef)
	}

	// T5: no workflow, no outbox row; the refs a write needs are ''.
	var wf, order, exec, wi string
	var outbox int
	if err := h.s.pool.QueryRow(ctx, `SELECT workflow_id, order_ref, execution_id, work_item_id,
		(SELECT count(*) FROM bridge_signal_outbox o WHERE o.command_id = c.command_id)
		FROM bridge_commands c WHERE c.tenant = $1`, h.tenant).Scan(&wf, &order, &exec, &wi, &outbox); err != nil {
		t.Fatal(err)
	}
	if wf+order+exec+wi != "" || outbox != 0 {
		t.Fatalf("read row has workflow refs %q or %d outbox rows", wf+order+exec+wi, outbox)
	}

	// T8: replay returns the same res_.
	var cmdID string
	if err := h.s.pool.QueryRow(ctx, `SELECT command_id FROM bridge_commands WHERE tenant = $1`, h.tenant).Scan(&cmdID); err != nil {
		t.Fatal(err)
	}
	if out, err := h.s.SubmitResult(ctx, h.caller(WireV1alpha1, WireV1alpha2), cmdID, body); err != nil || !out.Replayed || out.ResultRef != res.ResultRef {
		t.Fatalf("replay = %+v, %v", out, err)
	}

	fetch := ReadFetch{ResultRef: res.ResultRef, Tenant: h.tenant, PrincipalID: h.req.OwnerPrincipalID,
		ConnectionRef: h.req.ConnectionRef, InstallRevision: "7", Scopes: []string{ReadScope}}
	if _, err := h.s.FetchReadResult(ctx, fetch); err != nil {
		t.Fatal(err)
	}
	// T10 / T10b: another owner, another tenant and an unknown ref are one sentinel.
	other := fetch
	other.PrincipalID = "prr-someone-else"
	foreign := fetch
	foreign.Tenant = "another-tenant"
	unknown := fetch
	unknown.ResultRef = "res_00000000000000000000000000"
	for name, f := range map[string]ReadFetch{"owner": other, "tenant": foreign, "unknown": unknown} {
		if _, err := h.s.FetchReadResult(ctx, f); !errors.Is(err, ErrCommandNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
	noScope := fetch
	noScope.Scopes = nil
	if _, err := h.s.FetchReadResult(ctx, noScope); !errors.Is(err, ErrReadNotAuthorized) {
		t.Errorf("no scope: %v", err)
	}
	// T12: a moved install revision, a revoked connection and a checker error.
	moved := fetch
	moved.InstallRevision = "8"
	if _, err := h.s.FetchReadResult(ctx, moved); !errors.Is(err, ErrBindingMismatch) {
		t.Errorf("moved revision: %v", err)
	}
	h.s.SetConnectionChecker(liveChecker{live: LiveConnection{ConnectionRef: h.req.ConnectionRef, InstallRevision: "8"}})
	if _, err := h.s.FetchReadResult(ctx, fetch); !errors.Is(err, ErrBindingMismatch) {
		t.Errorf("live revision moved: %v", err)
	}
	h.s.SetConnectionChecker(liveChecker{err: &NotLiveError{State: "connection_revoked"}})
	if _, err := h.s.FetchReadResult(ctx, fetch); !errors.Is(err, ErrBindingMismatch) {
		t.Errorf("revoked: %v", err)
	}
	h.s.SetConnectionChecker(liveChecker{err: errors.New("db down")})
	if _, err := h.s.FetchReadResult(ctx, fetch); !errors.Is(err, ErrReadUnavailable) {
		t.Errorf("checker error: %v", err)
	}
	h.s.SetConnectionChecker(nil)
	if _, err := h.s.FetchReadResult(ctx, fetch); !errors.Is(err, ErrReadUnavailable) {
		t.Errorf("default checker must deny: %v", err)
	}
	h.s.SetConnectionChecker(liveChecker{live: LiveConnection{ConnectionRef: h.req.ConnectionRef, InstallRevision: "7"}})

	// T9: a stored byte flipped by raw SQL fails closed.
	if _, err := h.s.pool.Exec(ctx, `UPDATE bridge_read_results SET data = set_byte(data, 2, get_byte(data, 2) # 1) WHERE result_ref = $1`, res.ResultRef); err != nil {
		t.Fatal(err)
	}
	if _, err := h.s.FetchReadResult(ctx, fetch); !errors.Is(err, ErrReadUnavailable) {
		t.Errorf("tampered bytes: %v", err)
	}

	// T11 / T14: after expiry the fetch says expired, the sweep erases the
	// bytes and the row is deleted 24 h later.
	if _, err := h.s.pool.Exec(ctx, `UPDATE bridge_read_results SET expires_at = clock_timestamp() - interval '1 second' WHERE result_ref = $1`, res.ResultRef); err != nil {
		t.Fatal(err)
	}
	if _, err := h.s.FetchReadResult(ctx, fetch); !errors.Is(err, ErrCommandExpired) {
		t.Errorf("expired: %v", err)
	}
	if _, _, err := h.s.EraseExpiredReads(ctx, 1000); err != nil {
		t.Fatal(err)
	}
	var nulled bool
	if err := h.s.pool.QueryRow(ctx, `SELECT data IS NULL AND erased_at IS NOT NULL FROM bridge_read_results WHERE result_ref = $1`, res.ResultRef).Scan(&nulled); err != nil || !nulled {
		t.Fatalf("bytes not erased: %v %v", nulled, err)
	}
	if _, err := h.s.pool.Exec(ctx, `UPDATE bridge_read_results SET expires_at = clock_timestamp() - interval '25 hours' WHERE result_ref = $1`, res.ResultRef); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.s.EraseExpiredReads(ctx, 1000); err != nil {
		t.Fatal(err)
	}
	var left int
	if err := h.s.pool.QueryRow(ctx, `SELECT count(*) FROM bridge_read_results WHERE result_ref = $1`, res.ResultRef).Scan(&left); err != nil || left != 0 {
		t.Fatalf("row not deleted: %d %v", left, err)
	}
}

// T7c: a provider that declares only v1alpha1 never receives a read command,
// and an unclaimed read expires without a signal-outbox row (T5b).
func TestReadCommandGatedAndExpires(t *testing.T) {
	h := newReadHarness(t, ReadBasket)
	ctx := context.Background()
	tx, err := h.s.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id, _, err := h.s.EnqueueRead(ctx, tx, ReadEnqueue{ProviderRef: "glovo", Request: h.req, TTL: time.Second})
	if err := finish(ctx, tx, err); err != nil {
		t.Fatal(err)
	}
	if got, err := h.s.Claim(ctx, h.caller(), 10, 0); err != nil || len(got) != 0 {
		t.Fatalf("v1alpha1-only provider claimed %d read command(s): %v", len(got), err)
	}
	time.Sleep(1500 * time.Millisecond)
	if n, err := h.s.ExpireDue(ctx, 1000); err != nil || n < 1 {
		t.Fatalf("expire: %d %v", n, err)
	}
	var status string
	var outbox int
	if err := h.s.pool.QueryRow(ctx, `SELECT status, (SELECT count(*) FROM bridge_signal_outbox WHERE command_id = $1) FROM bridge_commands WHERE command_id = $1`, id).Scan(&status, &outbox); err != nil {
		t.Fatal(err)
	}
	if status != StatusExpired || outbox != 0 {
		t.Fatalf("status %s, outbox rows %d", status, outbox)
	}
}

// T13: a read that times out cancels its command and answers ErrReadUnavailable;
// a late result is refused.
func TestReadTimeoutCancels(t *testing.T) {
	h := newReadHarness(t, ReadBasket)
	ctx := context.Background()
	h.req.Deadline = time.Now().Add(1500 * time.Millisecond)
	if _, err := (&ReadClient{Store: h.s}).Read(ctx, h.req); !errors.Is(err, ErrReadUnavailable) {
		t.Fatalf("timeout: %v", err)
	}
	var status string
	if err := h.s.pool.QueryRow(ctx, `SELECT status FROM bridge_commands WHERE tenant = $1`, h.tenant).Scan(&status); err != nil || status != StatusCancelled {
		t.Fatalf("status %q: %v", status, err)
	}
}

// T12: a refused request never enqueues; an empty install ref is invalid input.
func TestEnqueueReadRefusals(t *testing.T) {
	h := newReadHarness(t, ReadBasket)
	ctx := context.Background()
	for name, mut := range map[string]func(*ReadRequest){
		"empty revision":     func(r *ReadRequest) { r.InstallRevision = "" },
		"empty revision ref": func(r *ReadRequest) { r.InstallRevisionRef = "" },
		"bad kind":           func(r *ReadRequest) { r.Kind = "read_prepare" },
	} {
		r := h.req
		mut(&r)
		tx, err := h.s.Pool().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = h.s.EnqueueRead(ctx, tx, ReadEnqueue{ProviderRef: "glovo", Request: r, TTL: 10 * time.Second})
		_ = tx.Rollback(ctx)
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestEnqueueReadRefusedWhileWireVersionsDisabled(t *testing.T) {
	h := newReadHarness(t, KindReadHistory)
	h.s.wireEnabled.Store(false)
	ctx := context.Background()
	tx, err := h.s.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, _, err = h.s.EnqueueRead(ctx, tx, ReadEnqueue{ProviderRef: "glovo", Request: h.req, TTL: 10 * time.Second})
	if !errors.Is(err, ErrReadUnavailable) {
		t.Fatalf("EnqueueRead with wire versions disabled = %v, want ErrReadUnavailable", err)
	}
}

func TestClaimGatesV1alpha2RowsWhileWireVersionsDisabled(t *testing.T) {
	h := newReadHarness(t, KindReadHistory)
	ctx := context.Background()
	v1 := enqueue(t, h.s, h.tenant, KindPlaceOrderFake)
	v2 := enqueue(t, h.s, h.tenant, KindPlaceOrderFake)
	if _, err := h.s.Pool().Exec(ctx, `UPDATE bridge_commands SET wire_version=$1 WHERE command_id=$2`, WireV1alpha2, v2); err != nil {
		t.Fatal(err)
	}
	h.s.wireEnabled.Store(false)
	got, err := h.s.Claim(ctx, h.caller(), MaxClaimBatch, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, g := range got {
		ids = append(ids, g.CommandID)
	}
	if len(ids) != 1 || ids[0] != v1 {
		t.Fatalf("claimed %v, want only the v1alpha1 command %s (v1alpha2 %s must stay gated)", ids, v1, v2)
	}
}
