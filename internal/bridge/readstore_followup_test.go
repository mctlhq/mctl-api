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

	"github.com/mctlhq/mctl-api/internal/jcs"
)

// Follow-up to the #986 bridge change: basket cross-field rules and the
// submit-side bindings that a reviewer found untested.

// tamperedResult builds a read result from a vendored fixture for a claimed
// command, lets mutate edit the payload, and recomputes payload_digest, so
// the only thing wrong with the body is what mutate broke.
func tamperedResult(t *testing.T, claimed json.RawMessage, fixtureName string, mutate func(payload map[string]any)) []byte {
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
	payload := res["payload"].(map[string]any)
	mutate(payload)
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := jcs.Canonicalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	res["payload_digest"] = digestOf(canon)
	out, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func basketOf(payload map[string]any) map[string]any { return payload["approval_basket"].(map[string]any) }

func bumpMinor(m map[string]any, key string) {
	n, _ := m[key].(json.Number).Int64()
	m[key] = json.Number(fmt.Sprint(n + 1))
}

// enqueueClaimRead enqueues one read of the harness kind and leases it as a
// v1alpha2 provider.
func (h *readHarness) enqueueClaimRead(t *testing.T) (id string, claimed json.RawMessage) {
	t.Helper()
	ctx := context.Background()
	if h.req.Kind == ReadPreview && len(h.req.Params) == 0 {
		h.req.Params = json.RawMessage(`{"history_order_ref":"pho_0123456789abcdef0123"}`)
	}
	tx, err := h.s.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id, _, err = h.s.EnqueueRead(ctx, tx, ReadEnqueue{ProviderRef: "glovo", Request: h.req, TTL: 60 * time.Second})
	if err := finish(ctx, tx, err); err != nil {
		t.Fatal(err)
	}
	got, err := h.s.Claim(ctx, h.caller(WireV1alpha1, WireV1alpha2), MaxClaimBatch, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range got {
		if g.CommandID == id {
			return id, g.Command
		}
	}
	t.Fatalf("read command %s not claimed", id)
	return "", nil
}

func (h *readHarness) storedResults(t *testing.T) int {
	t.Helper()
	var n int
	if err := h.s.pool.QueryRow(context.Background(), `SELECT count(*) FROM bridge_read_results WHERE tenant=$1`, h.tenant).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

var basketRuleCases = map[string]func(p map[string]any){
	"total_minor plus one": func(p map[string]any) { bumpMinor(basketOf(p), "total_minor") },
	"subtotal_minor plus one": func(p map[string]any) {
		bumpMinor(basketOf(p), "subtotal_minor")
		bumpMinor(basketOf(p), "total_minor") // keep the total identity, break the subtotal one
	},
	"unsorted lines": func(p map[string]any) {
		l := basketOf(p)["lines"].([]any)
		l[0], l[1] = l[1], l[0]
	},
	"duplicate item_code": func(p map[string]any) {
		l := basketOf(p)["lines"].([]any)
		l[1].(map[string]any)["item_code"] = l[0].(map[string]any)["item_code"]
	},
	"display item_code not a basket line": func(p map[string]any) {
		p["display"].([]any)[0].(map[string]any)["item_code"] = "FAKE-NOT-IN-BASKET"
	},
}

// A basket that breaks a rule JSON Schema cannot express is invalid_document
// and is never stored, even though its payload_digest was recomputed and
// matches.
func TestSubmitReadRefusesBasketRuleViolations(t *testing.T) {
	for _, tc := range []struct {
		kind    ReadKind
		fixture string
	}{{ReadPreview, "read-result.preview.valid.json"}, {ReadBasket, "read-result.basket.valid.json"}} {
		for name, mut := range basketRuleCases {
			t.Run(string(tc.kind)+"/"+name, func(t *testing.T) {
				h := newReadHarness(t, tc.kind)
				id, claimed := h.enqueueClaimRead(t)
				body := tamperedResult(t, claimed, tc.fixture, mut)
				doc, err := parseAnyResult(body)
				if err != nil {
					t.Fatalf("the tampered body must pass the schema stage so the basket rule is what refuses it: %v", err)
				}
				if _, err := doc.v2.canonicalPayload(); err != nil {
					t.Fatalf("the digest was recomputed, canonicalPayload must pass: %v", err)
				}
				_, err = h.s.SubmitResult(context.Background(), h.caller(WireV1alpha1, WireV1alpha2), id, body)
				if !errors.Is(err, ErrInvalidDocument) {
					t.Fatalf("submit = %v, want ErrInvalidDocument", err)
				}
				if n := h.storedResults(t); n != 0 {
					t.Fatalf("%d result row(s) stored for a refused basket", n)
				}
				if st := pgStatus(t, h, id); st != StatusLeased {
					t.Fatalf("status %s, want the command to stay leased", st)
				}
			})
		}
	}
	t.Run("preview unavailable_items overlaps a basket line", func(t *testing.T) {
		h := newReadHarness(t, ReadPreview)
		id, claimed := h.enqueueClaimRead(t)
		body := tamperedResult(t, claimed, "read-result.preview.valid.json", func(p map[string]any) {
			p["unavailable_items"] = []any{"FAKE-MILK"}
		})
		_, err := h.s.SubmitResult(context.Background(), h.caller(WireV1alpha1, WireV1alpha2), id, body)
		if !errors.Is(err, ErrInvalidDocument) {
			t.Fatalf("submit = %v, want ErrInvalidDocument", err)
		}
	})
	t.Run("valid payload is stored", func(t *testing.T) {
		h := newReadHarness(t, ReadPreview)
		id, claimed := h.enqueueClaimRead(t)
		body := tamperedResult(t, claimed, "read-result.preview.valid.json", func(map[string]any) {})
		if _, err := h.s.SubmitResult(context.Background(), h.caller(WireV1alpha1, WireV1alpha2), id, body); err != nil {
			t.Fatal(err)
		}
		if n := h.storedResults(t); n != 1 {
			t.Fatalf("%d rows stored", n)
		}
	})
}

func pgStatus(t *testing.T, h *readHarness, id string) string {
	t.Helper()
	var st string
	if err := h.s.pool.QueryRow(context.Background(), `SELECT status FROM bridge_commands WHERE command_id=$1`, id).Scan(&st); err != nil {
		t.Fatal(err)
	}
	return st
}

// The rule check also stands alone, without a database.
func TestCheckReadPayloadRules(t *testing.T) {
	for _, fx := range []string{"read-result.preview.valid.json", "read-result.basket.valid.json"} {
		var d struct {
			Kind    string          `json:"kind"`
			Payload json.RawMessage `json:"payload"`
		}
		if err := json.Unmarshal(v2fixture(t, fx), &d); err != nil {
			t.Fatal(err)
		}
		if err := checkReadPayloadRules(d.Kind, d.Payload); err != nil {
			t.Fatalf("%s: %v", fx, err)
		}
		var m map[string]any
		dec := json.NewDecoder(bytes.NewReader(d.Payload))
		dec.UseNumber()
		if err := dec.Decode(&m); err != nil {
			t.Fatal(err)
		}
		bumpMinor(basketOf(m), "total_minor")
		raw, _ := json.Marshal(m)
		if err := checkReadPayloadRules(d.Kind, raw); !errors.Is(err, ErrInvalidDocument) {
			t.Fatalf("%s: tampered total accepted: %v", fx, err)
		}
	}
	// read_history carries no basket and is not checked.
	if err := checkReadPayloadRules(KindReadHistory, []byte(`{"anything":true}`)); err != nil {
		t.Fatal(err)
	}
}

// A v1alpha2 place_order_fake payload is the approval basket itself: a broken
// basket is refused at Enqueue and nothing is written.
func TestEnqueueV2WriteRefusesBrokenBasket(t *testing.T) {
	h := newReadHarness(t, ReadHistory)
	ctx := context.Background()
	var cmd struct {
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(v2fixture(t, "command-place-order-fake.valid.json"), &cmd); err != nil {
		t.Fatal(err)
	}
	mk := func(payload []byte, key string) EnqueueInput {
		pgSeq++
		suffix := fmt.Sprintf("%016d", time.Now().UnixNano()%1e15+int64(pgSeq))
		return EnqueueInput{
			ExecutionID: "we_" + suffix, WorkItemID: "wi_" + suffix, WorkflowID: "wf-" + suffix, Tenant: h.tenant,
			OwnerPrincipalID: "owner", TenantRef: "tnr_" + suffix, PrincipalRef: "prr_" + suffix, OrderRef: "ordr_" + suffix,
			ConnectionRef: "gcn_" + suffix, InstallRevision: "r1", ProviderRef: "glovo", Kind: KindPlaceOrderFake, Attempt: 1,
			OperationKey: key + suffix, IntentHash: "sha256:" + strings.Repeat("0", 64), ApprovalRef: "aar_" + suffix,
			Payload: payload, WireVersion: WireV1alpha2,
		}
	}
	enq := func(in EnqueueInput) error {
		tx, err := h.s.Pool().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = h.s.Enqueue(ctx, tx, in)
		return finish(ctx, tx, err)
	}
	if err := enq(mk(cmd.Payload, "ok-")); err != nil {
		t.Fatalf("valid v2 write: %v", err)
	}
	bad := bytes.Replace(cmd.Payload, []byte(`"total_minor": 749`), []byte(`"total_minor": 750`), 1)
	if bytes.Equal(bad, cmd.Payload) {
		t.Fatal("fixture total changed; update the test")
	}
	if err := enq(mk(bad, "bad-")); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("v2 write with total+1 = %v, want ErrInvalidDocument", err)
	}
	var n int
	if err := h.s.pool.QueryRow(ctx, `SELECT count(*) FROM bridge_commands WHERE tenant=$1`, h.tenant).Scan(&n); err != nil || n != 1 {
		t.Fatalf("%d commands, want only the valid one: %v", n, err)
	}
}

// With wire versions off the Enqueue of a v2 write is refused and writes
// nothing.
func TestEnqueueV2WriteRefusedWhileWireVersionsDisabled(t *testing.T) {
	h := newReadHarness(t, ReadHistory)
	ctx := context.Background()
	var cmd struct {
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(v2fixture(t, "command-place-order-fake.valid.json"), &cmd); err != nil {
		t.Fatal(err)
	}
	h.s.wireEnabled.Store(false)
	pgSeq++
	suffix := fmt.Sprintf("%016d", time.Now().UnixNano()%1e15+int64(pgSeq))
	in := EnqueueInput{
		ExecutionID: "we_" + suffix, WorkItemID: "wi_" + suffix, WorkflowID: "wf-" + suffix, Tenant: h.tenant,
		OwnerPrincipalID: "owner", TenantRef: "tnr_" + suffix, PrincipalRef: "prr_" + suffix, OrderRef: "ordr_" + suffix,
		ConnectionRef: "gcn_" + suffix, InstallRevision: "r1", ProviderRef: "glovo", Kind: KindPlaceOrderFake, Attempt: 1,
		OperationKey: "op-" + suffix, IntentHash: "sha256:" + strings.Repeat("0", 64), ApprovalRef: "aar_" + suffix,
		Payload: cmd.Payload, WireVersion: WireV1alpha2,
	}
	tx, err := h.s.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = h.s.Enqueue(ctx, tx, in)
	_ = finish(ctx, tx, err)
	if !errors.Is(err, ErrReadUnavailable) {
		t.Fatalf("v2 enqueue with the flag off = %v, want ErrReadUnavailable", err)
	}
	var n int
	if err := h.s.pool.QueryRow(ctx, `SELECT count(*) FROM bridge_commands WHERE tenant=$1`, h.tenant).Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d commands written with the flag off: %v", n, err)
	}
}

// EnqueueRead refuses a caller without glovo:read at enqueue, not only at fetch.
func TestEnqueueReadRefusedWithoutReadScope(t *testing.T) {
	h := newReadHarness(t, ReadBasket)
	ctx := context.Background()
	for _, scopes := range [][]string{nil, {"glovo:write"}} {
		r := h.req
		r.Scopes = scopes
		tx, err := h.s.Pool().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = h.s.EnqueueRead(ctx, tx, ReadEnqueue{ProviderRef: "glovo", Request: r, TTL: 10 * time.Second})
		_ = tx.Rollback(ctx)
		if !errors.Is(err, ErrReadNotAuthorized) {
			t.Errorf("scopes %v: %v, want ErrReadNotAuthorized", scopes, err)
		}
	}
	var n int
	if err := h.s.pool.QueryRow(ctx, `SELECT count(*) FROM bridge_commands WHERE tenant=$1`, h.tenant).Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d commands written: %v", n, err)
	}
}

// The submit-side bindings of a read result, each with the one thing wrong.
func TestSubmitReadBindings(t *testing.T) {
	ctx := context.Background()
	t.Run("request_id of another command", func(t *testing.T) {
		h := newReadHarness(t, ReadBasket)
		id, claimed := h.enqueueClaimRead(t)
		body := tamperedResult(t, claimed, "read-result.basket.valid.json", func(map[string]any) {})
		// well formed, but not this command's request_id
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		m["request_id"] = "rdq_ZZZZZZZZZZZZZZZZZZZZZZZZZZ"
		body, _ = json.Marshal(m)
		if _, err := h.s.SubmitResult(ctx, h.caller(WireV1alpha1, WireV1alpha2), id, body); !errors.Is(err, ErrBindingMismatch) {
			t.Fatalf("foreign request_id = %v, want ErrBindingMismatch", err)
		}
		if st := pgStatus(t, h, id); st != StatusLeased {
			t.Fatalf("status %s", st)
		}
	})
	t.Run("lease token on a completed command", func(t *testing.T) {
		// leaseLive does not run for a completed row: only the token compare
		// above it stops a replay from a holder that never had the lease.
		h := newReadHarness(t, ReadBasket)
		id, claimed := h.enqueueClaimRead(t)
		body := tamperedResult(t, claimed, "read-result.basket.valid.json", func(map[string]any) {})
		caller := h.caller(WireV1alpha1, WireV1alpha2)
		if _, err := h.s.SubmitResult(ctx, caller, id, body); err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		m["lease_token"] = "lt_ffffffffffffffffffff"
		bad, _ := json.Marshal(m)
		if _, err := h.s.SubmitResult(ctx, caller, id, bad); !errors.Is(err, ErrLeaseStale) {
			t.Fatalf("replay with a wrong token = %v, want ErrLeaseStale", err)
		}
		if out, err := h.s.SubmitResult(ctx, caller, id, body); err != nil || !out.Replayed {
			t.Fatalf("replay with the right token = %+v, %v", out, err)
		}
	})
	t.Run("lease token on a leased command", func(t *testing.T) {
		h := newReadHarness(t, ReadBasket)
		id, claimed := h.enqueueClaimRead(t)
		body := tamperedResult(t, claimed, "read-result.basket.valid.json", func(map[string]any) {})
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		m["lease_token"] = "lt_ffffffffffffffffffff"
		bad, _ := json.Marshal(m)
		if _, err := h.s.SubmitResult(ctx, h.caller(WireV1alpha1, WireV1alpha2), id, bad); !errors.Is(err, ErrLeaseStale) {
			t.Fatalf("wrong token = %v, want ErrLeaseStale", err)
		}
	})
	t.Run("result kind differs from the command kind", func(t *testing.T) {
		h := newReadHarness(t, ReadBasket)
		id, claimed := h.enqueueClaimRead(t)
		// A self-consistent read_preview result for a read_basket command.
		body := tamperedResult(t, claimed, "read-result.preview.valid.json", func(map[string]any) {})
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		m["kind"] = KindReadPreview
		body, _ = json.Marshal(m)
		if _, err := h.s.SubmitResult(ctx, h.caller(WireV1alpha1, WireV1alpha2), id, body); !errors.Is(err, ErrBindingMismatch) {
			t.Fatalf("kind mismatch = %v, want ErrBindingMismatch", err)
		}
		if n := h.storedResults(t); n != 0 {
			t.Fatalf("%d result rows stored", n)
		}
	})
	t.Run("v1alpha2 result for a write command", func(t *testing.T) {
		h := newReadHarness(t, ReadBasket)
		id := enqueue(t, h.s, h.tenant, KindPlaceOrderFake)
		got, err := h.s.Claim(ctx, h.caller(WireV1alpha1, WireV1alpha2), MaxClaimBatch, time.Minute)
		if err != nil || len(got) != 1 || got[0].CommandID != id {
			t.Fatalf("claim: %v %v", got, err)
		}
		var cmd map[string]any
		_ = json.Unmarshal(got[0].Command, &cmd)
		// request_id and kind are arbitrary: the version/kind check comes first.
		res := resultFor(t, json.RawMessage(fmt.Sprintf(`{"command_id":%q,"request_id":"rdq_ZZZZZZZZZZZZZZZZZZZZZZZZZZ","lease_token":%q,"kind":"read_basket"}`,
			id, cmd["lease_token"])), "read-result.basket.valid.json")
		_, err = h.s.SubmitResult(ctx, h.caller(WireV1alpha1, WireV1alpha2), id, res)
		if !errors.Is(err, ErrBindingMismatch) || !strings.Contains(err.Error(), "result version does not match the command") {
			t.Fatalf("v2 result for a write = %v, want the version-mismatch ErrBindingMismatch", err)
		}
	})
	t.Run("v1alpha1 result for a read command", func(t *testing.T) {
		h := newReadHarness(t, ReadBasket)
		id, claimed := h.enqueueClaimRead(t)
		var cmd map[string]any
		_ = json.Unmarshal(claimed, &cmd)
		body, _ := json.Marshal(map[string]any{
			"schema_version": SchemaVersion, "command_id": id, "execution_id": "we_0123456789abcdef0123", "lease_token": cmd["lease_token"],
			"attempt": 1, "worker_identity": "provider:glovo", "outcome": "succeeded", "provider_effect": "none",
			"completed_at": "2026-11-08T10:01:00Z",
		})
		_, err := h.s.SubmitResult(ctx, h.caller(WireV1alpha1, WireV1alpha2), id, body)
		if !errors.Is(err, ErrBindingMismatch) || !strings.Contains(err.Error(), "a read command takes a v1alpha2 result") {
			t.Fatalf("v1 result for a read = %v, want the read-kind guard", err)
		}
		if st := pgStatus(t, h, id); st != StatusLeased {
			t.Fatalf("status %s", st)
		}
	})
}

// With wire versions off but the read level present, claim is pinned to
// wire_version v1alpha1: a v1alpha2 place_order_fake row and every read kind
// stay unleased, and the v1alpha1 row is still served.
func TestClaimFallbackPinsV1alpha1WithoutWireVersions(t *testing.T) {
	h := newReadHarness(t, ReadBasket)
	ctx := context.Background()
	v1 := enqueue(t, h.s, h.tenant, KindPlaceOrderFake)
	v2 := enqueue(t, h.s, h.tenant, KindPlaceOrderFake)
	if _, err := h.s.Pool().Exec(ctx, `UPDATE bridge_commands SET wire_version=$1 WHERE command_id=$2`, WireV1alpha2, v2); err != nil {
		t.Fatal(err)
	}
	tx, err := h.s.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	readID, _, err := h.s.EnqueueRead(ctx, tx, ReadEnqueue{ProviderRef: "glovo", Request: h.req, TTL: time.Minute})
	if err := finish(ctx, tx, err); err != nil {
		t.Fatal(err)
	}
	h.s.wireEnabled.Store(false)
	// Even a caller that declares v1alpha2 gets nothing but the v1alpha1 row.
	got, err := h.s.Claim(ctx, h.caller(WireV1alpha1, WireV1alpha2), MaxClaimBatch, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].CommandID != v1 {
		var ids []string
		for _, g := range got {
			ids = append(ids, g.CommandID)
		}
		t.Fatalf("claimed %v, want only %s (v2 write %s and read %s must stay unleased)", ids, v1, v2, readID)
	}
	for _, id := range []string{v2, readID} {
		if st := pgStatus(t, h, id); st != StatusPending {
			t.Errorf("%s is %s, want pending", id, st)
		}
	}
}
