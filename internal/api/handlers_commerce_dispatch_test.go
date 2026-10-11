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

package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/commerce"
)

func (f *commerceFixture) dispatch(t *testing.T, tenant, id string) *httptest.ResponseRecorder {
	t.Helper()
	return f.call(t, commerceAdmin(t), "POST", "/api/v1/commerce/tenants/"+tenant+"/invocations/"+id+"/dispatch",
		nil, map[string]string{"tenant": tenant, "invocation_id": id}, f.h.DispatchCommerceInvocation)
}

// reservedOverHTTP takes one invocation of the fixture capability to
// reserved and returns its id.
func (f *commerceFixture) reservedOverHTTP(t *testing.T, key string) string {
	t.Helper()
	owner := tenantUser(t, "acme-owner", "acme", "prn_owner")
	_, q := f.mint(t, owner, "acme", nil)
	if q == nil {
		t.Fatal("mint failed")
	}
	_, acc := f.accept(t, owner, "acme", q, key)
	if acc == nil {
		t.Fatal("accept failed")
	}
	if rec := f.money(t, "reserve", "acme", acc.InvocationID, map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("reserve: %d %s", rec.Code, rec.Body.String())
	}
	return acc.InvocationID
}

func TestCommerceDispatch_SignedFencedAndOwnedByItsEndpoint(t *testing.T) {
	f := newCommerceFixture(t)
	f.publish(t)
	if rec := f.setBudget(t, "acme", 100, 50); rec.Code != http.StatusOK {
		t.Fatalf("set budget: %d %s", rec.Code, rec.Body.String())
	}
	id := f.reservedOverHTTP(t, "k-dispatch")

	// Without a signing key nothing is dispatched: 503, the row unchanged.
	if rec := f.dispatch(t, "acme", id); rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "dispatch-unavailable") {
		t.Fatalf("dispatch without key: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.call(t, commerceAdmin(t), "GET", "/api/v1/commerce/dispatch-keys", nil, nil, f.h.ListCommerceDispatchKeys); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("keys without key: %d", rec.Code)
	}

	signer := testDispatchSigner(t)
	f.store.UseDispatchSigner(signer)
	auditLog := audit.NewLogger()
	f.h.opts.AuditLog = auditLog

	// The generic transition does not own the dispatching edge.
	if rec := f.transition(t, "acme", id, commerce.PhaseReserved, commerce.PhaseDispatching); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "/dispatch") {
		t.Fatalf("generic transition to dispatching: %d %s", rec.Code, rec.Body.String())
	}
	// A tenant owner cannot dispatch its own invocation.
	owner := tenantUser(t, "acme-owner", "acme", "prn_owner")
	if rec := f.call(t, owner, "POST", "/api/v1/commerce/tenants/acme/invocations/"+id+"/dispatch", map[string]any{},
		map[string]string{"tenant": "acme", "invocation_id": id}, f.h.DispatchCommerceInvocation); rec.Code != http.StatusForbidden {
		t.Fatalf("owner dispatch: want 403, got %d", rec.Code)
	}

	rec := f.dispatch(t, "acme", id)
	if rec.Code != http.StatusOK {
		t.Fatalf("dispatch: %d %s", rec.Code, rec.Body.String())
	}
	var res commerce.DispatchResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Replayed || res.Invocation.Phase != commerce.PhaseDispatching || res.Authorization.TenantID != "acme" ||
		res.Authorization.ProviderID != "pilot-provider" || res.Authorization.InputSchemaHash != commerceTestSchemaHash {
		t.Fatalf("dispatch = %+v", res)
	}
	if err := commerce.VerifyDispatchAuthorization(signer.PublicKey(), res.Authorization); err != nil {
		t.Fatalf("authorization does not verify: %v", err)
	}
	// The body carries no arguments, results or money.
	for _, leak := range []string{"amount_minor", "currency", "arguments", "result"} {
		if strings.Contains(string(mustJSON(t, res.Authorization)), leak) {
			t.Fatalf("authorization carries %q", leak)
		}
	}
	// A body is optional, but an unknown field in one is still refused.
	if rec := f.call(t, commerceAdmin(t), "POST", "/api/v1/commerce/tenants/acme/invocations/"+id+"/dispatch", map[string]any{"amount_minor": 1},
		map[string]string{"tenant": "acme", "invocation_id": id}, f.h.DispatchCommerceInvocation); rec.Code != http.StatusBadRequest {
		t.Fatalf("dispatch with an unknown field: want 400, got %d", rec.Code)
	}
	again := f.dispatch(t, "acme", id)
	var res2 commerce.DispatchResult
	if err := json.Unmarshal(again.Body.Bytes(), &res2); err != nil || !res2.Replayed || res2.Authorization != res.Authorization {
		t.Fatalf("replay = %d %s", again.Code, again.Body.String())
	}
	// Every hand-out of the signed authorization is audited: one first
	// dispatch, then one row per replay.
	statuses := map[string]int{}
	for _, e := range auditLog.List(100) {
		if e.Operation == "commerce-dispatch" && e.Status != "failed" {
			statuses[e.Status]++
		}
	}
	if statuses["succeeded"] != 1 || statuses["replayed"] != 1 || len(statuses) != 2 {
		t.Fatalf("dispatch audit = %v", statuses)
	}

	keys := f.call(t, owner, "GET", "/api/v1/commerce/dispatch-keys", nil, nil, f.h.ListCommerceDispatchKeys)
	want := base64.RawURLEncoding.EncodeToString(signer.PublicKey())
	if keys.Code != http.StatusOK || !strings.Contains(keys.Body.String(), want) || !strings.Contains(keys.Body.String(), `"algorithm":"ed25519"`) {
		t.Fatalf("keys: %d %s", keys.Code, keys.Body.String())
	}
}

func TestCommerceAccept_ApprovalBindsOneInvocationOverHTTP(t *testing.T) {
	f := newCommerceFixture(t)
	f.publish(t)
	owner := tenantUser(t, "acme-owner", "acme", "prn_owner")
	approval := "aar_" + strings.ToLower(t.Name())
	acceptWith := func(key string) (int, string) {
		_, q := f.mint(t, owner, "acme", nil)
		rec := f.call(t, owner, "POST", "/api/v1/commerce/tenants/acme/invocations", map[string]any{
			"quote_id": q.QuoteID, "quote_digest": q.QuoteDigest, "idempotency_key": key, "args_digest": q.ArgsDigest,
			"execution_id": q.ExecutionID, "approval_id": approval,
		}, map[string]string{"tenant": "acme"}, f.h.AcceptCommerceInvocation)
		return rec.Code, rec.Body.String()
	}
	if code, body := acceptWith("k-a"); code != http.StatusCreated {
		t.Fatalf("first: %d %s", code, body)
	}
	if code, body := acceptWith("k-b"); code != http.StatusConflict || !strings.Contains(body, `"policy-denied"`) {
		t.Fatalf("second invocation on one approval: %d %s", code, body)
	}
}

func TestCommerceList_FindsByIdempotencyKeyForTheCallerOnly(t *testing.T) {
	f := newCommerceFixture(t)
	f.publish(t)
	owner := tenantUser(t, "acme-owner", "acme", "prn_owner")
	_, q := f.mint(t, owner, "acme", nil)
	_, acc := f.accept(t, owner, "acme", q, "gw:key-1")
	list := func(key string) (int, string) {
		rec := f.call(t, owner, "GET", "/api/v1/commerce/tenants/acme/invocations?idempotency_key="+key, nil,
			map[string]string{"tenant": "acme"}, f.h.ListCommerceInvocations)
		return rec.Code, rec.Body.String()
	}
	code, body := list("gw:key-1")
	if code != http.StatusOK || !strings.Contains(body, acc.InvocationID) {
		t.Fatalf("lookup: %d %s", code, body)
	}
	if code, body := list("gw:key-other"); code != http.StatusOK || strings.Contains(body, acc.InvocationID) {
		t.Fatalf("other key: %d %s", code, body)
	}
	// An admin is another principal: the key does not find the owner's row.
	rec := f.call(t, commerceAdmin(t), "GET", "/api/v1/commerce/tenants/acme/invocations?idempotency_key=gw:key-1", nil,
		map[string]string{"tenant": "acme"}, f.h.ListCommerceInvocations)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), acc.InvocationID) {
		t.Fatalf("admin lookup of the owner's key: %d %s", rec.Code, rec.Body.String())
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testDispatchSigner(t *testing.T) *commerce.DispatchSigner {
	t.Helper()
	signer, err := commerce.NewDispatchSigner("kid-api-test", []byte(strings.Repeat("\x09", ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	return signer
}
