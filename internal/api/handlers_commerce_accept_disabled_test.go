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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/commerce"
)

// COMMERCE_ACCEPT_DISABLED (mctl-api#570) stops new paid acceptances only:
// quotes and accepts are refused with 422 unsupported-execution, and every
// route that drains outstanding liability stays live.

func TestCommerceAcceptDisabled_NilStoreStillWins(t *testing.T) {
	h := &Handlers{opts: Options{CommerceAcceptDisabled: true}}
	for name, fn := range map[string]http.HandlerFunc{"quote": h.MintCommerceQuote, "accept": h.AcceptCommerceInvocation} {
		rec := httptest.NewRecorder()
		fn(rec, adminCtx(httptest.NewRequest("POST", "/api/v1/commerce/tenants/acme/quotes", nil)))
		if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "commerce ledger not configured") {
			t.Errorf("%s with nil store and the switch on: want 503, got %d %s", name, rec.Code, rec.Body.String())
		}
	}
}

func TestCommerceAcceptDisabled_RefusesQuoteAndAcceptAfterAccessChecks(t *testing.T) {
	f := newCommerceFixture(t)
	f.publish(t)
	owner := tenantUser(t, "acme-owner", "acme", "prn_owner")
	// A quote minted before the switch, so the accept below is well-formed.
	_, q := f.mint(t, owner, "acme", nil)
	if q == nil {
		t.Fatal("mint before the switch failed")
	}
	logger := audit.NewLogger()
	f.h.opts.AuditLog = logger
	f.h.opts.CommerceAcceptDisabled = true

	rec, _ := f.mint(t, owner, "acme", nil)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), `"code":"unsupported-execution"`) {
		t.Fatalf("quote while paused: want 422 unsupported-execution, got %d %s", rec.Code, rec.Body.String())
	}
	rec, _ = f.accept(t, owner, "acme", q, "k-paused")
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), `"code":"unsupported-execution"`) {
		t.Fatalf("accept while paused: want 422 unsupported-execution, got %d %s", rec.Code, rec.Body.String())
	}

	// The access checks still answer first, so the refusal reveals nothing
	// about a tenant the caller cannot see.
	beta := tenantUser(t, "beta-owner", "beta", "prn_beta")
	if rec, _ = f.mint(t, beta, "acme", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant quote while paused: want 404, got %d %s", rec.Code, rec.Body.String())
	}
	if rec, _ = f.accept(t, beta, "acme", q, "k-beta"); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant accept while paused: want 404, got %d %s", rec.Code, rec.Body.String())
	}
	noPrincipal := tenantUser(t, "acme-owner", "acme", "")
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"quote":  func() *httptest.ResponseRecorder { r, _ := f.mint(t, noPrincipal, "acme", nil); return r }(),
		"accept": func() *httptest.ResponseRecorder { r, _ := f.accept(t, noPrincipal, "acme", q, "k-np"); return r }(),
	} {
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), commerce.ReasonIdentityUnresolved) {
			t.Fatalf("unresolved principal %s while paused: want 403 identity-unresolved, got %d %s", name, rec.Code, rec.Body.String())
		}
	}

	// Nothing was written: one quote (from before the switch), no invocation.
	var quotes, invocations int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM commerce_quotes WHERE capability_id = $1`, f.cap).Scan(&quotes); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM commerce_invocations WHERE capability_id = $1`, f.cap).Scan(&invocations); err != nil {
		t.Fatal(err)
	}
	if quotes != 1 || invocations != 0 {
		t.Fatalf("rows while paused: quotes=%d invocations=%d, want 1 and 0", quotes, invocations)
	}

	// Each refusal is audited as denied under its own operation.
	denied := map[string]int{}
	for _, e := range logger.List(100) {
		if e.Status == "denied" && strings.Contains(e.Message, "COMMERCE_ACCEPT_DISABLED") {
			denied[e.Operation]++
		}
	}
	if denied["commerce-quote-mint"] != 1 || denied["commerce-invocation-accept"] != 1 {
		t.Fatalf("denied audit entries = %v, want one quote-mint and one invocation-accept", denied)
	}
}

func TestCommerceAcceptDisabled_LiabilityStillDrains(t *testing.T) {
	f := newCommerceFixture(t)
	f.publish(t)
	if rec := f.setBudget(t, "acme", 100, 50); rec.Code != http.StatusOK {
		t.Fatalf("set budget: %d %s", rec.Code, rec.Body.String())
	}
	f.store.UseDispatchSigner(testDispatchSigner(t))
	owner := tenantUser(t, "acme-owner", "acme", "prn_owner")
	newInvocation := func(key string) string {
		_, q := f.mint(t, owner, "acme", nil)
		rec, res := f.accept(t, owner, "acme", q, key)
		if res == nil {
			t.Fatalf("accept %s: %d %s", key, rec.Code, rec.Body.String())
		}
		return res.InvocationID
	}
	// Four rows accepted before the switch; two of them reserved.
	quoteExpired := newInvocation("k-quote-expired")
	deadlinePassed := newInvocation("k-deadline")
	toFinalize := newInvocation("k-finalize")
	toRelease := newInvocation("k-release")
	for _, id := range []string{deadlinePassed, toFinalize, toRelease} {
		if rec := f.money(t, "reserve", "acme", id, nil); rec.Code != http.StatusOK {
			t.Fatalf("reserve %s: %d %s", id, rec.Code, rec.Body.String())
		}
	}

	f.h.opts.CommerceAcceptDisabled = true

	// Time-driven drain: the reconciler still refuses and releases.
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `UPDATE commerce_invocations SET quote_expires_at = now() - interval '1 minute' WHERE invocation_id = $1`, quoteExpired); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE commerce_invocations SET reservation_deadline = now() - interval '1 minute' WHERE invocation_id = $1`, deadlinePassed); err != nil {
		t.Fatal(err)
	}
	rec := f.call(t, commerceAdmin(t), "POST", "/api/v1/commerce/reconcile/expired?limit=500", nil, nil, f.h.ReconcileCommerceExpired)
	if rec.Code != http.StatusOK {
		t.Fatalf("reconcile while paused: %d %s", rec.Code, rec.Body.String())
	}
	var res commerce.ExpireResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if !contains(res.Refused, quoteExpired) || !contains(res.Released, deadlinePassed) {
		t.Fatalf("reconcile while paused = %+v, want %s refused and %s released", res, quoteExpired, deadlinePassed)
	}

	// Outcome-driven drain: dispatch, finalize and release still work.
	if rec = f.dispatch(t, "acme", toFinalize); rec.Code != http.StatusOK {
		t.Fatalf("dispatch while paused: %d %s", rec.Code, rec.Body.String())
	}
	if rec = f.transition(t, "acme", toFinalize, "dispatching", "dispatched"); rec.Code != http.StatusOK {
		t.Fatalf("dispatched while paused: %d %s", rec.Code, rec.Body.String())
	}
	if rec = f.money(t, "finalize", "acme", toFinalize, map[string]any{"execution_outcome": "succeeded"}); rec.Code != http.StatusOK {
		t.Fatalf("finalize while paused: %d %s", rec.Code, rec.Body.String())
	}
	if rec = f.money(t, "release", "acme", toRelease, map[string]any{"reason_code": "provider-unavailable"}); rec.Code != http.StatusOK {
		t.Fatalf("release while paused: %d %s", rec.Code, rec.Body.String())
	}

	want := map[string]string{quoteExpired: "refused", deadlinePassed: "released", toFinalize: "finalized", toRelease: "released"}
	for id, phase := range want {
		rec = f.call(t, owner, "GET", "/api/v1/commerce/tenants/acme/invocations/"+id, nil,
			map[string]string{"tenant": "acme", "invocation_id": id}, f.h.GetCommerceInvocation)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"phase":"`+phase+`"`) {
			t.Fatalf("invocation %s while paused: want 200 phase %s, got %d %s", id, phase, rec.Code, rec.Body.String())
		}
	}

	// The reads a tenant and an operator need stay live.
	params := map[string]string{"tenant": "acme"}
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"terms":       f.call(t, owner, "GET", "/api/v1/commerce/terms?capability_id="+url.QueryEscape(f.cap), nil, nil, f.h.ListCommerceTerms),
		"budget":      f.call(t, owner, "GET", "/api/v1/commerce/tenants/acme/budget", nil, params, f.h.GetCommerceBudget),
		"invocations": f.call(t, owner, "GET", "/api/v1/commerce/tenants/acme/invocations", nil, params, f.h.ListCommerceInvocations),
		"transitions": f.call(t, owner, "GET", "/api/v1/commerce/tenants/acme/invocations/"+toFinalize+"/transitions", nil,
			map[string]string{"tenant": "acme", "invocation_id": toFinalize}, f.h.ListCommerceInvocationTransitions),
		"overdue": f.call(t, commerceAdmin(t), "GET", "/api/v1/commerce/invocations/overdue", nil, nil, f.h.ListOverdueCommerceInvocations),
	} {
		if rec.Code != http.StatusOK {
			t.Errorf("%s while paused: want 200, got %d %s", name, rec.Code, rec.Body.String())
		}
	}
}
