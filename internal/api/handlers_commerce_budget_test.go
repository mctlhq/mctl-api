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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/commerce"
)

func (f *commerceFixture) setBudget(t *testing.T, tenant string, monthly, perRequest int64) *httptest.ResponseRecorder {
	t.Helper()
	return f.call(t, commerceAdmin(t), "PUT", "/api/v1/commerce/tenants/"+tenant+"/budget",
		map[string]any{"currency": "EUR", "monthly_limit_minor": monthly, "per_request_max_minor": perRequest, "reason": "test"},
		map[string]string{"tenant": tenant}, f.h.SetCommerceBudget)
}

func (f *commerceFixture) money(t *testing.T, action, tenant, id string, body any) *httptest.ResponseRecorder {
	t.Helper()
	fn := map[string]http.HandlerFunc{"reserve": f.h.ReserveCommerceInvocation, "finalize": f.h.FinalizeCommerceInvocation,
		"release": f.h.ReleaseCommerceInvocation}[action]
	return f.call(t, commerceAdmin(t), "POST", "/api/v1/commerce/tenants/"+tenant+"/invocations/"+id+"/"+action, body,
		map[string]string{"tenant": tenant, "invocation_id": id}, fn)
}

func (f *commerceFixture) transition(t *testing.T, tenant, id, from, to string) *httptest.ResponseRecorder {
	t.Helper()
	return f.call(t, commerceAdmin(t), "POST", "/api/v1/commerce/tenants/"+tenant+"/invocations/"+id+"/transitions",
		map[string]any{"expected_phase": from, "to_phase": to}, map[string]string{"tenant": tenant, "invocation_id": id},
		f.h.TransitionCommerceInvocation)
}

func TestCommerceBudget_GrantedByAdminReadByTenant(t *testing.T) {
	f := newCommerceFixture(t)
	owner := tenantUser(t, "acme-owner", "acme", "prn_owner")
	params := map[string]string{"tenant": "acme"}
	body := map[string]any{"currency": "EUR", "monthly_limit_minor": 100, "per_request_max_minor": 50, "reason": "self"}

	// No self-granted limits: the tenant owner cannot set its own budget.
	rec := f.call(t, owner, "PUT", "/api/v1/commerce/tenants/acme/budget", body, params, f.h.SetCommerceBudget)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("owner set budget: want 403, got %d %s", rec.Code, rec.Body.String())
	}
	// Before a budget exists the read is 404, the same as another tenant's.
	rec = f.call(t, owner, "GET", "/api/v1/commerce/tenants/acme/budget", nil, params, f.h.GetCommerceBudget)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("budget before grant: want 404, got %d", rec.Code)
	}
	// A change without a reason is refused: the audit is explicit.
	rec = f.call(t, commerceAdmin(t), "PUT", "/api/v1/commerce/tenants/acme/budget",
		map[string]any{"currency": "EUR", "monthly_limit_minor": 100, "per_request_max_minor": 50}, params, f.h.SetCommerceBudget)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("budget without reason: want 400, got %d %s", rec.Code, rec.Body.String())
	}
	// A body naming the payer account or funds mode is an unknown field.
	rec = f.call(t, commerceAdmin(t), "PUT", "/api/v1/commerce/tenants/acme/budget",
		map[string]any{"currency": "EUR", "monthly_limit_minor": 100, "per_request_max_minor": 50, "reason": "r", "funds_mode": "live"},
		params, f.h.SetCommerceBudget)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("funds_mode in body: want 400, got %d", rec.Code)
	}
	if rec = f.setBudget(t, "acme", 100, 50); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"funds_mode":"simulated"`) {
		t.Fatalf("admin set budget: %d %s", rec.Code, rec.Body.String())
	}

	rec = f.call(t, owner, "GET", "/api/v1/commerce/tenants/acme/budget", nil, params, f.h.GetCommerceBudget)
	if rec.Code != http.StatusOK {
		t.Fatalf("owner read: %d %s", rec.Code, rec.Body.String())
	}
	var bal commerce.Balance
	if err := json.Unmarshal(rec.Body.Bytes(), &bal); err != nil {
		t.Fatal(err)
	}
	if bal.AvailableMinor != 100 || bal.Currency != "EUR" || bal.FundsMode != commerce.FundsModeSimulated || bal.PayerAccountID != "acct_tenant_acme" {
		t.Fatalf("balance = %+v", bal)
	}
	// A developer is below the milestone role; an unresolved principal and
	// another tenant are refused as everywhere in commerce.
	dev := tenantUser(t, "acme-dev", "acme", "prn_dev")
	if rec = f.call(t, dev, "GET", "/api/v1/commerce/tenants/acme/budget", nil, params, f.h.GetCommerceBudget); rec.Code != http.StatusForbidden {
		t.Fatalf("developer read: want 403, got %d", rec.Code)
	}
	noPrincipal := tenantUser(t, "acme-owner", "acme", "")
	rec = f.call(t, noPrincipal, "GET", "/api/v1/commerce/tenants/acme/budget", nil, params, f.h.GetCommerceBudget)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), commerce.ReasonIdentityUnresolved) {
		t.Fatalf("unresolved principal: %d %s", rec.Code, rec.Body.String())
	}
	beta := tenantUser(t, "beta-owner", "beta", "prn_beta")
	if rec = f.call(t, beta, "GET", "/api/v1/commerce/tenants/acme/budget", nil, params, f.h.GetCommerceBudget); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant read: want 404, got %d", rec.Code)
	}

	rec = f.call(t, owner, "GET", "/api/v1/commerce/tenants/acme/budget/changes", nil, params, f.h.ListCommerceBudgetChanges)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"actor":"prn_admin"`) || !strings.Contains(rec.Body.String(), `"reason":"test"`) {
		t.Fatalf("changes: %d %s", rec.Code, rec.Body.String())
	}

	// Precheck holds nothing and answers from the same balance.
	precheck := func(currency string, amount int64) *httptest.ResponseRecorder {
		return f.call(t, owner, "POST", "/api/v1/commerce/tenants/acme/budget/precheck",
			map[string]any{"amount": map[string]any{"currency": currency, "amount_minor": amount}}, params, f.h.PrecheckCommerceBudget)
	}
	if rec = precheck("EUR", 50); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"sufficient":true`) {
		t.Fatalf("precheck 50: %d %s", rec.Code, rec.Body.String())
	}
	if rec = precheck("EUR", 51); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"sufficient":false`) ||
		!strings.Contains(rec.Body.String(), commerce.ReasonBudgetExhausted) {
		t.Fatalf("precheck 51 (per-request max): %d %s", rec.Code, rec.Body.String())
	}
	if rec = precheck("USD", 1); rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), commerce.ReasonCurrencyMismatch) {
		t.Fatalf("precheck usd: %d %s", rec.Code, rec.Body.String())
	}
	rec = f.call(t, owner, "GET", "/api/v1/commerce/tenants/acme/budget", nil, params, f.h.GetCommerceBudget)
	if !strings.Contains(rec.Body.String(), `"reserved_minor":0`) {
		t.Fatalf("precheck held something: %s", rec.Body.String())
	}
}

func TestCommerceBudget_MoneyEdgesOverHTTP(t *testing.T) {
	f := newCommerceFixture(t)
	f.publish(t) // EUR 0.12 per_successful_call
	if rec := f.setBudget(t, "acme", 100, 50); rec.Code != http.StatusOK {
		t.Fatalf("set budget: %d %s", rec.Code, rec.Body.String())
	}
	owner := tenantUser(t, "acme-owner", "acme", "prn_owner")
	newInvocation := func(key string) string {
		_, q := f.mint(t, owner, "acme", nil)
		rec, res := f.accept(t, owner, "acme", q, key)
		if res == nil {
			t.Fatalf("accept: %d %s", rec.Code, rec.Body.String())
		}
		return res.InvocationID
	}

	first := newInvocation("k1")
	// A tenant never moves its own charge.
	rec := f.call(t, owner, "POST", "/api/v1/commerce/tenants/acme/invocations/"+first+"/reserve", nil,
		map[string]string{"tenant": "acme", "invocation_id": first}, f.h.ReserveCommerceInvocation)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("owner reserve: want 403, got %d", rec.Code)
	}
	// The generic transition refuses the edges that move budget.
	if rec = f.transition(t, "acme", first, "accepted", "reserved"); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "/reserve") {
		t.Fatalf("generic transition to reserved: %d %s", rec.Code, rec.Body.String())
	}
	rec = f.money(t, "reserve", "acme", first, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"phase":"reserved"`) ||
		!strings.Contains(rec.Body.String(), `"payment_status":"authorized"`) || !strings.Contains(rec.Body.String(), `"status":"held"`) {
		t.Fatalf("reserve: %d %s", rec.Code, rec.Body.String())
	}
	if rec = f.money(t, "reserve", "acme", first, nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"replayed":true`) {
		t.Fatalf("reserve replay: %d %s", rec.Code, rec.Body.String())
	}
	for _, step := range [][2]string{{"reserved", "dispatching"}, {"dispatching", "dispatched"}} {
		if rec = f.transition(t, "acme", first, step[0], step[1]); rec.Code != http.StatusOK {
			t.Fatalf("%s -> %s: %d %s", step[0], step[1], rec.Code, rec.Body.String())
		}
	}
	if rec = f.transition(t, "acme", first, "dispatched", "finalized"); rec.Code != http.StatusBadRequest {
		t.Fatalf("generic transition to finalized: %d %s", rec.Code, rec.Body.String())
	}
	if rec = f.money(t, "finalize", "acme", first, map[string]any{"execution_outcome": "unknown"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("finalize unknown: %d %s", rec.Code, rec.Body.String())
	}
	rec = f.money(t, "finalize", "acme", first, map[string]any{"execution_outcome": "succeeded"})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"charge_status":"captured"`) ||
		!strings.Contains(rec.Body.String(), `"settlement_status":"settled"`) || !strings.Contains(rec.Body.String(), `"status":"captured"`) {
		t.Fatalf("finalize: %d %s", rec.Code, rec.Body.String())
	}
	rec = f.call(t, owner, "GET", "/api/v1/commerce/tenants/acme/budget", nil, map[string]string{"tenant": "acme"}, f.h.GetCommerceBudget)
	if !strings.Contains(rec.Body.String(), `"committed_minor":12`) || !strings.Contains(rec.Body.String(), `"available_minor":88`) {
		t.Fatalf("balance after capture: %s", rec.Body.String())
	}

	// Release before dispatch, and not after.
	second := newInvocation("k2")
	f.money(t, "reserve", "acme", second, nil)
	if rec = f.money(t, "release", "acme", second, map[string]any{}); rec.Code != http.StatusBadRequest {
		t.Fatalf("release without reason: %d %s", rec.Code, rec.Body.String())
	}
	rec = f.money(t, "release", "acme", second, map[string]any{"reason_code": "provider-unavailable"})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"phase":"released"`) || !strings.Contains(rec.Body.String(), `"payment_status":"voided"`) {
		t.Fatalf("release: %d %s", rec.Code, rec.Body.String())
	}
	if rec = f.money(t, "release", "acme", first, map[string]any{"reason_code": "x"}); rec.Code != http.StatusConflict {
		t.Fatalf("release finalized: want 409, got %d %s", rec.Code, rec.Body.String())
	}

	// Exhaustion is a durable refusal with its reason.
	if rec = f.setBudget(t, "acme", 20, 50); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	third := newInvocation("k3")
	rec = f.money(t, "reserve", "acme", third, nil)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), commerce.ReasonBudgetExhausted) {
		t.Fatalf("exhausted reserve: %d %s", rec.Code, rec.Body.String())
	}
	rec = f.call(t, owner, "GET", "/api/v1/commerce/tenants/acme/invocations/"+third, nil,
		map[string]string{"tenant": "acme", "invocation_id": third}, f.h.GetCommerceInvocation)
	if !strings.Contains(rec.Body.String(), `"phase":"refused"`) || !strings.Contains(rec.Body.String(), `"reason_code":"budget-exhausted"`) {
		t.Fatalf("refused receipt: %s", rec.Body.String())
	}

	// The reconciler is admin-only and answers what it changed.
	rec = f.call(t, owner, "POST", "/api/v1/commerce/reconcile/expired", nil, nil, f.h.ReconcileCommerceExpired)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("owner reconcile: want 403, got %d", rec.Code)
	}
	rec = f.call(t, commerceAdmin(t), "POST", "/api/v1/commerce/reconcile/expired?limit=5", nil, nil, f.h.ReconcileCommerceExpired)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"released":[`) || !strings.Contains(rec.Body.String(), `"unresolved":[`) {
		t.Fatalf("reconcile: %d %s", rec.Code, rec.Body.String())
	}
}
