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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/commerce"
	"github.com/mctlhq/mctl-api/internal/gitops"
)

// The commerce handler tests pin ADR 020 sec. 3 at the HTTP boundary: no
// body field can choose the tenant, the principal or the payer, and a
// caller without a canonical principal is refused before any row exists.

const commerceTestSchemaHash = "sha256:abababababababababababababababababababababababababababababababab"
const commerceTestArgsDigest = "sha256:73fd22bf1a31b2661710f8e3413afb2705c876302e6cbf8a112aed3317130c8c"

// commerceGitReader answers only MemberRoles, which is all the tenant-role
// gate reads; every other method is the nil embedded interface.
type commerceGitReader struct {
	GitReader
	tenants []gitops.Tenant
}

func (r *commerceGitReader) MemberRoles(namespace, login string) ([][]string, error) {
	var roles []string
	for i := range r.tenants {
		if r.tenants[i].Name != namespace {
			continue
		}
		for _, m := range r.tenants[i].Members {
			if strings.EqualFold(m.UserID, login) {
				roles = append(roles, m.Role)
			}
		}
	}
	if len(roles) == 0 {
		return nil, nil
	}
	return [][]string{roles}, nil
}

type commerceFixture struct {
	h     *Handlers
	store *commerce.Store
	cap   string
}

func newCommerceFixture(t *testing.T) *commerceFixture {
	t.Helper()
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed commerce handler test")
	}
	ctx := context.Background()
	store, err := commerce.NewStore(ctx, connStr)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	capID := fmt.Sprintf("mctl://test-commerce-api/%s/%d", strings.ToLower(t.Name()), time.Now().UnixNano())
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("cleanup pool: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM commerce_invocation_transitions WHERE invocation_id IN
			(SELECT invocation_id FROM commerce_invocations WHERE capability_id = $1)`, capID)
		_, _ = pool.Exec(ctx, `DELETE FROM commerce_invocations WHERE capability_id = $1`, capID)
		_, _ = pool.Exec(ctx, `DELETE FROM commerce_quotes WHERE capability_id = $1`, capID)
		_, _ = pool.Exec(ctx, `DELETE FROM commerce_terms WHERE capability_id = $1`, capID)
		pool.Close()
		store.Close()
	})
	git := &commerceGitReader{tenants: []gitops.Tenant{
		{Name: "acme", Members: []gitops.TenantMember{{UserID: "acme-owner", Role: "owner"}, {UserID: "acme-dev", Role: "developer"}}},
		{Name: "beta", Members: []gitops.TenantMember{{UserID: "beta-owner", Role: "owner"}}},
	}}
	h := &Handlers{opts: Options{Commerce: store, GitReader: git}}
	return &commerceFixture{h: h, store: store, cap: capID}
}

// tenantUser is a GitHub-proven member of tenant with a resolved principal.
func tenantUser(t *testing.T, login, tenant, principal string) *auth.User {
	t.Helper()
	u := auth.NewGitHubUser(login, []string{tenant})
	if principal != "" {
		if err := auth.AttachPrincipal(context.Background(), fixedPrincipal(principal), u); err != nil {
			t.Fatalf("AttachPrincipal: %v", err)
		}
	}
	return u
}

func commerceAdmin(t *testing.T) *auth.User {
	t.Helper()
	u := auth.NewGitHubUser("platform-admin", []string{"admins"})
	if err := auth.AttachPrincipal(context.Background(), fixedPrincipal("prn_admin"), u); err != nil {
		t.Fatalf("AttachPrincipal: %v", err)
	}
	return u
}

func (f *commerceFixture) call(t *testing.T, u *auth.User, method, path string, body any, params map[string]string, fn http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	if u != nil {
		req = withUser(req, u)
	}
	if len(params) > 0 {
		// One route context for every param: withURLParam makes a fresh
		// context per call and would keep only the last key.
		rctx := chi.NewRouteContext()
		for k, v := range params {
			rctx.URLParams.Add(k, v)
		}
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	}
	rec := httptest.NewRecorder()
	fn(rec, req)
	return rec
}

func (f *commerceFixture) publish(t *testing.T) *commerce.Terms {
	t.Helper()
	rec := f.call(t, commerceAdmin(t), "POST", "/api/v1/commerce/terms", map[string]any{
		"capability_id": f.cap, "input_schema_hash": commerceTestSchemaHash, "provider_id": "pilot-provider",
		"price_mode": "per_successful_call", "price": map[string]any{"currency": "EUR", "amount_minor": 12},
		"funds_mode": "simulated", "quote_ttl_seconds": 300,
	}, nil, f.h.PublishCommerceTerms)
	if rec.Code != http.StatusCreated {
		t.Fatalf("publish: %d %s", rec.Code, rec.Body.String())
	}
	var terms commerce.Terms
	if err := json.Unmarshal(rec.Body.Bytes(), &terms); err != nil {
		t.Fatal(err)
	}
	return &terms
}

func (f *commerceFixture) mint(t *testing.T, u *auth.User, tenant string, extra map[string]any) (*httptest.ResponseRecorder, *commerce.Quote) {
	t.Helper()
	body := map[string]any{"capability_id": f.cap, "input_schema_hash": commerceTestSchemaHash,
		"args_digest": commerceTestArgsDigest, "execution_id": "we_01JZ8Q0000000000000000000C"}
	for k, v := range extra {
		body[k] = v
	}
	rec := f.call(t, u, "POST", "/api/v1/commerce/tenants/"+tenant+"/quotes", body, map[string]string{"tenant": tenant}, f.h.MintCommerceQuote)
	if rec.Code != http.StatusCreated {
		return rec, nil
	}
	var q commerce.Quote
	if err := json.Unmarshal(rec.Body.Bytes(), &q); err != nil {
		t.Fatal(err)
	}
	return rec, &q
}

func (f *commerceFixture) accept(t *testing.T, u *auth.User, tenant string, q *commerce.Quote, key string) (*httptest.ResponseRecorder, *acceptInvocationResponse) {
	t.Helper()
	body := map[string]any{"quote_id": q.QuoteID, "quote_digest": q.QuoteDigest, "idempotency_key": key,
		"args_digest": q.ArgsDigest, "execution_id": q.ExecutionID}
	rec := f.call(t, u, "POST", "/api/v1/commerce/tenants/"+tenant+"/invocations", body, map[string]string{"tenant": tenant}, f.h.AcceptCommerceInvocation)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		return rec, nil
	}
	var res acceptInvocationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	return rec, &res
}

func TestCommerceHandlers_NilStoreIs503(t *testing.T) {
	h := &Handlers{opts: Options{}}
	for name, fn := range map[string]http.HandlerFunc{
		"terms": h.ListCommerceTerms, "quote": h.MintCommerceQuote, "accept": h.AcceptCommerceInvocation,
		"list": h.ListCommerceInvocations, "transition": h.TransitionCommerceInvocation, "overdue": h.ListOverdueCommerceInvocations,
	} {
		req := adminCtx(httptest.NewRequest("GET", "/api/v1/commerce/terms", nil))
		rec := httptest.NewRecorder()
		fn(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s with nil store: want 503, got %d", name, rec.Code)
		}
	}
}

func TestCommerceHandlers_TermsArePlatformAdminOnly(t *testing.T) {
	f := newCommerceFixture(t)
	owner := tenantUser(t, "acme-owner", "acme", "prn_owner")
	rec := f.call(t, owner, "POST", "/api/v1/commerce/terms", map[string]any{"capability_id": f.cap}, nil, f.h.PublishCommerceTerms)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("tenant owner publishing terms: want 403, got %d", rec.Code)
	}
	rec = f.call(t, nil, "POST", "/api/v1/commerce/terms", nil, nil, f.h.PublishCommerceTerms)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: want 401, got %d", rec.Code)
	}
	// Live funds are refused at the boundary with the ADR reason code.
	rec = f.call(t, commerceAdmin(t), "POST", "/api/v1/commerce/terms", map[string]any{
		"capability_id": f.cap, "input_schema_hash": commerceTestSchemaHash, "provider_id": "p",
		"price_mode": "per_call", "price": map[string]any{"currency": "EUR", "amount_minor": 1},
		"funds_mode": "live", "quote_ttl_seconds": 60,
	}, nil, f.h.PublishCommerceTerms)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), commerce.ReasonFundsModeUnavailable) {
		t.Fatalf("live funds: %d %s", rec.Code, rec.Body.String())
	}
	terms := f.publish(t)
	// Anyone authenticated may read a price.
	rec = f.call(t, owner, "GET", "/api/v1/commerce/terms?capability_id="+f.cap+"&current=true&input_schema_hash="+commerceTestSchemaHash,
		nil, nil, f.h.ListCommerceTerms)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), terms.TermsID) {
		t.Fatalf("read terms: %d %s", rec.Code, rec.Body.String())
	}
	// Unknown terms are not free.
	rec = f.call(t, owner, "GET", "/api/v1/commerce/terms?capability_id="+f.cap+"/none&current=true&input_schema_hash="+commerceTestSchemaHash,
		nil, nil, f.h.ListCommerceTerms)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), commerce.ReasonTermsUnknown) {
		t.Fatalf("unknown terms: %d %s", rec.Code, rec.Body.String())
	}
}

func TestCommerceHandlers_IdentityIsServerResolved(t *testing.T) {
	f := newCommerceFixture(t)
	f.publish(t)
	owner := tenantUser(t, "acme-owner", "acme", "prn_owner")

	// Body fields naming identity are unknown fields: rejected, not ignored.
	for _, field := range []string{"tenant_id", "principal_id", "payer_account_id"} {
		rec, _ := f.mint(t, owner, "acme", map[string]any{field: "attacker"})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %s: want 400, got %d %s", field, rec.Code, rec.Body.String())
		}
	}
	rec, q := f.mint(t, owner, "acme", nil)
	if q == nil {
		t.Fatalf("mint: %d %s", rec.Code, rec.Body.String())
	}
	if q.TenantID != "acme" || q.PrincipalID != "prn_owner" || q.SubjectPrincipalID != "prn_owner" ||
		q.PayerAccountID != "acct_tenant_acme" || q.ExecutionID != "we_01JZ8Q0000000000000000000C" {
		t.Fatalf("identities = %+v", q.Identities)
	}

	// No canonical principal: refused before any row, with the ADR code.
	noPrincipal := tenantUser(t, "acme-owner", "acme", "")
	rec, _ = f.mint(t, noPrincipal, "acme", nil)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), commerce.ReasonIdentityUnresolved) {
		t.Fatalf("unresolved principal: %d %s", rec.Code, rec.Body.String())
	}

	// A developer is below the milestone role.
	dev := tenantUser(t, "acme-dev", "acme", "prn_dev")
	rec, _ = f.mint(t, dev, "acme", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("developer: want 403, got %d %s", rec.Code, rec.Body.String())
	}

	// Another tenant's owner gets the not-found of ADR 020 sec. 12, both on
	// the write and on the read of an existing quote.
	beta := tenantUser(t, "beta-owner", "beta", "prn_beta")
	rec, _ = f.mint(t, beta, "acme", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant mint: want 404, got %d", rec.Code)
	}
	rec = f.call(t, beta, "GET", "/api/v1/commerce/tenants/beta/quotes/"+q.QuoteID, nil,
		map[string]string{"tenant": "beta", "quote_id": q.QuoteID}, f.h.GetCommerceQuote)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant quote read: want 404, got %d", rec.Code)
	}
	rec = f.call(t, owner, "GET", "/api/v1/commerce/tenants/acme/quotes/"+q.QuoteID, nil,
		map[string]string{"tenant": "acme", "quote_id": q.QuoteID}, f.h.GetCommerceQuote)
	if rec.Code != http.StatusOK {
		t.Fatalf("own quote read: %d %s", rec.Code, rec.Body.String())
	}
	// The service principal (admins group) passes without a tenant role.
	svc := auth.NewServiceUser()
	if err := auth.AttachPrincipal(context.Background(), fixedPrincipal("prn_service"), svc); err != nil {
		t.Fatal(err)
	}
	rec, sq := f.mint(t, svc, "acme", nil)
	if sq == nil || sq.PrincipalID != "prn_service" || sq.TenantID != "acme" {
		t.Fatalf("service mint: %d %s", rec.Code, rec.Body.String())
	}
}

func TestCommerceHandlers_AcceptReplayAndConflictOverHTTP(t *testing.T) {
	f := newCommerceFixture(t)
	f.publish(t)
	owner := tenantUser(t, "acme-owner", "acme", "prn_owner")
	_, q := f.mint(t, owner, "acme", nil)

	rec, first := f.accept(t, owner, "acme", q, "key-1")
	if rec.Code != http.StatusCreated || first.Replayed || first.Phase != commerce.PhaseAccepted {
		t.Fatalf("first accept: %d %s", rec.Code, rec.Body.String())
	}
	rec, again := f.accept(t, owner, "acme", q, "key-1")
	if rec.Code != http.StatusOK || !again.Replayed || again.InvocationID != first.InvocationID {
		t.Fatalf("replay: %d %s", rec.Code, rec.Body.String())
	}
	_, q2 := f.mint(t, owner, "acme", nil)
	rec, _ = f.accept(t, owner, "acme", q2, "key-1")
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), commerce.ReasonIdempotencyConflict) {
		t.Fatalf("conflict: %d %s", rec.Code, rec.Body.String())
	}
	tampered := *q2
	tampered.QuoteDigest = "sha256:" + strings.Repeat("00", 32)
	rec, _ = f.accept(t, owner, "acme", &tampered, "key-2")
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), commerce.ReasonQuoteMismatch) {
		t.Fatalf("mismatch: %d %s", rec.Code, rec.Body.String())
	}
	// The receipt is tenant-scoped and lists the five facts.
	rec = f.call(t, owner, "GET", "/api/v1/commerce/tenants/acme/invocations?phase=accepted", nil,
		map[string]string{"tenant": "acme"}, f.h.ListCommerceInvocations)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), first.InvocationID) {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	for _, key := range []string{`"execution_outcome":"not_dispatched"`, `"charge_status":"none"`, `"payment_status":"none"`,
		`"settlement_status":"not_applicable"`, `"provider_operation_key":"mctl-op/v1:` + first.InvocationID + `"`} {
		if !strings.Contains(rec.Body.String(), key) {
			t.Errorf("receipt lacks %s", key)
		}
	}
	beta := tenantUser(t, "beta-owner", "beta", "prn_beta")
	rec = f.call(t, beta, "GET", "/api/v1/commerce/tenants/beta/invocations/"+first.InvocationID, nil,
		map[string]string{"tenant": "beta", "invocation_id": first.InvocationID}, f.h.GetCommerceInvocation)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant receipt: want 404, got %d", rec.Code)
	}

	// Transitions are platform-only: the tenant owner cannot move money
	// state, the admin can, and a wrong expected phase is a conflict.
	params := map[string]string{"tenant": "acme", "invocation_id": first.InvocationID}
	path := "/api/v1/commerce/tenants/acme/invocations/" + first.InvocationID + "/transitions"
	rec = f.call(t, owner, "POST", path, map[string]any{"expected_phase": "accepted", "to_phase": "refused", "reason_code": "budget-exhausted"},
		params, f.h.TransitionCommerceInvocation)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("owner transition: want 403, got %d", rec.Code)
	}
	admin := commerceAdmin(t)
	rec = f.call(t, admin, "POST", path, map[string]any{"expected_phase": "reserved", "to_phase": "dispatching"}, params, f.h.TransitionCommerceInvocation)
	if rec.Code != http.StatusConflict {
		t.Fatalf("wrong expected phase: want 409, got %d %s", rec.Code, rec.Body.String())
	}
	rec = f.call(t, admin, "POST", path, map[string]any{"expected_phase": "accepted", "to_phase": "refused", "reason_code": "budget-exhausted"},
		params, f.h.TransitionCommerceInvocation)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"phase":"refused"`) {
		t.Fatalf("admin transition: %d %s", rec.Code, rec.Body.String())
	}
	rec = f.call(t, owner, "GET", path, nil, params, f.h.ListCommerceInvocationTransitions)
	if rec.Code != http.StatusOK || strings.Count(rec.Body.String(), `"to_phase"`) != 2 || !strings.Contains(rec.Body.String(), `"actor":"prn_admin"`) {
		t.Fatalf("history: %d %s", rec.Code, rec.Body.String())
	}
}
