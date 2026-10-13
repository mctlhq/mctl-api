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

package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/commerce"
)

func TestCommerceEntitlement_AdminGrantedAndTenantRead(t *testing.T) {
	f := newCommerceFixture(t)
	f.publish(t)
	tenant := "acme"
	owner := tenantUser(t, "acme-owner", tenant, "prn_owner")
	dev := tenantUser(t, "acme-dev", tenant, "prn_dev")
	beta := tenantUser(t, "beta-owner", "beta", "prn_beta")
	expiry := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)

	grantBody := map[string]any{
		"capability_id": f.cap,
		"units":         100,
		"invoice_ref":   "INV-2026-ALPHA",
		"expires_at":    expiry,
		"reason":        "Pilot customer package",
	}

	// 0. Unknown capability returns 422 terms-unknown
	badGrantBody := map[string]any{
		"capability_id": "mctl://unknown/capability",
		"units":         100,
		"invoice_ref":   "INV-UNKNOWN",
		"expires_at":    expiry,
	}
	rec := f.call(t, commerceAdmin(t), "POST", "/api/v1/commerce/tenants/acme/entitlements", badGrantBody,
		map[string]string{"tenant": tenant}, f.h.GrantCommerceEntitlement)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("grant unknown cap: want 422, got %d (%s)", rec.Code, rec.Body.String())
	}

	// 1. Non-admin cannot grant entitlement
	rec = f.call(t, owner, "POST", "/api/v1/commerce/tenants/acme/entitlements", grantBody,
		map[string]string{"tenant": tenant}, f.h.GrantCommerceEntitlement)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("grant by tenant owner: want 403, got %d", rec.Code)
	}

	// 2. Admin successfully grants entitlement
	rec = f.call(t, commerceAdmin(t), "POST", "/api/v1/commerce/tenants/acme/entitlements", grantBody,
		map[string]string{"tenant": tenant}, f.h.GrantCommerceEntitlement)
	if rec.Code != http.StatusCreated {
		t.Fatalf("grant by admin: want 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	var created commerce.Entitlement
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode entitlement: %v", err)
	}
	if created.TotalUnits != 100 || created.RemainingUnits != 100 || created.InvoiceRef != "INV-2026-ALPHA" || created.Status != "active" {
		t.Fatalf("created = %+v", created)
	}

	// 3. Tenant owner can list entitlements
	rec = f.call(t, owner, "GET", "/api/v1/commerce/tenants/acme/entitlements", nil,
		map[string]string{"tenant": tenant}, f.h.ListCommerceEntitlements)
	if rec.Code != http.StatusOK {
		t.Fatalf("list by owner: want 200, got %d", rec.Code)
	}
	var resp struct {
		Entitlements []commerce.Entitlement `json:"entitlements"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(resp.Entitlements) != 1 || resp.Entitlements[0].EntitlementID != created.EntitlementID {
		t.Fatalf("list = %+v", resp.Entitlements)
	}

	// 3b. Duplicate invoice returns 409 Conflict
	rec = f.call(t, commerceAdmin(t), "POST", "/api/v1/commerce/tenants/acme/entitlements", grantBody,
		map[string]string{"tenant": tenant}, f.h.GrantCommerceEntitlement)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate grant: want 409, got %d (%s)", rec.Code, rec.Body.String())
	}

	// 4. Tenant owner can get entitlement by ID
	rec = f.call(t, owner, "GET", "/api/v1/commerce/tenants/acme/entitlements/"+created.EntitlementID, nil,
		map[string]string{"tenant": tenant, "entitlement_id": created.EntitlementID}, f.h.GetCommerceEntitlement)
	if rec.Code != http.StatusOK {
		t.Fatalf("get by owner: want 200, got %d", rec.Code)
	}

	// 4b. Get non-existent entitlement returns 404
	rec = f.call(t, owner, "GET", "/api/v1/commerce/tenants/acme/entitlements/ent_nonexistent", nil,
		map[string]string{"tenant": tenant, "entitlement_id": "ent_nonexistent"}, f.h.GetCommerceEntitlement)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get nonexistent: want 404, got %d", rec.Code)
	}

	// 4c. Cross-tenant get entitlement returns 404
	rec = f.call(t, beta, "GET", "/api/v1/commerce/tenants/acme/entitlements/"+created.EntitlementID, nil,
		map[string]string{"tenant": tenant, "entitlement_id": created.EntitlementID}, f.h.GetCommerceEntitlement)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant get: want 404, got %d", rec.Code)
	}

	// 5. Developer without permission cannot read
	rec = f.call(t, dev, "GET", "/api/v1/commerce/tenants/acme/entitlements", nil,
		map[string]string{"tenant": tenant}, f.h.ListCommerceEntitlements)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("list by developer: want 403, got %d", rec.Code)
	}

	// 6. Cross-tenant isolation: other tenant cannot read acme's entitlements
	rec = f.call(t, beta, "GET", "/api/v1/commerce/tenants/acme/entitlements", nil,
		map[string]string{"tenant": tenant}, f.h.ListCommerceEntitlements)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant list: want 404, got %d", rec.Code)
	}

	// 7. Retire entitlement: non-admin forbidden
	rec = f.call(t, owner, "DELETE", "/api/v1/commerce/tenants/acme/entitlements/"+created.EntitlementID, nil,
		map[string]string{"tenant": tenant, "entitlement_id": created.EntitlementID}, f.h.RetireCommerceEntitlement)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("retire by non-admin: want 403, got %d", rec.Code)
	}

	// 7b. Retire entitlement: cross-tenant 404
	rec = f.call(t, commerceAdmin(t), "DELETE", "/api/v1/commerce/tenants/beta/entitlements/"+created.EntitlementID, nil,
		map[string]string{"tenant": "beta", "entitlement_id": created.EntitlementID}, f.h.RetireCommerceEntitlement)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("retire cross-tenant: want 404, got %d", rec.Code)
	}

	// 7c. Admin retires entitlement (POST .../retire)
	rec = f.call(t, commerceAdmin(t), "POST", "/api/v1/commerce/tenants/acme/entitlements/"+created.EntitlementID+"/retire", nil,
		map[string]string{"tenant": tenant, "entitlement_id": created.EntitlementID}, f.h.RetireCommerceEntitlement)
	if rec.Code != http.StatusOK {
		t.Fatalf("retire by admin: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var retired commerce.Entitlement
	if err := json.Unmarshal(rec.Body.Bytes(), &retired); err != nil {
		t.Fatalf("decode retired: %v", err)
	}
	if retired.Status != "retired" {
		t.Fatalf("retired status: want retired, got %s", retired.Status)
	}

	// 7d. Admin retires entitlement idempotently (DELETE)
	rec = f.call(t, commerceAdmin(t), "DELETE", "/api/v1/commerce/tenants/acme/entitlements/"+created.EntitlementID, nil,
		map[string]string{"tenant": tenant, "entitlement_id": created.EntitlementID}, f.h.RetireCommerceEntitlement)
	if rec.Code != http.StatusOK {
		t.Fatalf("idempotent retire by admin: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
}
