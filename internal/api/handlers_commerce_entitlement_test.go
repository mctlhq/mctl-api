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
	tenant := "acme"
	owner := tenantUser(t, "acme-owner", tenant, "prn_owner")
	dev := tenantUser(t, "acme-dev", tenant, "prn_dev")
	beta := tenantUser(t, "beta-owner", "beta", "prn_beta")
	expiry := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)

	grantBody := map[string]any{
		"capability_id": "mctl://projects/projects_search",
		"units":         100,
		"invoice_ref":   "INV-2026-ALPHA",
		"expires_at":    expiry,
		"reason":        "Pilot customer package",
	}

	// 1. Non-admin cannot grant entitlement
	rec := f.call(t, owner, "POST", "/api/v1/commerce/tenants/acme/entitlements", grantBody,
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
	if created.TotalUnits != 100 || created.RemainingUnits != 100 || created.InvoiceRef != "INV-2026-ALPHA" {
		t.Fatalf("created = %+v", created)
	}

	// 3. Tenant owner can list entitlements
	rec = f.call(t, owner, "GET", "/api/v1/commerce/tenants/acme/entitlements", nil,
		map[string]string{"tenant": tenant}, f.h.ListCommerceEntitlements)
	if rec.Code != http.StatusOK {
		t.Fatalf("list by owner: want 200, got %d", rec.Code)
	}
	var list []commerce.Entitlement
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list) != 1 || list[0].EntitlementID != created.EntitlementID {
		t.Fatalf("list = %+v", list)
	}

	// 4. Tenant owner can get entitlement by ID
	rec = f.call(t, owner, "GET", "/api/v1/commerce/tenants/acme/entitlements/"+created.EntitlementID, nil,
		map[string]string{"tenant": tenant, "entitlement_id": created.EntitlementID}, f.h.GetCommerceEntitlement)
	if rec.Code != http.StatusOK {
		t.Fatalf("get by owner: want 200, got %d", rec.Code)
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
}
