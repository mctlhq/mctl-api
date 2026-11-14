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

package securityfindings

import (
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// twoTenantProvider is one provider configured for both tenants, the shape
// in which identical content for two tenants arrives.
func twoTenantProvider(a, b string) ProviderContext {
	return ProviderContext{Ref: "trivy", MaxStrength: StrengthScannerRerunExactRevision, Tenants: []string{a, b}, PrincipalID: "prn_trivy"}
}

// TestRedeliveryDedupIsPerTenant: the same provider sending byte-identical
// content (same delivery id, CVE, subject) for two tenants records two
// observations. The second tenant must never get a "duplicate" that points
// at the first tenant's finding, occurrence and observation.
func TestRedeliveryDedupIsPerTenant(t *testing.T) {
	s, _ := newTestStore(t)
	a, b := newTenant(), newTenant()
	pc := twoTenantProvider(a, b)
	cve := cveID()

	ra := mustIngest(t, s, pc, "delivery-shared", dep(a, cve, "o/shared"))[0]
	if ra.Status != ItemCreated {
		t.Fatalf("tenant A: want created, got %+v", ra)
	}
	rb := mustIngest(t, s, pc, "delivery-shared", dep(b, cve, "o/shared"))[0]
	if rb.Status != ItemCreated {
		t.Fatalf("tenant B: identical content for another tenant must be recorded, got %+v", rb)
	}
	if rb.FindingID == ra.FindingID || rb.OccurrenceID == ra.OccurrenceID || rb.ObservationID == ra.ObservationID {
		t.Fatalf("tenant B got tenant A's ids: A=%+v B=%+v", ra, rb)
	}
	if o := mustOccurrence(t, s, b, rb.OccurrenceID); o.Tenant != b {
		t.Fatalf("tenant B's occurrence is in tenant %q", o.Tenant)
	}
	var rows int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM security_observations WHERE tenant = $1`, b).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("tenant B: want 1 observation row, got %d (%v)", rows, err)
	}

	// Redelivery still dedups, each within its own tenant.
	for _, tc := range []struct {
		tenant string
		first  ItemResult
	}{{a, ra}, {b, rb}} {
		again := mustIngest(t, s, pc, "delivery-shared", dep(tc.tenant, cve, "o/shared"))[0]
		if again.Status != ItemDuplicate || again.ObservationID != tc.first.ObservationID || again.FindingID != tc.first.FindingID {
			t.Errorf("tenant %s redelivery: want duplicate of %+v, got %+v", tc.tenant, tc.first, again)
		}
	}
}

// TestDedupIndexMigratesAnOldTable applies the schema to a table in the
// shape the previous release left it (UNIQUE (provider_ref,
// observation_hash), no per-tenant index) holding a row, the way a deploy
// meets production. The old constraint must go, the per-tenant index must
// exist, the old row must still dedup its own redelivery, and identical
// content for another tenant must then be recorded.
func TestDedupIndexMigratesAnOldTable(t *testing.T) {
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed security findings store test")
	}
	// A schema of its own: the shared test schema already has the new index
	// and rows the old constraint would reject.
	shared, _ := newTestStore(t)
	ns := "sf_migrate_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	if _, err := shared.pool.Exec(ctx, `CREATE SCHEMA `+ns); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() { _, _ = shared.pool.Exec(ctx, `DROP SCHEMA `+ns+` CASCADE`) })

	u, err := url.Parse(connStr)
	if err != nil {
		t.Fatalf("parse TEST_DATABASE_URL: %v", err)
	}
	q := u.Query()
	q.Set("search_path", ns)
	u.RawQuery = q.Encode()
	s, err := NewStore(ctx, u.String())
	if err != nil {
		t.Fatalf("NewStore in %s: %v", ns, err)
	}
	t.Cleanup(s.Close)

	// Put the table back into the previous release's shape.
	for _, stmt := range []string{
		`DROP INDEX security_observations_provider_tenant_hash`,
		`ALTER TABLE security_observations ADD CONSTRAINT security_observations_provider_ref_observation_hash_key UNIQUE (provider_ref, observation_hash)`,
	} {
		if _, err := s.pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	a, b := newTenant(), newTenant()
	pc := twoTenantProvider(a, b)
	cve := cveID()
	old := mustIngest(t, s, pc, "delivery-old", dep(a, cve, "o/r"))[0]
	if old.Status != ItemCreated {
		t.Fatalf("seed row: %+v", old)
	}

	// The deploy: NewStore applies the schema again.
	if _, err := s.pool.Exec(ctx, schema); err != nil {
		t.Fatalf("schema over the old table: %v", err)
	}
	var constraints, indexes int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM pg_constraint
		WHERE conrelid = 'security_observations'::regclass AND conname = 'security_observations_provider_ref_observation_hash_key'`).Scan(&constraints); err != nil {
		t.Fatal(err)
	}
	if constraints != 0 {
		t.Errorf("the tenant-blind unique constraint is still there")
	}
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM pg_indexes
		WHERE schemaname = $1 AND indexname = 'security_observations_provider_tenant_hash'
		  AND indexdef LIKE 'CREATE UNIQUE INDEX%(provider_ref, tenant, observation_hash)'`, ns).Scan(&indexes); err != nil {
		t.Fatal(err)
	}
	if indexes != 1 {
		t.Errorf("want the per-tenant unique index, found %d", indexes)
	}

	if again := mustIngest(t, s, pc, "delivery-old", dep(a, cve, "o/r"))[0]; again.Status != ItemDuplicate || again.ObservationID != old.ObservationID {
		t.Errorf("redelivery of a row written before the migration: want duplicate of %s, got %+v", old.ObservationID, again)
	}
	if other := mustIngest(t, s, pc, "delivery-old", dep(b, cve, "o/r"))[0]; other.Status != ItemCreated {
		t.Errorf("identical content for another tenant after the migration: want created, got %+v", other)
	}
}
