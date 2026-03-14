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

package gitops

import (
	"os"
	"path/filepath"
	"testing"
)

func setupTempRepo(t *testing.T) (string, *Reader) {
	t.Helper()
	dir := t.TempDir()
	r := &Reader{localPath: dir}
	return dir, r
}

func writeTenantYAML(t *testing.T, dir, name, content string) {
	t.Helper()
	tenantDir := filepath.Join(dir, "platform-gitops", "tenants", name)
	if err := os.MkdirAll(tenantDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tenantDir, "values.yaml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeServiceYAML(t *testing.T, dir, team, app, content string) {
	t.Helper()
	svcDir := filepath.Join(dir, "platform-gitops", "services", team, app)
	if err := os.MkdirAll(svcDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(svcDir, "values.yaml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadTenant(t *testing.T) {
	dir, r := setupTempRepo(t)
	writeTenantYAML(t, dir, "billing", `
tenant:
  name: billing
  displayName: Billing Team
  description: Handles payments
  contactEmail: billing@example.com
  quotas:
    cpu: "2"
    memory: 4Gi
  members:
    - userId: alice
      role: admin
    - userId: bob
`)
	tenant, err := r.readTenant("billing")
	if err != nil {
		t.Fatalf("readTenant: %v", err)
	}
	if tenant.Name != "billing" {
		t.Errorf("name: got %q, want billing", tenant.Name)
	}
	if tenant.DisplayName != "Billing Team" {
		t.Errorf("displayName: got %q", tenant.DisplayName)
	}
	if tenant.Quotas["cpu"] != "2" {
		t.Errorf("quota cpu: got %q", tenant.Quotas["cpu"])
	}
	if len(tenant.Members) != 2 {
		t.Errorf("members: got %d, want 2", len(tenant.Members))
	}
}

func TestReadTenant_missing(t *testing.T) {
	_, r := setupTempRepo(t)
	_, err := r.readTenant("nonexistent")
	if err == nil {
		t.Error("expected error for missing tenant, got nil")
	}
}

func TestListTenants(t *testing.T) {
	dir, r := setupTempRepo(t)
	writeTenantYAML(t, dir, "alpha", `tenant: {name: alpha, quotas: {}}`)
	writeTenantYAML(t, dir, "beta", `tenant: {name: beta, quotas: {}}`)

	tenants, err := r.ListTenants()
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}
	if len(tenants) != 2 {
		t.Errorf("got %d tenants, want 2", len(tenants))
	}
}

func TestGetTenantsForUser(t *testing.T) {
	dir, r := setupTempRepo(t)
	writeTenantYAML(t, dir, "billing", `
tenant:
  name: billing
  quotas: {}
  members:
    - userId: Alice
    - userId: bob
`)
	writeTenantYAML(t, dir, "data-team", `
tenant:
  name: data-team
  quotas: {}
  members:
    - userId: alice
`)

	tenants, err := r.GetTenantsForUser("alice") // case-insensitive match
	if err != nil {
		t.Fatalf("GetTenantsForUser: %v", err)
	}
	if len(tenants) != 2 {
		t.Errorf("alice should belong to 2 tenants, got %d: %v", len(tenants), tenants)
	}

	tenants, err = r.GetTenantsForUser("bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(tenants) != 1 || tenants[0] != "billing" {
		t.Errorf("bob should belong to billing only, got %v", tenants)
	}

	tenants, err = r.GetTenantsForUser("charlie")
	if err != nil {
		t.Fatal(err)
	}
	if len(tenants) != 0 {
		t.Errorf("charlie should belong to no tenants, got %v", tenants)
	}
}

func TestReadService(t *testing.T) {
	dir, r := setupTempRepo(t)
	writeServiceYAML(t, dir, "billing", "payment-api", `
image:
  repository: ghcr.io/mctlhq/payment-api
  tag: "1.2.3"
host: payment-api.mctl.ai
port: 8080
dbSecret: billing-payment-api-db
`)
	svc, err := r.readService("billing", "payment-api")
	if err != nil {
		t.Fatalf("readService: %v", err)
	}
	if svc.ImageTag != "1.2.3" {
		t.Errorf("imageTag: got %q, want 1.2.3", svc.ImageTag)
	}
	if svc.Host != "payment-api.mctl.ai" {
		t.Errorf("host: got %q", svc.Host)
	}
	if !svc.HasDatabase {
		t.Error("should detect database from dbSecret field")
	}
	if svc.ComponentType != "base-service" {
		t.Errorf("componentType: got %q, want base-service", svc.ComponentType)
	}
}

func TestReadService_worker(t *testing.T) {
	dir, r := setupTempRepo(t)
	writeServiceYAML(t, dir, "billing", "worker", `
image:
  tag: "2.0.0"
# worker-service chart
`)
	svc, err := r.readService("billing", "worker")
	if err != nil {
		t.Fatal(err)
	}
	if svc.ComponentType != "worker-service" {
		t.Errorf("componentType: got %q, want worker-service", svc.ComponentType)
	}
}

func TestReadTenant_MultiTeam(t *testing.T) {
	dir, r := setupTempRepo(t)
	writeTenantYAML(t, dir, "knot-capital", `
tenant:
  name: knot-capital
  displayName: Knot Capital
  quotas:
    cpu: "4"
  members:
    - userId: owner1
      role: owner
  teams:
    - name: backend
      displayName: Backend Team
      members:
        - userId: dev1
        - userId: dev2
    - name: frontend
      displayName: Frontend Team
      members:
        - userId: dev3
`)
	tenant, err := r.readTenant("knot-capital")
	if err != nil {
		t.Fatalf("readTenant: %v", err)
	}
	if tenant.Name != "knot-capital" {
		t.Errorf("name: got %q", tenant.Name)
	}
	if !tenant.IsMultiTeam() {
		t.Error("should be multi-team")
	}
	if len(tenant.Teams) != 2 {
		t.Fatalf("teams: got %d, want 2", len(tenant.Teams))
	}
	if tenant.Teams[0].Name != "backend" {
		t.Errorf("team[0]: got %q", tenant.Teams[0].Name)
	}
	if len(tenant.Teams[0].Members) != 2 {
		t.Errorf("team[0] members: got %d, want 2", len(tenant.Teams[0].Members))
	}
}

func TestTenant_Namespaces(t *testing.T) {
	// Legacy tenant — single namespace.
	legacy := Tenant{Name: "billing", Members: []TenantMember{{UserID: "alice"}}}
	ns := legacy.Namespaces()
	if len(ns) != 1 || ns[0] != "billing" {
		t.Errorf("legacy namespaces: got %v, want [billing]", ns)
	}

	// Multi-team tenant — compound namespaces.
	multi := Tenant{
		Name: "knot-capital",
		Teams: []Team{
			{Name: "backend"},
			{Name: "frontend"},
		},
	}
	ns = multi.Namespaces()
	if len(ns) != 2 {
		t.Fatalf("multi-team namespaces: got %d, want 2", len(ns))
	}
	if ns[0] != "knot-capital-backend" || ns[1] != "knot-capital-frontend" {
		t.Errorf("multi-team namespaces: got %v", ns)
	}
}

func TestTenant_UserNamespaces(t *testing.T) {
	multi := Tenant{
		Name: "knot-capital",
		Members: []TenantMember{
			{UserID: "owner1", Role: "owner"},
		},
		Teams: []Team{
			{Name: "backend", Members: []TenantMember{{UserID: "dev1"}, {UserID: "dev2"}}},
			{Name: "frontend", Members: []TenantMember{{UserID: "dev3"}}},
		},
	}

	// Tenant-level member gets all team namespaces.
	ns := multi.UserNamespaces("owner1")
	if len(ns) != 2 {
		t.Errorf("owner1 should access 2 namespaces, got %v", ns)
	}

	// Team member gets only their team namespace.
	ns = multi.UserNamespaces("dev1")
	if len(ns) != 1 || ns[0] != "knot-capital-backend" {
		t.Errorf("dev1 should access [knot-capital-backend], got %v", ns)
	}

	ns = multi.UserNamespaces("dev3")
	if len(ns) != 1 || ns[0] != "knot-capital-frontend" {
		t.Errorf("dev3 should access [knot-capital-frontend], got %v", ns)
	}

	// Unknown user gets nothing.
	ns = multi.UserNamespaces("nobody")
	if len(ns) != 0 {
		t.Errorf("nobody should access 0 namespaces, got %v", ns)
	}

	// Case-insensitive match.
	ns = multi.UserNamespaces("Dev1")
	if len(ns) != 1 {
		t.Errorf("Dev1 (case-insensitive) should match dev1, got %v", ns)
	}
}

func TestGetTenantsForUser_MultiTeam(t *testing.T) {
	dir, r := setupTempRepo(t)

	// Legacy tenant.
	writeTenantYAML(t, dir, "billing", `
tenant:
  name: billing
  quotas: {}
  members:
    - userId: alice
`)

	// Multi-team tenant.
	writeTenantYAML(t, dir, "knot-capital", `
tenant:
  name: knot-capital
  quotas: {}
  members:
    - userId: alice
      role: owner
  teams:
    - name: backend
      members:
        - userId: bob
    - name: frontend
      members:
        - userId: charlie
`)

	// Alice: member of billing + owner of knot-capital (all teams).
	tenants, err := r.GetTenantsForUser("alice")
	if err != nil {
		t.Fatalf("GetTenantsForUser(alice): %v", err)
	}
	want := map[string]bool{"billing": true, "knot-capital-backend": true, "knot-capital-frontend": true}
	got := make(map[string]bool)
	for _, tn := range tenants {
		got[tn] = true
	}
	for k := range want {
		if !got[k] {
			t.Errorf("alice missing namespace %q, got %v", k, tenants)
		}
	}

	// Bob: team member of knot-capital/backend only.
	tenants, err = r.GetTenantsForUser("bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(tenants) != 1 || tenants[0] != "knot-capital-backend" {
		t.Errorf("bob should have [knot-capital-backend], got %v", tenants)
	}

	// Charlie: team member of knot-capital/frontend only.
	tenants, err = r.GetTenantsForUser("charlie")
	if err != nil {
		t.Fatal(err)
	}
	if len(tenants) != 1 || tenants[0] != "knot-capital-frontend" {
		t.Errorf("charlie should have [knot-capital-frontend], got %v", tenants)
	}
}

func TestTenant_IsMultiTeam(t *testing.T) {
	legacy := Tenant{Name: "billing"}
	if legacy.IsMultiTeam() {
		t.Error("legacy tenant should not be multi-team")
	}

	multi := Tenant{Name: "x", Teams: []Team{{Name: "a"}}}
	if !multi.IsMultiTeam() {
		t.Error("tenant with teams should be multi-team")
	}
}
