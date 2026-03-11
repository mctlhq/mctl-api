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
