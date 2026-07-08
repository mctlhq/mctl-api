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
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func writePlatformSkill(t *testing.T, dir, name, metadata, content string) {
	t.Helper()
	skillDir := filepath.Join(dir, "platform-gitops", "platform-skills", "catalog", name)
	if err := os.MkdirAll(skillDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "metadata.yaml"), []byte(metadata), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...) //nolint:gosec // test arguments are fixed by the test
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, bytes.TrimSpace(out))
	}
	return string(out)
}

func commitAll(t *testing.T, dir, message string) string {
	t.Helper()
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-m", message)
	return runGit(t, dir, "rev-parse", "--short", "HEAD")
}

func TestRefreshResetsDivergedCache(t *testing.T) {
	root := t.TempDir()
	remote := filepath.Join(root, "remote.git")
	work := filepath.Join(root, "work")
	cache := filepath.Join(root, "cache")

	runGit(t, root, "init", "--bare", remote)
	runGit(t, root, "clone", remote, work)
	runGit(t, work, "checkout", "-b", "main")
	runGit(t, work, "config", "user.email", "test@example.com")
	runGit(t, work, "config", "user.name", "Test User")

	writeTenantYAML(t, work, "alpha", `tenant: {name: alpha, quotas: {}}`)
	commitAll(t, work, "initial tenant")
	runGit(t, work, "push", "origin", "main")

	r := &Reader{
		repoURL:   remote,
		branch:    "main",
		localPath: cache,
	}
	if err := r.refresh(); err != nil {
		t.Fatalf("initial refresh: %v", err)
	}

	runGit(t, cache, "config", "user.email", "cache@example.com")
	runGit(t, cache, "config", "user.name", "Cache User")
	writeTenantYAML(t, cache, "local-only", `tenant: {name: local-only, quotas: {}}`)
	commitAll(t, cache, "local divergent commit")

	writeTenantYAML(t, work, "nfc", `
tenant:
  name: nfc
  quotas: {}
  members:
    - userId: WannaBeGeekster
      role: owner
`)
	remoteHead := commitAll(t, work, "add nfc tenant")
	runGit(t, work, "push", "origin", "main")

	if err := r.refresh(); err != nil {
		t.Fatalf("refresh after divergence: %v", err)
	}

	gotHead := strings.TrimSpace(runGit(t, cache, "rev-parse", "--short", "HEAD"))
	if gotHead != strings.TrimSpace(remoteHead) {
		t.Fatalf("cache HEAD = %q, want remote HEAD %q", gotHead, remoteHead)
	}
	if _, err := os.Stat(filepath.Join(cache, "platform-gitops", "tenants", "local-only")); !os.IsNotExist(err) {
		t.Fatalf("local-only tenant should be removed after cache reset, stat err=%v", err)
	}
	tenant, err := r.GetTenant("nfc")
	if err != nil {
		t.Fatalf("GetTenant(nfc): %v", err)
	}
	if tenant.Name != "nfc" || len(tenant.Members) != 1 || tenant.Members[0].UserID != "WannaBeGeekster" {
		t.Fatalf("unexpected nfc tenant: %+v", tenant)
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

func TestReadService_NestedHostAndPort(t *testing.T) {
	// Mirrors the shape that deploy-service actually writes today: top-level
	// host is absent, hostname lives in ingress.hosts[0], port lives in
	// service.port. Without the fallback both fields rendered empty in MCP
	// responses.
	dir, r := setupTempRepo(t)
	writeServiceYAML(t, dir, "admins", "mctl-docs", `
image:
  tag: "0.1.17"
service:
  port: 80
ingress:
  enabled: true
  hosts:
    - docs.mctl.ai
    - admins-mctl-docs.mctl.ai
`)
	svc, err := r.readService("admins", "mctl-docs")
	if err != nil {
		t.Fatalf("readService: %v", err)
	}
	if svc.Host != "docs.mctl.ai" {
		t.Errorf("Host (from ingress.hosts[0]): got %q, want docs.mctl.ai", svc.Host)
	}
	if svc.Port != "80" {
		t.Errorf("Port (from service.port): got %q, want 80", svc.Port)
	}
}

func TestReadService_TopLevelOverridesNested(t *testing.T) {
	// Legacy values still populate the fields when present at the top level.
	dir, r := setupTempRepo(t)
	writeServiceYAML(t, dir, "billing", "legacy", `
image:
  tag: "1.0.0"
host: legacy.example.com
port: 9090
service:
  port: 80
ingress:
  hosts:
    - other.example.com
`)
	svc, err := r.readService("billing", "legacy")
	if err != nil {
		t.Fatalf("readService: %v", err)
	}
	if svc.Host != "legacy.example.com" {
		t.Errorf("top-level host should win, got %q", svc.Host)
	}
	if svc.Port != "9090" {
		t.Errorf("top-level port should win, got %q", svc.Port)
	}
}

func TestReadService_IngressHostsLongForm(t *testing.T) {
	// Some charts (and a chunk of upstream Helm content) ship hosts as
	// `[{host: foo, paths: [...]}]`. Exercise that branch too.
	dir, r := setupTempRepo(t)
	writeServiceYAML(t, dir, "team", "longform", `
image:
  tag: "0.1.0"
service:
  port: 3000
ingress:
  hosts:
    - host: longform.example.com
      paths:
        - path: /
          pathType: Prefix
`)
	svc, err := r.readService("team", "longform")
	if err != nil {
		t.Fatalf("readService: %v", err)
	}
	if svc.Host != "longform.example.com" {
		t.Errorf("Host (from ingress.hosts[0].host): got %q", svc.Host)
	}
	if svc.Port != "3000" {
		t.Errorf("Port (from service.port): got %q", svc.Port)
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

func TestPlatformSkills_ListAndRead(t *testing.T) {
	dir, r := setupTempRepo(t)
	writePlatformSkill(t, dir, "mctl-platform", `
name: mctl-platform
title: MCTL Platform
description: Platform guidance
visibility: admin
status: active
owner: platform
runtimes: [mcp, codex]
`, "# MCTL Platform")

	skills, err := r.ListPlatformSkills()
	if err != nil {
		t.Fatalf("ListPlatformSkills: %v", err)
	}
	if len(skills) != 1 || skills[0].Metadata.Name != "mctl-platform" || !skills[0].HasContent {
		t.Fatalf("unexpected skills: %+v", skills)
	}
	skill, content, err := r.GetPlatformSkill("mctl-platform")
	if err != nil {
		t.Fatalf("GetPlatformSkill: %v", err)
	}
	if skill.Metadata.Visibility != "admin" || content != "# MCTL Platform" {
		t.Fatalf("unexpected skill/content: %+v %q", skill, content)
	}
}

func TestPlatformSkills_MalformedMetadataReturnsError(t *testing.T) {
	dir, r := setupTempRepo(t)
	writePlatformSkill(t, dir, "bad-skill", `
name: bad-skill
title: Bad
description: Missing valid visibility
visibility: everyone
status: active
owner: platform
runtimes: [mcp]
`, "# Bad")

	if _, err := r.ListPlatformSkills(); err == nil || !strings.Contains(err.Error(), "visibility") {
		t.Fatalf("expected visibility error, got %v", err)
	}
}

func TestPlatformSkills_MetadataNameMustMatchDirectory(t *testing.T) {
	dir, r := setupTempRepo(t)
	writePlatformSkill(t, dir, "beta-skill", `
name: alpha-skill
title: Beta
description: Mismatched skill
visibility: public
status: active
owner: platform
runtimes: [mcp]
`, "# Beta")

	if _, err := r.ListPlatformSkills(); err == nil || !strings.Contains(err.Error(), "must match") {
		t.Fatalf("expected name mismatch error, got %v", err)
	}
}
