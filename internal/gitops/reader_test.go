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
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
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

func TestPlatformSkills_GetUnknownSkillWrapsErrNotExist(t *testing.T) {
	_, r := setupTempRepo(t)
	_, _, err := r.GetPlatformSkill("does-not-exist")
	if err == nil {
		t.Fatal("expected error for unknown skill")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected error to wrap fs.ErrNotExist, got: %v", err)
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

// --- SSH host-key pinning (issue-198) ---
//
// The tests below exercise the SSH branch of refresh(): they never run
// against real GitHub. sshFixtureServer is a minimal in-process SSH server
// bound to 127.0.0.1 on an ephemeral port that presents a fixed host key
// and completes only the SSH transport-layer handshake — it does not
// implement git-upload-pack. That is sufficient: git/ssh abort at host-key
// verification before any git protocol exchange when the presented key
// doesn't match known_hosts, which is exactly the failure T2 asserts.

// TestBuildSSHCommand_PinsHostKeyChecking is a cheap regression guard for
// the GIT_SSH_COMMAND flags: it must enforce strict host-key checking
// against an explicit known_hosts file and must never fall back to
// trust-on-first-use. The forbidden flag value is split across two string
// literals below so this test file itself does not contain the literal
// substring being guarded against.
func TestBuildSSHCommand_PinsHostKeyChecking(t *testing.T) {
	cmd := buildSSHCommand("/path/to/deploy-key", "/path/to/known_hosts")
	if !strings.Contains(cmd, "StrictHostKeyChecking=yes") {
		t.Errorf("ssh command missing StrictHostKeyChecking=yes: %q", cmd)
	}
	if !strings.Contains(cmd, "UserKnownHostsFile='/path/to/known_hosts'") {
		t.Errorf("ssh command missing UserKnownHostsFile: %q", cmd)
	}
	// UserKnownHostsFile only replaces ~/.ssh/known_hosts; without this,
	// /etc/ssh/ssh_known_hosts remains a valid second source of truth.
	if !strings.Contains(cmd, "GlobalKnownHostsFile=/dev/null") {
		t.Errorf("ssh command must neutralise the global known_hosts file: %q", cmd)
	}
	forbiddenTOFUFlag := "accept" + "-new"
	if strings.Contains(cmd, forbiddenTOFUFlag) {
		t.Errorf("ssh command must never fall back to trust-on-first-use: %q", cmd)
	}
}

// TestBuildSSHCommand_QuotesPaths guards the shell-word construction: git
// hands GIT_SSH_COMMAND to a shell, so an unquoted path containing a space
// would silently split into two arguments, and anything more exotic would
// be interpreted rather than used as a path.
func TestBuildSSHCommand_QuotesPaths(t *testing.T) {
	cmd := buildSSHCommand("/keys/deploy key", "/hosts/known hosts")
	if !strings.Contains(cmd, "-i '/keys/deploy key'") {
		t.Errorf("key path not quoted as a single shell word: %q", cmd)
	}
	if !strings.Contains(cmd, "UserKnownHostsFile='/hosts/known hosts'") {
		t.Errorf("known_hosts path not quoted as a single shell word: %q", cmd)
	}

	// A single quote must not terminate the quoted word.
	if got, want := shellQuote("/a'b"), `'/a'\''b'`; got != want {
		t.Errorf("shellQuote = %s, want %s", got, want)
	}
	// A command substitution must survive as literal text.
	if got := shellQuote("/x$(touch /tmp/pwned)y"); got != `'/x$(touch /tmp/pwned)y'` {
		t.Errorf("shellQuote must not interpret the path: %s", got)
	}
}

// TestNewReader_NoFilesystemWriteWhenKnownHostsPathEmpty asserts the
// constructor performs no I/O: with knownHostsPath == "", the lazily
// materialized default known_hosts file must not exist immediately after
// construction.
func TestNewReader_NoFilesystemWriteWhenKnownHostsPathEmpty(t *testing.T) {
	localPath := filepath.Join(t.TempDir(), "repo")

	r := NewReader("git@github.com:mctlhq/mctl-gitops.git", "main", localPath, "", "/some/deploy-key", "")
	if r.knownHostsPath != "" {
		t.Fatalf("knownHostsPath should be stored verbatim as empty, got %q", r.knownHostsPath)
	}

	target := filepath.Join(localPath+".known-hosts", "known_hosts")
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("NewReader must not materialize the known_hosts file (no I/O in the constructor); stat err=%v", err)
	}
}

// TestResolveKnownHostsPathLocked_MaterializesAndCaches covers the lazy
// materializer used by the SSH branch of refresh(): it writes the embedded
// default with mode 0600 inside an owner-only (0700) sibling directory of
// localPath, and a second call against a fresh Reader pointed at the same
// localPath must not rewrite an already byte-identical file.
func TestResolveKnownHostsPathLocked_MaterializesAndCaches(t *testing.T) {
	localPath := filepath.Join(t.TempDir(), "repo")
	dir := localPath + ".known-hosts"

	r1 := &Reader{localPath: localPath}
	path, err := r1.resolveKnownHostsPathLocked()
	if err != nil {
		t.Fatalf("resolveKnownHostsPathLocked: %v", err)
	}
	wantPath := filepath.Join(dir, "known_hosts")
	if path != wantPath {
		t.Fatalf("resolved path = %q, want %q", path, wantPath)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if !dirInfo.IsDir() {
		t.Fatalf("%s is not a directory", dir)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode = %v, want 0700", dirInfo.Mode().Perm())
	}

	//nolint:gosec // path is resolveKnownHostsPathLocked's output under t.TempDir()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading materialized file: %v", err)
	}
	if !bytes.Equal(got, githubKnownHosts) {
		t.Fatalf("materialized content does not match the embedded default")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}

	// A second call, from a Reader with no in-memory cache, against a
	// byte-identical file already on disk must not rewrite it.
	time.Sleep(10 * time.Millisecond)
	r2 := &Reader{localPath: localPath}
	path2, err := r2.resolveKnownHostsPathLocked()
	if err != nil {
		t.Fatalf("second resolveKnownHostsPathLocked: %v", err)
	}
	if path2 != path {
		t.Fatalf("second resolved path = %q, want %q", path2, path)
	}
	info2, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat after second call: %v", err)
	}
	if !info2.ModTime().Equal(info.ModTime()) {
		t.Fatalf("materializer rewrote a byte-identical file (mtime changed)")
	}
}

// TestResolveKnownHostsPathLocked_RejectsGroupWorldWritableReuse covers the
// finding-#2 fix: a pre-existing file at the resolved path with
// byte-identical content must still be rejected for reuse if it carries
// group/world permission bits, since a local attacker who could plant it
// (the embedded known_hosts content is public) might intend to swap in a
// malicious host key once it's cached and trusted.
func TestResolveKnownHostsPathLocked_RejectsGroupWorldWritableReuse(t *testing.T) {
	localPath := filepath.Join(t.TempDir(), "repo")
	dir := localPath + ".known-hosts"
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("pre-creating known_hosts dir fixture: %v", err)
	}
	path := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(path, githubKnownHosts, 0o644); err != nil {
		t.Fatalf("pre-creating known_hosts fixture: %v", err)
	}

	r := &Reader{localPath: localPath}
	if _, err := r.resolveKnownHostsPathLocked(); err == nil {
		t.Fatalf("resolveKnownHostsPathLocked: expected error for group/world-readable pre-existing file, got nil")
	} else if !strings.Contains(err.Error(), "not owner-only") {
		t.Fatalf("resolveKnownHostsPathLocked: expected permission-bits error, got: %v", err)
	}
	if r.resolvedKnownHostsPath != "" {
		t.Fatalf("resolvedKnownHostsPath must not be cached on failure, got %q", r.resolvedKnownHostsPath)
	}
}

// TestResolveKnownHostsPathLocked_RejectsSymlinkedKnownHostsDir covers the
// directory-level symlink-plant defense described in the finding-#1 fix: if
// the known_hosts directory path is itself a symlink (planted by another
// local user before this Reader ever ran), resolution must fail closed
// instead of following it into wherever it points.
func TestResolveKnownHostsPathLocked_RejectsSymlinkedKnownHostsDir(t *testing.T) {
	root := t.TempDir()
	localPath := filepath.Join(root, "repo")
	dir := localPath + ".known-hosts"
	elsewhere := filepath.Join(root, "elsewhere")
	if err := os.Mkdir(elsewhere, 0o700); err != nil {
		t.Fatalf("creating symlink target: %v", err)
	}
	if err := os.Symlink(elsewhere, dir); err != nil {
		t.Fatalf("planting symlink fixture: %v", err)
	}

	r := &Reader{localPath: localPath}
	if _, err := r.resolveKnownHostsPathLocked(); err == nil {
		t.Fatalf("resolveKnownHostsPathLocked: expected error for symlinked known_hosts directory, got nil")
	} else if !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("resolveKnownHostsPathLocked: expected not-a-directory error, got: %v", err)
	}
	if r.resolvedKnownHostsPath != "" {
		t.Fatalf("resolvedKnownHostsPath must not be cached on failure, got %q", r.resolvedKnownHostsPath)
	}
}

// sshFixtureServer is a minimal in-process SSH server for testing host-key
// verification. It binds loopback only, on an ephemeral port, and never
// reaches the real network.
type sshFixtureServer struct {
	listener net.Listener
	pubKey   ssh.PublicKey
	host     string
	port     string
}

func startSSHFixtureServer(t *testing.T) *sshFixtureServer {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating fixture host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("wrapping fixture host key: %v", err)
	}

	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening on 127.0.0.1:0: %v", err)
	}
	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("splitting fixture listener address: %v", err)
	}

	srv := &sshFixtureServer{listener: ln, pubKey: signer.PublicKey(), host: host, port: port}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go func(c net.Conn) {
				defer c.Close() //nolint:errcheck
				// Complete (or fail) the SSH transport handshake. A client
				// that rejects our host key disconnects before this
				// returns successfully; we don't care about that outcome
				// here, only that a key was offered for the client to
				// verify. A client that accepts it gets a channel-open
				// rejection, since this fixture does not implement
				// git-upload-pack.
				sc, chans, reqs, err := ssh.NewServerConn(c, config)
				if err != nil {
					return
				}
				defer sc.Close() //nolint:errcheck
				go ssh.DiscardRequests(reqs)
				for newCh := range chans {
					_ = newCh.Reject(ssh.Prohibited, "fixture server does not implement git-upload-pack")
				}
			}(conn)
		}
	}()

	t.Cleanup(func() { _ = ln.Close() })
	return srv
}

// knownHostsLine returns a known_hosts entry for this server's real host key.
func (s *sshFixtureServer) knownHostsLine() string {
	return fmt.Sprintf("[%s]:%s %s", s.host, s.port, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.pubKey))))
}

// wrongKnownHostsLine returns a known_hosts entry for the same host:port
// but with a freshly generated, unrelated key — simulating an attacker (or
// a rotated/wrong host) presenting a key that does not match what's pinned.
func (s *sshFixtureServer) wrongKnownHostsLine(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating decoy key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("wrapping decoy key: %v", err)
	}
	return fmt.Sprintf("[%s]:%s %s", s.host, s.port, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))))
}

// sshURL returns a ssh:// clone URL pointing at this fixture server.
func (s *sshFixtureServer) sshURL() string {
	return fmt.Sprintf("ssh://git@%s:%s/fixture-repo.git", s.host, s.port)
}

// generateTestClientKey creates a throwaway ed25519 keypair for use as the
// -i argument to ssh; the fixture server accepts any/no client auth, so its
// content is irrelevant beyond being a well-formed, correctly permissioned
// private key file that ssh will accept without complaint.
func generateTestClientKey(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", keyPath, "-q") //nolint:gosec // fixed test arguments
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	return keyPath
}

func writeKnownHostsFixture(t *testing.T, line string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("writing known_hosts fixture: %v", err)
	}
	return path
}

// TestRefresh_SSHHostKeyMismatch_FailsClosed is the acceptance-criteria
// test the issue explicitly asks for: a mismatched host key must fail the
// clone closed, with an error identifying host-key verification as the
// cause, and must leave localPath unpopulated.
func TestRefresh_SSHHostKeyMismatch_FailsClosed(t *testing.T) {
	srv := startSSHFixtureServer(t)
	keyPath := generateTestClientKey(t)
	knownHosts := writeKnownHostsFixture(t, srv.wrongKnownHostsLine(t))
	localPath := filepath.Join(t.TempDir(), "cache")

	r := &Reader{
		repoURL:        srv.sshURL(),
		branch:         "main",
		localPath:      localPath,
		sshKeyPath:     keyPath,
		knownHostsPath: knownHosts,
	}

	err := r.refresh()
	if err == nil {
		t.Fatal("expected refresh to fail closed on a mismatched host key, got nil error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "Host key verification failed") && !strings.Contains(msg, "REMOTE HOST IDENTIFICATION HAS CHANGED") {
		t.Fatalf("expected a host-key verification failure, got: %v", err)
	}
	if _, statErr := os.Stat(localPath); !os.IsNotExist(statErr) {
		t.Fatalf("localPath must not be populated after a host-key verification failure, stat err=%v", statErr)
	}
}

// TestRefresh_SSHHostKeyMatch_PassesHostKeyVerification is the positive
// counterpart to the test above: pinning the fixture server's real host key
// must let the SSH transport get past host-key verification. This fixture
// does not implement git-upload-pack, so refresh() is still expected to
// fail overall — the assertion is on the *absence* of a host-key-failure
// error class, not end-to-end clone success.
func TestRefresh_SSHHostKeyMatch_PassesHostKeyVerification(t *testing.T) {
	srv := startSSHFixtureServer(t)
	keyPath := generateTestClientKey(t)
	knownHosts := writeKnownHostsFixture(t, srv.knownHostsLine())
	localPath := filepath.Join(t.TempDir(), "cache")

	r := &Reader{
		repoURL:        srv.sshURL(),
		branch:         "main",
		localPath:      localPath,
		sshKeyPath:     keyPath,
		knownHostsPath: knownHosts,
	}

	err := r.refresh()
	if err == nil {
		// An even stronger pass: host-key checking was clearly not the
		// blocker. Full git-upload-pack faking is out of scope for this
		// fixture.
		return
	}
	msg := err.Error()
	if strings.Contains(msg, "Host key verification failed") || strings.Contains(msg, "REMOTE HOST IDENTIFICATION HAS CHANGED") {
		t.Fatalf("expected the clone to get past host-key verification with the correct pinned key, got a host-key failure: %v", err)
	}
}
