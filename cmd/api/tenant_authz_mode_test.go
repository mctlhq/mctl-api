package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/gitops"
)

// TENANT_AUTHZ_MODE refuses the boot on a value it cannot honour, principal
// included when its configuration is incomplete, and no kill switch skips
// that check.
func TestConfigValidate_TenantAuthzMode(t *testing.T) {
	for _, raw := range []string{"principal", "shadwo", "Legacy"} {
		for _, killed := range []bool{false, true} {
			cfg := config{TenantAuthzModeRaw: raw, FederationDisabled: killed, CommerceDisabled: killed}
			err := cfg.validate()
			if err == nil || !strings.Contains(err.Error(), "TENANT_AUTHZ_MODE") {
				t.Errorf("TENANT_AUTHZ_MODE=%q (kill switches %v): validate() = %v, want a refusal naming it", raw, killed, err)
			}
		}
	}
	for raw, want := range map[string]mctlapi.TenantAuthzMode{"": mctlapi.TenantAuthzLegacy, "legacy": mctlapi.TenantAuthzLegacy, "shadow": mctlapi.TenantAuthzShadow, "principal": mctlapi.TenantAuthzPrincipal} {
		cfg := config{TenantAuthzModeRaw: raw, CommerceDisabled: true,
			AdminPrincipalsRaw: "prn_01JAAAAAAAAAAAAAAAAAAAAAAA", PrincipalDBConfigured: true}
		if err := cfg.validate(); err != nil {
			t.Errorf("TENANT_AUTHZ_MODE=%q: validate() = %v", raw, err)
		}
		if got := cfg.tenantAuthzMode(); got != want {
			t.Errorf("TENANT_AUTHZ_MODE=%q: mode %q, want %q", raw, got, want)
		}
	}
}

// An entry keyed only by principalId names no login: the principal
// backfill must not be handed an empty one.
func TestTenantMemberLogins_SkipsPrincipalOnlyEntries(t *testing.T) {
	dir := t.TempDir()
	tenant := filepath.Join(dir, "platform-gitops", "tenants", "acme")
	if err := os.MkdirAll(tenant, 0o750); err != nil {
		t.Fatal(err)
	}
	values := `tenant:
  name: acme
  members:
    - userId: boss
      role: owner
    - principalId: prn_01JZZZZZZZZZZZZZZZZZZZZZZZ
      role: viewer
  teams:
    - name: web
      members:
        - userId: dev
        - principalId: prn_01JBBBBBBBBBBBBBBBBBBBBBBB
`
	if err := os.WriteFile(filepath.Join(tenant, "values.yaml"), []byte(values), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := tenantMemberLogins(gitops.NewReader("", "main", dir, nil, "", ""))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"boss", "dev"}) {
		t.Fatalf("logins = %q, want [boss dev]", got)
	}
}

// ADMIN_PRINCIPALS is validated in every mode, and principal mode refuses
// a configuration that would leave no admin or no principal to decide on.
func TestConfigValidate_AdminPrincipals(t *testing.T) {
	const admin = "prn_01JAAAAAAAAAAAAAAAAAAAAAAA"
	for _, raw := range []string{"mashkovd", admin + ",prn_bad"} {
		cfg := config{TenantAuthzModeRaw: "shadow", AdminPrincipalsRaw: raw, CommerceDisabled: true}
		if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "ADMIN_PRINCIPALS") {
			t.Errorf("ADMIN_PRINCIPALS=%q in shadow: validate() = %v, want a refusal", raw, err)
		}
	}
	ok := config{AdminPrincipalsRaw: admin, PrincipalDBConfigured: true}
	if err := ok.validatePrincipalMode(mctlapi.TenantAuthzPrincipal); err != nil {
		t.Fatalf("complete principal config refused: %v", err)
	}
	for name, cfg := range map[string]config{
		"no admins":           {PrincipalDBConfigured: true},
		"principals disabled": {AdminPrincipalsRaw: admin, PrincipalDBConfigured: true, PrincipalsDisabled: true},
		"no principal store":  {AdminPrincipalsRaw: admin},
	} {
		if err := cfg.validatePrincipalMode(mctlapi.TenantAuthzPrincipal); err == nil {
			t.Errorf("%s: principal mode accepted", name)
		}
		if err := cfg.validatePrincipalMode(mctlapi.TenantAuthzShadow); err != nil {
			t.Errorf("%s: shadow refused: %v", name, err)
		}
	}
	if got := (config{AdminPrincipalsRaw: admin}).principalAuthz(nil); got != nil {
		t.Fatal("principal authz wired outside principal mode")
	}
}

// principalTenants is the only wiring between the GitOps reader and the
// principal-mode decision: readable tenants are the membership, unreadable
// ones are reported as such and never granted. Swapping the two would hand
// out the tenants that could not be read.
func TestPrincipalTenantsAdapter(t *testing.T) {
	// The membership read refuses a checkout that never synced, so the
	// reader clones a local repository once, as RefreshLoop does at boot.
	src := t.TempDir()
	write := func(name, values string) {
		tenant := filepath.Join(src, "platform-gitops", "tenants", name)
		if err := os.MkdirAll(tenant, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tenant, "values.yaml"), []byte(values), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	const member = "prn_01JZZZZZZZZZZZZZZZZZZZZZZZ"
	write("acme", "tenant:\n  name: acme\n  members:\n    - principalId: "+member+"\n      role: owner\n")
	write("broken", "tenant:\n  name: broken\n  members:\n    - principalId: prn_bad\n      role: owner\n")
	write("other", "tenant:\n  name: other\n  members:\n    - principalId: prn_01JBBBBBBBBBBBBBBBBBBBBBBB\n      role: owner\n")
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"},
		{"-c", "user.name=t", "-c", "user.email=t@example.com", "add", "."},
		{"-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "tenants"},
	} {
		cmd := exec.Command("git", args...) //nolint:gosec // fixed arguments from this test
		cmd.Dir = src
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	reader := gitops.NewReader(src, "main", filepath.Join(t.TempDir(), "checkout"), nil, "", "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reader.RefreshLoop(ctx, time.Hour)
	if reader.LastSync().IsZero() {
		t.Fatal("the local clone did not sync")
	}

	namespaces, unreadable, err := principalTenants{reader}.PrincipalTenants(member)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(namespaces, []string{"acme"}) || !reflect.DeepEqual(unreadable, []string{"broken"}) {
		t.Fatalf("namespaces = %q, unreadable = %q; want [acme] and [broken]", namespaces, unreadable)
	}
}
