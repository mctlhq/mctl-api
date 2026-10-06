package gitops

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const erpactYAML = `tenant:
  name: erpact
  members:
    - userId: Alice
      role: owner
    - userId: bob
      role: developer
    - userId: carol
      role: viewer
    - userId: dave
    - userId: erin
      role: maintainer
    - userId: twice
      role: owner
    - userId: twice
      role: viewer
`

func syncedRepo(t *testing.T) (string, *Reader) {
	t.Helper()
	dir, r := setupTempRepo(t)
	r.lastSync.Store(time.Now().UnixNano())
	return dir, r
}

func TestMemberRoles(t *testing.T) {
	dir, r := syncedRepo(t)
	writeTenantYAML(t, dir, "erpact", erpactYAML)
	writeTenantYAML(t, dir, "other", "tenant:\n  name: other\n  members:\n    - userId: bob\n      role: owner\n")

	tests := []struct {
		namespace, login string
		want             []string
	}{
		{"erpact", "alice", []string{"owner"}}, // login match ignores case, as membership does
		{"erpact", "bob", []string{"developer"}},
		{"erpact", "carol", []string{"viewer"}},
		{"erpact", "dave", []string{""}},           // a member with no role: reported, not dropped
		{"erpact", "erin", []string{"maintainer"}}, // returned as written; ranking is the caller's
		{"erpact", "twice", []string{"owner", "viewer"}},
		{"erpact", "mallory", nil},
		{"other", "bob", []string{"owner"}}, // a role in one tenant
		{"other", "alice", nil},             // is not a role in another
		{"ghost", "alice", nil},             // no such tenant
		{"erpact-web", "alice", nil},        // not a team of a legacy tenant
	}
	for _, tt := range tests {
		got, err := r.MemberRoles(tt.namespace, tt.login)
		if err != nil {
			t.Errorf("MemberRoles(%q, %q): %v", tt.namespace, tt.login, err)
			continue
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("MemberRoles(%q, %q) = %q, want %q", tt.namespace, tt.login, got, tt.want)
		}
	}
}

func TestMemberRoles_MultiTeam(t *testing.T) {
	dir, r := syncedRepo(t)
	writeTenantYAML(t, dir, "acme", `tenant:
  name: acme
  members:
    - userId: boss
      role: owner
    - userId: both
      role: owner
  teams:
    - name: web
      members:
        - userId: dev
          role: developer
        - userId: both
          role: viewer
    - name: data
      members:
        - userId: analyst
          role: viewer
`)
	tests := []struct {
		namespace, login string
		want             []string
	}{
		{"acme-web", "boss", []string{"owner"}}, // tenant-level members reach every team
		{"acme-data", "boss", []string{"owner"}},
		{"acme-web", "dev", []string{"developer"}},
		{"acme-data", "dev", nil}, // a team role stays in its team
		{"acme-web", "both", []string{"owner", "viewer"}},
		{"acme-data", "analyst", []string{"viewer"}},
		{"acme", "boss", nil}, // the bare tenant name is not a namespace of a multi-team tenant
	}
	for _, tt := range tests {
		got, err := r.MemberRoles(tt.namespace, tt.login)
		if err != nil {
			t.Errorf("MemberRoles(%q, %q): %v", tt.namespace, tt.login, err)
			continue
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("MemberRoles(%q, %q) = %q, want %q", tt.namespace, tt.login, got, tt.want)
		}
	}
}

// Everything MemberRoles could not read is an error. None of it may come
// back as "not a member", which the caller would turn into a plain 403, and
// still less as a role.
func TestMemberRoles_UnreadableIsNeverAnAnswer(t *testing.T) {
	t.Run("never synced", func(t *testing.T) {
		dir, r := setupTempRepo(t)
		writeTenantYAML(t, dir, "erpact", erpactYAML)
		if got, err := r.MemberRoles("erpact", "alice"); err == nil || !strings.Contains(err.Error(), "never synced") {
			t.Fatalf("got %q, %v; want a never-synced error", got, err)
		}
	})
	t.Run("stale checkout", func(t *testing.T) {
		dir, r := setupTempRepo(t)
		writeTenantYAML(t, dir, "erpact", erpactYAML)
		r.lastSync.Store(time.Now().Add(-MemberRolesMaxAge - time.Minute).UnixNano())
		if got, err := r.MemberRoles("erpact", "alice"); err == nil {
			t.Fatalf("a stale checkout answered %q", got)
		}
	})
	t.Run("no tenants directory", func(t *testing.T) {
		_, r := syncedRepo(t)
		if got, err := r.MemberRoles("erpact", "alice"); err == nil {
			t.Fatalf("a checkout with no tenants directory answered %q", got)
		}
	})
	t.Run("malformed values of the tenant asked about", func(t *testing.T) {
		dir, r := syncedRepo(t)
		writeTenantYAML(t, dir, "erpact", "tenant: [not, a, mapping\n")
		if got, err := r.MemberRoles("erpact", "alice"); err == nil {
			t.Fatalf("malformed values answered %q", got)
		}
	})
	t.Run("malformed values of another tenant", func(t *testing.T) {
		// tenant.name, not the directory, names a tenant, so a file that
		// cannot be parsed could be the one that owns the namespace.
		dir, r := syncedRepo(t)
		writeTenantYAML(t, dir, "erpact", erpactYAML)
		writeTenantYAML(t, dir, "broken", "tenant: [not, a, mapping\n")
		if got, err := r.MemberRoles("erpact", "alice"); err == nil {
			t.Fatalf("answered %q although one tenant could not be read", got)
		}
	})
	t.Run("unreadable values file", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root ignores file permissions")
		}
		dir, r := syncedRepo(t)
		writeTenantYAML(t, dir, "erpact", erpactYAML)
		path := filepath.Join(dir, "platform-gitops", "tenants", "erpact", "values.yaml")
		if err := os.Chmod(path, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
		if got, err := r.MemberRoles("erpact", "alice"); err == nil {
			t.Fatalf("an unreadable values file answered %q", got)
		}
	})
	t.Run("namespace claimed twice", func(t *testing.T) {
		dir, r := syncedRepo(t)
		writeTenantYAML(t, dir, "erpact", erpactYAML)
		writeTenantYAML(t, dir, "impostor", "tenant:\n  name: erpact\n  members:\n    - userId: mallory\n      role: owner\n")
		if got, err := r.MemberRoles("erpact", "mallory"); err == nil {
			t.Fatalf("an ambiguous namespace answered %q", got)
		}
	})
	t.Run("empty arguments", func(t *testing.T) {
		dir, r := syncedRepo(t)
		writeTenantYAML(t, dir, "erpact", erpactYAML)
		if _, err := r.MemberRoles("", "alice"); err == nil {
			t.Error("an empty namespace must be an error")
		}
		if _, err := r.MemberRoles("erpact", ""); err == nil {
			t.Error("an empty login must be an error")
		}
	})
}

// The one thing that is skipped: a directory with no values.yaml is not a
// tenant, so it neither answers nor blocks the answer.
func TestMemberRoles_DirectoryWithoutValuesIsNotATenant(t *testing.T) {
	dir, r := syncedRepo(t)
	writeTenantYAML(t, dir, "erpact", erpactYAML)
	if err := os.MkdirAll(filepath.Join(dir, "platform-gitops", "tenants", "half"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "platform-gitops", "tenants", "README.md"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := r.MemberRoles("erpact", "bob")
	if err != nil || !reflect.DeepEqual(got, []string{"developer"}) {
		t.Fatalf("MemberRoles = %q, %v; want [developer]", got, err)
	}
}
