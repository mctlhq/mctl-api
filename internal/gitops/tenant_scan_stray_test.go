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

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// strayRepo is a tenants directory holding a valid tenant plus directories
// whose names can never be tenants. Old-Tenant even carries a values.yaml
// that would claim the namespace "acme": it must be ignored, not read.
func strayRepo(t *testing.T) (string, *Reader) {
	t.Helper()
	dir, r := syncedRepo(t)
	writeTenantYAML(t, dir, "acme", keyedAcmeYAML)
	writeTenantYAML(t, dir, "Old-Tenant", keyedAcmeYAML)
	for _, n := range []string{"_template", ".archive"} {
		if err := os.MkdirAll(filepath.Join(dir, "platform-gitops", "tenants", n), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	return dir, r
}

// Every directory scan skips a directory whose name fails the allowlist
// (it can never be a tenant) instead of failing with ErrInvalidTenantName,
// which would be a fleet-wide authorization outage.
func TestScansSkipStrayInvalidlyNamedDirectories(t *testing.T) {
	_, r := strayRepo(t)

	t.Run("MemberRoles", func(t *testing.T) {
		got, err := r.MemberRoles("acme-web", "dev")
		if err != nil || len(got) != 1 || got[0][0] != "developer" {
			t.Fatalf("got %v, %v", got, err)
		}
	})
	t.Run("MemberRolesForPrincipal", func(t *testing.T) {
		got, err := r.MemberRolesForPrincipal("acme-web", prnBob)
		if err != nil || len(got) != 1 || got[0][0] != "developer" {
			t.Fatalf("got %v, %v", got, err)
		}
	})
	t.Run("NamespacesForPrincipal", func(t *testing.T) {
		got, err := r.NamespacesForPrincipal(prnAlice)
		if err != nil || len(got.Unreadable) != 0 || len(got.Namespaces) == 0 {
			t.Fatalf("got %+v, %v", got, err)
		}
	})
	t.Run("NamespaceProfile", func(t *testing.T) {
		_, owned, err := r.NamespaceProfile("acme")
		if err != nil || !owned {
			t.Fatalf("owned=%v err=%v", owned, err)
		}
	})
	t.Run("ListTenantsStrict", func(t *testing.T) {
		got, err := r.ListTenantsStrict()
		if err != nil || len(got) != 1 || got[0].Name != "acme" {
			t.Fatalf("got %v, %v", got, err)
		}
	})
	t.Run("ListTenants", func(t *testing.T) {
		got, err := r.ListTenants()
		if err != nil || len(got) != 1 {
			t.Fatalf("got %v, %v", got, err)
		}
	})
	t.Run("AllMemberEntries", func(t *testing.T) {
		got, err := r.AllMemberEntries()
		if err != nil || len(got.Unreadable) != 0 || len(got.Entries) == 0 {
			t.Fatalf("got %+v, %v", got, err)
		}
		for _, e := range got.Entries {
			if e.Tenant != "acme" {
				t.Fatalf("entry from %q", e.Tenant)
			}
		}
	})
	t.Run("counted", func(t *testing.T) {
		if _, err := r.ListTenantsStrict(); err != nil {
			t.Fatal(err)
		}
		if got := testutil.ToFloat64(tenantDirsSkipped); got != 3 {
			t.Fatalf("tenantDirsSkipped = %v, want 3", got)
		}
	})
}

// Only allowlist-failing names are skipped. A directory whose name is valid
// but whose values.yaml is corrupt still surfaces, in every scan.
func TestScansStillFailOnCorruptValidlyNamedTenant(t *testing.T) {
	dir, r := strayRepo(t)
	writeTenantYAML(t, dir, "broken", "tenant: [unclosed")

	if _, err := r.MemberRoles("acme", "boss"); err == nil {
		t.Error("MemberRoles: want error")
	}
	if _, err := r.MemberRolesForPrincipal("acme", prnAlice); err == nil {
		t.Error("MemberRolesForPrincipal: want error")
	}
	m, err := r.NamespacesForPrincipal(prnAlice)
	if err != nil || len(m.Unreadable) != 1 || m.Unreadable[0] != "broken" {
		t.Errorf("NamespacesForPrincipal: %+v, %v", m, err)
	}
	if _, _, err := r.NamespaceProfile("acme"); err == nil {
		t.Error("NamespaceProfile: want error")
	}
	if _, err := r.ListTenantsStrict(); err == nil {
		t.Error("ListTenantsStrict: want error")
	}
	e, err := r.AllMemberEntries()
	if err != nil || len(e.Unreadable) != 1 || e.Unreadable[0] != "broken" {
		t.Errorf("AllMemberEntries: %+v, %v", e, err)
	}
}

// The strict request path is unchanged.
func TestGetTenantStillRejectsInvalidName(t *testing.T) {
	_, r := strayRepo(t)
	if _, err := r.GetTenant("Old-Tenant"); err == nil {
		t.Fatal("want ErrInvalidTenantName")
	}
}
