package operations

import (
	"sort"
	"testing"
)

// wantMinRole pins the minimum role of every registered operation
// (mctl-api#478). It is deliberately a second copy of what the registry
// says: changing who may run an operation, or adding an operation, has to be
// done here too, in a diff a reviewer reads as an authorization change.
var wantMinRole = map[string]Role{
	// Tenant operations.
	"deploy-service":       RoleDeveloper,
	"rollback-service":     RoleDeveloper,
	"provision-database":   RoleDeveloper,
	"preview-deploy":       RoleDeveloper,
	"preview-delete":       RoleDeveloper, // ephemeral by design: no data outlives the preview's TTL anyway
	"add-custom-domain":    RoleDeveloper,
	"remove-custom-domain": RoleOwner,
	"retire-service":       RoleOwner,
	"delete-tenant":        RoleOwner,

	// HandlerOnly: reachable only through handlers that require the owner.
	"openclaw-skill-save":      RoleOwner,
	"openclaw-skill-delete":    RoleOwner,
	"openclaw-identity-save":   RoleOwner,
	"openclaw-identity-delete": RoleOwner,

	// No tenant yet.
	"create-tenant": RoleAuthenticated,

	// Platform.
	"smoke-test":                 RoleAdmin,
	"platform-skill-publish":     RoleAdmin,
	"platform-skill-deprecate":   RoleAdmin,
	"platform-skill-enable":      RoleAdmin,
	"platform-skill-disable":     RoleAdmin,
	"mctl-agents-run":            RoleAdmin,
	"mctl-agents-mentor-only":    RoleAdmin,
	"mctl-agents-single-service": RoleAdmin,
	"mctl-agents-incidents":      RoleAdmin,
	"mctl-agents-implement":      RoleAdmin,
	"mctl-agents-shepherd":       RoleAdmin,
	"mctl-agents-investigate":    RoleAdmin,
	"mctl-agents-approve":        RoleAdmin,
	"mctl-agents-reconcile":      RoleAdmin,
}

func TestRegistry_EveryOperationDeclaresItsMinimumRole(t *testing.T) {
	ops := NewRegistry().List()
	seen := map[string]bool{}
	for _, op := range ops {
		seen[op.Name] = true
		want, pinned := wantMinRole[op.Name]
		if !pinned {
			t.Errorf("%s: not in wantMinRole; a new operation must state who may run it", op.Name)
			continue
		}
		if op.MinRole == "" {
			t.Errorf("%s: MinRole is unset; the zero value must never mean \"anyone\"", op.Name)
		}
		if !op.MinRole.Valid() {
			t.Errorf("%s: MinRole %q is not a role", op.Name, op.MinRole)
		}
		if op.MinRole != want {
			t.Errorf("%s: MinRole = %q, want %q", op.Name, op.MinRole, want)
		}
	}
	var gone []string
	for name := range wantMinRole {
		if !seen[name] {
			gone = append(gone, name)
		}
	}
	sort.Strings(gone)
	if len(gone) > 0 {
		t.Errorf("wantMinRole pins operations the registry no longer has: %v", gone)
	}
}

func TestRegistry_MinimumRoleInvariants(t *testing.T) {
	for _, op := range NewRegistry().List() {
		// The class the issue is about: nothing high-risk is open to a
		// developer, whatever the pinned table says.
		if op.RiskLevel == RiskHigh && op.MinRole != RoleOwner && op.MinRole != RoleAdmin {
			t.Errorf("%s is RiskHigh but MinRole is %q; high-risk operations require owner", op.Name, op.MinRole)
		}
		if op.AdminOnly && op.MinRole != RoleAdmin {
			t.Errorf("%s is AdminOnly but MinRole is %q", op.Name, op.MinRole)
		}
		if op.MinRole == RoleAuthenticated && op.Name != "create-tenant" {
			t.Errorf("%s: RoleAuthenticated belongs to create-tenant alone", op.Name)
		}
		if op.MinRole == RoleViewer {
			t.Errorf("%s: no write operation may accept the read-only role", op.Name)
		}
	}
}

func TestRole_Satisfies(t *testing.T) {
	tests := []struct {
		have, min Role
		want      bool
	}{
		{RoleOwner, RoleOwner, true},
		{RoleOwner, RoleDeveloper, true},
		{RoleOwner, RoleViewer, true},
		{RoleDeveloper, RoleDeveloper, true},
		{RoleDeveloper, RoleOwner, false},
		{RoleViewer, RoleDeveloper, false},
		{RoleViewer, RoleOwner, false},
		// Nothing a member holds reaches a non-tenant minimum.
		{RoleOwner, RoleAdmin, false},
		{RoleOwner, RoleAuthenticated, false},
		{RoleOwner, "", false},
		{RoleOwner, "superuser", false},
		// An unknown held role satisfies nothing, not even viewer.
		{"", RoleViewer, false},
		{"maintainer", RoleViewer, false},
		{RoleAdmin, RoleDeveloper, false},
		{RoleAuthenticated, RoleViewer, false},
	}
	for _, tt := range tests {
		if got := tt.have.Satisfies(tt.min); got != tt.want {
			t.Errorf("Role(%q).Satisfies(%q) = %v, want %v", tt.have, tt.min, got, tt.want)
		}
	}
}

func TestLeastTenantRole(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   Role
		ok     bool
	}{
		{"owner", []string{"owner"}, RoleOwner, true},
		{"case is ignored", []string{"Owner"}, RoleOwner, true},
		{"listed twice: the lower one", []string{"owner", "viewer"}, RoleViewer, true},
		{"listed twice, other order", []string{"developer", "owner"}, RoleDeveloper, true},
		{"none", nil, "", false},
		{"empty role", []string{""}, "", false},
		{"unknown role", []string{"maintainer"}, "", false},
		{"one readable, one not: unknown", []string{"owner", ""}, "", false},
		{"admin is not a tenant role", []string{"admin"}, "", false},
		{"whitespace is not normalized", []string{" owner"}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := LeastTenantRole(tt.values)
			if got != tt.want || ok != tt.ok {
				t.Errorf("LeastTenantRole(%q) = %q, %v; want %q, %v", tt.values, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestEffectiveTenantRole(t *testing.T) {
	tests := []struct {
		name   string
		scopes [][]string
		want   Role
		known  bool
	}{
		{"not a member", nil, "", false},
		{"one list", [][]string{{"developer"}}, RoleDeveloper, true},
		{"one list, listed twice: the lesser", [][]string{{"owner", "viewer"}}, RoleViewer, true},
		// The review case: a tenant-wide owner also listed on a team.
		{"tenant owner, team viewer: owner", [][]string{{"owner"}, {"viewer"}}, RoleOwner, true},
		{"tenant viewer, team developer: developer", [][]string{{"viewer"}, {"developer"}}, RoleDeveloper, true},
		{"order of the lists does not matter", [][]string{{"viewer"}, {"owner"}}, RoleOwner, true},
		// Within a list still the lesser, then the greater of the lists.
		{"tenant owner+viewer, team developer", [][]string{{"owner", "viewer"}, {"developer"}}, RoleDeveloper, true},
		// An unreadable entry is never outvoted by a good one elsewhere.
		{"tenant owner, team role empty", [][]string{{"owner"}, {""}}, "", false},
		{"tenant role unknown, team owner", [][]string{{"maintainer"}, {"owner"}}, "", false},
		{"tenant owner twice, one unreadable", [][]string{{"owner", ""}}, "", false},
		{"an empty list is not a role", [][]string{{}}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, known := EffectiveTenantRole(tt.scopes)
			if got != tt.want || known != tt.known {
				t.Fatalf("EffectiveTenantRole(%q) = %q, %v; want %q, %v", tt.scopes, got, known, tt.want, tt.known)
			}
		})
	}
}
