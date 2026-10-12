package gitops

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
)

// principalIDRE is the canonical principal id format (prn_ + 26 Crockford
// base32 characters).
var principalIDRE = regexp.MustCompile(`^prn_[0-9A-HJKMNP-TV-Z]{26}$`)

// ValidPrincipalID reports whether id is a well-formed canonical principal id.
func ValidPrincipalID(id string) bool { return principalIDRE.MatchString(id) }

// validateMembers checks one members list for principal-keyed reading: every
// entry needs a well-formed principalId or at least a userId (a not yet
// backfilled entry), and a principalId may appear only once.
func validateMembers(scope string, members []TenantMember) error {
	seen := map[string]bool{}
	for i, m := range members {
		if m.PrincipalID == "" {
			if m.UserID == "" {
				return fmt.Errorf("%s members[%d]: neither principalId nor userId", scope, i)
			}
			continue
		}
		if !ValidPrincipalID(m.PrincipalID) {
			return fmt.Errorf("%s members[%d]: malformed principalId %q", scope, i, m.PrincipalID)
		}
		if seen[m.PrincipalID] {
			return fmt.Errorf("%s members[%d]: duplicate principalId %q", scope, i, m.PrincipalID)
		}
		seen[m.PrincipalID] = true
	}
	return nil
}

// ValidatePrincipalMembers reports why the tenant's membership cannot be
// read by principal. Such a tenant is unreadable for principal queries: they
// error rather than answer "not a member".
func (t *Tenant) ValidatePrincipalMembers() error {
	if err := validateMembers("tenant "+t.Name, t.Members); err != nil {
		return err
	}
	for _, team := range t.Teams {
		if err := validateMembers("tenant "+t.Name+" team "+team.Name, team.Members); err != nil {
			return err
		}
	}
	return nil
}

func hasPrincipal(members []TenantMember, prn string) bool {
	for _, m := range members {
		if m.PrincipalID != "" && m.PrincipalID == prn {
			return true
		}
	}
	return false
}

// PrincipalNamespaces returns the namespaces prn is a member of, with the
// same team/tenant-level semantics as UserNamespaces. Matching is exact on
// principalId; userId is never consulted.
func (t *Tenant) PrincipalNamespaces(prn string) []string {
	if !t.IsMultiTeam() {
		if hasPrincipal(t.Members, prn) {
			return []string{t.Name}
		}
		return nil
	}
	tenantLevel := hasPrincipal(t.Members, prn)
	var ns []string
	for _, team := range t.Teams {
		if tenantLevel || hasPrincipal(team.Members, prn) {
			ns = append(ns, t.Name+"-"+team.Name)
		}
	}
	return ns
}

// principalMemberRoles mirrors memberRoles, keyed by principal id.
func (t *Tenant) principalMemberRoles(namespace, prn string) (scopes [][]string, owns bool) {
	collect := func(members []TenantMember) {
		var roles []string
		for _, m := range members {
			if m.PrincipalID != "" && m.PrincipalID == prn {
				roles = append(roles, m.Role)
			}
		}
		if len(roles) > 0 {
			scopes = append(scopes, roles)
		}
	}
	if !t.IsMultiTeam() {
		if t.Name != namespace {
			return nil, false
		}
		collect(t.Members)
		return scopes, true
	}
	for _, team := range t.Teams {
		if t.Name+"-"+team.Name != namespace {
			continue
		}
		collect(t.Members)
		collect(team.Members)
		return scopes, true
	}
	return nil, false
}

// readTenantsStrictLocked reads every tenant, failing on any that cannot be
// read. Callers hold r.mu and have checked freshness.
// dirs[i] is the directory name tenants[i] was read from.
func (r *Reader) readTenantsStrictLocked() (tenants []Tenant, dirs []string, err error) {
	tenantsDir := filepath.Join(r.localPath, "platform-gitops", "tenants")
	entries, err := os.ReadDir(tenantsDir)
	if err != nil {
		return nil, nil, fmt.Errorf("reading tenants dir: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		t, err := r.readTenant(entry.Name())
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("reading tenant %q: %w", entry.Name(), err)
		}
		tenants = append(tenants, *t)
		dirs = append(dirs, entry.Name())
	}
	return tenants, dirs, nil
}

func principalNamespaces(tenants []Tenant, prn string) ([]string, error) {
	var result []string
	for i := range tenants {
		if err := tenants[i].ValidatePrincipalMembers(); err != nil {
			return nil, fmt.Errorf("tenant %q is unreadable by principal: %w", tenants[i].Name, err)
		}
		result = append(result, tenants[i].PrincipalNamespaces(prn)...)
	}
	return result, nil
}

// NamespacesForPrincipal returns the namespaces prn is a member of. A stale
// or unreadable checkout, or any tenant whose members cannot be read by
// principal, is an error: it never comes back as "no namespaces".
func (r *Reader) NamespacesForPrincipal(prn string) ([]string, error) {
	if !ValidPrincipalID(prn) {
		return nil, fmt.Errorf("namespaces for principal: malformed principal %q", prn)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if err := r.checkFreshLocked(); err != nil {
		return nil, err
	}
	tenants, _, err := r.readTenantsStrictLocked()
	if err != nil {
		return nil, err
	}
	return principalNamespaces(tenants, prn)
}

// TryNamespacesForPrincipal is NamespacesForPrincipal without waiting: ok is
// false at once when a refresh holds the write lock.
func (r *Reader) TryNamespacesForPrincipal(prn string) (namespaces []string, ok bool, err error) {
	if !ValidPrincipalID(prn) {
		return nil, true, fmt.Errorf("namespaces for principal: malformed principal %q", prn)
	}
	if !r.mu.TryRLock() {
		return nil, false, nil
	}
	defer r.mu.RUnlock()
	if err := r.checkFreshLocked(); err != nil {
		return nil, true, err
	}
	tenants, _, err := r.readTenantsStrictLocked()
	if err != nil {
		return nil, true, err
	}
	namespaces, err = principalNamespaces(tenants, prn)
	return namespaces, true, err
}

// MemberRolesForPrincipal mirrors MemberRoles, keyed by principal id. Only the
// tenant that owns namespace has to be readable by principal.
func (r *Reader) MemberRolesForPrincipal(namespace, prn string) ([][]string, error) {
	if namespace == "" {
		return nil, errors.New("member roles: namespace is required")
	}
	if !ValidPrincipalID(prn) {
		return nil, fmt.Errorf("member roles: malformed principal %q", prn)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if err := r.checkFreshLocked(); err != nil {
		return nil, err
	}
	tenants, dirs, err := r.readTenantsStrictLocked()
	if err != nil {
		return nil, err
	}
	var roles [][]string
	owner := ""
	ownerDir := ""
	for i := range tenants {
		t := &tenants[i]
		// Ownership does not depend on members, so an unreadable member
		// list only matters for the tenant that owns the namespace.
		if !ownsNamespace(t, namespace) {
			continue
		}
		if owner != "" {
			return nil, fmt.Errorf("namespace %q is claimed by tenant directories %q and %q", namespace, ownerDir, dirs[i])
		}
		owner = t.Name
		ownerDir = dirs[i]
		if err := t.ValidatePrincipalMembers(); err != nil {
			return nil, fmt.Errorf("tenant %q is unreadable by principal: %w", t.Name, err)
		}
		roles, _ = t.principalMemberRoles(namespace, prn)
	}
	return roles, nil
}

func ownsNamespace(t *Tenant, namespace string) bool {
	for _, ns := range t.Namespaces() {
		if ns == namespace {
			return true
		}
	}
	return false
}
