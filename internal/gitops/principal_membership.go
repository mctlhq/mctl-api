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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/prometheus/client_golang/prometheus"
)

// Principal-keyed tenant membership (mctl-api#377). A member entry's
// principalId is the canonical principal it grants to. These readers are
// what principal mode will authorize on; until then shadow mode compares
// them with the login-keyed answer and nothing authorizes on them.

// principalIDRE is a canonical principal id: "prn_" and a 26-character
// Crockford base32 ULID (internal/principals/ulid.go).
var principalIDRE = regexp.MustCompile(`^prn_[0-9A-HJKMNP-TV-Z]{26}$`)

// ValidPrincipalID reports whether id has the shape of a canonical
// principal id. It says nothing about whether that principal exists.
func ValidPrincipalID(id string) bool { return principalIDRE.MatchString(id) }

// validatePrincipalKeys reports why this tenant's principal-keyed
// membership cannot be read, or nil. A member list naming one principal
// twice is refused rather than resolved, because two roles for the same key
// in one list contradict each other; a principal may still appear once at
// tenant level and once in a team, as a login may (Tenant.memberRoles).
func (t *Tenant) validatePrincipalKeys() error {
	check := func(scope string, members []TenantMember) error {
		seen := make(map[string]bool, len(members))
		for i, m := range members {
			if m.UserID == "" && m.PrincipalID == "" {
				return fmt.Errorf("%s member %d names neither principalId nor userId", scope, i)
			}
			if m.PrincipalID == "" {
				continue
			}
			if !ValidPrincipalID(m.PrincipalID) {
				return fmt.Errorf("%s member %d: malformed principalId %q", scope, i, m.PrincipalID)
			}
			if seen[m.PrincipalID] {
				return fmt.Errorf("%s lists principalId %q more than once", scope, m.PrincipalID)
			}
			seen[m.PrincipalID] = true
		}
		return nil
	}
	if err := check("tenant", t.Members); err != nil {
		return err
	}
	for _, team := range t.Teams {
		if err := check("team "+team.Name, team.Members); err != nil {
			return err
		}
	}
	return nil
}

// PrincipalKeysErr is why this tenant's principal-keyed membership cannot
// be read, or nil.
func (t *Tenant) PrincipalKeysErr() error { return t.principalErr }

// PrincipalNamespaces is UserNamespaces keyed by canonical principal id.
// The caller must check PrincipalKeysErr first: a tenant whose keys are
// unreadable answers nothing here, which is not the same as "not a member".
func (t *Tenant) PrincipalNamespaces(principalID string) []string {
	return t.namespacesFor(matchPrincipal(principalID))
}

// UnkeyedMembers counts the member entries, tenant level and teams, that
// carry no principalId. Principal mode grants them nothing.
func (t *Tenant) UnkeyedMembers() int {
	n := 0
	for _, m := range t.Members {
		if m.PrincipalID == "" {
			n++
		}
	}
	for _, team := range t.Teams {
		for _, m := range team.Members {
			if m.PrincipalID == "" {
				n++
			}
		}
	}
	return n
}

// PrincipalMembership is one principal's tenant namespaces as far as the
// checkout could answer.
type PrincipalMembership struct {
	// Namespaces are those the principal is a member of, among the tenants
	// that could be read.
	Namespaces []string
	// Unreadable names every tenant whose membership could not be read for
	// any principal: a values.yaml that failed to read or parse, or one
	// whose principal keys are invalid. The principal may or may not be a
	// member of these; a caller must treat them as unknown.
	Unreadable []string
}

// NamespacesForPrincipal is GetTenantsForUser keyed by canonical principal
// id, except that it never drops what it could not read. A checkout that
// never synced or is stale, or a tenants directory that cannot be listed,
// is an error; a single unreadable tenant is reported in Unreadable instead,
// so a caller can still rely on what was read and knows exactly what was
// not.
func (r *Reader) NamespacesForPrincipal(principalID string) (PrincipalMembership, error) {
	if !ValidPrincipalID(principalID) {
		return PrincipalMembership{}, fmt.Errorf("invalid principal id %q", principalID)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if err := r.checkFreshLocked(); err != nil {
		return PrincipalMembership{}, err
	}
	entries, err := os.ReadDir(filepath.Join(r.localPath, "platform-gitops", "tenants"))
	if err != nil {
		return PrincipalMembership{}, fmt.Errorf("reading tenants dir: %w", err)
	}
	var out PrincipalMembership
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		t, err := r.readTenant(entry.Name())
		if errors.Is(err, fs.ErrNotExist) {
			// No values.yaml: not a tenant, exactly as MemberRoles reads it.
			continue
		}
		if err != nil || t.principalErr != nil {
			out.Unreadable = append(out.Unreadable, entry.Name())
			continue
		}
		out.Namespaces = append(out.Namespaces, t.PrincipalNamespaces(principalID)...)
	}
	sort.Strings(out.Namespaces)
	return out, nil
}

// MemberRolesForPrincipal is MemberRoles keyed by canonical principal id,
// with the same contract: an empty result with a nil error means "read, and
// not a member", and anything that could not be read, including the owning
// tenant's principal keys, is an error.
func (r *Reader) MemberRolesForPrincipal(namespace, principalID string) ([][]string, error) {
	if namespace == "" {
		return nil, errors.New("member roles: namespace is required")
	}
	if !ValidPrincipalID(principalID) {
		return nil, fmt.Errorf("member roles: invalid principal id %q", principalID)
	}
	return r.memberRolesMatching(namespace, matchPrincipal(principalID), true)
}

// tenantMemberEntryUnkeyed is the number of member entries per tenant with
// no principalId. Principal mode may be switched on only once it is zero
// everywhere (mctl-api#377 design.md, switch criterion).
var tenantMemberEntryUnkeyed = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "tenant_member_entry_unkeyed",
	Help: "GitOps tenant member entries without a principalId, per tenant.",
}, []string{"tenant"})

// tenantPrincipalKeysInvalid is 1 for a tenant whose principal keys cannot
// be read (malformed or duplicate principalId, or an entry naming nobody).
var tenantPrincipalKeysInvalid = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "tenant_principal_keys_invalid",
	Help: "1 when a GitOps tenant's principalId keys cannot be read, else 0.",
}, []string{"tenant"})

// tenantPrincipalKeysScanOK is 1 when the last scan read the tenants
// directory, else 0. The two gauges above are cleared on a failed scan, so
// an empty series there means "not observed" only when this is 0; the
// switch criterion reads all three.
var tenantPrincipalKeysScanOK = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "tenant_principal_keys_scan_ok",
	Help: "1 when the last scan of GitOps tenant principal keys could list the tenants, else 0.",
})

func init() {
	prometheus.MustRegister(tenantMemberEntryUnkeyed, tenantPrincipalKeysInvalid, tenantPrincipalKeysScanOK)
}

// recordPrincipalKeyMetrics refreshes the gauges from the checkout after
// each successful sync (RefreshLoop). It takes the read lock itself.
// A tenant that cannot be read at all is reported as invalid: its keys were
// not observed, so it must not look like "zero unkeyed".
func (r *Reader) recordPrincipalKeyMetrics() {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tenantMemberEntryUnkeyed.Reset()
	tenantPrincipalKeysInvalid.Reset()
	entries, err := os.ReadDir(filepath.Join(r.localPath, "platform-gitops", "tenants"))
	if err != nil {
		tenantPrincipalKeysScanOK.Set(0)
		return
	}
	tenantPrincipalKeysScanOK.Set(1)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		t, err := r.readTenant(entry.Name())
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			tenantPrincipalKeysInvalid.WithLabelValues(entry.Name()).Set(1)
			continue
		}
		invalid := 0.0
		if t.principalErr != nil {
			invalid = 1
		}
		tenantPrincipalKeysInvalid.WithLabelValues(entry.Name()).Set(invalid)
		tenantMemberEntryUnkeyed.WithLabelValues(entry.Name()).Set(float64(t.UnkeyedMembers()))
	}
}
