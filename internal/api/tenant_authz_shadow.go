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

package api

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// Tenant authorization by canonical principal (mctl-api#377).
//
// Tenant membership and roles are decided today on a GitHub login
// (members[].userId). The target is the canonical principal
// (members[].principalId). TENANT_AUTHZ_MODE moves between the two:
//
//   - legacy: the login decides. Nothing below runs.
//   - shadow: the login still decides, exactly as in legacy. The principal
//     decision is computed beside it for the same request and the two are
//     compared into metrics and logs. Nothing the principal path computes
//     is used to authorize.
//   - principal: the principal decides. Not in this build; refused at boot
//     until it exists (PR-B).

// TenantAuthzMode is the parsed TENANT_AUTHZ_MODE.
type TenantAuthzMode string

const (
	TenantAuthzLegacy    TenantAuthzMode = "legacy"
	TenantAuthzShadow    TenantAuthzMode = "shadow"
	TenantAuthzPrincipal TenantAuthzMode = "principal"
)

// ParseTenantAuthzMode reads TENANT_AUTHZ_MODE. Empty is legacy. principal
// is refused until this build can honour it, and any other value is
// refused: a mistyped mode must stop the boot, not fall back to one the
// operator did not ask for.
func ParseTenantAuthzMode(raw string) (TenantAuthzMode, error) {
	switch m := TenantAuthzMode(strings.TrimSpace(raw)); m {
	case "", TenantAuthzLegacy:
		return TenantAuthzLegacy, nil
	case TenantAuthzShadow:
		return TenantAuthzShadow, nil
	case TenantAuthzPrincipal:
		return "", errors.New("TENANT_AUTHZ_MODE=principal is not implemented in this build (mctl-api#377 PR-B); use legacy or shadow")
	default:
		return "", fmt.Errorf("TENANT_AUTHZ_MODE %q is not one of legacy, shadow", raw)
	}
}

// PrincipalMembershipReader is the principal-keyed membership the shadow
// comparison reads (gitops.Reader). It is separate from GitReader so the
// many GitReader stubs need not grow it; nil in shadow mode makes every
// comparison unresolved, never a match.
type PrincipalMembershipReader interface {
	TryNamespacesForPrincipal(principalID string) (gitops.PrincipalMembership, bool, error)
	MemberRolesForPrincipal(namespace, principalID string) ([][]string, error)
}

// Shadow outcomes. unresolved is a comparison that could not be made and is
// never counted as a match or a diff: it is not evidence either way.
const (
	shadowMatch      = "match"
	shadowDiff       = "diff"
	shadowUnresolved = "unresolved"
)

// Why a comparison was unresolved. no_pid: the caller carries no principal
// id (resolution failed at authentication, which phase 1 degrades on).
// membership_*: the principal-keyed membership could not be read.
const (
	unresolvedNoPID                 = "no_pid"
	unresolvedMembershipUnavailable = "membership_unavailable"
	unresolvedMembershipBusy        = "membership_busy"
	unresolvedMembershipUnreadable  = "membership_unreadable"
)

var (
	tenantAuthzShadowTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tenant_authz_shadow_total",
		Help: "Shadow comparisons of login- and principal-keyed tenant authorization, by result (match, diff, unresolved).",
	}, []string{"result"})
	tenantAuthzShadowDiffTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tenant_authz_shadow_diff_total",
		Help: "Shadow comparisons that differed, by kind (tenant_only_legacy, tenant_only_principal, role_mismatch, admin_mismatch).",
	}, []string{"kind"})
	tenantAuthzPrincipalUnresolvedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tenant_authz_principal_unresolved_total",
		Help: "Shadow comparisons that could not be made, by reason.",
	}, []string{"reason"})
)

func init() {
	prometheus.MustRegister(tenantAuthzShadowTotal, tenantAuthzShadowDiffTotal, tenantAuthzPrincipalUnresolvedTotal)
}

func recordShadowUnresolved(reason string) {
	tenantAuthzShadowTotal.WithLabelValues(shadowUnresolved).Inc()
	tenantAuthzPrincipalUnresolvedTotal.WithLabelValues(reason).Inc()
}

// shadowEligible reports whether user is a human whose tenant decisions the
// shadow compares: relayed and delegated humans included, service, surface,
// agent, CI and dev callers not, since principal mode leaves them as they
// are.
func shadowEligible(user *auth.User) bool {
	id, ok := user.Identity()
	return ok && id.Kind == auth.KindHuman && id.Provider != auth.ProviderDev
}

// tenantAuthzShadow compares, for every request of an eligible caller, the
// tenant set the request is authorized on (User.Groups, which every
// HasTenantAccess decision reads) with the set principal mode would give
// it. One comparison of the whole set covers every HasTenantAccess call the
// request goes on to make, without touching the handlers that make them.
// Platform admin is compared too once ADMIN_PRINCIPALS is set (without it
// every admin would read as a diff): the legacy "admins" decision against
// membership of ADMIN_PRINCIPALS.
func (h *Handlers) tenantAuthzShadow(next http.Handler) http.Handler {
	if h.opts.TenantAuthzMode != TenantAuthzShadow {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user := auth.UserFromContext(r.Context()); user != nil && shadowEligible(user) {
			h.shadowTenantSet(r, user)
		}
		next.ServeHTTP(w, r)
	})
}

func (h *Handlers) shadowTenantSet(r *http.Request, user *auth.User) {
	prn := user.PrincipalID()
	if prn == "" {
		recordShadowUnresolved(unresolvedNoPID)
		return
	}
	// The admin comparison reads neither the checkout nor the membership,
	// so a membership read that fails must not suppress it: one broken
	// tenant file would otherwise hide every admin_mismatch platform-wide
	// while the rollout gate read 0. Principal mode never makes a relayed
	// or delegated caller an admin (PrincipalAuthz.Apply), and neither
	// does this comparison.
	legacyAdmin := user.IsAdmin()
	principalAdmin := legacyAdmin
	if len(h.opts.AdminPrincipals) > 0 {
		principalAdmin = h.opts.AdminPrincipals[prn] && user.ActingPrincipal() == ""
	}
	tenantsUnresolved := func(reason string) {
		recordShadowUnresolved(reason)
		if legacyAdmin != principalAdmin {
			tenantAuthzShadowDiffTotal.WithLabelValues("admin_mismatch").Inc()
			if h.principalSets.shouldLog(fmt.Sprintf("%s|admin|%t", prn, principalAdmin)) {
				slog.Warn("tenant authz shadow diff",
					"kind", "admin", "path", r.URL.Path, "principal", prn, "login", user.ID,
					"legacy_admin", legacyAdmin, "principal_admin", principalAdmin)
			}
		}
	}
	if h.opts.PrincipalMembership == nil {
		tenantsUnresolved(unresolvedMembershipUnavailable)
		return
	}
	got, ok, err := h.principalSet(prn)
	switch {
	case !ok:
		tenantsUnresolved(unresolvedMembershipBusy)
		return
	case err != nil || len(got.Unreadable) > 0:
		// A tenant that could not be read may hold either answer.
		tenantsUnresolved(unresolvedMembershipUnreadable)
		return
	}

	legacy := tenantSet(user.Groups)
	principal := tenantSet(got.Namespaces)
	onlyLegacy := setMinus(legacy, principal)
	onlyPrincipal := setMinus(principal, legacy)
	if len(onlyLegacy) == 0 && len(onlyPrincipal) == 0 && legacyAdmin == principalAdmin {
		tenantAuthzShadowTotal.WithLabelValues(shadowMatch).Inc()
		return
	}
	tenantAuthzShadowTotal.WithLabelValues(shadowDiff).Inc()
	if len(onlyLegacy) > 0 {
		tenantAuthzShadowDiffTotal.WithLabelValues("tenant_only_legacy").Inc()
	}
	if len(onlyPrincipal) > 0 {
		tenantAuthzShadowDiffTotal.WithLabelValues("tenant_only_principal").Inc()
	}
	if legacyAdmin != principalAdmin {
		tenantAuthzShadowDiffTotal.WithLabelValues("admin_mismatch").Inc()
	}
	if !h.principalSets.shouldLog(fmt.Sprintf("%s|tenants|%s|%s|%t", prn, strings.Join(onlyLegacy, ","), strings.Join(onlyPrincipal, ","), principalAdmin)) {
		return
	}
	slog.Warn("tenant authz shadow diff",
		"kind", "tenants", "path", r.URL.Path, "principal", prn, "login", user.ID,
		"legacy", legacy, "principal_tenants", principal,
		"only_legacy", onlyLegacy, "only_principal", onlyPrincipal,
		"legacy_admin", legacyAdmin, "principal_admin", principalAdmin)
}

// shadowTenantRole compares checkTenantRole's login-keyed decision with the
// one principal mode would make for the same write. Only an allow or a deny
// is compared: a legacy decision that itself could not be made (503/500)
// has nothing to compare against, and an admin passes on both sides before
// a role is read.
func (h *Handlers) shadowTenantRole(user *auth.User, tenant string, min operations.Role, legacy roleRefusal) {
	if !shadowEligible(user) || user.IsAdmin() || !min.IsTenantRole() || legacy.auditStatus == "error" {
		return
	}
	prn := user.PrincipalID()
	if prn == "" {
		recordShadowUnresolved(unresolvedNoPID)
		return
	}
	if h.opts.PrincipalMembership == nil {
		recordShadowUnresolved(unresolvedMembershipUnavailable)
		return
	}
	written, err := h.opts.PrincipalMembership.MemberRolesForPrincipal(tenant, prn)
	if err != nil {
		recordShadowUnresolved(unresolvedMembershipUnreadable)
		return
	}
	role, known := operations.EffectiveTenantRole(written)
	principalAllows := len(written) > 0 && known && role.Satisfies(min)
	legacyAllows := !legacy.refused()
	if principalAllows == legacyAllows {
		tenantAuthzShadowTotal.WithLabelValues(shadowMatch).Inc()
		return
	}
	tenantAuthzShadowTotal.WithLabelValues(shadowDiff).Inc()
	tenantAuthzShadowDiffTotal.WithLabelValues("role_mismatch").Inc()
	if !h.principalSets.shouldLog(prn + "|role|" + tenant + "|" + string(min)) {
		return
	}
	slog.Warn("tenant authz shadow diff",
		"kind", "role", "tenant", tenant, "min", string(min), "principal", prn, "login", user.ID,
		"legacy_allows", legacyAllows, "legacy_detail", legacy.detail,
		"principal_allows", principalAllows, "principal_roles", written)
}

// tenantSet is groups as a sorted set of tenant namespaces: "admins" is the
// platform-admin marker, not a tenant (PR-0), so it is left out.
func tenantSet(groups []string) []string {
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		if g != "" && g != "admins" {
			out = append(out, g)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func setMinus(a, b []string) []string {
	var out []string
	for _, x := range a {
		if _, found := slices.BinarySearch(b, x); !found {
			out = append(out, x)
		}
	}
	return out
}

// principalSet is TryNamespacesForPrincipal through the cache. Only a
// complete read is cached; busy and failed reads are retried next time.
func (h *Handlers) principalSet(prn string) (gitops.PrincipalMembership, bool, error) {
	if m, hit := h.principalSets.get(prn); hit {
		return m, true, nil
	}
	m, ok, err := h.opts.PrincipalMembership.TryNamespacesForPrincipal(prn)
	if ok && err == nil {
		h.principalSets.put(prn, m)
	}
	return m, ok, err
}

// principalSetCacheTTL bounds how stale a cached principal set may be. The
// legacy side it is compared with comes from a groups cache of 30s, so a
// shorter window adds no disagreement of its own, and it caps the checkout
// reads shadow mode costs at one per principal per window.
const principalSetCacheTTL = 10 * time.Second

// principalSetCacheMax bounds the cache; past it the cache is cleared
// rather than grown.
const principalSetCacheMax = 4096

type principalSetCache struct {
	mu  sync.Mutex
	ttl time.Duration
	now func() time.Time
	m   map[string]cachedPrincipalSet
	// logged is when each distinct diff was last logged. The counters carry
	// every diff; the log needs one line per distinct diff per interval,
	// not one per request for a multi-day window.
	logged map[string]time.Time
}

// diffLogInterval is how often one distinct diff is logged again.
const diffLogInterval = 10 * time.Minute

type cachedPrincipalSet struct {
	at  time.Time
	set gitops.PrincipalMembership
}

func newPrincipalSetCache(ttl time.Duration) *principalSetCache {
	return &principalSetCache{ttl: ttl, now: time.Now, m: map[string]cachedPrincipalSet{}, logged: map[string]time.Time{}}
}

// shouldLog reports whether the diff named key is due to be logged, and
// records it as logged. A nil cache logs everything.
func (c *principalSetCache) shouldLog(key string) bool {
	if c == nil {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if at, ok := c.logged[key]; ok && now.Sub(at) < diffLogInterval {
		return false
	}
	if len(c.logged) >= principalSetCacheMax {
		clear(c.logged)
	}
	c.logged[key] = now
	return true
}

func (c *principalSetCache) get(prn string) (gitops.PrincipalMembership, bool) {
	if c == nil {
		return gitops.PrincipalMembership{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[prn]
	if !ok || c.now().Sub(e.at) >= c.ttl {
		return gitops.PrincipalMembership{}, false
	}
	return e.set, true
}

func (c *principalSetCache) put(prn string, m gitops.PrincipalMembership) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= principalSetCacheMax {
		clear(c.m)
	}
	c.m[prn] = cachedPrincipalSet{at: c.now(), set: m}
}
