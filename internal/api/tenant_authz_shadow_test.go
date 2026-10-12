package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/operations"
)

const shadowPRN = "prn_01JBBBBBBBBBBBBBBBBBBBBBBB"

func TestParseTenantAuthzMode(t *testing.T) {
	for raw, want := range map[string]TenantAuthzMode{"": TenantAuthzLegacy, "legacy": TenantAuthzLegacy, "shadow": TenantAuthzShadow, "\tshadow\n": TenantAuthzShadow} {
		if got, err := ParseTenantAuthzMode(raw); err != nil || got != want {
			t.Errorf("ParseTenantAuthzMode(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{"principal", "Shadow", "off", "legacy,shadow"} {
		if got, err := ParseTenantAuthzMode(raw); err == nil {
			t.Errorf("ParseTenantAuthzMode(%q) = %q, want a refusal", raw, got)
		}
	}
}

// stubPrincipalMembership answers principal-keyed membership from fixed
// data, or with the configured failure.
type stubPrincipalMembership struct {
	reads      atomic.Int64
	namespaces []string
	unreadable []string
	busy       bool
	err        error
	roles      map[string][][]string // namespace -> roles
	rolesErr   error
}

func (s *stubPrincipalMembership) TryNamespacesForPrincipal(string) (gitops.PrincipalMembership, bool, error) {
	s.reads.Add(1)
	if s.busy {
		return gitops.PrincipalMembership{}, false, nil
	}
	return gitops.PrincipalMembership{Namespaces: s.namespaces, Unreadable: s.unreadable}, true, s.err
}

func (s *stubPrincipalMembership) MemberRolesForPrincipal(namespace, _ string) ([][]string, error) {
	if s.rolesErr != nil {
		return nil, s.rolesErr
	}
	return s.roles[namespace], nil
}

func withPrincipal(t *testing.T, u *auth.User, prn string) *auth.User {
	t.Helper()
	if err := auth.AttachPrincipal(context.Background(), fixedPrincipal(prn), u); err != nil {
		t.Fatal(err)
	}
	return u
}

// shadowCounts snapshots every shadow counter, so a test reads its own
// increments on top of whatever earlier tests left.
type shadowCounts map[string]float64

func snapshotShadow() shadowCounts {
	c := shadowCounts{}
	for _, r := range []string{shadowMatch, shadowDiff, shadowUnresolved} {
		c["result:"+r] = testutil.ToFloat64(tenantAuthzShadowTotal.WithLabelValues(r))
	}
	for _, k := range []string{"tenant_only_legacy", "tenant_only_principal", "role_mismatch", "admin_mismatch"} {
		c["kind:"+k] = testutil.ToFloat64(tenantAuthzShadowDiffTotal.WithLabelValues(k))
	}
	for _, r := range []string{unresolvedNoPID, unresolvedMembershipUnavailable, unresolvedMembershipBusy, unresolvedMembershipUnreadable} {
		c["reason:"+r] = testutil.ToFloat64(tenantAuthzPrincipalUnresolvedTotal.WithLabelValues(r))
	}
	return c
}

// delta is what changed since before; keys that did not move are left out.
func (before shadowCounts) delta() map[string]float64 {
	d := map[string]float64{}
	for k, v := range snapshotShadow() {
		if v != before[k] {
			d[k] = v - before[k]
		}
	}
	return d
}

func assertDelta(t *testing.T, got map[string]float64, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("counter changes = %v, want exactly %v", got, want)
	}
	for _, k := range want {
		if got[k] != 1 {
			t.Fatalf("counter changes = %v, want %s +1", got, k)
		}
	}
}

func TestTenantAuthzShadow_TenantSet(t *testing.T) {
	member := func() *auth.User { return auth.NewGitHubUser("dev", []string{"acme-web", "admins", "solo"}) }
	tests := []struct {
		name string
		mode TenantAuthzMode
		user *auth.User
		pm   PrincipalMembershipReader
		want []string
	}{
		{"match ignores order, duplicates and the admin marker", TenantAuthzShadow, withPrincipal(t, member(), shadowPRN),
			&stubPrincipalMembership{namespaces: []string{"solo", "acme-web"}},
			[]string{"result:match"}},
		{"a tenant only the login grants", TenantAuthzShadow, withPrincipal(t, member(), shadowPRN),
			&stubPrincipalMembership{namespaces: []string{"solo"}},
			[]string{"result:diff", "kind:tenant_only_legacy"}},
		{"a tenant only the principal grants", TenantAuthzShadow, withPrincipal(t, member(), shadowPRN),
			&stubPrincipalMembership{namespaces: []string{"acme-web", "solo", "labs"}},
			[]string{"result:diff", "kind:tenant_only_principal"}},
		{"both directions", TenantAuthzShadow, withPrincipal(t, member(), shadowPRN),
			&stubPrincipalMembership{namespaces: []string{"labs"}},
			[]string{"result:diff", "kind:tenant_only_legacy", "kind:tenant_only_principal"}},
		// A principal store error at authentication leaves no principal id;
		// that is unresolved, never a diff against an empty set.
		{"no principal id", TenantAuthzShadow, member(),
			&stubPrincipalMembership{namespaces: []string{"acme-web", "solo"}},
			[]string{"result:unresolved", "reason:no_pid"}},
		{"membership reader not wired", TenantAuthzShadow, withPrincipal(t, member(), shadowPRN), nil,
			[]string{"result:unresolved", "reason:membership_unavailable"}},
		{"checkout held by a refresh", TenantAuthzShadow, withPrincipal(t, member(), shadowPRN),
			&stubPrincipalMembership{busy: true},
			[]string{"result:unresolved", "reason:membership_busy"}},
		{"checkout unreadable", TenantAuthzShadow, withPrincipal(t, member(), shadowPRN),
			&stubPrincipalMembership{err: errors.New("stale")},
			[]string{"result:unresolved", "reason:membership_unreadable"}},
		// One unreadable tenant could hold the missing grant: not a diff.
		{"one tenant unreadable", TenantAuthzShadow, withPrincipal(t, member(), shadowPRN),
			&stubPrincipalMembership{namespaces: []string{"solo"}, unreadable: []string{"acme"}},
			[]string{"result:unresolved", "reason:membership_unreadable"}},
		{"legacy mode compares nothing", TenantAuthzLegacy, withPrincipal(t, member(), shadowPRN),
			&stubPrincipalMembership{namespaces: []string{"labs"}}, nil},
		{"zero mode is legacy", "", withPrincipal(t, member(), shadowPRN),
			&stubPrincipalMembership{namespaces: []string{"labs"}}, nil},
		{"service caller is not compared", TenantAuthzShadow, withPrincipal(t, auth.NewServiceUser(), shadowPRN),
			&stubPrincipalMembership{namespaces: []string{"labs"}}, nil},
		{"surface caller is not compared", TenantAuthzShadow, withPrincipal(t, auth.NewSurfaceUser("telegram"), shadowPRN),
			&stubPrincipalMembership{namespaces: []string{"labs"}}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handlers{opts: Options{TenantAuthzMode: tt.mode, PrincipalMembership: tt.pm}}
			served := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { served = true })
			req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants", nil)
			req = req.WithContext(auth.WithUser(req.Context(), tt.user))
			before := snapshotShadow()
			h.tenantAuthzShadow(next).ServeHTTP(httptest.NewRecorder(), req)
			if !served {
				t.Fatal("the shadow stopped the request")
			}
			assertDelta(t, before.delta(), tt.want...)
		})
	}
}

// Shadow never changes what checkTenantRole decides; it only records how
// principal mode would have decided.
func TestCheckTenantRole_Shadow(t *testing.T) {
	dev := func() *auth.User { return withPrincipal(t, erpactMember("dan-dev"), shadowPRN) }
	root := func() *auth.User { return withPrincipal(t, auth.NewGitHubUser("root", []string{"admins"}), shadowPRN) }
	const otherPRN = "prn_01JAAAAAAAAAAAAAAAAAAAAAAA"
	legacyRoles := rolesOf("erpact/dan-dev=developer")
	tests := []struct {
		name       string
		user       *auth.User
		min        operations.Role
		git        GitReader
		pm         *stubPrincipalMembership
		wantStatus int
		want       []string
		admins     map[string]bool
	}{
		{"both allow", dev(), operations.RoleDeveloper, legacyRoles,
			&stubPrincipalMembership{roles: map[string][][]string{"erpact": {{"developer"}}}}, 0, []string{"result:match"}, nil},
		{"both deny", dev(), operations.RoleOwner, legacyRoles,
			&stubPrincipalMembership{roles: map[string][][]string{"erpact": {{"developer"}}}}, http.StatusForbidden, []string{"result:match"}, nil},
		{"principal would deny: legacy still allows", dev(), operations.RoleDeveloper, legacyRoles,
			&stubPrincipalMembership{roles: map[string][][]string{"erpact": {{"viewer"}}}}, 0, []string{"result:diff", "kind:role_mismatch"}, nil},
		{"principal would allow: legacy still denies", dev(), operations.RoleOwner, legacyRoles,
			&stubPrincipalMembership{roles: map[string][][]string{"erpact": {{"owner"}}}}, http.StatusForbidden, []string{"result:diff", "kind:role_mismatch"}, nil},
		{"not a member by principal", dev(), operations.RoleViewer, legacyRoles,
			&stubPrincipalMembership{}, 0, []string{"result:diff", "kind:role_mismatch"}, nil},
		{"principal roles unreadable", dev(), operations.RoleDeveloper, legacyRoles,
			&stubPrincipalMembership{rolesErr: errors.New("tenant \"erpact\": malformed principalId")}, 0, []string{"result:unresolved", "reason:membership_unreadable"}, nil},
		{"no principal id", erpactMember("dan-dev"), operations.RoleDeveloper, legacyRoles,
			&stubPrincipalMembership{roles: map[string][][]string{"erpact": {{"viewer"}}}}, 0, []string{"result:unresolved", "reason:no_pid"}, nil},
		// A legacy decision that could not be made has nothing to compare.
		{"legacy unreadable", dev(), operations.RoleDeveloper, &stubRoles{err: errors.New("stale")},
			&stubPrincipalMembership{roles: map[string][][]string{"erpact": {{"developer"}}}}, http.StatusServiceUnavailable, nil, nil},
		{"admin passes before any role", root(), operations.RoleOwner, legacyRoles,
			&stubPrincipalMembership{}, 0, nil, nil},
		{"admin on both sides", root(), operations.RoleOwner, legacyRoles,
			&stubPrincipalMembership{}, 0, nil, map[string]bool{shadowPRN: true}},
		// Admin on one side only: the switch changes the answer here, so the
		// role is compared.
		{"admin by login only, no written role", root(), operations.RoleOwner, legacyRoles,
			&stubPrincipalMembership{}, 0, []string{"result:diff", "kind:role_mismatch"}, map[string]bool{otherPRN: true}},
		{"admin by login only, written owner", root(), operations.RoleOwner, legacyRoles,
			&stubPrincipalMembership{roles: map[string][][]string{"erpact": {{"owner"}}}}, 0, []string{"result:match"}, map[string]bool{otherPRN: true}},
		{"admin by principal only", dev(), operations.RoleOwner, legacyRoles,
			&stubPrincipalMembership{rolesErr: errors.New("must not be read")}, http.StatusForbidden, []string{"result:diff", "kind:role_mismatch"}, map[string]bool{shadowPRN: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handlers{opts: Options{GitReader: tt.git, TenantAuthzMode: TenantAuthzShadow, PrincipalMembership: tt.pm, AdminPrincipals: tt.admins}}
			before := snapshotShadow()
			d := h.checkTenantRole(tt.user, "erpact", tt.min, "test")
			if d.status != tt.wantStatus {
				t.Fatalf("status = %d (%s), want %d", d.status, d.detail, tt.wantStatus)
			}
			assertDelta(t, before.delta(), tt.want...)
		})
	}

	t.Run("legacy mode reads no principal roles", func(t *testing.T) {
		pm := &stubPrincipalMembership{rolesErr: errors.New("must not be read")}
		h := &Handlers{opts: Options{GitReader: legacyRoles, PrincipalMembership: pm}}
		before := snapshotShadow()
		if d := h.checkTenantRole(dev(), "erpact", operations.RoleDeveloper, "test"); d.refused() {
			t.Fatalf("refused: %s", d.detail)
		}
		assertDelta(t, before.delta())
	})
}

func TestTenantSet(t *testing.T) {
	got := tenantSet([]string{"b", "admins", "a", "b", ""})
	if strings.Join(got, ",") != "a,b" {
		t.Fatalf("tenantSet = %v", got)
	}
}

// The shadow is mounted on the authenticated API: a request through the
// router is compared, and is served exactly as without it.
func TestTenantAuthzShadow_MountedInRouter(t *testing.T) {
	user := withPrincipal(t, auth.NewGitHubUser("dev", []string{"labs"}), shadowPRN)
	router := NewRouter(Options{
		AuthMiddleware:      injectUser(user),
		TenantAuthzMode:     TenantAuthzShadow,
		PrincipalMembership: &stubPrincipalMembership{namespaces: []string{"labs"}},
	})
	before := snapshotShadow()
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/whoami", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("whoami = %d: %s", rec.Code, rec.Body)
	}
	assertDelta(t, before.delta(), "result:match")
}

func TestPrincipalSetCache(t *testing.T) {
	now := time.Unix(1000, 0)
	pm := &stubPrincipalMembership{namespaces: []string{"labs"}}
	h := &Handlers{opts: Options{PrincipalMembership: pm}, principalSets: newPrincipalSetCache(10 * time.Second)}
	h.principalSets.now = func() time.Time { return now }

	for range 3 {
		if m, ok, err := h.principalSet(shadowPRN); !ok || err != nil || m.Namespaces[0] != "labs" {
			t.Fatalf("principalSet = %+v, %v, %v", m, ok, err)
		}
	}
	if n := pm.reads.Load(); n != 1 {
		t.Fatalf("%d checkout reads for three comparisons in one window, want 1", n)
	}
	now = now.Add(10 * time.Second)
	_, _, _ = h.principalSet(shadowPRN)
	if n := pm.reads.Load(); n != 2 {
		t.Fatalf("%d reads after the window, want 2: a stale set must be re-read", n)
	}

	// Only a complete read is kept: a busy or failed one is retried.
	busy := &stubPrincipalMembership{busy: true}
	h = &Handlers{opts: Options{PrincipalMembership: busy}, principalSets: newPrincipalSetCache(time.Minute)}
	_, _, _ = h.principalSet(shadowPRN)
	_, _, _ = h.principalSet(shadowPRN)
	failing := &stubPrincipalMembership{err: errors.New("stale")}
	h2 := &Handlers{opts: Options{PrincipalMembership: failing}, principalSets: newPrincipalSetCache(time.Minute)}
	_, _, _ = h2.principalSet(shadowPRN)
	_, _, _ = h2.principalSet(shadowPRN)
	if busy.reads.Load() != 2 || failing.reads.Load() != 2 {
		t.Fatalf("busy %d, failing %d reads; want 2 each (never cached)", busy.reads.Load(), failing.reads.Load())
	}

	c := newPrincipalSetCache(time.Minute)
	for i := range principalSetCacheMax + 1 {
		c.put(fmt.Sprintf("prn_%d", i), gitops.PrincipalMembership{})
	}
	if len(c.m) > principalSetCacheMax {
		t.Fatalf("cache grew to %d, cap %d", len(c.m), principalSetCacheMax)
	}
}

// The global limiter runs first: a request it refuses is never compared,
// so it costs no checkout read (claude P2 on #590).
func TestTenantAuthzShadow_BelowRateLimiter(t *testing.T) {
	user := withPrincipal(t, auth.NewGitHubUser("dev", []string{"labs"}), shadowPRN)
	router := NewRouter(Options{
		AuthMiddleware:      injectUser(user),
		TenantAuthzMode:     TenantAuthzShadow,
		PrincipalMembership: &stubPrincipalMembership{namespaces: []string{"labs"}},
	})
	before := snapshotShadow()
	served, limited := 0, 0
	for range 320 {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/whoami", nil)
		req.RemoteAddr = "203.0.113.7:1234" // not loopback, so the limiter applies
		router.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			limited++
		} else {
			served++
		}
	}
	if limited == 0 {
		t.Fatal("the limiter never refused; the test proves nothing")
	}
	if got := before.delta()["result:match"]; got != float64(served) {
		t.Fatalf("%v comparisons for %d served and %d refused requests; refused ones must not be compared", got, served, limited)
	}
}

func TestShadowDiffLogIsDeduplicated(t *testing.T) {
	now := time.Unix(1000, 0)
	c := newPrincipalSetCache(time.Minute)
	c.now = func() time.Time { return now }
	if !c.shouldLog("a") || c.shouldLog("a") {
		t.Fatal("one diff logged twice within the interval")
	}
	if !c.shouldLog("b") {
		t.Fatal("a different diff was suppressed")
	}
	now = now.Add(diffLogInterval)
	if !c.shouldLog("a") {
		t.Fatal("a diff was never logged again")
	}
	var nilCache *principalSetCache
	for range 2 {
		if !nilCache.shouldLog("a") {
			t.Fatal("no cache must log every diff")
		}
	}
}
