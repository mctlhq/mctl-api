package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/operations"
)

const shadowPRN = "prn_01JBBBBBBBBBBBBBBBBBBBBBBB"

func TestParseTenantAuthzMode(t *testing.T) {
	for raw, want := range map[string]TenantAuthzMode{"": TenantAuthzLegacy, "legacy": TenantAuthzLegacy, " shadow ": TenantAuthzShadow} {
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
	namespaces []string
	unreadable []string
	busy       bool
	err        error
	roles      map[string][][]string // namespace -> roles
	rolesErr   error
}

func (s *stubPrincipalMembership) TryNamespacesForPrincipal(string) (gitops.PrincipalMembership, bool, error) {
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
	for _, k := range []string{"tenant_only_legacy", "tenant_only_principal", "role_mismatch"} {
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
	legacyRoles := rolesOf("erpact/dan-dev=developer")
	tests := []struct {
		name       string
		user       *auth.User
		min        operations.Role
		git        GitReader
		pm         *stubPrincipalMembership
		wantStatus int
		want       []string
	}{
		{"both allow", dev(), operations.RoleDeveloper, legacyRoles,
			&stubPrincipalMembership{roles: map[string][][]string{"erpact": {{"developer"}}}}, 0, []string{"result:match"}},
		{"both deny", dev(), operations.RoleOwner, legacyRoles,
			&stubPrincipalMembership{roles: map[string][][]string{"erpact": {{"developer"}}}}, http.StatusForbidden, []string{"result:match"}},
		{"principal would deny: legacy still allows", dev(), operations.RoleDeveloper, legacyRoles,
			&stubPrincipalMembership{roles: map[string][][]string{"erpact": {{"viewer"}}}}, 0, []string{"result:diff", "kind:role_mismatch"}},
		{"principal would allow: legacy still denies", dev(), operations.RoleOwner, legacyRoles,
			&stubPrincipalMembership{roles: map[string][][]string{"erpact": {{"owner"}}}}, http.StatusForbidden, []string{"result:diff", "kind:role_mismatch"}},
		{"not a member by principal", dev(), operations.RoleViewer, legacyRoles,
			&stubPrincipalMembership{}, 0, []string{"result:diff", "kind:role_mismatch"}},
		{"principal roles unreadable", dev(), operations.RoleDeveloper, legacyRoles,
			&stubPrincipalMembership{rolesErr: errors.New("tenant \"erpact\": malformed principalId")}, 0, []string{"result:unresolved", "reason:membership_unreadable"}},
		{"no principal id", erpactMember("dan-dev"), operations.RoleDeveloper, legacyRoles,
			&stubPrincipalMembership{roles: map[string][][]string{"erpact": {{"viewer"}}}}, 0, []string{"result:unresolved", "reason:no_pid"}},
		// A legacy decision that could not be made has nothing to compare.
		{"legacy unreadable", dev(), operations.RoleDeveloper, &stubRoles{err: errors.New("stale")},
			&stubPrincipalMembership{roles: map[string][][]string{"erpact": {{"developer"}}}}, http.StatusServiceUnavailable, nil},
		{"admin passes before any role", withPrincipal(t, auth.NewGitHubUser("root", []string{"admins"}), shadowPRN), operations.RoleOwner, legacyRoles,
			&stubPrincipalMembership{}, 0, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handlers{opts: Options{GitReader: tt.git, TenantAuthzMode: TenantAuthzShadow, PrincipalMembership: tt.pm}}
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
