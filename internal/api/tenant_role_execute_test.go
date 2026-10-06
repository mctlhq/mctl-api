package api_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/operations"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
)

// Tenant role gate on POST /operations/{name}/execute (mctl-api#478).
//
// The fixture is the erpact tenant as it stands: one owner and two
// developers, plus the members that must never be read as more than they
// are (a viewer, a member with no role, one with an unknown role, one listed
// twice).

type roleFixture struct {
	router http.Handler
	git    *fakeGitReader
	exec   *fakeExecutor
	audit  *audit.Logger
}

func newRoleFixture(t *testing.T) *roleFixture {
	t.Helper()
	t.Setenv("AUTH_REQUIRED", "false")
	f := &roleFixture{
		git: &fakeGitReader{tenants: []gitops.Tenant{{
			Name: "erpact",
			Members: []gitops.TenantMember{
				{UserID: "olga-owner", Role: "owner"},
				{UserID: "dan-dev", Role: "developer"},
				{UserID: "vic-viewer", Role: "viewer"},
				{UserID: "nora-norole"},
				{UserID: "max-maintainer", Role: "maintainer"},
				{UserID: "dup", Role: "owner"},
				{UserID: "dup", Role: "viewer"},
			},
		}}},
		exec:  &fakeExecutor{},
		audit: audit.NewLogger(),
	}
	f.router = mctlapi.NewRouter(mctlapi.Options{
		Registry:  operations.NewRegistry(),
		GitReader: f.git,
		AuditLog:  f.audit,
		Executor:  f.exec,
	})
	return f
}

func member(login string) *auth.User { return auth.NewGitHubUser(login, []string{"erpact"}) }

var (
	deleteTenantBody = map[string]string{"tenant_name": "erpact"}
	retireBody       = map[string]string{"team_name": "erpact", "component_name": "web"}
	removeDomainBody = map[string]string{"team_name": "erpact", "service_name": "web", "domain": "app.example.com"}
	rollbackBody     = map[string]string{"team_name": "erpact", "component_name": "web", "target_tag": "1.2.3"}
)

// lastAudit returns the newest audit entry, failing if there is none.
func (f *roleFixture) lastAudit(t *testing.T) audit.Entry {
	t.Helper()
	entries := f.audit.List(1)
	if len(entries) == 0 {
		t.Fatal("no audit entry was written")
	}
	return entries[0]
}

// assertRefused checks the whole shape of a refusal: the status, that
// nothing was submitted, and that exactly one audit entry with the given
// status records it.
func (f *roleFixture) assertRefused(t *testing.T, op string, body map[string]string, user *auth.User, wantCode int, wantAudit string) string {
	t.Helper()
	before := len(f.audit.List(1000))
	w := postAs(t, f.router, "/api/v1/operations/"+op+"/execute", body, user)
	if w.Code != wantCode {
		t.Fatalf("%s as %s: status %d, want %d; body: %s", op, user.ID, w.Code, wantCode, w.Body.String())
	}
	if len(f.exec.submitted) != 0 {
		t.Fatalf("%s as %s: a workflow was submitted: %v", op, user.ID, f.exec.submitted)
	}
	entries := f.audit.List(1000)
	if len(entries) != before+1 {
		t.Fatalf("%s as %s: %d audit entries written, want 1", op, user.ID, len(entries)-before)
	}
	e := f.lastAudit(t)
	if e.Status != wantAudit || e.Operation != op || e.UserID != user.ID {
		t.Fatalf("%s as %s: audit entry = {user %q, operation %q, status %q}, want status %q", op, user.ID, e.UserID, e.Operation, e.Status, wantAudit)
	}
	if e.Parameters["tenant"] != "erpact" {
		t.Errorf("audit entry does not name the tenant: %v", e.Parameters)
	}
	msg, _ := decodeJSON(t, w)["error"].(string)
	return msg
}

func (f *roleFixture) assertSubmitted(t *testing.T, op string, body map[string]string, user *auth.User) {
	t.Helper()
	w := postAs(t, f.router, "/api/v1/operations/"+op+"/execute", body, user)
	if w.Code != http.StatusAccepted {
		t.Fatalf("%s as %s: status %d, want 202; body: %s", op, user.ID, w.Code, w.Body.String())
	}
	if n := len(f.exec.submitted); n != 1 || f.exec.submitted[0] != op {
		t.Fatalf("%s as %s: submitted = %v, want exactly [%s]", op, user.ID, f.exec.submitted, op)
	}
	if e := f.lastAudit(t); e.Status != "submitted" || e.Operation != op {
		t.Fatalf("audit entry = {%q, %q}, want {%q, submitted}", e.Operation, e.Status, op)
	}
}

// The defect itself: a developer deleting the tenant they belong to.
func TestExecuteOperation_DeveloperCannotDeleteTenant(t *testing.T) {
	f := newRoleFixture(t)
	msg := f.assertRefused(t, "delete-tenant", deleteTenantBody, member("dan-dev"), http.StatusForbidden, "denied")
	for _, want := range []string{`"delete-tenant"`, `requires role "owner"`, `"erpact"`, `your role is "developer"`} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q does not say %s", msg, want)
		}
	}
}

func TestExecuteOperation_OwnerCanDeleteTenant(t *testing.T) {
	f := newRoleFixture(t)
	f.assertSubmitted(t, "delete-tenant", deleteTenantBody, member("olga-owner"))
}

// A platform admin passes whatever the members list says, including when it
// does not list them and when it cannot be read: IsAdmin is decided before
// any role is looked up.
func TestExecuteOperation_PlatformAdminPassesTheRoleGate(t *testing.T) {
	for name, user := range map[string]*auth.User{
		"admin group, not a member": auth.NewGitHubUser("root", []string{"admins"}),
		"service principal":         auth.NewServiceUser(),
	} {
		t.Run(name, func(t *testing.T) {
			f := newRoleFixture(t)
			f.git.memberRolesErr = errors.New("checkout unreadable")
			f.assertSubmitted(t, "delete-tenant", deleteTenantBody, user)
			if f.git.memberRolesCalls != 0 {
				t.Errorf("an admin's role was looked up %d time(s)", f.git.memberRolesCalls)
			}
		})
	}
}

// Every way of not holding a sufficient, known role is a 403 with a denied
// audit entry and no workflow.
func TestExecuteOperation_InsufficientOrUnknownRoleIsDenied(t *testing.T) {
	tests := []struct {
		name string
		op   string
		body map[string]string
		user *auth.User
		says string
	}{
		{"developer retires a service", "retire-service", retireBody, member("dan-dev"), `requires role "owner"`},
		{"developer removes a custom domain", "remove-custom-domain", removeDomainBody, member("dan-dev"), `requires role "owner"`},
		{"viewer deletes the tenant", "delete-tenant", deleteTenantBody, member("vic-viewer"), `your role is "viewer"`},
		{"viewer rolls back a service", "rollback-service", rollbackBody, member("vic-viewer"), `requires role "developer"`},
		{"member with no role rolls back", "rollback-service", rollbackBody, member("nora-norole"), "missing or not recognized"},
		{"member with no role deletes the tenant", "delete-tenant", deleteTenantBody, member("nora-norole"), "missing or not recognized"},
		{"member with an unknown role rolls back", "rollback-service", rollbackBody, member("max-maintainer"), "missing or not recognized"},
		// Listed as owner and as viewer: the least of the two, not the first
		// or the best.
		{"member listed twice deletes the tenant", "delete-tenant", deleteTenantBody, member("dup"), `your role is "viewer"`},
		{"member listed twice rolls back", "rollback-service", rollbackBody, member("dup"), `your role is "viewer"`},
		// Groups say member (a session older than the removal), the
		// checkout says no.
		{"former member deletes the tenant", "delete-tenant", deleteTenantBody, member("gone"), "not listed as a member"},
		// A name that equals the owner's login is not the owner unless
		// authentication proved a GitHub login (Dex and other OIDC tokens
		// do not).
		{"unproven identity named like the owner", "delete-tenant", deleteTenantBody,
			&auth.User{ID: "olga-owner", Groups: []string{"erpact"}}, "does not carry a tenant role"},
		{"unproven identity rolls back", "rollback-service", rollbackBody,
			&auth.User{ID: "olga-owner", Groups: []string{"erpact"}}, "does not carry a tenant role"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newRoleFixture(t)
			msg := f.assertRefused(t, tt.op, tt.body, tt.user, http.StatusForbidden, "denied")
			if !strings.Contains(msg, tt.says) {
				t.Errorf("message %q does not say %q", msg, tt.says)
			}
		})
	}
}

// The other side of the same table: the gate must not take away what a role
// does grant.
func TestExecuteOperation_SufficientRoleIsAllowed(t *testing.T) {
	tests := []struct {
		name string
		op   string
		body map[string]string
		user *auth.User
	}{
		{"developer rolls back a service", "rollback-service", rollbackBody, member("dan-dev")},
		{"owner rolls back a service", "rollback-service", rollbackBody, member("olga-owner")},
		{"owner retires a service", "retire-service", retireBody, member("olga-owner")},
		{"owner removes a custom domain", "remove-custom-domain", removeDomainBody, member("olga-owner")},
		{"login case does not matter", "delete-tenant", deleteTenantBody, member("Olga-Owner")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newRoleFixture(t)
			f.assertSubmitted(t, tt.op, tt.body, tt.user)
		})
	}
}

// "Could not read the role" is not "has no role" and still less a pass: it
// is 503 with an audit entry of status error, for the owner as for anyone.
func TestExecuteOperation_UnreadableRoleIsAnErrorNotADecision(t *testing.T) {
	for _, login := range []string{"olga-owner", "dan-dev"} {
		t.Run(login, func(t *testing.T) {
			f := newRoleFixture(t)
			f.git.memberRolesErr = errors.New("open /data/gitops/platform-gitops/tenants/erpact/values.yaml: permission denied")
			msg := f.assertRefused(t, "delete-tenant", deleteTenantBody, member(login), http.StatusServiceUnavailable, "error")
			if !strings.Contains(msg, "cannot verify your role") {
				t.Errorf("message = %q", msg)
			}
			if strings.Contains(msg, "/data/gitops") {
				t.Errorf("the response leaks the checkout path: %q", msg)
			}
			if e := f.lastAudit(t); !strings.Contains(e.Message, "permission denied") {
				t.Errorf("the audit entry does not carry the cause: %q", e.Message)
			}
		})
	}
}

// A non-member is stopped by the tenant-access check, before any role is
// read: the gate adds to that check, it does not replace it.
func TestExecuteOperation_NonMemberStillDeniedBeforeTheRoleGate(t *testing.T) {
	f := newRoleFixture(t)
	outsider := auth.NewGitHubUser("olga-owner", []string{"another"})
	w := postAs(t, f.router, "/api/v1/operations/delete-tenant/execute", deleteTenantBody, outsider)
	assertStatus(t, w, http.StatusForbidden)
	if f.git.memberRolesCalls != 0 || len(f.exec.submitted) != 0 {
		t.Fatalf("role lookups = %d, submitted = %v; want neither", f.git.memberRolesCalls, f.exec.submitted)
	}
}

// ── OpenClaw ─────────────────────────────────────────────────────────────────

// The OpenClaw owner actions use the same gate. A developer was already
// refused; what changes is that a name equal to the owner's login no longer
// passes unless authentication proved that login.
func TestOpenClaw_OwnerGateUsesTheSharedRoleGate(t *testing.T) {
	f := newRoleFixture(t)
	const path = "/api/v1/openclaw/erpact/skills"

	if w := getAs(t, f.router, path, member("olga-owner")); w.Code != http.StatusOK {
		t.Fatalf("owner: status %d, want 200; body: %s", w.Code, w.Body.String())
	}
	for name, user := range map[string]*auth.User{
		"developer":                        member("dan-dev"),
		"viewer":                           member("vic-viewer"),
		"listed twice":                     member("dup"),
		"unproven identity named as owner": {ID: "olga-owner", Groups: []string{"erpact"}},
	} {
		w := getAs(t, f.router, path, user)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403; body: %s", name, w.Code, w.Body.String())
		}
		save := postAs(t, f.router, path, map[string]string{"name": "my-skill", "content": "---\nname: my-skill\ndescription: d\n---\n# body"}, user)
		if save.Code != http.StatusForbidden {
			t.Errorf("%s: save status %d, want 403; body: %s", name, save.Code, save.Body.String())
		}
	}
	if len(f.exec.submitted) != 0 {
		t.Fatalf("a refused save submitted a workflow: %v", f.exec.submitted)
	}

	f.git.memberRolesErr = errors.New("checkout unreadable")
	if w := getAs(t, f.router, path, member("olga-owner")); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unreadable role: status %d, want 503; body: %s", w.Code, w.Body.String())
	}
}
