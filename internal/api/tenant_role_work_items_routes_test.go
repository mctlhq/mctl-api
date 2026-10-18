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
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
)

// Route-level tests of the work-item role gate (mctl-api#489): every gated
// route through the router, against Postgres.

var (
	rrDevPRN  = "prn_01JD" + strings.Repeat("0", 22)
	rrViewPRN = "prn_01JV" + strings.Repeat("0", 22)
	rrZedPRN  = "prn_01JZ" + strings.Repeat("1", 22)
)

// rolesByPrincipal is a principal membership reader with one role per
// principal on one tenant.
type rolesByPrincipal struct {
	tenant string
	roles  map[string]string
	err    error
}

func (p *rolesByPrincipal) TryNamespacesForPrincipal(prn string) (gitops.PrincipalMembership, bool, error) {
	if _, ok := p.roles[prn]; ok {
		return gitops.PrincipalMembership{Namespaces: []string{p.tenant}}, true, nil
	}
	return gitops.PrincipalMembership{}, true, nil
}

func (p *rolesByPrincipal) MemberRolesForPrincipal(namespace, prn string) ([][]string, error) {
	if p.err != nil {
		return nil, p.err
	}
	if role, ok := p.roles[prn]; ok && namespace == p.tenant {
		return [][]string{{role}}, nil
	}
	return nil, nil
}

type roleEnv struct {
	*sidEnv
	roles   *rolesByPrincipal
	members tenantsByPrincipal
}

// newRoleEnv is the surface identity harness in mode, with principal roles
// read from roles; mutate has the last say over the router options.
func newRoleEnv(t *testing.T, mode TenantAuthzMode, mutate func(*Options)) *roleEnv {
	t.Helper()
	re := &roleEnv{members: tenantsByPrincipal{}}
	pr := &relayPrincipals{byLogin: map[string]string{"zed@example.com": rrZedPRN}}
	re.sidEnv = newSIDEnvOpts(t, pr, func(o *Options) {
		o.TenantAuthzMode = mode
		tenant := o.TenantResolver.(sidTenants)["carol"][0]
		re.roles = &rolesByPrincipal{tenant: tenant, roles: map[string]string{}}
		o.PrincipalAuthz = &auth.PrincipalAuthz{Members: re.members}
		o.PrincipalMembership = re.roles
		if mutate != nil {
			mutate(o)
		}
	})
	return re
}

// human adds name, a direct caller u with principal prn holding role on
// the harness tenant, as principal mode leaves it.
func (re *roleEnv) human(name string, u *auth.User, prn, role string) *auth.User {
	re.t.Helper()
	re.members[prn] = []string{re.tenant}
	re.roles.roles[prn] = role
	u = principalUser(re.t, u, prn, map[string][]string{prn: {re.tenant}})
	re.users[name] = u
	return u
}

// item opens a tenant-visible work item as a platform admin.
func (re *roleEnv) item() string {
	re.t.Helper()
	code, body := re.do("root", "POST", "/api/v1/work-items", map[string]any{"tenant": re.tenant, "title": "gated"})
	if code != http.StatusCreated {
		re.t.Fatalf("create = %d %v", code, body)
	}
	return body["work_item"].(map[string]any)["id"].(string)
}

// storeState fingerprints every work-item row of the harness tenant, so a
// refused write can be shown to have written nothing.
func (re *roleEnv) storeState() string {
	re.t.Helper()
	var out []string
	q := func(label, sql string) {
		var n int64
		if err := re.pool.QueryRow(context.Background(), sql, re.tenant).Scan(&n); err != nil {
			re.t.Fatal(err)
		}
		out = append(out, fmt.Sprintf("%s=%d", label, n))
	}
	q("items", `SELECT count(*) FROM work_items WHERE tenant=$1`)
	q("versions", `SELECT coalesce(sum(state_version),0) FROM work_items WHERE tenant=$1`)
	for _, table := range []string{"work_item_events", "work_item_intents", "work_item_executions",
		"work_item_surface_refs", "work_item_execution_requests", "work_item_requests"} {
		q(table, `SELECT count(*) FROM `+table+` t JOIN work_items w ON w.id=t.work_item_id WHERE w.tenant=$1`)
	}
	return strings.Join(out, " ")
}

// auditCount counts audit entries for operation with status.
func (re *roleEnv) auditCount(operation, status string) int {
	n := 0
	entries := re.audit.List(10000)
	for i := range entries {
		if entries[i].Operation == operation && entries[i].Status == status {
			n++
		}
	}
	return n
}

// gatedRoute is one work-item write behind requireWorkItemRole.
type gatedRoute struct {
	op        string // the audit operation suffix
	method    string
	path      string // "%s" is the item id; no "%s" for create
	body      func(tenant string) map[string]any
	relay     bool // a surface may relay it
	delegated bool // an agent may carry a delegation on it
	finished  bool // needs a finished execution to continue
}

var gatedWorkItemRoutes = []gatedRoute{
	{"create", "POST", "/api/v1/work-items", func(tenant string) map[string]any {
		return map[string]any{"tenant": tenant, "title": "t"}
	}, true, false, false},
	{"create", "POST", "/api/v1/work-items", func(tenant string) map[string]any {
		return map[string]any{"tenant": tenant, "title": "t", "visibility": "private"}
	}, false, false, false},
	{"transition", "PATCH", "/api/v1/work-items/%s", func(string) map[string]any {
		return map[string]any{"action": "archive", "expected_state_version": 1}
	}, false, false, false},
	{"intent", "POST", "/api/v1/work-items/%s/intents", func(string) map[string]any {
		return map[string]any{"text": "do it"}
	}, true, true, false},
	{"execution", "POST", "/api/v1/work-items/%s/executions", func(string) map[string]any {
		return map[string]any{"engine": "temporal", "engine_ref": "run-1"}
	}, false, false, false},
	{"resume", "POST", "/api/v1/work-items/%s/resume", func(string) map[string]any {
		return map[string]any{"expected_state_version": 1, "engine": "temporal", "engine_ref": "run-2"}
	}, false, false, true},
	{"surface-ref", "POST", "/api/v1/work-items/%s/surface-refs", func(string) map[string]any {
		return map[string]any{"surface": "portal", "external_id": "ext-1"}
	}, true, true, false},
	{"execution-request", "POST", "/api/v1/work-items/%s/execution-requests", func(string) map[string]any {
		return map[string]any{"kind": "start", "expected_state_version": 1}
	}, true, true, false},
}

func (g gatedRoute) name() string {
	if v, _ := g.body("")["visibility"].(string); v != "" {
		return g.op + "/" + v
	}
	return g.op
}

// target is g's path on a fresh item ready for it.
func (re *roleEnv) target(g gatedRoute) string {
	re.t.Helper()
	if !strings.Contains(g.path, "%s") {
		return g.path
	}
	id := re.item()
	if g.finished {
		if code, body := re.do("service", "POST", "/api/v1/work-items/"+id+"/executions",
			map[string]any{"engine": "temporal", "engine_ref": "run-0", "phase": "Succeeded"}); code != http.StatusCreated {
			re.t.Fatalf("attach = %d %v", code, body)
		}
	}
	return fmt.Sprintf(g.path, id)
}

// call runs g as who on a fresh item and answers the response.
func (re *roleEnv) call(g gatedRoute, who string, headers ...string) (int, map[string]any) {
	re.t.Helper()
	return re.do(who, g.method, re.target(g), g.body(re.tenant), headers...)
}

// T1: principal mode, a GitHub-linked developer or owner passes every gated
// route.
func TestWorkItemRoutes_PrincipalDeveloperAndOwnerPass(t *testing.T) {
	for _, role := range []string{"developer", "owner"} {
		re := newRoleEnv(t, TenantAuthzPrincipal, nil)
		re.human("dan", auth.NewGitHubUser("dan", nil), rrDevPRN, role)
		for _, g := range gatedWorkItemRoutes {
			if code, body := re.call(g, "dan"); code != http.StatusCreated && code != http.StatusOK {
				t.Errorf("%s %s = %d %v, want success", role, g.name(), code, body)
			}
		}
	}
}

// T2 and T8: principal mode, a viewer is refused every gated route with a
// typed 403 and a denied audit entry, and nothing is written. The legacy
// login reader says owner for the same caller, so a login comparison
// anywhere in the path would let it through.
func TestWorkItemRoutes_PrincipalViewerRefused(t *testing.T) {
	re := newRoleEnv(t, TenantAuthzPrincipal, func(o *Options) { o.GitReader = ownerEverywhere{} })
	re.human("vic", auth.NewGitHubUser("vic", nil), rrViewPRN, "viewer")
	for _, g := range gatedWorkItemRoutes {
		path := re.target(g)
		before, denied := re.storeState(), re.auditCount("work_item."+g.op, "denied")
		code, body := re.do("vic", g.method, path, g.body(re.tenant))
		if code != http.StatusForbidden || body["code"] != wiCodeRoleForbidden {
			t.Errorf("viewer %s = %d %v, want 403 %s", g.name(), code, body, wiCodeRoleForbidden)
		}
		if after := re.storeState(); after != before {
			t.Errorf("viewer %s wrote: %s -> %s", g.name(), before, after)
		}
		if n := re.auditCount("work_item."+g.op, "denied") - denied; n != 1 {
			t.Errorf("viewer %s: %d denied audit entries, want 1", g.name(), n)
		}
	}
}

// expectRefused runs g as who and checks the typed refusal, one audit entry
// of auditStatus, and that nothing was written.
func (re *roleEnv) expectRefused(label string, g gatedRoute, who string, wantCode int, wantType, auditStatus string, headers ...string) {
	re.t.Helper()
	path := re.target(g)
	before, audited := re.storeState(), re.auditCount("work_item."+g.op, auditStatus)
	code, body := re.do(who, g.method, path, g.body(re.tenant), headers...)
	if code != wantCode || body["code"] != wantType {
		re.t.Errorf("%s %s = %d %v, want %d %s", label, g.name(), code, body, wantCode, wantType)
	}
	if after := re.storeState(); after != before {
		re.t.Errorf("%s %s wrote: %s -> %s", label, g.name(), before, after)
	}
	if n := re.auditCount("work_item."+g.op, auditStatus) - audited; n != 1 {
		re.t.Errorf("%s %s: %d %s audit entries, want 1", label, g.name(), n, auditStatus)
	}
}

// T3: a ZITADEL-only human (no GitHub login) is decided by its principal
// alike directly, relayed by a surface, and delegated to an agent: viewer
// is refused every gated route each way, developer passes.
func TestWorkItemRoutes_ZitadelOnlyHuman(t *testing.T) {
	for _, role := range []string{"viewer", "developer"} {
		t.Run(role, func(t *testing.T) {
			re := newRoleEnv(t, TenantAuthzPrincipal, nil)
			zed := re.human("zed", auth.NewFederatedUser("zitadel", "https://auth.mctl.ai", "330001", "zed@example.com", auth.KindHuman), rrZedPRN, role)
			if _, gh := zed.GitHubLogin(); gh {
				t.Fatal("zed must have no GitHub login")
			}
			re.link("zed", "telegram", "7070")
			agent := auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: "we_1", WorkItemID: "wi_1"})
			re.users["as-zed"] = auth.NewDelegatedPrincipalUser("zed@example.com", rrZedPRN, false, []string{re.tenant}, agent)
			ways := map[string]struct {
				who     string
				headers []string
				only    func(gatedRoute) bool
			}{
				"direct":    {who: "zed", only: func(gatedRoute) bool { return true }},
				"relayed":   {who: "telegram", headers: []string{SurfaceActorHeader, "7070"}, only: func(g gatedRoute) bool { return g.relay }},
				"delegated": {who: "as-zed", only: func(g gatedRoute) bool { return g.delegated }},
			}
			for way, w := range ways {
				for _, g := range gatedWorkItemRoutes {
					if !w.only(g) {
						continue
					}
					if role == "viewer" {
						re.expectRefused(way+" viewer", g, w.who, http.StatusForbidden, wiCodeRoleForbidden, "denied", w.headers...)
						continue
					}
					if way != "direct" && g.op == "surface-ref" {
						// A relayed or delegated reference is on the
						// relaying surface and binds an actor; the gate's
						// pass is what is under test.
						continue
					}
					if code, body := re.call(g, w.who, w.headers...); code != http.StatusCreated && code != http.StatusOK {
						t.Errorf("%s developer %s = %d %v, want success", way, g.name(), code, body)
					}
				}
			}
		})
	}
}

// T4: a role that cannot be read is 503 tenant_role_unavailable with an
// error audit entry and no write: no membership reader, a failing one, or
// a human whose principal is unresolved.
func TestWorkItemRoutes_RoleUnreadable(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate     func(*Options)
		readErr    error
		unresolved bool
	}{
		"reader not configured": {mutate: func(o *Options) { o.PrincipalMembership = nil }},
		"reader failing":        {readErr: errors.New("checkout is stale")},
		"principal unresolved":  {unresolved: true},
	} {
		t.Run(name, func(t *testing.T) {
			re := newRoleEnv(t, TenantAuthzPrincipal, tc.mutate)
			re.human("dan", auth.NewGitHubUser("dan", nil), rrDevPRN, "developer")
			if tc.unresolved {
				// Tenant access without a principal: what a session that
				// lost its principal would look like past the middleware.
				re.users["dan"] = auth.NewGitHubUser("dan", []string{re.tenant})
			}
			if re.roles != nil {
				re.roles.err = tc.readErr
			}
			for _, g := range gatedWorkItemRoutes {
				re.expectRefused(name, g, "dan", http.StatusServiceUnavailable, wiCodeRoleUnavailable, "error")
			}
		})
	}
}

// T5: the service principal passes the gate in every mode on the routes it
// uses, and still may not request execution on a user's behalf.
func TestWorkItemRoutes_ServicePrincipal(t *testing.T) {
	for _, mode := range []TenantAuthzMode{TenantAuthzPrincipal, TenantAuthzLegacy, TenantAuthzShadow} {
		re := newRoleEnv(t, mode, func(o *Options) { o.GitReader = rolesOf() })
		for _, g := range gatedWorkItemRoutes {
			switch g.op {
			case "execution", "resume":
				if code, body := re.call(g, "service"); code != http.StatusCreated && code != http.StatusOK {
					t.Errorf("%s service %s = %d %v, want success", mode, g.name(), code, body)
				}
			case "execution-request":
				if code, body := re.call(g, "service"); code != http.StatusForbidden || body["code"] != xrCodeRequesterForbidden {
					t.Errorf("%s service %s = %d %v, want 403 %s", mode, g.name(), code, body, xrCodeRequesterForbidden)
				}
			}
		}
	}
}

// T6: an agent token acting for no human has no tenant access, so a tenant
// item is not found; one given a tenant group directly is refused by the
// gate as a non-human caller.
func TestWorkItemRoutes_AgentToken(t *testing.T) {
	re := newRoleEnv(t, TenantAuthzPrincipal, nil)
	re.users["agent"] = auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: "we_1", WorkItemID: "wi_1"})
	scoped := auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: "we_2", WorkItemID: "wi_2"})
	scoped.Groups = []string{re.tenant}
	re.users["scoped-agent"] = scoped
	for _, g := range gatedWorkItemRoutes {
		if g.op == "create" {
			continue
		}
		if code, body := re.call(g, "agent"); code != http.StatusNotFound || body["code"] != wiCodeNotFound {
			t.Errorf("agent %s = %d %v, want 404 %s", g.name(), code, body, wiCodeNotFound)
		}
		re.expectRefused("tenant-scoped agent", g, "scoped-agent", http.StatusForbidden, wiCodeRoleForbidden, "denied")
	}
}

// T7: a role refusal never confirms an item exists. A viewer asking about
// an item of another tenant, or another principal's private item, gets
// 404 as anyone without access does.
func TestWorkItemRoutes_RefusalAfterVisibility(t *testing.T) {
	re := newRoleEnv(t, TenantAuthzPrincipal, nil)
	re.human("vic", auth.NewGitHubUser("vic", nil), rrViewPRN, "viewer")
	re.human("dan", auth.NewGitHubUser("dan", nil), rrDevPRN, "developer")
	code, body := re.do("root", "POST", "/api/v1/work-items", map[string]any{"tenant": "acme", "title": "elsewhere"})
	if code != http.StatusCreated {
		t.Fatalf("create in acme = %d %v", code, body)
	}
	foreign := body["work_item"].(map[string]any)["id"].(string)
	code, body = re.do("dan", "POST", "/api/v1/work-items", map[string]any{"tenant": re.tenant, "title": "mine", "visibility": "private"})
	if code != http.StatusCreated {
		t.Fatalf("private create = %d %v", code, body)
	}
	private := body["work_item"].(map[string]any)["id"].(string)
	for _, g := range gatedWorkItemRoutes {
		if g.op == "create" {
			continue
		}
		for _, id := range []string{foreign, private} {
			if code, body := re.do("vic", g.method, fmt.Sprintf(g.path, id), g.body(re.tenant)); code != http.StatusNotFound || body["code"] != wiCodeNotFound {
				t.Errorf("viewer %s on %s = %d %v, want 404 %s", g.name(), id, code, body, wiCodeNotFound)
			}
		}
	}
	// Creating in a tenant the caller is not a member of is the membership
	// refusal, never the role one.
	if code, body := re.do("vic", "POST", "/api/v1/work-items", map[string]any{"tenant": "acme", "title": "t"}); code != http.StatusForbidden || body["code"] == wiCodeRoleForbidden {
		t.Errorf("viewer create in acme = %d %v, want the tenant refusal", code, body)
	}
}

// T9: in principal mode repo sync is decided by principal: a viewer is
// refused with no upstream request, a developer is proxied, and an
// unreadable role is 503 with no upstream request.
func TestSyncRepos_PrincipalMode(t *testing.T) {
	for name, tc := range map[string]struct {
		role      string
		rolesErr  error
		wantCode  int
		wantCalls int
	}{
		"viewer":     {role: "viewer", wantCode: http.StatusForbidden},
		"developer":  {role: "developer", wantCode: http.StatusOK, wantCalls: 1},
		"unreadable": {role: "developer", rolesErr: errors.New("checkout is stale"), wantCode: http.StatusServiceUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			srv, seen := captureBackstage(t)
			pm := &stubPrincipalMembership{roles: map[string][][]string{"labs": {{tc.role}}}, rolesErr: tc.rolesErr}
			// The login reader says owner: it must not be consulted.
			h := &Handlers{opts: Options{BackstageInternalURL: srv.URL, GitReader: ownerEverywhere{},
				TenantAuthzMode: TenantAuthzPrincipal, PrincipalMembership: pm, AuditLog: audit.NewLogger()}}
			u := principalUser(t, auth.NewGitHubUser("vic", nil), rrViewPRN, map[string][]string{rrViewPRN: {"labs"}})
			req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/repos/sync", strings.NewReader(`{"team":"labs"}`)), u)
			rec := httptest.NewRecorder()
			h.SyncRepos(rec, req)
			if rec.Code != tc.wantCode || len(*seen) != tc.wantCalls {
				t.Fatalf("status = %d, upstream calls = %d; want %d, %d (%s)", rec.Code, len(*seen), tc.wantCode, tc.wantCalls, rec.Body.String())
			}
		})
	}
}

// T10: legacy mode decides by the GitHub-proven login: a viewer is refused
// every gated route, a developer passes, and a Dex or other OIDC human
// with no GitHub login has no tenant role at all.
func TestWorkItemRoutes_LegacyMode(t *testing.T) {
	var tenant string
	re := newRoleEnv(t, TenantAuthzLegacy, func(o *Options) {
		tenant = o.TenantResolver.(sidTenants)["carol"][0]
		o.GitReader = rolesOf(tenant+"/vic=viewer", tenant+"/dan=developer", tenant+"/dex-dan=developer")
	})
	re.users["vic"] = auth.NewGitHubUser("vic", []string{tenant})
	re.users["dan"] = auth.NewGitHubUser("dan", []string{tenant})
	// Named like a developer member, but not proven by GitHub.
	re.users["dex-dan"] = &auth.User{ID: "dex-dan", Groups: []string{tenant}}
	for _, g := range gatedWorkItemRoutes {
		re.expectRefused("legacy viewer", g, "vic", http.StatusForbidden, wiCodeRoleForbidden, "denied")
		re.expectRefused("legacy dex", g, "dex-dan", http.StatusForbidden, wiCodeRoleForbidden, "denied")
		if code, body := re.call(g, "dan"); code != http.StatusCreated && code != http.StatusOK {
			t.Errorf("legacy developer %s = %d %v, want success", g.name(), code, body)
		}
	}
}

// T11: shadow mode authorizes as legacy does and records how principal
// mode would have decided the role: here the principal is an owner where
// the login is a viewer, so every gated write is refused and counted as a
// role mismatch.
func TestWorkItemRoutes_ShadowMode(t *testing.T) {
	var tenant string
	re := newRoleEnv(t, TenantAuthzShadow, func(o *Options) {
		tenant = o.TenantResolver.(sidTenants)["carol"][0]
		o.GitReader = rolesOf(tenant + "/vic=viewer")
	})
	re.members[rrViewPRN] = []string{tenant}
	re.roles.roles[rrViewPRN] = "owner"
	re.users["vic"] = withPrincipal(t, auth.NewGitHubUser("vic", []string{tenant}), rrViewPRN)
	for _, g := range gatedWorkItemRoutes {
		before := snapshotShadow()
		re.expectRefused("shadow viewer", g, "vic", http.StatusForbidden, wiCodeRoleForbidden, "denied")
		if d := before.delta(); d["kind:role_mismatch"] < 1 {
			t.Errorf("shadow %s: counters %v, want a role_mismatch", g.name(), d)
		}
	}
}

// T12: what #489 leaves ungated stays as it was. A tenant owner who is not
// a platform admin may not decide an action approval; a human-input answer
// is decided by actor_refs, not by role; reads are never role-gated.
func TestWorkItemRoutes_UngatedStayUngated(t *testing.T) {
	t.Run("action approval decision", func(t *testing.T) {
		e := newWorkItemsEnv(t) // GitReader: every login an owner
		id := e.requestApproval("k-489")["id"].(string)
		if res := e.decide(e.user("alice"), id, "approve"); res.code != http.StatusForbidden || code(res) != aarCodeDeciderForbidden {
			t.Fatalf("tenant owner decision = %d %s, want 403 %s", res.code, res.raw, aarCodeDeciderForbidden)
		}
	})
	t.Run("human input", func(t *testing.T) {
		h, tc, _, _ := newHumanInputResponseHandlers(t)
		tc.onSignal = workflowAccepts
		h.opts.GitReader = viewerEverywhere{h.opts.GitReader}
		if got := respond(t, h, alice, hiASCII, answer(`"library A"`)); got.code != http.StatusOK {
			t.Fatalf("viewer in actor_refs = %d %s, want 200", got.code, got.raw)
		}
		h, tc, _, _ = newHumanInputResponseHandlers(t)
		tc.onSignal = workflowAccepts
		h.opts.GitReader = ownerEverywhere{h.opts.GitReader}
		if got := respond(t, h, bob, hiASCII, answer(`"library A"`)); got.code != http.StatusNotFound {
			t.Fatalf("owner not in actor_refs = %d %s, want 404", got.code, got.raw)
		}
	})
	t.Run("reads", func(t *testing.T) {
		re := newRoleEnv(t, TenantAuthzPrincipal, nil)
		re.human("vic", auth.NewGitHubUser("vic", nil), rrViewPRN, "viewer")
		id := re.item()
		for _, path := range []string{"/api/v1/work-items", "/api/v1/work-items/" + id, "/api/v1/work-items/" + id + "/executions",
			"/api/v1/work-items/" + id + "/events", "/api/v1/work-items/" + id + "/intents", "/api/v1/work-items/" + id + "/execution-requests"} {
			if code, body := re.do("vic", "GET", path, nil); code != http.StatusOK {
				t.Errorf("viewer GET %s = %d %v, want 200", path, code, body)
			}
		}
	})
}

// viewerEverywhere is a GitReader that lists every login as a viewer of
// every tenant.
type viewerEverywhere struct{ GitReader }

func (viewerEverywhere) MemberRoles(_, _ string) ([][]string, error) {
	return [][]string{{"viewer"}}, nil
}
