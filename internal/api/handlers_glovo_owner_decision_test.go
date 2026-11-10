package api

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"sync"
	"testing"
	"unsafe"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

const (
	glovoOwnerPRN = "prn_AAAAAAAAAAAAAAAAAAAAAAAAA1"
	glovoOtherPRN = "prn_BBBBBBBBBBBBBBBBBBBBBBBBB2"
	glovoTenant   = "acme"
)

type fakeGlovoDecisions struct {
	mu       sync.Mutex
	binding  *workitems.GlovoBinding
	forErr   error
	readyErr error
	decided  []workitems.ActionDecisionInput
}

func (f *fakeGlovoDecisions) Ready(context.Context) error { return f.readyErr }

func (f *fakeGlovoDecisions) ForDecision(_ context.Context, id string) (*workitems.ActionApprovalRequest, *workitems.GlovoBinding, error) {
	if f.forErr != nil {
		return nil, nil, f.forErr
	}
	return &workitems.ActionApprovalRequest{ID: id}, f.binding, nil
}

func (f *fakeGlovoDecisions) Decide(_ context.Context, in workitems.ActionDecisionInput) (*workitems.ActionApprovalRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.decided = append(f.decided, in)
	return &workitems.ActionApprovalRequest{ID: in.ID, ActionKind: workitems.ActionKindGlovoPlaceOrderFake,
		State: workitems.ApprovalApproved, AuthorityBasis: in.AuthorityBasis, PolicyRuleID: workitems.GlovoPolicyRuleID}, nil
}

func (f *fakeGlovoDecisions) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.decided)
}

// glovoMembers answers the live membership read by (tenant, principal).
type glovoMembers struct {
	roles map[string]string
	err   error
}

func (m *glovoMembers) TryNamespacesForPrincipal(string) (gitops.PrincipalMembership, bool, error) {
	return gitops.PrincipalMembership{}, false, errors.New("unused")
}

func (m *glovoMembers) MemberRolesForPrincipal(tenant, prn string) ([][]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	if r, ok := m.roles[tenant+"|"+prn]; ok {
		return [][]string{{r}}, nil
	}
	return nil, nil
}

type glovoOwnerEnv struct {
	*workItemsEnv
	dec     *fakeGlovoDecisions
	members *glovoMembers
	aar     string
}

func newGlovoOwnerEnv(t *testing.T) *glovoOwnerEnv {
	t.Helper()
	e := &glovoOwnerEnv{workItemsEnv: newWorkItemsEnv(t)}
	e.dec = &fakeGlovoDecisions{binding: &workitems.GlovoBinding{Tenant: glovoTenant, OwnerPrincipalID: glovoOwnerPRN, OrderRef: "ordr_X"}}
	// The other person is a live developer of the same tenant: only the
	// binding's owner comparison keeps them out, not a missing membership.
	e.members = &glovoMembers{roles: map[string]string{glovoTenant + "|" + glovoOwnerPRN: "developer", glovoTenant + "|" + glovoOtherPRN: "developer"}}
	e.h.opts.GlovoApprovals = e.dec
	e.h.opts.TenantAuthzMode = TenantAuthzPrincipal
	e.h.opts.PrincipalMembership = e.members
	prev := glovo.Default
	glovo.Default = glovo.Gate{Open: true}
	t.Cleanup(func() { glovo.Default = prev })
	// A Glovo-kind row in the generic table. The shared test database has no
	// Glovo guard (workitems tests cover the database side); this only
	// gives the route's pre-read a row of that kind.
	id := e.requestApproval("k-glovo")["id"].(string)
	pool, err := pgxpool.New(context.Background(), e.connStr)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(context.Background(),
		`UPDATE action_approval_requests SET action_kind=$2, requested_by='service:glovo-prepare' WHERE id=$1`,
		id, workitems.ActionKindGlovoPlaceOrderFake); err != nil {
		t.Fatal(err)
	}
	e.aar = id
	return e
}

func (e *glovoOwnerEnv) human(prn, login string, groups ...string) *auth.User {
	return principalUser(e.t, auth.NewGitHubUser(login, groups), prn, nil)
}

// T19 (route half): who may decide a Glovo order approval, and what the
// others are told.
func TestGlovoOwnerDecision(t *testing.T) {
	e := newGlovoOwnerEnv(t)
	owner := e.human(glovoOwnerPRN, "olga")
	other := e.human(glovoOtherPRN, "oleg")
	adminOwner := e.human(glovoOwnerPRN, "root-owner", "admins")
	adminOther := e.human(glovoOtherPRN, "root", "admins")

	forbidden := e.decide(other, e.aar, "approve")
	if forbidden.code != http.StatusForbidden || code(forbidden) != aarCodeDeciderForbidden {
		t.Fatalf("non-owner = %d %s", forbidden.code, forbidden.raw)
	}
	// No oracle: unknown id, a generic row and someone else's order read alike.
	generic := e.requestApproval("k-generic")["id"].(string)
	for name, id := range map[string]string{"unknown": "aar_nope", "generic": generic} {
		if res := e.decide(other, id, "approve"); res.code != forbidden.code || res.raw != forbidden.raw {
			t.Errorf("%s answered %d %s, want the uniform %d %s", name, res.code, res.raw, forbidden.code, forbidden.raw)
		}
	}
	if adminNonOwner := e.decide(adminOther, e.aar, "approve"); adminNonOwner.code != http.StatusForbidden || adminNonOwner.raw != forbidden.raw {
		t.Fatalf("an admin who is not the owner = %d %s", adminNonOwner.code, adminNonOwner.raw)
	}
	for name, u := range map[string]*auth.User{
		"service": auth.NewServiceUser(),
		"agent":   auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: "we_1", WorkItemID: "wi_1"}),
		"nobody":  auth.NewGitHubUser("x", nil),
	} {
		if res := e.decide(u, e.aar, "approve"); res.code != http.StatusForbidden || code(res) != aarCodeDeciderForbidden {
			t.Errorf("%s = %d %s", name, res.code, res.raw)
		}
	}
	if n := e.dec.count(); n != 0 {
		t.Fatalf("a refused caller reached the ledger %d times", n)
	}

	// Membership is live and roleGate gives an admin no pass.
	e.members.roles = map[string]string{glovoTenant + "|" + glovoOwnerPRN: "viewer"}
	if res := e.decide(owner, e.aar, "approve"); res.code != http.StatusForbidden || res.raw != forbidden.raw {
		t.Fatalf("a viewer owner = %d %s", res.code, res.raw)
	}
	e.members.roles = map[string]string{}
	if res := e.decide(adminOwner, e.aar, "approve"); res.code != http.StatusForbidden || res.raw != forbidden.raw {
		t.Fatalf("an admin owner with no membership = %d %s", res.code, res.raw)
	}
	e.members.err = errors.New("checkout unreadable")
	if res := e.decide(owner, e.aar, "approve"); res.code != http.StatusServiceUnavailable {
		t.Fatalf("a membership read error = %d %s", res.code, res.raw)
	}
	e.members.err = nil
	e.members.roles = map[string]string{glovoTenant + "|" + glovoOwnerPRN: "developer"}

	// Not ready: gate closed, readiness failing, a failing binding read.
	glovo.Default = glovo.Gate{Open: false}
	if res := e.decide(owner, e.aar, "approve"); res.code != http.StatusServiceUnavailable || code(res) != "not_ready" {
		t.Fatalf("closed gate = %d %s", res.code, res.raw)
	}
	glovo.Default = glovo.Gate{Open: true}
	e.dec.readyErr = errors.New("not ready")
	if res := e.decide(owner, e.aar, "approve"); res.code != http.StatusServiceUnavailable || code(res) != "not_ready" {
		t.Fatalf("readiness failing = %d %s", res.code, res.raw)
	}
	e.dec.readyErr = nil
	e.dec.forErr = errors.New("pool down")
	if res := e.decide(owner, e.aar, "approve"); res.code != http.StatusServiceUnavailable {
		t.Fatalf("binding read failing = %d %s", res.code, res.raw)
	}
	e.dec.forErr = workitems.ErrApprovalNotFound
	if res := e.decide(owner, e.aar, "approve"); res.code != http.StatusForbidden || res.raw != forbidden.raw {
		t.Fatalf("an absent binding = %d %s", res.code, res.raw)
	}
	e.dec.forErr = nil
	if n := e.dec.count(); n != 0 {
		t.Fatalf("a not-ready decision reached the ledger %d times", n)
	}

	// The owner decides; the basis is resource_owner and the audit names the
	// order, not the basket.
	res := e.decide(owner, e.aar, "approve")
	if res.code != http.StatusOK {
		t.Fatalf("owner = %d %s", res.code, res.raw)
	}
	if n := e.dec.count(); n != 1 {
		t.Fatalf("decide calls = %d", n)
	}
	in := e.dec.decided[0]
	if in.AuthorityBasis != "resource_owner" || in.DecidedByPrincipalID != glovoOwnerPRN || in.ContextDigest == "" {
		t.Fatalf("decision input %+v", in)
	}
	found := false
	for _, en := range e.audit.List(1000) {
		if en.Operation != "action_approval.decision" || en.Parameters["approval_id"] != e.aar {
			continue
		}
		found = true
		if en.Parameters["order_ref"] != "ordr_X" {
			t.Errorf("audit order_ref %q", en.Parameters["order_ref"])
		}
		if _, leaked := en.Parameters["args_digest"]; leaked {
			t.Errorf("audit carries args_digest")
		}
	}
	if !found {
		t.Fatal("no decision audit entry")
	}
	// An admin who is the owner with live membership may decide too.
	e.members.roles[glovoTenant+"|"+glovoOwnerPRN] = "developer"
	if res := e.decide(adminOwner, e.aar, "deny"); res.code != http.StatusOK {
		t.Fatalf("admin owner = %d %s", res.code, res.raw)
	}

	// Without a wired ledger nobody but an admin on a generic row decides.
	e.h.opts.GlovoApprovals = nil
	if res := e.decide(owner, e.aar, "approve"); res.code != http.StatusForbidden || res.raw != forbidden.raw {
		t.Fatalf("no ledger wired = %d %s", res.code, res.raw)
	}
	// A generic row stays admin-only and unchanged.
	if res := e.decide(owner, generic, "approve"); res.code != http.StatusForbidden {
		t.Fatalf("generic row by a non-admin = %d", res.code)
	}
	if res := e.decide(rootAdmin, generic, "approve"); res.code != http.StatusOK {
		t.Fatalf("generic row by an admin = %d %s", res.code, res.raw)
	}
}

// Read access: the bound owner sees the order's approval, another person does not.
func TestGlovoOwnerSeesTheApproval(t *testing.T) {
	e := newGlovoOwnerEnv(t)
	get := func(u *auth.User) wiResponse { return e.do(u, "GET", "/api/v1/action-approvals/"+e.aar, nil) }
	if res := get(e.human(glovoOwnerPRN, "olga")); res.code != http.StatusOK {
		t.Fatalf("owner read = %d %s", res.code, res.raw)
	}
	if res := get(e.human(glovoOtherPRN, "oleg")); res.code != http.StatusForbidden {
		t.Fatalf("other read = %d %s", res.code, res.raw)
	}
	e.h.opts.GlovoApprovals = nil
	if res := get(e.human(glovoOwnerPRN, "olga")); res.code != http.StatusForbidden {
		t.Fatalf("no ledger wired, owner read = %d", res.code)
	}
}

// setUnexported flips a private flag of a test user. auth has no constructor
// for a Glovo-audience or Glovo-worker caller that is otherwise a valid owner,
// and the bar must hold exactly for that caller, so the test builds one.
func setUnexported(t *testing.T, u *auth.User, field string) *auth.User {
	t.Helper()
	f := reflect.ValueOf(u).Elem().FieldByName(field)
	if !f.IsValid() || f.Kind() != reflect.Bool {
		t.Fatalf("auth.User has no bool field %q", field)
	}
	reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().SetBool(true) //nolint:gosec // test-only
	return u
}

// The facade's own tokens never decide, even when they carry the owner's
// principal and a live developer membership: only the bar keeps them out.
func TestGlovoOwnerDecisionBarsGlovoTokens(t *testing.T) {
	e := newGlovoOwnerEnv(t)
	owner := e.human(glovoOwnerPRN, "olga")
	if res := e.decide(owner, e.aar, "approve"); res.code != http.StatusOK {
		t.Fatalf("control: the owner alone = %d %s", res.code, res.raw)
	}
	forbidden := e.decide(e.human(glovoOtherPRN, "oleg"), e.aar, "approve")
	for name, field := range map[string]string{"audience caller": "glovoAudience", "worker caller": "glovoWorker"} {
		u := setUnexported(t, e.human(glovoOwnerPRN, "olga"), field)
		res := e.decide(u, e.aar, "approve")
		if res.code != http.StatusForbidden || res.raw != forbidden.raw {
			t.Errorf("%s = %d %s, want the uniform 403", name, res.code, res.raw)
		}
	}
	if n := e.dec.count(); n != 1 { // only the control decision
		t.Fatalf("a barred token reached the ledger: %d decisions, want 1", n)
	}
}

// glovoWorkerGate already keeps the worker off this route, so the route-level
// test cannot see the handler's own bar for it. The predicate is held directly.
func TestGlovoOwnerCandidateExcludesGlovoCallers(t *testing.T) {
	e := newGlovoOwnerEnv(t)
	if !isGlovoOwnerCandidate(e.human(glovoOwnerPRN, "olga")) {
		t.Fatal("control: a plain human owner must be a candidate")
	}
	for _, field := range []string{"glovoAudience", "glovoWorker"} {
		if isGlovoOwnerCandidate(setUnexported(t, e.human(glovoOwnerPRN, "olga"), field)) {
			t.Errorf("a caller with %s set must not be a candidate", field)
		}
	}
}
