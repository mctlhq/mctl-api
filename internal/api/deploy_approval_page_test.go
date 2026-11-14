package api

import (
	"context"
	"encoding/json"
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/deployplan"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// mctl-api#1026 slice 2: a live owner of the plan's tenant decides a
// deploy.apply grant on a server-rendered page, after a fresh ZITADEL
// sign-in, bound to the plan they were shown.

const (
	deployDiffMarker = `+  image: web:<b>"1.2.3"</b>&`
	deployRev        = "0123456789abcdef0123456789abcdef01234567"
	deployGitopsSHA  = "89abcdef0123456789abcdef0123456789abcdef"
)

// deployPlansFake is the deploy-plan store.
type deployPlansFake struct {
	mu    sync.Mutex
	plans map[string]*deployplan.Plan
	err   error
}

func (s *deployPlansFake) Insert(context.Context, *deployplan.Plan) (*deployplan.Plan, bool, error) {
	return nil, false, errors.New("unused")
}

func (s *deployPlansFake) Get(_ context.Context, id string) (*deployplan.Plan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	p, ok := s.plans[id]
	if !ok {
		return nil, deployplan.ErrNotFound
	}
	cp := *p
	return &cp, nil
}

func (s *deployPlansFake) edit(id string, f func(*deployplan.Plan)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(s.plans[id])
}

type deployPageEnv struct {
	*basketEnv
	plans *deployPlansFake
	dopts *DeployApprovalPageOptions
}

func newDeployPageEnv(t *testing.T) *deployPageEnv {
	t.Helper()
	b := newBasketEnv(t)
	e := &deployPageEnv{basketEnv: b, plans: &deployPlansFake{plans: map[string]*deployplan.Plan{}}}
	// The plans' tenant is this test's own; the owner owns it, the others are
	// live developers in it, the admin included.
	b.members.roles[b.tenant+"|"+glovoOwnerPRN] = "owner"
	b.members.roles[b.tenant+"|"+glovoOtherPRN] = "developer"
	b.members.roles[b.tenant+"|"+basketAdminPRN] = "developer"
	b.h.opts.DeployPlans = e.plans
	b.idp.clientID, b.idp.clientSecret = "deploy-client", "deploy-secret"
	o := *b.opts
	e.dopts = &DeployApprovalPageOptions{
		ProviderName: o.ProviderName, Issuer: o.Issuer, ClientID: "deploy-client", ClientSecret: "deploy-secret",
		BaseURL: o.BaseURL, Principals: o.Principals, Authz: o.Authz, Flow: o.Flow,
	}
	b.h.deployApproval = newDeployDecider(e.dopts)
	b.page = deployRouter(b.h)
	return e
}

func deployRouter(h *Handlers) http.Handler {
	r := chi.NewRouter()
	r.Post(deployStartPath, h.handleDeployApprovalStart)
	r.Get(deployCallbackPath, h.handleDeployApprovalCallback)
	r.Post(deployConfirmPath, h.handleDeployApprovalConfirm)
	r.Get(deployPagePrefix+"{approval_ref}", h.handleDeployApprovalPage)
	return r
}

// plan stores an applicable preview plan of this test's tenant; edit adjusts
// it before its digest is computed.
func (e *deployPageEnv) plan(key string, edit ...func(*deployplan.Plan)) *deployplan.Plan {
	e.t.Helper()
	raw, _ := json.Marshal(map[string]any{
		"apiVersion": "deploy.mctl.ai/v1alpha1", "kind": "DeployIntent",
		"metadata": map[string]any{"tenant": e.tenant, "service": "web"},
		"spec": map[string]any{
			"environment": "preview",
			"source":      map[string]any{"repository": "acme/web", "revision": deployRev},
			"detection":   map[string]any{"tier": "tier0"},
			"runtime":     map[string]any{"port": 8080, "healthPath": "/healthz"},
			"exposure":    map[string]any{"mode": "public"},
		},
	})
	_, canonical, err := deployplan.ParseIntent(raw)
	if err != nil {
		e.t.Fatalf("ParseIntent: %v", err)
	}
	no := false
	now := time.Now().UTC()
	p := &deployplan.Plan{
		ID: e.tenant + "-plan-" + key, SchemaVersion: deployplan.SchemaVersion,
		Tenant: e.tenant, Service: "web", Environment: deployplan.EnvironmentPreview,
		Intent: raw, IntentCanonical: string(canonical), Revision: deployRev, GitopsBaseSHA: deployGitopsSHA,
		Action: deployplan.ActionUpdate, PreviewID: "abc123", ValuesAfter: "image: web:1.2.3\n",
		Diff: deployDiffMarker, Host: "web-abc123.mctl.ai", IntentChangesValues: &no,
		CreatedBy: "principal:" + glovoOwnerPRN, Surface: "mcp", CreatedAt: now, ExpiresAt: now.Add(30 * time.Minute),
	}
	for _, f := range edit {
		f(p)
	}
	p.Digest = deployplan.Digest(deployplan.DigestInput{
		Tenant: p.Tenant, Service: p.Service, Environment: p.Environment,
		IntentCanonical: p.IntentCanonical, Revision: p.Revision, GitopsBaseSHA: p.GitopsBaseSHA,
		Action: p.Action, PreviewID: p.PreviewID, ValuesAfter: p.ValuesAfter, Host: p.Host,
	})
	e.plans.mu.Lock()
	e.plans.plans[p.ID] = p
	e.plans.mu.Unlock()
	return p
}

// grantFor opens the pending deploy.apply grant for p, asked for by
// requester's principal, as RequestDeployApproval would.
func (e *deployPageEnv) grantFor(p *deployplan.Plan, requester string) string {
	e.t.Helper()
	pol := e.h.approvalPolicies()[workitems.DeployApplyPolicyRuleID]
	a, _, err := e.h.opts.WorkItems.CreateDeployApproval(context.Background(), workitems.ActionApprovalInput{
		ActionIntent: deployApplyIntent(p), RequestedBy: "principal:" + requester, RequestedByPrincipalID: requester,
		ActorKind: "agent", ActorName: "claude-code",
		IdempotencyKey: workitems.DeployIdempotencyKey(p.ID), ExpiresAt: p.ExpiresAt, RiskLevel: "medium",
		IntentSource: "deploy_plan:" + p.ID, SideEffect: pol.SideEffect, PolicyDecision: pol.Decision,
		PolicyReasons: append([]string(nil), pol.Reasons...),
	})
	if err != nil {
		e.t.Fatalf("CreateDeployApproval: %v", err)
	}
	return a.ID
}

func (e *deployPageEnv) pendingGrant(key string) (string, *deployplan.Plan) {
	p := e.plan(key)
	return e.grantFor(p, glovoOwnerPRN), p
}

// signIn opens the link, starts the sign-in and comes back from ZITADEL as
// subject: the callback's answer, the browser's cookie and the decide form.
func (e *deployPageEnv) signIn(ref, subject string) (*httptest.ResponseRecorder, *http.Cookie, url.Values) {
	e.t.Helper()
	page := e.send(http.MethodGet, deployPagePrefix+ref, nil, nil)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `action="`+deployStartPath+`"`) {
		e.t.Fatalf("link page = %d %s", page.Code, page.Body.String())
	}
	if len(page.Result().Cookies()) != 0 || strings.Contains(page.Body.String(), "web-abc123") {
		e.t.Fatal("the link page set state or showed the plan")
	}
	start := e.send(http.MethodPost, deployStartPath, nil, url.Values{"approval_ref": {ref}})
	if start.Code != http.StatusSeeOther {
		e.t.Fatalf("start = %d %s", start.Code, start.Body.String())
	}
	var ck *http.Cookie
	for _, c := range start.Result().Cookies() {
		if c.Name == deployPageCookie {
			ck = c
		}
	}
	if ck == nil || !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteLaxMode || ck.Path != "/" || ck.Domain != "" {
		e.t.Fatalf("cookie = %+v", ck)
	}
	u, _ := url.Parse(start.Header().Get("Location"))
	q := u.Query()
	if !strings.HasPrefix(u.String(), e.idp.srv.URL+"/authorize") || q.Get("client_id") != "deploy-client" ||
		q.Get("code_challenge_method") != "S256" || q.Get("prompt") != "login" || q.Get("max_age") != "0" ||
		q.Get("nonce") == "" || q.Get("redirect_uri") != "https://api.example"+deployCallbackPath {
		e.t.Fatalf("authorize URL %s", u)
	}
	e.idp.mu.Lock()
	e.idp.challenge, e.idp.nonce = q.Get("code_challenge"), q.Get("nonce")
	e.idp.extra = map[string]any{"sub": subject}
	e.idp.mu.Unlock()
	rec := e.send(http.MethodGet, deployCallbackPath+"?code=z-code&state="+url.QueryEscape(q.Get("state")), ck, nil)
	form := url.Values{}
	for _, m := range basketField.FindAllStringSubmatch(rec.Body.String(), -1) {
		form.Set(m[1], html.UnescapeString(m[2]))
	}
	return rec, ck, form
}

func (e *deployPageEnv) confirm(ck *http.Cookie, form url.Values, decision string) *httptest.ResponseRecorder {
	return e.send(http.MethodPost, deployConfirmPath, ck, url.Values{
		"challenge": {form.Get("challenge")}, "csrf": {form.Get("csrf")}, "decision": {decision},
	})
}

func (e *deployPageEnv) approval(id string) *workitems.ActionApprovalRequest {
	e.t.Helper()
	a, err := e.h.opts.WorkItems.ActionApproval(context.Background(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	return a
}

// The owner approves the plan their own agent asked for: the presence of a
// fresh sign-in, not a different principal, is what the page checks.
func TestDeployApprovalPage_OwnerApprovesWhatWasShown(t *testing.T) {
	e := newDeployPageEnv(t)
	id, p := e.pendingGrant("approve")
	rec, ck, form := e.signIn(id, "z-owner")
	body := rec.Body.String()
	if rec.Code != http.StatusOK || form.Get("csrf") == "" || form.Get("challenge") == "" {
		t.Fatalf("callback = %d %s", rec.Code, body)
	}
	cd := e.h.decisionContext(e.approval(id)).ContextDigest
	for _, want := range []string{"Team: " + e.tenant + ", service: web, environment: preview", "Source revision: " + deployRev,
		"https://web-abc123.mctl.ai", p.ID, p.Digest, deployGitopsSHA, id, cd, "(agent claude-code)",
		deployDiffMarker, "Approve this deploy"} {
		if !strings.Contains(html.UnescapeString(body), want) {
			t.Errorf("the page does not show %q", want)
		}
	}
	if strings.Contains(body, "<b>") {
		t.Fatal("the diff reached the page unescaped")
	}
	if e.approval(id).State != workitems.ApprovalPending {
		t.Fatal("showing the plan decided something")
	}

	res := e.confirm(ck, form, "approve")
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "Deploy approved") || !strings.Contains(res.Body.String(), "can now apply this plan once") {
		t.Fatalf("confirm = %d %s", res.Code, res.Body.String())
	}
	a := e.approval(id)
	if a.State != workitems.ApprovalApproved || a.DecidedByPrincipalID != glovoOwnerPRN ||
		a.AuthorityBasis != workitems.DeployAuthorityBasis || a.DecidedContextDigest != cd {
		t.Fatalf("decided row %+v", a)
	}
	if e.auditOps("action_approval.decision", id) != 1 {
		t.Fatal("no decision audit entry")
	}
	// The grant is spendable exactly as the apply route spends it.
	if _, err := e.h.opts.WorkItems.ConsumeDeployApproval(context.Background(), id, workitems.IntentHash(deployApplyIntent(p))); err != nil {
		t.Fatalf("the approved grant does not spend: %v", err)
	}

	// A double click or a replayed form finds nothing.
	if again := e.confirm(ck, form, "reject"); again.Code != http.StatusBadRequest || e.approval(id).State != workitems.ApprovalConsumed {
		t.Fatalf("replay = %d, state %s", again.Code, e.approval(id).State)
	}
	// Signing in again shows the final state and offers nothing.
	after, _, f2 := e.signIn(id, "z-owner")
	if after.Code != http.StatusOK || f2.Get("csrf") != "" || !strings.Contains(after.Body.String(), "nothing to decide") {
		t.Fatalf("after = %d %s", after.Code, after.Body.String())
	}
}

func TestDeployApprovalPage_OwnerRejects(t *testing.T) {
	e := newDeployPageEnv(t)
	id, _ := e.pendingGrant("reject")
	_, ck, form := e.signIn(id, "z-owner")
	res := e.confirm(ck, form, "reject")
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "Deploy rejected") ||
		!strings.Contains(res.Body.String(), "cannot apply this plan") || strings.Contains(res.Body.String(), "can now apply") {
		t.Fatalf("confirm = %d %s", res.Code, res.Body.String())
	}
	if a := e.approval(id); a.State != workitems.ApprovalDenied || a.DecidedByPrincipalID != glovoOwnerPRN {
		t.Fatalf("row %+v", a)
	}
}

// Anyone but a live owner of the plan's tenant meets "no such approval" and
// is shown nothing of the plan: a developer, an admin, a member elsewhere,
// an unknown sign-in. So does an owner given another kind or no approval.
func TestDeployApprovalPage_OnlyAnOwnerSeesIt(t *testing.T) {
	e := newDeployPageEnv(t)
	id, p := e.pendingGrant("others")
	for _, subject := range []string{"z-other", "z-admin", "z-foreign", "z-nobody"} {
		rec, _, form := e.signIn(id, subject)
		body := rec.Body.String()
		if rec.Code != http.StatusNotFound || !strings.Contains(body, html.EscapeString(deployNotFoundMessage)) {
			t.Errorf("%s: %d %s", subject, rec.Code, body)
		}
		if form.Get("csrf") != "" || strings.Contains(body, p.ID) || strings.Contains(body, "web-abc123") || strings.Contains(body, "image: web") {
			t.Errorf("%s was shown the plan or offered a decision", subject)
		}
	}
	// A generic approval pointed at a real plan of the tenant is still not
	// a deploy grant.
	generic := e.requestApproval("generic")["id"].(string)
	if _, err := e.pool.Exec(context.Background(), `UPDATE action_approval_requests SET execution_id=$2, target=$3 WHERE id=$1`,
		generic, p.ID, p.Tenant+"/"+p.Service); err != nil {
		t.Fatal(err)
	}
	if rec, _, _ := e.signIn(generic, "z-owner"); rec.Code != http.StatusNotFound {
		t.Errorf("a generic approval on the deploy page: %d", rec.Code)
	}
	if rec, _, _ := e.signIn("aar_"+strings.Repeat("0", 32), "z-owner"); rec.Code != http.StatusNotFound {
		t.Errorf("an unknown approval: %d", rec.Code)
	}
	// A plan that names another target than its grant reads as absent too.
	e.plans.edit(p.ID, func(pl *deployplan.Plan) { pl.Service = "api" })
	if rec, _, _ := e.signIn(id, "z-owner"); rec.Code != http.StatusNotFound {
		t.Errorf("a plan of another service: %d", rec.Code)
	}
	if e.approval(id).State != workitems.ApprovalPending {
		t.Fatal("a refused sign-in decided something")
	}
}

// Ownership, the plan and the approval are read again at confirm: a change
// since the sign-in decides now, and nothing is decided.
func TestDeployApprovalPage_ConfirmReadsAgain(t *testing.T) {
	e := newDeployPageEnv(t)

	id, _ := e.pendingGrant("demoted")
	_, ck, form := e.signIn(id, "z-owner")
	e.members.roles[e.tenant+"|"+glovoOwnerPRN] = "developer"
	if res := e.confirm(ck, form, "approve"); res.Code != http.StatusNotFound {
		t.Errorf("demoted owner confirm = %d %s", res.Code, res.Body.String())
	}
	e.members.roles[e.tenant+"|"+glovoOwnerPRN] = "owner"

	id2, _ := e.pendingGrant("unreadable")
	_, ck, form = e.signIn(id2, "z-owner")
	e.members.err = errors.New("checkout unavailable")
	if res := e.confirm(ck, form, "approve"); res.Code != http.StatusServiceUnavailable {
		t.Errorf("unreadable membership confirm = %d %s", res.Code, res.Body.String())
	}
	e.members.err = nil

	id3, p3 := e.pendingGrant("replanned")
	_, ck, form = e.signIn(id3, "z-owner")
	e.plans.edit(p3.ID, func(pl *deployplan.Plan) { pl.Digest = "sha256:" + strings.Repeat("f", 64) })
	if res := e.confirm(ck, form, "approve"); res.Code != http.StatusConflict {
		t.Errorf("plan changed after view = %d %s", res.Code, res.Body.String())
	}

	// A principal refused after the sign-in decides nothing.
	id5, _ := e.pendingGrant("disabled")
	_, ck, form = e.signIn(id5, "z-owner")
	e.prins.mu.Lock()
	e.prins.err = auth.ErrPrincipalDisabled
	e.prins.mu.Unlock()
	res := e.confirm(ck, form, "approve")
	e.prins.mu.Lock()
	e.prins.err = nil
	e.prins.mu.Unlock()
	if res.Code != http.StatusNotFound {
		t.Errorf("disabled principal confirm = %d %s", res.Code, res.Body.String())
	}

	id4, _ := e.pendingGrant("recontexted")
	_, ck, form = e.signIn(id4, "z-owner")
	if _, err := e.pool.Exec(context.Background(), `UPDATE action_approval_requests SET policy_reasons=$2 WHERE id=$1`,
		id4, []string{"something else"}); err != nil {
		t.Fatal(err)
	}
	if res := e.confirm(ck, form, "approve"); res.Code != http.StatusConflict ||
		!strings.Contains(res.Body.String(), "changed after you were shown it") {
		t.Errorf("context changed after view = %d %s", res.Code, res.Body.String())
	}

	for _, ref := range []string{id, id2, id3, id4, id5} {
		if s := e.approval(ref).State; s != workitems.ApprovalPending {
			t.Errorf("%s: state %s after a refused confirm", ref, s)
		}
	}
}

// A plan that is no longer what its grant is bound to is not shown for a
// decision at all: approving it would grant a plan nobody asked for.
func TestDeployApprovalPage_PlanMustMatchItsGrant(t *testing.T) {
	e := newDeployPageEnv(t)
	id, p := e.pendingGrant("rebound")
	// The same plan id stored again with other values: its own digest is
	// sound, it just is not the plan the grant was asked for.
	if again := e.plan("rebound", func(pl *deployplan.Plan) { pl.ValuesAfter = "image: web:6.6.6\n" }); again.Digest == p.Digest {
		t.Fatal("the replanned plan kept its digest")
	}
	rec, _, form := e.signIn(id, "z-owner")
	if rec.Code != http.StatusConflict || form.Get("csrf") != "" {
		t.Fatalf("callback = %d %s", rec.Code, rec.Body.String())
	}
}

// A plan the apply would refuse is shown, but not offered for approval.
func TestDeployApprovalPage_UnapplicablePlanIsNotOffered(t *testing.T) {
	e := newDeployPageEnv(t)
	for name, edit := range map[string]func(*deployplan.Plan){
		"changes values": func(p *deployplan.Plan) { yes := true; p.IntentChangesValues = &yes },
		"legacy plan":    func(p *deployplan.Plan) { p.IntentChangesValues = nil },
	} {
		p := e.plan(strings.ReplaceAll(name, " ", "-"), edit)
		id := e.grantFor(p, glovoOwnerPRN)
		rec, _, form := e.signIn(id, "z-owner")
		if rec.Code != http.StatusConflict || form.Get("csrf") != "" || !strings.Contains(rec.Body.String(), "cannot be applied") {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	// A plan that expires between the sign-in and the click is refused at
	// confirm.
	id, p := e.pendingGrant("expiring")
	_, ck, form := e.signIn(id, "z-owner")
	e.plans.edit(p.ID, func(pl *deployplan.Plan) { pl.ExpiresAt = time.Now().Add(-time.Minute) })
	if res := e.confirm(ck, form, "approve"); res.Code != http.StatusConflict || e.approval(id).State != workitems.ApprovalPending {
		t.Errorf("expired plan confirm = %d %s", res.Code, res.Body.String())
	}
}

// The confirm is bound to the browser and to its one-time CSRF token.
func TestDeployApprovalPage_ConfirmIsBoundToTheBrowser(t *testing.T) {
	e := newDeployPageEnv(t)
	id, _ := e.pendingGrant("csrf")
	_, ck, form := e.signIn(id, "z-owner")
	other := &http.Cookie{Name: deployPageCookie, Value: "another-browser"}
	bad := url.Values{"challenge": {form.Get("challenge")}, "csrf": {"forged"}}
	for name, res := range map[string]*httptest.ResponseRecorder{
		"no cookie":     e.confirm(nil, form, "approve"),
		"other browser": e.confirm(other, form, "approve"),
		"forged csrf":   e.confirm(ck, bad, "approve"),
		"no decision":   e.confirm(ck, form, "maybe"),
	} {
		if res.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", name, res.Code)
		}
	}
	if e.approval(id).State != workitems.ApprovalPending {
		t.Fatal("a refused confirm decided something")
	}
	// None of them consumed the real form.
	if res := e.confirm(ck, form, "approve"); res.Code != http.StatusOK || e.approval(id).State != workitems.ApprovalApproved {
		t.Fatalf("the real confirm = %d %s", res.Code, res.Body.String())
	}
}

// Dark by default: without complete options, or without the stores it reads,
// no route is mounted and the request answer says the grant cannot be
// decided yet.
func TestDeployApprovalPage_DarkByDefault(t *testing.T) {
	ref := deployPagePrefix + "aar_" + strings.Repeat("0", 32)
	complete := &DeployApprovalPageOptions{ProviderName: "zitadel", Issuer: "https://auth.example", ClientID: "id",
		ClientSecret: "s", BaseURL: "https://api.example", Principals: &fakeSignInPrincipals{}, Authz: &auth.PrincipalAuthz{},
		Flow: basketFlowStore(t, testDBOrSkip(t))}
	for name, opts := range map[string]Options{
		"no options":    {},
		"no client":     {DeployApproval: &DeployApprovalPageOptions{Issuer: "https://auth.example"}, DeployPlans: &deployPlansFake{}},
		"no stores":     {DeployApproval: complete},
		"no plan store": {DeployApproval: complete, WorkItems: &workitems.Store{}},
		"no work items": {DeployApproval: complete, DeployPlans: &deployPlansFake{}},
	} {
		rec := httptest.NewRecorder()
		NewRouter(opts).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, ref, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	NewRouter(Options{DeployApproval: complete, WorkItems: &workitems.Store{}, DeployPlans: &deployPlansFake{}}).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, ref, nil))
	if rec.Code != http.StatusOK {
		t.Errorf("complete: %d", rec.Code)
	}
}

func testDBOrSkip(t *testing.T) string {
	t.Helper()
	e := newWorkItemsEnv(t)
	return e.connStr
}

// Only a fresh sign-in that belongs to this attempt opens the decision: an
// old session's ID token, or one minted for another nonce, does not.
func TestDeployApprovalPage_RequiresAFreshSignIn(t *testing.T) {
	e := newDeployPageEnv(t)
	id, p := e.pendingGrant("fresh")
	for name, edit := range map[string]func(*fakeIdP){
		"stale":       func(f *fakeIdP) { f.authTime = time.Now().Add(-time.Hour) },
		"other nonce": func(f *fakeIdP) { f.nonceOverride = "someone-elses" },
	} {
		e.idp.mu.Lock()
		at, no := e.idp.authTime, e.idp.nonceOverride
		edit(e.idp)
		e.idp.mu.Unlock()
		rec, _, form := e.signIn(id, "z-owner")
		e.idp.mu.Lock()
		e.idp.authTime, e.idp.nonceOverride = at, no
		e.idp.mu.Unlock()
		if rec.Code != http.StatusBadRequest || form.Get("csrf") != "" || strings.Contains(rec.Body.String(), p.ID) {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	if e.approval(id).State != workitems.ApprovalPending {
		t.Fatal("a refused sign-in decided something")
	}
}
