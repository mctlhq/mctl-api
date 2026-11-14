package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Deploy grants (mctl-api#1026): a preview apply is authorized only by a
// deploy.apply grant for exactly the applied plan, decided by a live owner of
// the tenant, spent once. These tests run against the real approval ledger.

const (
	grantDevPRN   = "prn_grantdev"
	grantOwnerPRN = "prn_grantowner"
	grantRootPRN  = "prn_grantroot"
)

// faithfulValues already hold what the reproducible intent below sets, so
// the plan's values_after equals what preview-deploy renders.
const faithfulValues = planBaseValues + `
service:
  port: 8080
probes:
  liveness:
    path: /healthz
  readiness:
    path: /healthz
replicaCount: 1
`

// faithfulIntent changes no values: no env, no secrets, the runtime the
// values already have.
func faithfulIntent() map[string]any {
	return planIntent(func(in map[string]any) {
		delete(spec(in), "env")
		delete(spec(in), "secretRefs")
	})
}

type grantPrincipals struct{ disabled map[string]bool }

func (p *grantPrincipals) ResolvePrincipal(_ context.Context, id auth.Identity) (string, error) {
	return "", errors.New("unused")
}

func (p *grantPrincipals) CheckPrincipal(_ context.Context, prn string) error {
	if p.disabled[prn] {
		return auth.ErrPrincipalDisabled
	}
	return nil
}

func (p *grantPrincipals) CheckHumanPrincipal(ctx context.Context, prn string) error {
	return p.CheckPrincipal(ctx, prn)
}

// grantMembers is the live principal membership: tenant|prn -> role.
type grantMembers struct {
	roles map[string]string
	// errFor fails the read for one principal only.
	errFor string
}

func (m *grantMembers) TryNamespacesForPrincipal(string) (gitops.PrincipalMembership, bool, error) {
	return gitops.PrincipalMembership{}, false, errors.New("unused")
}

func (m *grantMembers) MemberRolesForPrincipal(tenant, prn string) ([][]string, error) {
	if prn == m.errFor {
		return nil, errors.New("gitops reader unavailable")
	}
	if r, ok := m.roles[tenant+"|"+prn]; ok {
		return [][]string{{r}}, nil
	}
	return nil, nil
}

func (m *grantMembers) PrincipalTenants(prn string) ([]string, []string, error) {
	var out []string
	for k := range m.roles {
		if t, p, _ := strings.Cut(k, "|"); p == prn {
			out = append(out, t)
		}
	}
	return out, nil, nil
}

type fixedPRN string

func (p fixedPRN) ResolvePrincipal(context.Context, auth.Identity) (string, error) {
	return string(p), nil
}

type grantFixture struct {
	*planFixture
	wi      *workitems.Store
	members *grantMembers
	prins   *grantPrincipals
	dev     *auth.User
	owner   *auth.User
	root    *auth.User
	plans   []string
}

func newGrantFixture(t *testing.T, values string) *grantFixture {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL is unset in CI: the deploy grant tests must run, not skip")
		}
		t.Skip("TEST_DATABASE_URL not set")
	}
	t.Setenv("AUTH_REQUIRED", "false")
	ctx := context.Background()
	wi, err := workitems.NewStore(ctx, dsn)
	if err != nil {
		t.Fatalf("workitems.NewStore: %v", err)
	}
	f := &grantFixture{
		planFixture: &planFixture{
			log: audit.NewLogger(), content: &fakeContent{}, store: newFakePlanStore(), exec: &fakeExecutor{},
			gitops: &fakePlanGitops{data: values, sourceRepo: "acme/web", exists: true, rev: planBaseSHA},
			now:    time.Now().UTC(),
		},
		wi:      wi,
		members: &grantMembers{roles: map[string]string{"acme|" + grantDevPRN: "developer", "acme|" + grantOwnerPRN: "owner"}},
		prins:   &grantPrincipals{disabled: map[string]bool{}},
	}
	t.Cleanup(func() {
		if pool, err := pgxpool.New(ctx, dsn); err == nil {
			_, _ = pool.Exec(ctx, `DELETE FROM action_approval_requests WHERE execution_id = ANY($1)`, f.plans)
			pool.Close()
		}
		wi.Close()
	})
	// acme/web is connected to acme in the portal.
	portal := httptest.NewServer(http.HandlerFunc(bindingAnswer(true)))
	t.Cleanup(portal.Close)
	f.router = mctlapi.NewRouter(mctlapi.Options{
		Registry: operations.NewRegistry(), GitReader: &fakeGitReader{tenants: []gitops.Tenant{{Name: "acme"}}}, ArgoCD: &fakeArgoCD{}, AuditLog: f.log, Executor: f.exec,
		BackstageInternalURL: portal.URL, BackstageGithubAppConnectToken: "tok",
		SourceRepoBindings:  repoBindings{},
		DeployContentReader: f.content, DeployPlans: f.store, DeployGitops: f.gitops,
		PlatformDomain: "mctl.ai", Clock: func() time.Time { return f.now },
		WorkItems: wi, TenantAuthzMode: mctlapi.TenantAuthzPrincipal, PrincipalMembership: f.members,
		Principals: f.prins, AdminPrincipals: map[string]bool{grantRootPRN: true},
	})
	f.dev = f.human(t, "alice", grantDevPRN)
	f.owner = f.human(t, "olga", grantOwnerPRN)
	f.root = f.human(t, "root", grantRootPRN)
	return f
}

func (f *grantFixture) human(t *testing.T, login, prn string) *auth.User {
	t.Helper()
	u := auth.NewGitHubUser(login, nil)
	if err := auth.AttachPrincipal(context.Background(), fixedPRN(prn), u); err != nil {
		t.Fatal(err)
	}
	if err := (&auth.PrincipalAuthz{Members: f.members, Admins: map[string]bool{grantRootPRN: true}}).Apply(u); err != nil {
		t.Fatal(err)
	}
	return u
}

// newPlan stores a plan for intent and returns its id.
func (f *grantFixture) newPlan(t *testing.T, intent map[string]any) string {
	t.Helper()
	w := f.plan(t, f.dev, intent, "")
	assertStatus(t, w, http.StatusCreated)
	id, _ := decodeJSON(t, w)["id"].(string)
	f.plans = append(f.plans, id)
	return id
}

// request asks for the plan's grant and returns the response body.
func (f *grantFixture) request(t *testing.T, user *auth.User, planID string, want int) map[string]any {
	t.Helper()
	w := postAs(t, f.router, "/api/v1/deploy/plans/"+planID+"/approval", map[string]any{}, user)
	assertStatus(t, w, want)
	return decodeJSON(t, w)
}

// grant requests and owner-approves the plan's grant, as the decide page
// will, and returns its id.
func (f *grantFixture) grant(t *testing.T, planID string) string {
	t.Helper()
	body := f.request(t, f.dev, planID, http.StatusCreated)
	id := body["approval"].(map[string]any)["id"].(string)
	digest := body["decision_context"].(map[string]any)["context_digest"].(string)
	if _, err := f.wi.DecideDeployApproval(context.Background(), workitems.ActionDecisionInput{
		ID: id, DecidedBy: "github:olga", DecidedByPrincipalID: grantOwnerPRN,
		Decision: workitems.DecisionApprove, ContextDigest: digest, FreshFor: time.Hour,
	}); err != nil {
		t.Fatalf("DecideDeployApproval: %v", err)
	}
	return id
}

func (f *grantFixture) apply(t *testing.T, user *auth.User, body any) *httptest.ResponseRecorder {
	t.Helper()
	return postAsRaw(t, f.router, "/api/v1/deploy/apply", body, user)
}

func (f *grantFixture) state(t *testing.T, id string) string {
	t.Helper()
	a, err := f.wi.ActionApproval(context.Background(), id)
	if err != nil {
		t.Fatalf("ActionApproval(%s): %v", id, err)
	}
	return a.State
}

func errCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body) // Bytes does not drain the body
	return body.Code
}

// The whole path: request, owner decision, one apply with the plan's own
// preview id and gitops commit, and no second apply on the same grant.
func TestDeployApply_GrantedOnceExactlyAsPlanned(t *testing.T) {
	f := newGrantFixture(t, faithfulValues)
	planID := f.newPlan(t, faithfulIntent())
	plan, err := f.store.Get(context.Background(), planID)
	if err != nil {
		t.Fatal(err)
	}

	first := f.request(t, f.dev, planID, http.StatusCreated)
	again := f.request(t, f.dev, planID, http.StatusOK)
	id := first["approval"].(map[string]any)["id"].(string)
	if again["approval"].(map[string]any)["id"] != id {
		t.Fatalf("a repeated request made a second grant: %v", again["approval"])
	}
	if f.state(t, id) != workitems.ApprovalPending {
		t.Fatalf("a requested grant is %s, want pending", f.state(t, id))
	}

	// Undecided: nothing is spent or submitted.
	w := f.apply(t, f.dev, map[string]any{"plan_id": planID, "approval_id": id})
	if w.Code == http.StatusAccepted || len(f.exec.submitted) != 0 {
		t.Fatalf("a pending grant applied: %d %s", w.Code, w.Body.String())
	}

	digest := first["decision_context"].(map[string]any)["context_digest"].(string)
	if _, err := f.wi.DecideDeployApproval(context.Background(), workitems.ActionDecisionInput{
		ID: id, DecidedBy: "github:olga", DecidedByPrincipalID: grantOwnerPRN,
		Decision: workitems.DecisionApprove, ContextDigest: digest, FreshFor: time.Hour,
	}); err != nil {
		t.Fatalf("DecideDeployApproval: %v", err)
	}

	w = f.apply(t, f.dev, map[string]any{"plan_id": planID, "approval_id": id})
	assertStatus(t, w, http.StatusAccepted)
	if len(f.exec.submitted) != 1 || f.exec.submitted[0] != "preview-deploy" {
		t.Fatalf("submitted = %v", f.exec.submitted)
	}
	got := f.exec.submittedParams[0]
	for k, want := range map[string]string{
		"team_name": "acme", "component_name": "web", "preview_id": plan.PreviewID,
		"gitops_ref": planBaseSHA, "git_ref": deploySHA, "image_tag": "rev-" + deploySHA,
	} {
		if got[k] != want {
			t.Errorf("preview-deploy %s = %q, want %q", k, got[k], want)
		}
	}
	if res := decodeJSON(t, w); res["preview_url"] != "https://"+plan.Host {
		t.Errorf("preview_url = %v, want https://%s", res["preview_url"], plan.Host)
	}
	if f.state(t, id) != workitems.ApprovalConsumed {
		t.Fatalf("a spent grant is %s, want consumed", f.state(t, id))
	}

	// Replay: the same grant does not apply twice.
	w = f.apply(t, f.dev, map[string]any{"plan_id": planID, "approval_id": id})
	if w.Code != http.StatusConflict || len(f.exec.submitted) != 1 {
		t.Fatalf("replayed apply = %d %s, submitted %v", w.Code, w.Body.String(), f.exec.submitted)
	}
}

// A grant binds one plan: it does not apply another plan of the same
// service, and the refusal leaves it spendable on its own plan.
func TestDeployApply_GrantDoesNotTransferBetweenPlans(t *testing.T) {
	f := newGrantFixture(t, faithfulValues)
	planA := f.newPlan(t, faithfulIntent())
	planB := f.newPlan(t, faithfulIntent())
	grantA := f.grant(t, planA)

	w := f.apply(t, f.dev, map[string]any{"plan_id": planB, "approval_id": grantA})
	if w.Code != http.StatusConflict || errCode(t, w) != "approval_intent_mismatch" {
		t.Fatalf("plan B on plan A's grant = %d %s", w.Code, w.Body.String())
	}
	if len(f.exec.submitted) != 0 || f.state(t, grantA) != workitems.ApprovalApproved {
		t.Fatalf("a refused apply spent or submitted: %v %s", f.exec.submitted, f.state(t, grantA))
	}
	assertStatus(t, f.apply(t, f.dev, map[string]any{"plan_id": planA, "approval_id": grantA}), http.StatusAccepted)
}

// confirm authorizes nothing: without a grant there is no apply, and the
// body takes no other field.
func TestDeployApply_NoGrantNoApply(t *testing.T) {
	f := newGrantFixture(t, faithfulValues)
	planID := f.newPlan(t, faithfulIntent())
	for name, tc := range map[string]struct {
		body   any
		status int
		code   string
	}{
		"no approval":        {map[string]any{"plan_id": planID}, http.StatusForbidden, "deploy_apply_grant_required"},
		"confirm":            {map[string]any{"plan_id": planID, "confirm": "yes"}, http.StatusBadRequest, "deploy_apply_invalid_input"},
		"confirm with grant": {map[string]any{"plan_id": planID, "approval_id": "aar_x", "confirm": "yes"}, http.StatusBadRequest, "deploy_apply_invalid_input"},
		"no plan":            {map[string]any{"approval_id": "aar_x"}, http.StatusBadRequest, "deploy_apply_invalid_input"},
	} {
		t.Run(name, func(t *testing.T) {
			w := f.apply(t, f.dev, tc.body)
			if w.Code != tc.status || errCode(t, w) != tc.code {
				t.Fatalf("= %d %s, want %d %s", w.Code, w.Body.String(), tc.status, tc.code)
			}
		})
	}
	if len(f.exec.submitted) != 0 {
		t.Fatalf("submitted without a grant: %v", f.exec.submitted)
	}
}

// No bearer route decides or spends a deploy grant: the generic decision
// and consume routes refuse it for the owner and for an admin alike, and it
// stays pending.
func TestDeployApply_GenericRoutesCannotDecideOrSpend(t *testing.T) {
	f := newGrantFixture(t, faithfulValues)
	planID := f.newPlan(t, faithfulIntent())
	body := f.request(t, f.dev, planID, http.StatusCreated)
	id := body["approval"].(map[string]any)["id"].(string)
	digest := body["decision_context"].(map[string]any)["context_digest"].(string)
	for _, u := range []*auth.User{f.owner, f.root, f.dev} {
		w := postAsRaw(t, f.router, "/api/v1/action-approvals/"+id+"/decision",
			map[string]any{"decision": "approve", "context_digest": digest}, u)
		if w.Code == http.StatusOK {
			t.Fatalf("%s decided a deploy grant on the generic route: %s", u.ID, w.Body.String())
		}
	}
	if f.state(t, id) != workitems.ApprovalPending {
		t.Fatalf("state = %s, want pending", f.state(t, id))
	}

	// Approved through its own path, it is still not spendable generically.
	id = f.grant(t, f.newPlan(t, faithfulIntent()))
	a, err := f.wi.ActionApproval(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []*auth.User{f.root, auth.NewServiceUser()} {
		w := postAsRaw(t, f.router, "/api/v1/action-approvals/"+id+"/consume",
			map[string]any{"intent_hash": a.IntentHash}, u)
		if w.Code == http.StatusOK {
			t.Fatalf("%s spent a deploy grant on the generic route: %s", u.ID, w.Body.String())
		}
	}
	// Nor through the store's generic spend, whatever route calls it.
	if _, err := f.wi.ConsumeActionApproval(context.Background(), id, a.IntentHash); !errors.Is(err, workitems.ErrApprovalKindNotSpendable) {
		t.Fatalf("generic ConsumeActionApproval = %v, want ErrApprovalKindNotSpendable", err)
	}
	if f.state(t, id) != workitems.ApprovalApproved {
		t.Fatalf("state = %s, want approved", f.state(t, id))
	}
}

// Only a tenant-owner decision authorizes an apply. A deploy row approved on
// any other basis (here a live platform admin, which revalidation alone
// would accept) is refused and left approved.
func TestDeployApply_OnlyOwnerBasisAuthorizes(t *testing.T) {
	f := newGrantFixture(t, faithfulValues)
	planID := f.newPlan(t, faithfulIntent())
	id := f.grant(t, planID)
	pool, err := pgxpool.New(context.Background(), os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(context.Background(),
		`UPDATE action_approval_requests SET authority_basis='platform_admin', decided_by_principal_id=$2 WHERE id=$1`,
		id, grantRootPRN); err != nil {
		t.Fatal(err)
	}
	w := f.apply(t, f.dev, map[string]any{"plan_id": planID, "approval_id": id})
	if w.Code != http.StatusConflict || errCode(t, w) != "approval_authority_revoked" {
		t.Fatalf("admin-basis grant = %d %s", w.Code, w.Body.String())
	}
	if len(f.exec.submitted) != 0 || f.state(t, id) != workitems.ApprovalApproved {
		t.Fatalf("submitted %v, state %s", f.exec.submitted, f.state(t, id))
	}
}

// Ownership is re-read at spend: a decider who is no longer an owner, or
// whose membership cannot be read, or who is disabled, does not authorize an
// apply, and the grant is left approved.
func TestDeployApply_DeciderRevalidatedAtSpend(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(f *grantFixture)
		status int
		code   string
	}{
		"demoted":    {func(f *grantFixture) { f.members.roles["acme|"+grantOwnerPRN] = "developer" }, http.StatusConflict, "approval_authority_revoked"},
		"removed":    {func(f *grantFixture) { delete(f.members.roles, "acme|"+grantOwnerPRN) }, http.StatusConflict, "approval_authority_revoked"},
		"disabled":   {func(f *grantFixture) { f.prins.disabled[grantOwnerPRN] = true }, http.StatusConflict, "approval_decider_disabled"},
		"unreadable": {func(f *grantFixture) { f.members.errFor = grantOwnerPRN }, http.StatusServiceUnavailable, "approval_authority_unavailable"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newGrantFixture(t, faithfulValues)
			planID := f.newPlan(t, faithfulIntent())
			id := f.grant(t, planID)
			tc.mutate(f)
			w := f.apply(t, f.dev, map[string]any{"plan_id": planID, "approval_id": id})
			if w.Code != tc.status || errCode(t, w) != tc.code {
				t.Fatalf("= %d %s, want %d %s", w.Code, w.Body.String(), tc.status, tc.code)
			}
			if len(f.exec.submitted) != 0 || f.state(t, id) != workitems.ApprovalApproved {
				t.Fatalf("submitted %v, state %s", f.exec.submitted, f.state(t, id))
			}
		})
	}
}

// A plan preview-deploy cannot reproduce is refused before a grant is asked
// for: the intent's env would be dropped by the build.
func TestDeployApply_UnreproduciblePlanIsRefused(t *testing.T) {
	f := newGrantFixture(t, faithfulValues)
	planID := f.newPlan(t, planIntent(nil))
	body := f.request(t, f.dev, planID, http.StatusUnprocessableEntity)
	if body["code"] != "deploy_apply_not_reproducible" {
		t.Fatalf("request = %v", body)
	}
}

// preview_id and gitops_ref come only from an approved plan.
func TestPreviewDeploy_ServerSetParamsRefusedInBody(t *testing.T) {
	f := newGrantFixture(t, faithfulValues)
	for _, p := range []string{"preview_id", "gitops_ref"} {
		w := postAs(t, f.router, "/api/v1/operations/preview-deploy/execute", map[string]string{
			"team_name": "acme", "component_name": "web", "image_tag": "1.0.0", p: "ab12cd",
		}, f.owner)
		if w.Code != http.StatusBadRequest || errCode(t, w) != "actor_not_accepted" {
			t.Fatalf("%s in body = %d %s", p, w.Code, w.Body.String())
		}
	}
	if len(f.exec.submitted) != 0 {
		t.Fatalf("submitted = %v", f.exec.submitted)
	}
}
