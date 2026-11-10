package api

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// mctl-api#1006: the owner of a synthetic basket approves or rejects its
// frozen revision on a server-rendered page, after a fresh ZITADEL sign-in,
// through the existing decision handler.

const (
	basketAdminPRN   = "prn_CCCCCCCCCCCCCCCCCCCCCCCCC3"
	basketForeignPRN = "prn_DDDDDDDDDDDDDDDDDDDDDDDDD4"
	basketForeignTnt = "globex"
	basketFP         = "sha256:diff" // approvalBody's artifact_hash
	hostileName      = `<script>alert(1)</script><img src=x onerror=alert(2)>"'&`
)

// basketLedger is the Glovo approvals ledger for basket rows: a binding per
// aar_, and a decide that really moves the row, as DecideGlovoApprovalTx
// would, so replays meet a decided row.
type basketLedger struct {
	mu       sync.Mutex
	bindings map[string]*workitems.GlovoBinding
	pool     *pgxpool.Pool
	store    *workitems.Store
	decided  []workitems.ActionDecisionInput
}

func (l *basketLedger) Ready(context.Context) error { return nil }

func (l *basketLedger) ForDecision(_ context.Context, id string) (*workitems.ActionApprovalRequest, *workitems.GlovoBinding, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.bindings[id]
	if !ok {
		return nil, nil, workitems.ErrApprovalNotFound
	}
	return &workitems.ActionApprovalRequest{ID: id}, b, nil
}

func (l *basketLedger) Decide(ctx context.Context, in workitems.ActionDecisionInput) (*workitems.ActionApprovalRequest, error) {
	l.mu.Lock()
	l.decided = append(l.decided, in)
	l.mu.Unlock()
	to := workitems.ApprovalDenied
	if in.Decision == workitems.DecisionApprove {
		to = workitems.ApprovalApproved
	}
	tag, err := l.pool.Exec(ctx, `UPDATE action_approval_requests
		SET state=$2, decided_by=$3, decided_at=now(), reason=$4, decided_by_principal_id=$5,
		    decided_context_digest=$6, authority_basis=$7
		WHERE id=$1 AND state='pending' AND expires_at > now()`,
		in.ID, to, in.DecidedBy, in.Reason, in.DecidedByPrincipalID, in.ContextDigest, in.AuthorityBasis)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		cur, err := l.store.ActionApproval(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if cur.State == workitems.ApprovalExpired {
			return nil, fmt.Errorf("%w: %s", workitems.ErrApprovalExpired, in.ID)
		}
		return nil, fmt.Errorf("%w: %s", workitems.ErrApprovalAlreadyDecided, in.ID)
	}
	return l.store.ActionApproval(ctx, in.ID)
}

func (l *basketLedger) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.decided)
}

// basketViewFake is the basket store's side.
type basketViewFake struct {
	mu    sync.Mutex
	snaps map[string]*GlovoBasketApprovalSnapshot
	err   error
}

func (v *basketViewFake) BasketApproval(_ context.Context, ref string) (*GlovoBasketApprovalSnapshot, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.err != nil {
		return nil, v.err
	}
	s, ok := v.snaps[ref]
	if !ok {
		return nil, ErrGlovoBasketApprovalNotFound
	}
	cp := *s
	cp.Lines = append([]GlovoBasketLine(nil), s.Lines...)
	return &cp, nil
}

func (v *basketViewFake) edit(ref string, f func(*GlovoBasketApprovalSnapshot)) {
	v.mu.Lock()
	defer v.mu.Unlock()
	f(v.snaps[ref])
}

type basketEnv struct {
	*workItemsEnv
	idp     *fakeIdP
	ledger  *basketLedger
	view    *basketViewFake
	members *glovoMembers
	prins   *fakeSignInPrincipals
	page    http.Handler
	pool    *pgxpool.Pool
}

func newBasketEnv(t *testing.T) *basketEnv {
	t.Helper()
	e := &basketEnv{workItemsEnv: newWorkItemsEnv(t)}
	pool, err := pgxpool.New(context.Background(), e.connStr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	e.pool = pool
	e.ledger = &basketLedger{bindings: map[string]*workitems.GlovoBinding{}, pool: pool, store: e.h.opts.WorkItems}
	e.view = &basketViewFake{snaps: map[string]*GlovoBasketApprovalSnapshot{}}
	// Every person below is a live developer somewhere: only ownership, not
	// a missing membership, keeps the non-owners out.
	e.members = &glovoMembers{roles: map[string]string{
		glovoTenant + "|" + glovoOwnerPRN:         "developer",
		glovoTenant + "|" + glovoOtherPRN:         "developer",
		glovoTenant + "|" + basketAdminPRN:        "developer",
		basketForeignTnt + "|" + basketForeignPRN: "developer",
	}}
	e.h.opts.GlovoApprovals = e.ledger
	e.h.opts.TenantAuthzMode = TenantAuthzPrincipal
	e.h.opts.PrincipalMembership = e.members
	prev := glovo.Default
	glovo.Default = glovo.Gate{Open: true}
	t.Cleanup(func() { glovo.Default = prev })

	e.idp = newFakeIdP(t)
	e.idp.clientID, e.idp.clientSecret = "basket-client", "basket-secret"
	e.prins = &fakeSignInPrincipals{ids: map[string]string{
		"z-owner": glovoOwnerPRN, "z-other": glovoOtherPRN, "z-admin": basketAdminPRN, "z-foreign": basketForeignPRN,
	}}
	opts := &GlovoBasketApprovalPageOptions{
		ProviderName: "zitadel", Issuer: e.idp.srv.URL, ClientID: "basket-client", ClientSecret: "basket-secret",
		BaseURL: "https://api.example", Principals: e.prins,
		Authz: &auth.PrincipalAuthz{Admins: map[string]bool{basketAdminPRN: true}, Members: noTenants{}},
		View:  e.view,
	}
	e.h.glovoBasketApproval = newBasketDecider(opts)
	r := chi.NewRouter()
	r.Post(basketStartPath, e.h.handleGlovoBasketApprovalStart)
	r.Get(basketCallbackPath, e.h.handleGlovoBasketApprovalCallback)
	r.Post(basketConfirmPath, e.h.handleGlovoBasketApprovalConfirm)
	r.Get(basketPagePrefix+"{approval_ref}", e.h.handleGlovoBasketApprovalPage)
	e.page = r
	return e
}

// basketApproval opens a pending basket aar_ owned by owner in tenant, with
// its binding and its frozen revision.
func (e *basketEnv) basketApproval(key, kind, owner, tenant string) string {
	e.t.Helper()
	id := e.requestApproval(key)["id"].(string)
	if _, err := e.pool.Exec(context.Background(),
		`UPDATE action_approval_requests SET action_kind=$2, requested_by=$3 WHERE id=$1`,
		id, kind, workitems.GlovoRequester); err != nil {
		e.t.Fatal(err)
	}
	e.ledger.mu.Lock()
	e.ledger.bindings[id] = &workitems.GlovoBinding{ApprovalID: id, Tenant: tenant, OwnerPrincipalID: owner, BasketFingerprint: basketFP}
	e.ledger.mu.Unlock()
	e.view.mu.Lock()
	e.view.snaps[id] = &GlovoBasketApprovalSnapshot{
		ApprovalRef: id, Tenant: tenant, OwnerPrincipalID: owner, BasketID: "bkt_" + key, Revision: 3, CurrentRevision: 3,
		Fingerprint: basketFP, Currency: "EUR", FeesMinor: 199, TotalMinor: 2*450 + 1250 + 199,
		Lines: []GlovoBasketLine{
			{ProductID: "p1", Name: "Synthetic Margherita", Quantity: 2, UnitPriceMinor: 450, LineTotalMinor: 900},
			{ProductID: "p2", Name: "Synthetic Lasagne", Quantity: 1, UnitPriceMinor: 1250, LineTotalMinor: 1250},
		},
	}
	e.view.mu.Unlock()
	return id
}

func (e *basketEnv) pending(key string) string {
	return e.basketApproval(key, GlovoBasketApprovalKind, glovoOwnerPRN, glovoTenant)
}

func (e *basketEnv) send(method, target string, ck *http.Cookie, form url.Values) *httptest.ResponseRecorder {
	var req *http.Request
	if form != nil {
		req = httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	if ck != nil {
		req.AddCookie(ck)
	}
	rec := httptest.NewRecorder()
	e.page.ServeHTTP(rec, req)
	return rec
}

// signIn opens the link, starts the sign-in and comes back from ZITADEL as
// subject. It returns the callback's answer, the cookie and the decide form.
func (e *basketEnv) signIn(ref, subject string) (*httptest.ResponseRecorder, *http.Cookie, url.Values) {
	e.t.Helper()
	page := e.send(http.MethodGet, basketPagePrefix+ref, nil, nil)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `action="`+basketStartPath+`"`) {
		e.t.Fatalf("link page = %d %s", page.Code, page.Body.String())
	}
	if len(page.Result().Cookies()) != 0 || strings.Contains(page.Body.String(), "Synthetic") {
		e.t.Fatalf("the link page set state or showed the basket")
	}
	start := e.send(http.MethodPost, basketStartPath, nil, url.Values{"approval_ref": {ref}})
	if start.Code != http.StatusSeeOther {
		e.t.Fatalf("start = %d %s", start.Code, start.Body.String())
	}
	var ck *http.Cookie
	for _, c := range start.Result().Cookies() {
		if c.Name == basketCookieName {
			ck = c
		}
	}
	if ck == nil || !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteLaxMode || ck.Path != "/" || ck.Domain != "" {
		e.t.Fatalf("cookie = %+v", ck)
	}
	u, _ := url.Parse(start.Header().Get("Location"))
	q := u.Query()
	if !strings.HasPrefix(u.String(), e.idp.srv.URL+"/authorize") || q.Get("client_id") != "basket-client" ||
		q.Get("code_challenge_method") != "S256" || q.Get("prompt") != "login" || q.Get("max_age") != "0" ||
		q.Get("nonce") == "" || q.Get("redirect_uri") != "https://api.example"+basketCallbackPath {
		e.t.Fatalf("authorize URL %s", u)
	}
	e.idp.mu.Lock()
	e.idp.challenge, e.idp.nonce = q.Get("code_challenge"), q.Get("nonce")
	e.idp.extra = map[string]any{"sub": subject}
	e.idp.mu.Unlock()
	rec := e.send(http.MethodGet, basketCallbackPath+"?code=z-code&state="+url.QueryEscape(q.Get("state")), ck, nil)
	form := url.Values{}
	for _, m := range basketField.FindAllStringSubmatch(rec.Body.String(), -1) {
		form.Set(m[1], html.UnescapeString(m[2]))
	}
	return rec, ck, form
}

var basketField = regexp.MustCompile(`name="(challenge|csrf)" value="([^"]+)"`)

func (e *basketEnv) confirm(ck *http.Cookie, form url.Values, decision string) *httptest.ResponseRecorder {
	return e.send(http.MethodPost, basketConfirmPath, ck, url.Values{
		"challenge": {form.Get("challenge")}, "csrf": {form.Get("csrf")}, "decision": {decision},
	})
}

func (e *basketEnv) state(id string) string {
	e.t.Helper()
	a, err := e.h.opts.WorkItems.ActionApproval(context.Background(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	return a.State
}

func TestGlovoBasketPage_OwnerApprovesExactlyWhatWasShown(t *testing.T) {
	e := newBasketEnv(t)
	id := e.pending("approve")
	rec, ck, form := e.signIn(id, "z-owner")
	body := rec.Body.String()
	if rec.Code != http.StatusOK || form.Get("csrf") == "" {
		t.Fatalf("callback = %d %s", rec.Code, body)
	}
	cd := e.bindingOf(id)["context_digest"].(string)
	for _, want := range []string{"Synthetic Margherita", "Synthetic Lasagne", "4.50", "9.00", "12.50", "1.99", "23.49", "EUR",
		"Team: " + glovoTenant, "revision 3", id, basketFP, cd, "Expires: ", "Approve this basket"} {
		if !strings.Contains(body, html.EscapeString(want)) {
			t.Errorf("the page does not show %q", want)
		}
	}
	if e.ledger.count() != 0 || e.state(id) != workitems.ApprovalPending {
		t.Fatal("showing the basket decided something")
	}

	res := e.confirm(ck, form, "approve")
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "Basket approved") || !strings.Contains(res.Body.String(), "(approved)") {
		t.Fatalf("confirm = %d %s", res.Code, res.Body.String())
	}
	if e.ledger.count() != 1 {
		t.Fatalf("ledger decisions = %d", e.ledger.count())
	}
	in := e.ledger.decided[0]
	if in.Decision != workitems.DecisionApprove || in.DecidedByPrincipalID != glovoOwnerPRN ||
		in.AuthorityBasis != workitems.GlovoAuthorityBasis || in.ContextDigest != cd {
		t.Fatalf("decision input %+v", in)
	}
	if e.state(id) != workitems.ApprovalApproved {
		t.Fatalf("state = %s", e.state(id))
	}
	if e.auditOps("action_approval.decision", id) != 1 {
		t.Fatal("the decision handler wrote no audit entry")
	}

	// A double click or a replayed form finds nothing and changes nothing.
	again := e.confirm(ck, form, "approve")
	if again.Code != http.StatusBadRequest || e.ledger.count() != 1 {
		t.Fatalf("replay = %d, ledger %d", again.Code, e.ledger.count())
	}
	if flip := e.confirm(ck, form, "reject"); flip.Code != http.StatusBadRequest || e.state(id) != workitems.ApprovalApproved {
		t.Fatalf("a reject replayed on the used form = %d, state %s", flip.Code, e.state(id))
	}

	// Signing in again shows the final state and offers nothing.
	after, _, f2 := e.signIn(id, "z-owner")
	if after.Code != http.StatusOK || f2.Get("csrf") != "" || !strings.Contains(after.Body.String(), "This basket is approved") {
		t.Fatalf("after = %d %s", after.Code, after.Body.String())
	}
}

func TestGlovoBasketPage_OwnerRejects(t *testing.T) {
	e := newBasketEnv(t)
	id := e.pending("reject")
	_, ck, form := e.signIn(id, "z-owner")
	res := e.confirm(ck, form, "reject")
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "Basket rejected") || !strings.Contains(res.Body.String(), "(rejected)") {
		t.Fatalf("reject = %d %s", res.Code, res.Body.String())
	}
	if e.state(id) != workitems.ApprovalDenied || e.ledger.decided[0].Decision != workitems.DecisionDeny {
		t.Fatalf("state %s, input %+v", e.state(id), e.ledger.decided)
	}
	after, _, _ := e.signIn(id, "z-owner")
	if !strings.Contains(after.Body.String(), "This basket is rejected") {
		t.Fatalf("after = %s", after.Body.String())
	}
}

// Nobody but the bound owner learns that the approval exists: another member
// of the team, a platform admin, a member of another team, an unresolved
// identity, an unknown id and another Glovo kind all read the same 404.
func TestGlovoBasketPage_NonOwnersSeeOneUniformNotFound(t *testing.T) {
	e := newBasketEnv(t)
	id := e.pending("uniform")
	orderKind := e.basketApproval("order-kind", workitems.ActionKindGlovoPlaceOrderFake, glovoOwnerPRN, glovoTenant)
	unknown := "aar_" + strings.Repeat("0", 32)

	type probe struct{ ref, subject string }
	probes := map[string]probe{
		"same-team developer":    {id, "z-other"},
		"platform admin":         {id, "z-admin"},
		"other tenant developer": {id, "z-foreign"},
		"unresolved identity":    {id, "z-nobody"},
		"unknown id, owner":      {unknown, "z-owner"},
		"order kind, owner":      {orderKind, "z-owner"},
	}
	var first string
	for name, p := range probes {
		rec, _, form := e.signIn(p.ref, p.subject)
		if rec.Code != http.StatusNotFound || form.Get("csrf") != "" {
			t.Errorf("%s = %d %s", name, rec.Code, rec.Body.String())
			continue
		}
		b := strings.ReplaceAll(rec.Body.String(), p.ref, "REF")
		if strings.Contains(b, "Synthetic") || strings.Contains(b, basketFP) || strings.Contains(b, glovoTenant) {
			t.Errorf("%s saw the basket: %s", name, b)
		}
		if first == "" {
			first = b
		} else if b != first {
			t.Errorf("%s answered differently:\n%s\nvs\n%s", name, b, first)
		}
	}
	if e.ledger.count() != 0 || e.state(id) != workitems.ApprovalPending {
		t.Fatal("a non-owner decided something")
	}
}

// The decision itself is owner-bound and admin-free (route half): the
// decision route a non-owner could call directly refuses everyone but the
// owner, whatever else they are.
func TestGlovoBasketDecisionRoute_OwnerBoundNoAdminPass(t *testing.T) {
	e := newBasketEnv(t)
	id := e.pending("route")
	bind := e.bindingOf(id)
	bind["content_digest"] = basketFP
	asHuman := func(prn, login string, groups ...string) *auth.User {
		return principalUser(t, auth.NewGitHubUser(login, groups), prn, nil)
	}
	// A real platform admin in principal mode: the admin bit comes from the
	// principal, not from a group claim.
	admin := withPrincipal(t, auth.NewGitHubUser("root", nil), basketAdminPRN)
	if err := (&auth.PrincipalAuthz{Admins: map[string]bool{basketAdminPRN: true}, Members: noTenants{}}).Apply(admin); err != nil {
		t.Fatal(err)
	}
	if !isHumanAdmin(admin) {
		t.Fatal("control: the admin must be a human admin")
	}
	refused := map[string]*auth.User{
		"same-team developer":    asHuman(glovoOtherPRN, "oleg"),
		"admin, not the owner":   admin,
		"other tenant developer": asHuman(basketForeignPRN, "fred"),
		"owner's audience token": setUnexported(t, asHuman(glovoOwnerPRN, "olga"), "glovoAudience"),
		"owner's worker token":   setUnexported(t, asHuman(glovoOwnerPRN, "olga"), "glovoWorker"),
		"owner's facade token":   setUnexported(t, asHuman(glovoOwnerPRN, "olga"), "glovoFacade"),
		"service":                auth.NewServiceUser(),
		"agent run":              auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: "we_1", WorkItemID: "wi_1"}),
		"no principal":           auth.NewGitHubUser("x", nil),
	}
	for name, u := range refused {
		if res := e.decideBound(u, id, bind); res.code != http.StatusForbidden || code(res) != aarCodeDeciderForbidden {
			t.Errorf("%s = %d %s", name, res.code, res.raw)
		}
	}
	// The owner without live membership of the binding's team is refused
	// too, even as a member of another team.
	delete(e.members.roles, glovoTenant+"|"+glovoOwnerPRN)
	e.members.roles[basketForeignTnt+"|"+glovoOwnerPRN] = "developer"
	if res := e.decideBound(asHuman(glovoOwnerPRN, "olga"), id, bind); res.code != http.StatusForbidden {
		t.Errorf("owner outside the binding's team = %d %s", res.code, res.raw)
	}
	if e.ledger.count() != 0 {
		t.Fatalf("a refused caller reached the ledger %d times", e.ledger.count())
	}
	e.members.roles[glovoTenant+"|"+glovoOwnerPRN] = "developer"
	owner := asHuman(glovoOwnerPRN, "olga")
	if owner.IsAdmin() {
		t.Fatal("control: the owner must not be an admin")
	}
	if res := e.decideBound(owner, id, bind); res.code != http.StatusOK {
		t.Fatalf("owner (developer, not admin) = %d %s", res.code, res.raw)
	}
	if e.ledger.count() != 1 || e.state(id) != workitems.ApprovalApproved {
		t.Fatalf("ledger %d, state %s", e.ledger.count(), e.state(id))
	}
}

func TestGlovoBasketPage_ExpiredOffersNothingAndRefusesConfirm(t *testing.T) {
	e := newBasketEnv(t)
	id := e.pending("expired")
	e.expire(id)
	rec, _, form := e.signIn(id, "z-owner")
	if rec.Code != http.StatusOK || form.Get("csrf") != "" || !strings.Contains(rec.Body.String(), "This basket is expired") {
		t.Fatalf("expired view = %d %s", rec.Code, rec.Body.String())
	}

	// Expiring between the view and the click.
	id2 := e.pending("expires-late")
	_, ck, form2 := e.signIn(id2, "z-owner")
	if form2.Get("csrf") == "" {
		t.Fatal("no decide form")
	}
	e.expire(id2)
	res := e.confirm(ck, form2, "approve")
	if res.Code != http.StatusConflict || e.ledger.count() != 0 || e.state(id2) != workitems.ApprovalExpired {
		t.Fatalf("late confirm = %d %s, ledger %d, state %s", res.Code, res.Body.String(), e.ledger.count(), e.state(id2))
	}
}

func TestGlovoBasketPage_SupersededRevisionIsRefused(t *testing.T) {
	e := newBasketEnv(t)
	id := e.pending("superseded")
	e.view.edit(id, func(s *GlovoBasketApprovalSnapshot) { s.CurrentRevision = 4 })
	rec, _, form := e.signIn(id, "z-owner")
	if rec.Code != http.StatusConflict || form.Get("csrf") != "" || !strings.Contains(rec.Body.String(), "newer revision (4)") {
		t.Fatalf("superseded view = %d %s", rec.Code, rec.Body.String())
	}

	// Revised between the view and the click.
	id2 := e.pending("superseded-late")
	_, ck, form2 := e.signIn(id2, "z-owner")
	e.view.edit(id2, func(s *GlovoBasketApprovalSnapshot) { s.CurrentRevision = 4 })
	res := e.confirm(ck, form2, "approve")
	if res.Code != http.StatusConflict || e.ledger.count() != 0 || e.state(id2) != workitems.ApprovalPending {
		t.Fatalf("late confirm = %d %s, ledger %d, state %s", res.Code, res.Body.String(), e.ledger.count(), e.state(id2))
	}
}

// What is decided is what was shown: an approval rebound to other content
// after the view is not decided, even though it is now self-consistent.
func TestGlovoBasketPage_ContentChangedAfterViewIsRefused(t *testing.T) {
	e := newBasketEnv(t)
	id := e.pending("rebound")
	_, ck, form := e.signIn(id, "z-owner")
	if _, err := e.pool.Exec(context.Background(), `UPDATE action_approval_requests SET artifact_hash='sha256:other' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	e.view.edit(id, func(s *GlovoBasketApprovalSnapshot) { s.Fingerprint = "sha256:other" })
	res := e.confirm(ck, form, "approve")
	if res.Code != http.StatusConflict || !strings.Contains(res.Body.String(), "changed after you were shown it") ||
		e.ledger.count() != 0 || e.state(id) != workitems.ApprovalPending {
		t.Fatalf("confirm = %d %s, ledger %d", res.Code, res.Body.String(), e.ledger.count())
	}
}

func TestGlovoBasketPage_RefusesInconsistentSnapshots(t *testing.T) {
	e := newBasketEnv(t)
	for name, mut := range map[string]func(*GlovoBasketApprovalSnapshot){
		"fingerprint is not the approval's": func(s *GlovoBasketApprovalSnapshot) { s.Fingerprint = "sha256:elsewhere" },
		"line total wrong":                  func(s *GlovoBasketApprovalSnapshot) { s.Lines[0].LineTotalMinor = 1 },
		"basket total wrong":                func(s *GlovoBasketApprovalSnapshot) { s.TotalMinor = 1 },
		"no lines":                          func(s *GlovoBasketApprovalSnapshot) { s.Lines = nil },
		"malformed currency":                func(s *GlovoBasketApprovalSnapshot) { s.Currency = "<b>" },
	} {
		id := e.pending("bad-" + strings.ReplaceAll(name, " ", "-"))
		e.view.edit(id, mut)
		rec, _, form := e.signIn(id, "z-owner")
		if rec.Code != http.StatusConflict || form.Get("csrf") != "" {
			t.Errorf("%s = %d %s", name, rec.Code, rec.Body.String())
		}
	}
	e.view.err = errors.New("basket store down")
	id := e.pending("store-down")
	if rec, _, form := e.signIn(id, "z-owner"); rec.Code != http.StatusServiceUnavailable || form.Get("csrf") != "" {
		t.Errorf("store down = %d", rec.Code)
	}
	if e.ledger.count() != 0 {
		t.Fatal("an inconsistent basket was decided")
	}
}

// Product names (and the signed-in name) are data: escaped, never markup,
// and the page runs no script and cannot be framed or cached.
func TestGlovoBasketPage_EscapesHostileNamesAndSetsHeaders(t *testing.T) {
	e := newBasketEnv(t)
	id := e.pending("xss")
	e.view.edit(id, func(s *GlovoBasketApprovalSnapshot) { s.Lines[0].Name = hostileName })
	e.idp.username = `<b onmouseover=alert(3)>olga</b>`
	rec, _, form := e.signIn(id, "z-owner")
	body := rec.Body.String()
	if rec.Code != http.StatusOK || form.Get("csrf") == "" {
		t.Fatalf("callback = %d %s", rec.Code, body)
	}
	for _, raw := range []string{"<script>alert", "<img src=x", "<b onmouseover"} {
		if strings.Contains(body, raw) {
			t.Errorf("unescaped %q in the page", raw)
		}
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;&lt;img src=x onerror=alert(2)&gt;") {
		t.Errorf("the hostile name is not shown escaped:\n%s", body)
	}
	if strings.Contains(strings.ToLower(body), "<script") {
		t.Error("the page carries a script")
	}
	h := rec.Header()
	csp := h.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
	if strings.Contains(csp, "script-src") || h.Get("Cache-Control") != "no-store" || h.Get("X-Frame-Options") != "DENY" {
		t.Errorf("headers %v", h)
	}
}

// The confirm POST needs this browser's cookie and the one-time CSRF token;
// a forged or cross-browser post decides nothing and spends nothing.
func TestGlovoBasketPage_ConfirmNeedsCookieAndCSRF(t *testing.T) {
	e := newBasketEnv(t)
	id := e.pending("csrf")
	_, ck, form := e.signIn(id, "z-owner")
	forged := url.Values{"challenge": {form.Get("challenge")}, "csrf": {"guess"}}
	if res := e.confirm(ck, forged, "approve"); res.Code != http.StatusBadRequest {
		t.Errorf("wrong csrf = %d", res.Code)
	}
	if res := e.confirm(nil, form, "approve"); res.Code != http.StatusBadRequest {
		t.Errorf("no cookie = %d", res.Code)
	}
	other := &http.Cookie{Name: basketCookieName, Value: "another-browser"}
	if res := e.confirm(other, form, "approve"); res.Code != http.StatusBadRequest {
		t.Errorf("another browser = %d", res.Code)
	}
	if res := e.confirm(ck, form, "maybe"); res.Code != http.StatusBadRequest {
		t.Errorf("no decision = %d", res.Code)
	}
	if e.ledger.count() != 0 || e.state(id) != workitems.ApprovalPending {
		t.Fatal("a forged confirm decided")
	}
	if res := e.confirm(ck, form, "approve"); res.Code != http.StatusOK {
		t.Fatalf("the real confirm = %d %s", res.Code, res.Body.String())
	}
}

// A malformed reference is refused before anything is read or started.
func TestGlovoBasketPage_MalformedRef(t *testing.T) {
	e := newBasketEnv(t)
	for _, ref := range []string{"aar_XYZ", "wi_" + strings.Repeat("0", 32), "aar_" + strings.Repeat("0", 31) + "G"} {
		if rec := e.send(http.MethodGet, basketPagePrefix+ref, nil, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("GET %s = %d", ref, rec.Code)
		}
		if rec := e.send(http.MethodPost, basketStartPath, nil, url.Values{"approval_ref": {ref}}); rec.Code != http.StatusBadRequest || len(rec.Result().Cookies()) != 0 {
			t.Errorf("start %s = %d", ref, rec.Code)
		}
	}
}

// Dark by default: without complete options NewRouter mounts no route.
func TestGlovoBasketPage_DarkByDefault(t *testing.T) {
	ref := basketPagePrefix + "aar_" + strings.Repeat("a", 32)
	view := &basketViewFake{}
	full := GlovoBasketApprovalPageOptions{
		ProviderName: "zitadel", Issuer: "https://auth.example", ClientID: "c", ClientSecret: "s",
		BaseURL: "https://api.example", Principals: &fakeSignInPrincipals{}, Authz: &auth.PrincipalAuthz{}, View: view,
	}
	incomplete := full
	incomplete.View = nil
	for name, o := range map[string]*GlovoBasketApprovalPageOptions{"nil": nil, "no view": &incomplete} {
		for _, req := range []*http.Request{
			httptest.NewRequest(http.MethodGet, ref, nil),
			httptest.NewRequest(http.MethodPost, basketStartPath, nil),
			httptest.NewRequest(http.MethodPost, basketConfirmPath, nil),
		} {
			rec := httptest.NewRecorder()
			NewRouter(Options{GlovoBasketApproval: o}).ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s: %s %s = %d", name, req.Method, req.URL.Path, rec.Code)
			}
		}
	}
	rec := httptest.NewRecorder()
	NewRouter(Options{GlovoBasketApproval: &full}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, ref, nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), basketStartPath) {
		t.Fatalf("enabled: %d %s", rec.Code, rec.Body.String())
	}
}

// The basket store and the decision ledger must agree on whose basket this
// is: a snapshot naming another owner, team or approval is not shown, even to
// the ledger's owner.
func TestGlovoBasketPage_SnapshotMustAgreeWithBinding(t *testing.T) {
	e := newBasketEnv(t)
	for name, mut := range map[string]func(*GlovoBasketApprovalSnapshot){
		"another owner":    func(s *GlovoBasketApprovalSnapshot) { s.OwnerPrincipalID = glovoOtherPRN },
		"another team":     func(s *GlovoBasketApprovalSnapshot) { s.Tenant = basketForeignTnt },
		"another approval": func(s *GlovoBasketApprovalSnapshot) { s.ApprovalRef = "aar_" + strings.Repeat("f", 32) },
	} {
		id := e.pending("disagree-" + strings.ReplaceAll(name, " ", "-"))
		e.view.edit(id, mut)
		rec, _, form := e.signIn(id, "z-owner")
		if rec.Code != http.StatusNotFound || form.Get("csrf") != "" || strings.Contains(rec.Body.String(), "Synthetic") {
			t.Errorf("%s = %d %s", name, rec.Code, rec.Body.String())
		}
	}
	if e.ledger.count() != 0 {
		t.Fatal("a disagreeing basket was decided")
	}
}
