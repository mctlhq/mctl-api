package api

import (
	"context"
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// mctl-api#964: a DevLoop is decided from a link, by a human admin who signs
// in to ZITADEL in that browser, through the same approve and deny handlers
// as the API routes.

const testDecideClientID, testDecideClientSecret = "decide-client", "decide-secret"

// fakeSignInPrincipals maps the fake IdP's subject to a principal.
type fakeSignInPrincipals struct {
	mu  sync.Mutex
	ids map[string]string // subject -> principal
	err error
}

func (f *fakeSignInPrincipals) ResolvePrincipal(_ context.Context, id auth.Identity) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return "", f.err
	}
	if p, ok := f.ids[id.Subject]; ok {
		return p, nil
	}
	return "", auth.ErrIdentityRefused
}

type noTenants struct{}

func (noTenants) PrincipalTenants(string) ([]string, []string, error) { return nil, nil, nil }

type decideEnv struct {
	*workItemsEnv
	fake   *fakeDevLoopClient
	idp    *fakeIdP
	router http.Handler
	prins  *fakeSignInPrincipals
	authz  *auth.PrincipalAuthz

	clockMu sync.Mutex
	clock   time.Time
}

func newDecideEnv(t *testing.T) *decideEnv {
	t.Helper()
	e, fake := newDevLoopGrantEnv(t)
	idp := newFakeIdP(t)
	idp.clientID, idp.clientSecret = testDecideClientID, testDecideClientSecret
	d := &decideEnv{workItemsEnv: e, fake: fake, idp: idp, clock: time.Now(),
		prins: &fakeSignInPrincipals{ids: map[string]string{"z-sub": "prn_admin"}},
		authz: &auth.PrincipalAuthz{Admins: map[string]bool{"prn_admin": true}, Members: noTenants{}},
	}
	e.h.devLoopDecide = newDevLoopDecider(&DevLoopDecideOptions{
		ProviderName: "zitadel", Issuer: idp.srv.URL,
		ClientID: testDecideClientID, ClientSecret: testDecideClientSecret,
		BaseURL: "https://api.example", Principals: d.prins, Authz: d.authz,
		clock: func() time.Time {
			d.clockMu.Lock()
			defer d.clockMu.Unlock()
			return d.clock
		},
	})
	r := chi.NewRouter()
	r.Post(decideStartPath, e.h.handleDevLoopDecideStart)
	r.Get(decideCallbackPath, e.h.handleDevLoopDecideCallback)
	r.Post(decideConfirmPath, e.h.handleDevLoopDecideConfirm)
	r.Get(decidePathPrefix+"{workflow_id}", e.h.handleDevLoopDecidePage)
	d.router = r
	return d
}

func (d *decideEnv) advance(dur time.Duration) {
	d.clockMu.Lock()
	d.clock = d.clock.Add(dur)
	d.clockMu.Unlock()
}

func (d *decideEnv) do(method, target string, ck *http.Cookie, form url.Values) *httptest.ResponseRecorder {
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
	d.router.ServeHTTP(rec, req)
	return rec
}

// decideRun is a DevLoop with a pending grant, and the link a notification
// would carry for it.
type decideRun struct {
	devLoopRun
	grant string
	link  url.Values
}

func (d *decideEnv) run(suffix string) decideRun {
	d.t.Helper()
	svc := auth.NewServiceUser()
	item := d.open(svc, nil)
	run := devLoopRun{workflowID: "dev-loop-" + d.tenant + "-" + suffix, itemID: item["id"].(string)}
	run.execID = d.attachExecution(svc, run.itemID, run.workflowID, "Running")
	d.forgetApprovalsOf(run.execID)
	grant := d.requestDevLoopGrant(run.execID, "gate-"+suffix)
	read := d.readDevLoopApproval(rootAdmin, run.workflowID)
	if read.code != http.StatusOK {
		d.t.Fatalf("read = %d %s", read.code, read.raw)
	}
	dc := read.body["decision_context"].(map[string]any)
	link := url.Values{"grant": {grant}, "cd": {dc["context_digest"].(string)}, "xd": {testContentDigest}}
	return decideRun{devLoopRun: run, grant: grant, link: link}
}

// signIn opens the link, starts the sign-in and returns the cookie and the
// state the browser carries to ZITADEL.
func (d *decideEnv) signIn(run decideRun) (*http.Cookie, string) {
	d.t.Helper()
	page := d.do(http.MethodGet, decidePathPrefix+run.workflowID+"?"+run.link.Encode(), nil, nil)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `action="`+decideStartPath+`"`) {
		d.t.Fatalf("page = %d %s", page.Code, page.Body.String())
	}
	if len(page.Result().Cookies()) != 0 {
		d.t.Fatalf("the link page set state: %v", page.Result().Cookies())
	}
	form := url.Values{"workflow_id": {run.workflowID}}
	for k, v := range run.link {
		form[k] = v
	}
	rec := d.do(http.MethodPost, decideStartPath, nil, form)
	if rec.Code != http.StatusSeeOther {
		d.t.Fatalf("start = %d %s", rec.Code, rec.Body.String())
	}
	var ck *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == decideCookieName {
			ck = c
		}
	}
	if ck == nil || !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteLaxMode || ck.Path != "/" || ck.Domain != "" {
		d.t.Fatalf("decide cookie = %+v", ck)
	}
	authURL := rec.Header().Get("Location")
	u, err := url.Parse(authURL)
	if err != nil || !strings.HasPrefix(authURL, d.idp.srv.URL+"/authorize") {
		d.t.Fatalf("not sent to ZITADEL: %q", authURL)
	}
	q := u.Query()
	if q.Get("client_id") != testDecideClientID || q.Get("code_challenge_method") != "S256" ||
		q.Get("prompt") != "login" || q.Get("max_age") != "0" || q.Get("redirect_uri") != "https://api.example"+decideCallbackPath {
		d.t.Fatalf("authorize params: %v", q)
	}
	d.idp.mu.Lock()
	d.idp.challenge, d.idp.nonce = q.Get("code_challenge"), q.Get("nonce")
	d.idp.mu.Unlock()
	return ck, q.Get("state")
}

var decideField = regexp.MustCompile(`name="(challenge|csrf)" value="([^"]+)"`)

// callback returns from ZITADEL and returns the decide form's fields.
func (d *decideEnv) callback(ck *http.Cookie, state string) (*httptest.ResponseRecorder, url.Values) {
	d.t.Helper()
	rec := d.do(http.MethodGet, decideCallbackPath+"?code=z-code&state="+url.QueryEscape(state), ck, nil)
	form := url.Values{}
	for _, m := range decideField.FindAllStringSubmatch(rec.Body.String(), -1) {
		form.Set(m[1], html.UnescapeString(m[2]))
	}
	return rec, form
}

func (d *decideEnv) signedIn(run decideRun) (*http.Cookie, url.Values) {
	d.t.Helper()
	ck, state := d.signIn(run)
	rec, form := d.callback(ck, state)
	if rec.Code != http.StatusOK || form.Get("csrf") == "" {
		d.t.Fatalf("callback = %d %s", rec.Code, rec.Body.String())
	}
	return ck, form
}

func (d *decideEnv) confirm(ck *http.Cookie, form url.Values, decision string) *httptest.ResponseRecorder {
	f := url.Values{"challenge": {form.Get("challenge")}, "csrf": {form.Get("csrf")}, "decision": {decision}}
	return d.do(http.MethodPost, decideConfirmPath, ck, f)
}

func (d *decideEnv) pageAudits(status string) int {
	n := 0
	entries := d.audit.List(1000)
	for i := range entries {
		if entries[i].Operation == decideAuditOp && entries[i].Status == status {
			n++
		}
	}
	return n
}

func TestDevLoopDecide_ApproveSignalsTheBoundGrant(t *testing.T) {
	d := newDecideEnv(t)
	run := d.run("approve")
	ck, form := d.signedIn(run)

	rec := d.confirm(ck, form, "approve")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Approved") {
		t.Fatalf("confirm = %d %s", rec.Code, rec.Body.String())
	}
	if d.fake.lastApprovedWorkflow != run.workflowID || d.fake.lastApprovePayload["approval_ref"] != run.grant {
		t.Fatalf("signalled %q %v, want %s with %s", d.fake.lastApprovedWorkflow, d.fake.lastApprovePayload, run.workflowID, run.grant)
	}
	a := d.approvalState(run.grant)
	if a["state"] != workitems.ApprovalApproved || a["decided_by"] != "oidc:dmitrii" {
		t.Fatalf("grant state %v decided_by %v", a["state"], a["decided_by"])
	}
	if d.pageAudits("succeeded") != 1 {
		t.Fatalf("decide page audited %d successes, want 1", d.pageAudits("succeeded"))
	}
	// Used once.
	if again := d.confirm(ck, form, "approve"); again.Code != http.StatusBadRequest {
		t.Fatalf("replayed confirm = %d, want 400", again.Code)
	}
}

func TestDevLoopDecide_RejectDeniesAndNeverSignals(t *testing.T) {
	d := newDecideEnv(t)
	run := d.run("reject")
	ck, form := d.signedIn(run)

	rec := d.confirm(ck, form, "reject")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Rejected") {
		t.Fatalf("confirm = %d %s", rec.Code, rec.Body.String())
	}
	if d.fake.lastApprovePayload != nil {
		t.Fatalf("a reject signalled %v", d.fake.lastApprovePayload)
	}
	if st := d.approvalState(run.grant)["state"]; st != workitems.ApprovalDenied {
		t.Fatalf("grant = %v, want denied", st)
	}
}

func TestDevLoopDecide_OnlyAHumanAdminIsOfferedADecision(t *testing.T) {
	d := newDecideEnv(t)
	run := d.run("member")
	d.prins.ids["z-sub"] = "prn_member"
	ck, state := d.signIn(run)
	rec, form := d.callback(ck, state)
	if rec.Code != http.StatusForbidden || form.Get("csrf") != "" {
		t.Fatalf("non-admin callback = %d %s", rec.Code, rec.Body.String())
	}
	if st := d.approvalState(run.grant)["state"]; st != workitems.ApprovalPending {
		t.Fatalf("grant = %v", st)
	}
	if d.pageAudits("denied") != 1 {
		t.Fatalf("refusal audited %d times, want 1", d.pageAudits("denied"))
	}

	// An identity no principal holds, and a principal store that does not
	// answer, are refused too: never decided as an unknown caller.
	for name, set := range map[string]func(){
		"unlinked":    func() { d.prins.ids = map[string]string{} },
		"unavailable": func() { d.prins.err = errors.New("store down") },
	} {
		d.prins.ids, d.prins.err = map[string]string{"z-sub": "prn_admin"}, nil
		ck, state := d.signIn(run)
		set()
		if rec, _ := d.callback(ck, state); rec.Code != http.StatusForbidden {
			t.Errorf("%s callback = %d, want 403", name, rec.Code)
		}
	}
}

func TestDevLoopDecide_AdminRemovedBeforeConfirmIsRefused(t *testing.T) {
	d := newDecideEnv(t)
	run := d.run("removed")
	ck, form := d.signedIn(run)
	delete(d.authz.Admins, "prn_admin")
	if rec := d.confirm(ck, form, "approve"); rec.Code != http.StatusForbidden {
		t.Fatalf("confirm = %d %s, want 403", rec.Code, rec.Body.String())
	}
	if d.fake.lastApprovePayload != nil {
		t.Fatalf("signalled %v", d.fake.lastApprovePayload)
	}
	if st := d.approvalState(run.grant)["state"]; st != workitems.ApprovalPending {
		t.Fatalf("grant = %v", st)
	}
}

func TestDevLoopDecide_ABindingThatMovedOffersNoDecision(t *testing.T) {
	d := newDecideEnv(t)
	for name, mutate := range map[string]func(url.Values){
		"context": func(v url.Values) { v.Set("cd", "sha256:other") },
		"content": func(v url.Values) { v.Set("xd", "sha256:other") },
		"grant":   func(v url.Values) { v.Set("grant", "aar_other") },
	} {
		run := d.run("moved-" + name)
		mutate(run.link)
		ck, state := d.signIn(run)
		rec, form := d.callback(ck, state)
		if rec.Code != http.StatusConflict || form.Get("csrf") != "" {
			t.Errorf("%s: callback = %d %s, want 409 and no form", name, rec.Code, rec.Body.String())
		}
		if st := d.approvalState(run.grant)["state"]; st != workitems.ApprovalPending {
			t.Errorf("%s: grant = %v", name, st)
		}
	}
}

func TestDevLoopDecide_RefusesAnotherBrowserAndAForgedForm(t *testing.T) {
	d := newDecideEnv(t)
	run := d.run("browser")
	other := &http.Cookie{Name: decideCookieName, Value: "someone-else"}

	_, state := d.signIn(run)
	if rec, _ := d.callback(other, state); rec.Code != http.StatusBadRequest {
		t.Fatalf("callback in another browser = %d, want 400", rec.Code)
	}

	ck, form := d.signedIn(run)
	if rec := d.confirm(other, form, "approve"); rec.Code != http.StatusBadRequest {
		t.Fatalf("confirm in another browser = %d, want 400", rec.Code)
	}
	ck2, form2 := d.signedIn(run)
	form2.Set("csrf", "forged")
	if rec := d.confirm(ck2, form2, "approve"); rec.Code != http.StatusBadRequest {
		t.Fatalf("forged csrf = %d, want 400", rec.Code)
	}
	if rec := d.confirm(ck, form, "maybe"); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown decision = %d, want 400", rec.Code)
	}
	if d.fake.lastApprovePayload != nil {
		t.Fatalf("signalled %v", d.fake.lastApprovePayload)
	}
	if st := d.approvalState(run.grant)["state"]; st != workitems.ApprovalPending {
		t.Fatalf("grant = %v", st)
	}
}

func TestDevLoopDecide_RefusesAForeignOrStaleSignIn(t *testing.T) {
	d := newDecideEnv(t)
	run := d.run("stale")
	cases := map[string]func(){
		"nonce":    func() { d.idp.nonceOverride = "other" },
		"audience": func() { d.idp.audOverride = testLinkClientID },
		"stale":    func() { d.idp.authTime = time.Now().Add(-time.Hour) },
	}
	for name, set := range cases {
		d.idp.nonceOverride, d.idp.audOverride, d.idp.authTime = "", "", time.Now()
		ck, state := d.signIn(run)
		set()
		if rec, form := d.callback(ck, state); rec.Code != http.StatusBadRequest || form.Get("csrf") != "" {
			t.Errorf("%s: callback = %d %s, want 400", name, rec.Code, rec.Body.String())
		}
	}
}

func TestDevLoopDecide_ExpiredChallengeIsRefused(t *testing.T) {
	d := newDecideEnv(t)
	run := d.run("expired")
	ck, state := d.signIn(run)
	d.advance(decideChallengeTTL + time.Second)
	if rec, _ := d.callback(ck, state); rec.Code != http.StatusBadRequest {
		t.Fatalf("expired callback = %d, want 400", rec.Code)
	}
	d.idp.authTime = d.clock // ZITADEL's clock moved with ours
	ck, form := d.signedIn(run)
	d.advance(decideChallengeTTL + time.Second)
	if rec := d.confirm(ck, form, "approve"); rec.Code != http.StatusBadRequest {
		t.Fatalf("expired confirm = %d, want 400", rec.Code)
	}
}

func TestDevLoopDecide_MalformedLinkAndOffPage(t *testing.T) {
	d := newDecideEnv(t)
	run := d.run("link")
	for name, target := range map[string]string{
		"no binding":   decidePathPrefix + run.workflowID,
		"bad workflow": decidePathPrefix + "not-a-devloop?" + run.link.Encode(),
		"bad grant":    decidePathPrefix + run.workflowID + "?grant=x&cd=a&xd=b",
	} {
		if rec := d.do(http.MethodGet, target, nil, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", name, rec.Code)
		}
	}
	d.h.devLoopDecide = nil
	if rec := d.do(http.MethodGet, decidePathPrefix+run.workflowID+"?"+run.link.Encode(), nil, nil); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("off page = %d, want 503", rec.Code)
	}
}

func TestDevLoopDecide_CapsUnfinishedSignInsPerSource(t *testing.T) {
	d := newDecideEnv(t)
	run := d.run("cap")
	for i := 0; i < decideMaxPerIP+2; i++ {
		d.signIn(run)
	}
	dd := d.h.devLoopDecide
	dd.mu.Lock()
	n := len(dd.byID)
	dd.mu.Unlock()
	if n != decideMaxPerIP {
		t.Fatalf("%d challenges from one source, want %d", n, decideMaxPerIP)
	}
}

func TestDevLoopDecide_FormActionAdmitsOnlyTheIssuer(t *testing.T) {
	dd := newDevLoopDecider(&DevLoopDecideOptions{Issuer: "https://auth.example/"})
	rec := httptest.NewRecorder()
	dd.renderPage(rec, http.StatusOK, "t", nil, decidePageData{})
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self' https://auth.example;") {
		t.Fatalf("CSP = %q", csp)
	}
}

// A grant decided elsewhere (the API, MCP, another link) offers nothing.
func TestDevLoopDecide_ADecidedGrantOffersNoDecision(t *testing.T) {
	d := newDecideEnv(t)
	run := d.run("decided")
	bind := map[string]any{"approval_ref": run.grant, "context_digest": run.link.Get("cd"), "content_digest": testContentDigest}
	if a := d.approveDevLoop(rootAdmin, run.workflowID, bindingJSON(bind)); a.code != http.StatusOK {
		t.Fatalf("approve = %d %s", a.code, a.raw)
	}
	ck, state := d.signIn(run)
	rec, form := d.callback(ck, state)
	if rec.Code != http.StatusConflict || form.Get("csrf") != "" {
		t.Fatalf("callback on a decided grant = %d %s, want 409 and no form", rec.Code, rec.Body.String())
	}
}
