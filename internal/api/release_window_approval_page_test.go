package api

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
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
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Sync-window write path, S2: a release.window is decided only by a
// configured decider, signed in fresh with a second factor, through the
// release page's client on the window page's own callback, and only while
// Argo CD still knows the Applications the request names.

type stubWindowHead struct{}

func (stubWindowHead) Head(context.Context) (string, error) { return strings.Repeat("a", 40), nil }

// windowArgoFake answers GetAppSyncWindows from a map; a name missing from it
// is Argo's 404.
type windowArgoFake struct {
	statusOnlyArgo
	mu    sync.Mutex
	known map[string]*argocd.AppSyncWindows // "<project>/<app>"
	err   error
}

func (a *windowArgoFake) GetProjectSyncWindows(string) (*argocd.ProjectSyncWindows, error) {
	return nil, errors.New("not used")
}

func (a *windowArgoFake) GetAppSyncWindows(project, app string) (*argocd.AppSyncWindows, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return nil, a.err
	}
	w, ok := a.known[project+"/"+app]
	if !ok {
		return nil, argocd.ErrNotFound
	}
	return w, nil
}

func (a *windowArgoFake) set(project, app string, w *argocd.AppSyncWindows, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if w == nil {
		delete(a.known, project+"/"+app)
	} else {
		a.known[project+"/"+app] = w
	}
	a.err = err
}

// windowPageEnv mounts the grant page and the window page side by side on one
// router, so the tests can prove they do not accept each other's rows or
// challenges.
type windowPageEnv struct {
	*releasePageEnv
	argo *windowArgoFake
}

func newWindowPageEnv(t *testing.T) *windowPageEnv {
	t.Helper()
	r := newReleasePageEnv(t)
	e := &windowPageEnv{releasePageEnv: r, argo: &windowArgoFake{known: map[string]*argocd.AppSyncWindows{
		"apps/labs-mctl-web":      {Application: "labs-mctl-web", CanSync: true},
		"apps/labs-mctl-telegram": {Application: "labs-mctl-telegram", CanSync: false, ActiveWindows: []argocd.AppSyncWindow{{Kind: "deny"}}},
	}}}
	r.h.opts.ReleaseWindows = &ReleaseWindowOptions{Head: stubWindowHead{}, Repository: "mctlhq/mctl-gitops"}
	r.h.opts.ArgoCD = e.argo
	r.h.releaseWindowApproval = newWindowDecider(r.ropts)
	r.page = windowRouter(r.h)
	t.Cleanup(func() {
		ctx := context.Background()
		if pool, err := pgxpool.New(ctx, r.connStr); err == nil {
			_, _ = pool.Exec(ctx, `DELETE FROM action_approval_requests WHERE action_kind=$1 AND execution_id LIKE 'abab%'`, workitems.ActionKindReleaseWindow)
			pool.Close()
		}
	})
	return e
}

func windowRouter(h *Handlers) http.Handler {
	r := chi.NewRouter()
	r.Post(releaseStartPath, h.handleReleaseApprovalStart)
	r.Get(releaseCallbackPath, h.handleReleaseApprovalCallback)
	r.Post(releaseConfirmPath, h.handleReleaseApprovalConfirm)
	r.Get(releasePagePrefix+"{approval_ref}", h.handleReleaseApprovalPage)
	r.Post(releaseWindowStartPath, h.handleReleaseWindowApprovalStart)
	r.Get(releaseWindowCallbackPath, h.handleReleaseWindowApprovalCallback)
	r.Post(releaseWindowConfirmPath, h.handleReleaseWindowApprovalConfirm)
	r.Get(releaseWindowPagePrefix+"{approval_ref}", h.handleReleaseWindowApprovalPage)
	return r
}

func (e *windowPageEnv) pendingWindow() (string, workitems.ReleaseWindow) {
	e.t.Helper()
	b := make([]byte, 18)
	if _, err := crand.Read(b); err != nil {
		e.t.Fatal(err)
	}
	win := workitems.ReleaseWindow{Project: "apps", Applications: []string{"labs-mctl-telegram", "labs-mctl-web"},
		Schedule: "0 22 * * 5", Duration: "48h", BaseSHA: "abab" + hex.EncodeToString(b)}
	intent, err := workitems.ReleaseWindowIntent(win)
	if err != nil {
		e.t.Fatal(err)
	}
	key, _ := workitems.ReleaseWindowIdempotencyKey(win)
	id, _ := win.ReleaseWindowID()
	pol := e.h.approvalPolicies()[workitems.ReleaseWindowPolicyRuleID]
	a, _, err := e.h.opts.WorkItems.CreateReleaseWindowApproval(context.Background(), win, workitems.ActionApprovalInput{
		ActionIntent: intent, RequestedBy: "principal:" + glovoOtherPRN, RequestedByPrincipalID: glovoOtherPRN,
		ActorKind: "agent", ActorName: "claude-code",
		IdempotencyKey: key, ExpiresAt: time.Now().Add(time.Hour), RiskLevel: "high",
		IntentSource: "release-window:" + win.Project + "/" + id,
		SideEffect:   pol.SideEffect, PolicyDecision: pol.Decision, PolicyReasons: append([]string(nil), pol.Reasons...),
	})
	if err != nil {
		e.t.Fatalf("CreateReleaseWindowApproval: %v", err)
	}
	return a.ID, win
}

func (e *windowPageEnv) signIn(ref string, claims map[string]any) (*httptest.ResponseRecorder, *http.Cookie, url.Values) {
	e.t.Helper()
	page := e.send(http.MethodGet, releaseWindowPagePrefix+ref, nil, nil)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `action="`+releaseWindowStartPath+`"`) {
		e.t.Fatalf("link page = %d %s", page.Code, page.Body.String())
	}
	if len(page.Result().Cookies()) != 0 || strings.Contains(page.Body.String(), "sha256:") {
		e.t.Fatal("the link page set state or showed the window")
	}
	start := e.send(http.MethodPost, releaseWindowStartPath, nil, url.Values{"approval_ref": {ref}})
	if start.Code != http.StatusSeeOther {
		e.t.Fatalf("start = %d %s", start.Code, start.Body.String())
	}
	var ck *http.Cookie
	for _, c := range start.Result().Cookies() {
		if c.Name == releaseWindowPageCookie {
			ck = c
		}
	}
	if ck == nil || !ck.HttpOnly || !ck.Secure || ck.Path != "/" || ck.Domain != "" {
		e.t.Fatalf("cookie = %+v", ck)
	}
	u, _ := url.Parse(start.Header().Get("Location"))
	q := u.Query()
	if q.Get("client_id") != "release-client" || q.Get("code_challenge_method") != "S256" || q.Get("prompt") != "login" ||
		q.Get("max_age") != "0" || q.Get("nonce") == "" || q.Get("redirect_uri") != "https://api.example"+releaseWindowCallbackPath {
		e.t.Fatalf("authorize URL %s", u)
	}
	e.idp.mu.Lock()
	e.idp.challenge, e.idp.nonce = q.Get("code_challenge"), q.Get("nonce")
	e.idp.extra = claims
	e.idp.mu.Unlock()
	if e.beforeCallback != nil {
		e.beforeCallback()
	}
	rec := e.send(http.MethodGet, releaseWindowCallbackPath+"?code=z-code&state="+url.QueryEscape(q.Get("state")), ck, nil)
	form := url.Values{}
	for _, m := range basketField.FindAllStringSubmatch(rec.Body.String(), -1) {
		form.Set(m[1], html.UnescapeString(m[2]))
	}
	return rec, ck, form
}

func (e *windowPageEnv) confirm(ck *http.Cookie, form url.Values, decision string) *httptest.ResponseRecorder {
	return e.send(http.MethodPost, releaseWindowConfirmPath, ck, url.Values{
		"challenge": {form.Get("challenge")}, "csrf": {form.Get("csrf")}, "decision": {decision},
	})
}

func TestReleaseWindowPage_DeciderApprovesWithEvidence(t *testing.T) {
	e := newWindowPageEnv(t)
	id, win := e.pendingWindow()
	rec, ck, form := e.signIn(id, deciderClaims())
	// html/template escapes the quotes around the cron text; compare the text a browser shows.
	body := html.UnescapeString(rec.Body.String())
	hash, _ := win.WindowSHA256()
	for _, want := range []string{"Project: apps", "labs-mctl-telegram, labs-mctl-web", `cron "0 22 * * 5" (UTC), duration 48h`,
		"sha256:" + hash, win.BaseSHA, "labs-mctl-web: exists, can sync now yes", "labs-mctl-telegram: exists, can sync now no, active windows 1",
		"https://github.com/mctlhq/mctl-gitops/commit/" + win.BaseSHA, "nothing is added to Git",
		"queued for merge", "no person reviews or merges it after you"} {
		if !strings.Contains(body, want) {
			t.Fatalf("the decide page lacks %q:\n%s", want, body)
		}
	}
	if rec.Code != http.StatusOK || form.Get("csrf") == "" {
		t.Fatalf("callback = %d", rec.Code)
	}
	if e.approval(id).State != workitems.ApprovalPending {
		t.Fatal("showing the window decided it")
	}
	got := e.confirm(ck, form, "approve")
	if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "Release window approved") {
		t.Fatalf("confirm = %d %s", got.Code, got.Body.String())
	}
	if b := got.Body.String(); !strings.Contains(b, "no pull request exists yet") || !strings.Contains(b, "queued for merge") || strings.Contains(b, "deployed") {
		t.Fatalf("approved page overclaims: %s", b)
	}
	a := e.approval(id)
	ev, err := workitems.ReleaseWindowDecisionOf(a)
	if a.State != workitems.ApprovalApproved || a.DecidedByPrincipalID != basketAdminPRN || err != nil || ev == nil ||
		a.AuthorityBasis != workitems.ReleaseWindowAuthorityBasis {
		t.Fatalf("decided row %+v, evidence %+v %v", a, ev, err)
	}
	if ev.ClientID != "release-client" || ev.Subject != "z-admin" || strings.Join(ev.AMR, ",") != "mfa,pwd,user" || ev.Issuer != e.idp.srv.URL {
		t.Fatalf("evidence %+v", ev)
	}
	// The decide form is spent.
	if again := e.confirm(ck, form, "approve"); again.Code != http.StatusBadRequest {
		t.Fatalf("replayed confirm = %d", again.Code)
	}
}

func TestReleaseWindowPage_AcceptsZitadelAudience(t *testing.T) {
	e := newWindowPageEnv(t)
	id, _ := e.pendingWindow()
	c := deciderClaims()
	c["aud"] = []string{"release-client", "369000000000000001", "deploy-client@mctl"}
	c["azp"] = "release-client"
	rec, _, form := e.signIn(id, c)
	if rec.Code != http.StatusOK || form.Get("csrf") == "" {
		t.Fatalf("callback = %d %s", rec.Code, rec.Body.String())
	}
}

func TestReleaseWindowPage_DeciderRejects(t *testing.T) {
	e := newWindowPageEnv(t)
	id, _ := e.pendingWindow()
	_, ck, form := e.signIn(id, deciderClaims())
	got := e.confirm(ck, form, "reject")
	if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "No pull request will be opened") {
		t.Fatalf("reject = %d %s", got.Code, got.Body.String())
	}
	a := e.approval(id)
	if ev, err := workitems.ReleaseWindowDecisionOf(a); a.State != workitems.ApprovalDenied || ev == nil || err != nil {
		t.Fatalf("rejected row %+v %v %v", a, ev, err)
	}
}

// Every sign-in the page must not trust is refused at the callback, shows no
// window, and decides nothing.
func TestReleaseWindowPage_RefusesSignIns(t *testing.T) {
	e := newWindowPageEnv(t)
	id, win := e.pendingWindow()
	hash, _ := win.WindowSHA256()
	with := func(over map[string]any) map[string]any {
		c := deciderClaims()
		for k, v := range over {
			c[k] = v
		}
		return c
	}
	cases := []struct {
		name   string
		claims map[string]any
		idp    func(*fakeIdP)
		deci   []string
		want   int
		body   string
	}{
		{name: "not an admin", claims: with(map[string]any{"sub": "z-owner"}), want: http.StatusNotFound},
		{name: "admin not a decider", claims: deciderClaims(), deci: []string{glovoOwnerPRN}, want: http.StatusNotFound},
		{name: "decider not an admin", claims: with(map[string]any{"sub": "z-owner"}), deci: []string{glovoOwnerPRN}, want: http.StatusNotFound},
		// A person who is not a decider learns nothing about the page, not even
		// that a second factor was wanted.
		{name: "not a decider and no second factor", claims: with(map[string]any{"amr": nil}), deci: []string{glovoOwnerPRN}, want: http.StatusNotFound},
		{name: "no amr", claims: with(map[string]any{"amr": nil}), want: http.StatusForbidden, body: "amr: none"},
		{name: "password only", claims: with(map[string]any{"amr": []string{"pwd", "user"}}), want: http.StatusForbidden, body: "amr: pwd, user"},
		{name: "several audiences without azp", claims: with(map[string]any{"aud": []string{"release-client", "mcp-client"}}), want: http.StatusBadRequest},
		{name: "authorized party is another client", claims: with(map[string]any{"azp": "mcp-client"}), want: http.StatusBadRequest},
		{name: "audience lacks this client", claims: with(map[string]any{"aud": []string{"mcp-client", "369000000000000001"}, "azp": "release-client"}), want: http.StatusBadRequest},
		{name: "audience is another client", claims: with(map[string]any{"aud": "mcp-client"}), want: http.StatusBadRequest},
		{name: "empty audience", claims: with(map[string]any{"aud": []string{}}), want: http.StatusBadRequest},
		{name: "stale sign-in", claims: deciderClaims(), idp: func(f *fakeIdP) { f.authTime = time.Now().Add(-time.Hour) }, want: http.StatusBadRequest},
		{name: "other nonce", claims: deciderClaims(), idp: func(f *fakeIdP) { f.nonceOverride = "someone-elses" }, want: http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e.idp.mu.Lock()
			at, no := e.idp.authTime, e.idp.nonceOverride
			if c.idp != nil {
				c.idp(e.idp)
			}
			e.idp.mu.Unlock()
			if c.deci != nil {
				prev := e.ropts.Deciders
				e.ropts.Deciders = c.deci
				defer func() { e.ropts.Deciders = prev }()
			}
			rec, _, form := e.signIn(id, c.claims)
			e.idp.mu.Lock()
			e.idp.authTime, e.idp.nonceOverride = at, no
			e.idp.mu.Unlock()
			b := rec.Body.String()
			if rec.Code != c.want || form.Get("csrf") != "" || strings.Contains(b, hash) {
				t.Fatalf("%d %s", rec.Code, b)
			}
			if c.body != "" && !strings.Contains(b, c.body) {
				t.Fatalf("body %s, want %q", b, c.body)
			}
		})
	}
	if e.approval(id).State != workitems.ApprovalPending {
		t.Fatal("a refused sign-in decided something")
	}
}

// The Applications are read again from Argo CD at the callback and at confirm:
// one that is gone, or an Argo CD that cannot be read, decides nothing and is
// never shown as fine.
func TestReleaseWindowPage_ReadsArgoAgain(t *testing.T) {
	gone := func(e *windowPageEnv) { e.argo.set("apps", "labs-mctl-web", nil, nil) }
	down := func(e *windowPageEnv) {
		e.argo.set("apps", "labs-mctl-web", &argocd.AppSyncWindows{}, errors.New("argo down"))
	}
	forbidden := func(e *windowPageEnv) {
		e.argo.set("apps", "labs-mctl-web", &argocd.AppSyncWindows{}, argocd.ErrForbidden)
	}

	for name, c := range map[string]struct {
		break_ func(*windowPageEnv)
		want   int
	}{
		"application gone": {gone, http.StatusConflict},
		"argo down":        {down, http.StatusServiceUnavailable},
		"argo forbidden":   {forbidden, http.StatusServiceUnavailable},
	} {
		t.Run(name+" at the callback", func(t *testing.T) {
			e := newWindowPageEnv(t)
			id, _ := e.pendingWindow()
			c.break_(e)
			rec, _, form := e.signIn(id, deciderClaims())
			if rec.Code != c.want || form.Get("csrf") != "" {
				t.Fatalf("%d %s", rec.Code, rec.Body.String())
			}
		})
		t.Run(name+" before confirm", func(t *testing.T) {
			e := newWindowPageEnv(t)
			id, _ := e.pendingWindow()
			_, ck, form := e.signIn(id, deciderClaims())
			c.break_(e)
			if got := e.confirm(ck, form, "approve"); got.Code != c.want {
				t.Fatalf("confirm = %d %s", got.Code, got.Body.String())
			}
			if e.approval(id).State != workitems.ApprovalPending {
				t.Fatal("approved a window whose Applications could not be confirmed")
			}
		})
	}
	t.Run("no reader at all", func(t *testing.T) {
		e := newWindowPageEnv(t)
		id, _ := e.pendingWindow()
		e.h.opts.ArgoCD = statusOnlyArgo{}
		rec, _, form := e.signIn(id, deciderClaims())
		if rec.Code != http.StatusServiceUnavailable || form.Get("csrf") != "" {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
	})
}

// The decide form belongs to the browser that signed in, and the decider
// list is read again at confirm.
func TestReleaseWindowPage_ConfirmIsBound(t *testing.T) {
	e := newWindowPageEnv(t)
	id, _ := e.pendingWindow()
	_, _, form := e.signIn(id, deciderClaims())
	other := &http.Cookie{Name: releaseWindowPageCookie, Value: "another-browser"}
	if got := e.confirm(other, form, "approve"); got.Code != http.StatusBadRequest {
		t.Fatalf("other browser = %d", got.Code)
	}
	id2, _ := e.pendingWindow()
	_, ck, form2 := e.signIn(id2, deciderClaims())
	e.ropts.Deciders = []string{glovoOwnerPRN}
	if got := e.confirm(ck, form2, "approve"); got.Code != http.StatusNotFound {
		t.Fatalf("removed decider = %d %s", got.Code, got.Body.String())
	}
	for _, x := range []string{id, id2} {
		if e.approval(x).State != workitems.ApprovalPending {
			t.Fatal("a refused confirm decided something")
		}
	}
	// Neither a missing decision nor a made-up one decides.
	id3, _ := e.pendingWindow()
	e.ropts.Deciders = []string{basketAdminPRN}
	_, ck3, form3 := e.signIn(id3, deciderClaims())
	for _, d := range []string{"", "approved", "yes"} {
		if got := e.confirm(ck3, form3, d); got.Code != http.StatusBadRequest {
			t.Fatalf("decision %q = %d", d, got.Code)
		}
	}
}

// The page's own clock bounds each step to the challenge lifetime.
func TestReleaseWindowPage_ChallengesExpire(t *testing.T) {
	e := newWindowPageEnv(t)
	d := e.h.releaseWindowApproval
	later := func() time.Time { return time.Now().Add(releaseChallengeTTL + time.Minute) }

	id, _ := e.pendingWindow()
	e.beforeCallback = func() { d.now = later }
	rec, _, form := e.signIn(id, deciderClaims())
	if rec.Code != http.StatusBadRequest || form.Get("csrf") != "" {
		t.Fatalf("late callback = %d %s", rec.Code, rec.Body.String())
	}
	e.beforeCallback, d.now = nil, time.Now

	id2, _ := e.pendingWindow()
	_, ck, form2 := e.signIn(id2, deciderClaims())
	d.now = later
	if got := e.confirm(ck, form2, "approve"); got.Code != http.StatusBadRequest {
		t.Fatalf("late confirm = %d %s", got.Code, got.Body.String())
	}
	d.now = time.Now
}

// What is not decidable is shown as what it is, with no decide form.
func TestReleaseWindowPage_NothingToDecide(t *testing.T) {
	e := newWindowPageEnv(t)
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		pool, err := pgxpool.New(ctx, e.connStr)
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	idExpired, _ := e.pendingWindow()
	exec(`UPDATE action_approval_requests SET expires_at = now() - interval '1 minute' WHERE id = $1`, idExpired)
	rec, _, form := e.signIn(idExpired, deciderClaims())
	if rec.Code != http.StatusOK || form.Get("csrf") != "" || !strings.Contains(rec.Body.String(), "expired") {
		t.Fatalf("expired: %d %s", rec.Code, rec.Body.String())
	}
	idDone, _ := e.pendingWindow()
	_, ck, f := e.signIn(idDone, deciderClaims())
	if got := e.confirm(ck, f, "reject"); got.Code != http.StatusOK {
		t.Fatalf("reject = %d", got.Code)
	}
	rec, _, form = e.signIn(idDone, deciderClaims())
	if rec.Code != http.StatusOK || form.Get("csrf") != "" || !strings.Contains(rec.Body.String(), "There is nothing to decide here") {
		t.Fatalf("decided: %d %s", rec.Code, rec.Body.String())
	}
}

// A record that does not reproduce its digests is not a window.
func TestReleaseWindowPage_RefusesInconsistentRecord(t *testing.T) {
	e := newWindowPageEnv(t)
	id, _ := e.pendingWindow()
	pool, err := pgxpool.New(context.Background(), e.connStr)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(context.Background(), `UPDATE action_approval_requests SET artifact_hash = $2 WHERE id = $1`,
		id, "sha256:"+strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	rec, _, form := e.signIn(id, deciderClaims())
	if rec.Code != http.StatusConflict || form.Get("csrf") != "" {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

// The two pages do not accept each other's rows, in either direction, and
// neither accepts the other's sign-in challenge.
func TestReleaseWindowPage_IsIsolatedFromTheGrantPage(t *testing.T) {
	e := newWindowPageEnv(t)
	winID, win := e.pendingWindow()
	hash, _ := win.WindowSHA256()
	grantID, art := e.pendingRelease()

	// A grant at the window page.
	rec, _, form := e.signIn(grantID, deciderClaims())
	if rec.Code != http.StatusNotFound || form.Get("csrf") != "" || strings.Contains(rec.Body.String(), art.ImageDigest) {
		t.Fatalf("grant row at the window page: %d %s", rec.Code, rec.Body.String())
	}
	// A window at the grant page.
	rec, _, form = e.releasePageEnv.signIn(winID, deciderClaims())
	if rec.Code != http.StatusNotFound || form.Get("csrf") != "" || strings.Contains(rec.Body.String(), hash) {
		t.Fatalf("window row at the grant page: %d %s", rec.Code, rec.Body.String())
	}
	for _, id := range []string{winID, grantID} {
		if e.approval(id).State != workitems.ApprovalPending {
			t.Fatalf("a cross-page sign-in decided %s", id)
		}
	}

	// A sign-in started on the grant page cannot be finished on the window
	// page, even with the browser value carried over under the window cookie.
	start := e.send(http.MethodPost, releaseStartPath, nil, url.Values{"approval_ref": {grantID}})
	u, _ := url.Parse(start.Header().Get("Location"))
	var browser string
	for _, c := range start.Result().Cookies() {
		if c.Name == releasePageCookie {
			browser = c.Value
		}
	}
	if browser == "" {
		t.Fatal("no grant cookie")
	}
	cb := e.send(http.MethodGet, releaseWindowCallbackPath+"?code=z-code&state="+url.QueryEscape(u.Query().Get("state")),
		&http.Cookie{Name: releaseWindowPageCookie, Value: browser}, nil)
	if cb.Code != http.StatusBadRequest {
		t.Fatalf("grant challenge at the window callback = %d %s", cb.Code, cb.Body.String())
	}
}

func TestReleaseWindowPage_NotEnabled(t *testing.T) {
	e := newWindowPageEnv(t)
	id, _ := e.pendingWindow()
	e.h.releaseWindowApproval = nil
	for _, c := range []struct{ method, target string }{
		{http.MethodGet, releaseWindowPagePrefix + id}, {http.MethodPost, releaseWindowStartPath},
		{http.MethodGet, releaseWindowCallbackPath}, {http.MethodPost, releaseWindowConfirmPath},
	} {
		rec := e.send(c.method, c.target, nil, nil)
		if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "not enabled") {
			t.Errorf("%s %s = %d %s", c.method, c.target, rec.Code, rec.Body.String())
		}
	}
}

// What confirm finds must still be what was shown: a decide entry whose
// binding was altered after the callback is refused and decides nothing.
func TestReleaseWindowPage_ConfirmRefusesAChangedBinding(t *testing.T) {
	e := newWindowPageEnv(t)
	id, _ := e.pendingWindow()
	_, ck, form := e.signIn(id, deciderClaims())
	ctx := context.Background()
	key := basketDecideKey(form.Get("challenge"), form.Get("csrf"), ck.Value)
	raw, found, err := e.ropts.Flow.Take(ctx, releaseWindowKindDecide, key)
	if err != nil || !found {
		t.Fatalf("take the decide entry: %v %v", found, err)
	}
	// Only the shown binding: the evidence keeps its own args digest, so the
	// store's own check cannot be what refuses this.
	altered := strings.Replace(string(raw), `"content_digest":"sha256:`, `"content_digest":"sha256:0`, 1)
	if altered == string(raw) {
		t.Fatalf("entry holds no shown content digest to alter: %s", raw)
	}
	if err := e.ropts.Flow.Put(ctx, releaseWindowKindDecide, key, []byte(altered), time.Minute); err != nil {
		t.Fatal(err)
	}
	got := e.confirm(ck, form, "approve")
	if got.Code != http.StatusConflict || !strings.Contains(got.Body.String(), "changed after you were shown it") {
		t.Fatalf("confirm = %d %s", got.Code, got.Body.String())
	}
	if e.approval(id).State != workitems.ApprovalPending {
		t.Fatal("approved on a binding that changed")
	}
}

// The policy the request was asked under is read again at approve.
func TestReleaseWindowPage_ApproveRefusesAPolicyThatIsNotCurrent(t *testing.T) {
	e := newWindowPageEnv(t)
	e.h.opts.RequireRegisteredPolicy = true
	id, _ := e.pendingWindow()
	_, ck, form := e.signIn(id, deciderClaims())
	pool, err := pgxpool.New(context.Background(), e.connStr)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(context.Background(), `UPDATE action_approval_requests SET policy_version = '99' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	got := e.confirm(ck, form, "approve")
	if got.Code != http.StatusConflict || !strings.Contains(got.Body.String(), "policy this approval was asked under is not current") {
		t.Fatalf("confirm = %d %s", got.Code, got.Body.String())
	}
	if e.approval(id).State != workitems.ApprovalPending {
		t.Fatal("approved under a policy that is not current")
	}
}

// An approval that lapses between the sign-in and the click is not decided.
func TestReleaseWindowPage_ConfirmRefusesAnApprovalThatExpired(t *testing.T) {
	e := newWindowPageEnv(t)
	id, _ := e.pendingWindow()
	_, ck, form := e.signIn(id, deciderClaims())
	pool, err := pgxpool.New(context.Background(), e.connStr)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(context.Background(), `UPDATE action_approval_requests SET expires_at = now() - interval '1 minute' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if got := e.confirm(ck, form, "approve"); got.Code != http.StatusConflict {
		t.Fatalf("confirm = %d %s", got.Code, got.Body.String())
	}
	if a := e.approval(id); a.State == workitems.ApprovalApproved {
		t.Fatal("approved an expired request")
	}
}

func TestReleaseWindowPage_DecideURL(t *testing.T) {
	e := newWindowPageEnv(t)
	id, _ := e.pendingWindow()
	if got, want := e.h.releaseWindowApproval.decideURL(id), "https://api.example"+releaseWindowPagePrefix+id; got != want {
		t.Fatalf("decideURL = %s, want %s", got, want)
	}
}
