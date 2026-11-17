package api

import (
	"context"
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"html"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/auth/flowstore"
	"github.com/mctlhq/mctl-api/internal/releaseartifact"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// mctl-api#1022 slice S2: a release.grant is decided only by a configured
// decider, signed in fresh with a second factor, through the release page's
// own client, and only while the tag and the image are still what the
// request binds.

type pageReleaseResolver struct {
	mu  sync.Mutex
	out map[string]workitems.ReleaseArtifact
	err map[string]error
}

func (f *pageReleaseResolver) Resolve(_ context.Context, repo, version string) (workitems.ReleaseArtifact, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.err[version]; err != nil {
		return workitems.ReleaseArtifact{}, err
	}
	a, ok := f.out[version]
	if !ok || a.Repository != repo {
		return workitems.ReleaseArtifact{}, releaseartifact.ErrNotFound
	}
	return a, nil
}

func (f *pageReleaseResolver) set(version string, a *workitems.ReleaseArtifact, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if a != nil {
		f.out[version] = *a
	}
	if err != nil {
		f.err[version] = err
	} else {
		delete(f.err, version)
	}
}

type releasePageEnv struct {
	*basketEnv
	resolver *pageReleaseResolver
	ropts    *ReleaseApprovalPageOptions
	// beforeCallback runs between the start and the callback.
	beforeCallback func()
}

var releasePageSeq atomic.Int64

func newReleasePageEnv(t *testing.T) *releasePageEnv {
	t.Helper()
	b := newBasketEnv(t)
	e := &releasePageEnv{basketEnv: b, resolver: &pageReleaseResolver{out: map[string]workitems.ReleaseArtifact{}, err: map[string]error{}}}
	b.h.opts.ReleaseGrants = &ReleaseGrantOptions{Resolver: e.resolver, Repositories: []string{"mctlhq/mctl-api"}}
	b.idp.clientID, b.idp.clientSecret = "release-client", "release-secret"
	o := *b.opts
	e.ropts = &ReleaseApprovalPageOptions{
		ProviderName: o.ProviderName, Issuer: o.Issuer, ClientID: "release-client", ClientSecret: "release-secret",
		BaseURL: o.BaseURL, Principals: o.Principals, Authz: o.Authz, Flow: o.Flow,
		Deciders: []string{basketAdminPRN}, RequiredAMR: []string{"mfa"},
	}
	b.h.releaseApproval = newReleaseDecider(e.ropts)
	b.page = releaseRouter(b.h)
	t.Cleanup(func() {
		ctx := context.Background()
		if pool, err := pgxpool.New(ctx, b.connStr); err == nil {
			_, _ = pool.Exec(ctx, `DELETE FROM action_approval_requests WHERE action_kind=$1 AND target LIKE 'mctlhq/mctl-api@88.%'`, workitems.ActionKindReleaseGrant)
			pool.Close()
		}
	})
	return e
}

func releaseRouter(h *Handlers) http.Handler {
	r := chi.NewRouter()
	r.Post(releaseStartPath, h.handleReleaseApprovalStart)
	r.Get(releaseCallbackPath, h.handleReleaseApprovalCallback)
	r.Post(releaseConfirmPath, h.handleReleaseApprovalConfirm)
	r.Get(releasePagePrefix+"{approval_ref}", h.handleReleaseApprovalPage)
	return r
}

// pendingRelease publishes a release to the resolver and opens its grant.
func (e *releasePageEnv) pendingRelease() (string, workitems.ReleaseArtifact) {
	e.t.Helper()
	n, err := crand.Int(crand.Reader, big.NewInt(1_000_000_000))
	if err != nil {
		e.t.Fatal(err)
	}
	version := fmt.Sprintf("88.%d.%d", n.Int64(), releasePageSeq.Add(1))
	art := workitems.ReleaseArtifact{Repository: "mctlhq/mctl-api", Version: version,
		TagCommit: strings.Repeat("a", 40), ImageDigest: "sha256:" + strings.Repeat("b", 64)}
	e.resolver.set(version, &art, nil)
	pol := e.h.approvalPolicies()[workitems.ReleaseGrantPolicyRuleID]
	a, _, err := e.h.opts.WorkItems.CreateReleaseApproval(context.Background(), art, workitems.ActionApprovalInput{
		ActionIntent: workitems.ReleaseIntent(art), RequestedBy: "principal:" + glovoOtherPRN, RequestedByPrincipalID: glovoOtherPRN,
		ActorKind: "agent", ActorName: "claude-code",
		IdempotencyKey: workitems.ReleaseIdempotencyKey(art), ExpiresAt: time.Now().Add(time.Hour), RiskLevel: "high",
		IntentSource: "release:" + workitems.ReleaseTarget(art.Repository, art.Version),
		SideEffect:   pol.SideEffect, PolicyDecision: pol.Decision, PolicyReasons: append([]string(nil), pol.Reasons...),
	})
	if err != nil {
		e.t.Fatalf("CreateReleaseApproval: %v", err)
	}
	return a.ID, art
}

// signIn opens the link, starts the sign-in and comes back from ZITADEL with
// the given ID token claims.
func (e *releasePageEnv) signIn(ref string, claims map[string]any) (*httptest.ResponseRecorder, *http.Cookie, url.Values) {
	e.t.Helper()
	page := e.send(http.MethodGet, releasePagePrefix+ref, nil, nil)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `action="`+releaseStartPath+`"`) {
		e.t.Fatalf("link page = %d %s", page.Code, page.Body.String())
	}
	if len(page.Result().Cookies()) != 0 || strings.Contains(page.Body.String(), "sha256:") {
		e.t.Fatal("the link page set state or showed the release")
	}
	start := e.send(http.MethodPost, releaseStartPath, nil, url.Values{"approval_ref": {ref}})
	if start.Code != http.StatusSeeOther {
		e.t.Fatalf("start = %d %s", start.Code, start.Body.String())
	}
	var ck *http.Cookie
	for _, c := range start.Result().Cookies() {
		if c.Name == releasePageCookie {
			ck = c
		}
	}
	if ck == nil || !ck.HttpOnly || !ck.Secure || ck.Path != "/" || ck.Domain != "" {
		e.t.Fatalf("cookie = %+v", ck)
	}
	u, _ := url.Parse(start.Header().Get("Location"))
	q := u.Query()
	if q.Get("client_id") != "release-client" || q.Get("code_challenge_method") != "S256" || q.Get("prompt") != "login" ||
		q.Get("max_age") != "0" || q.Get("nonce") == "" || q.Get("redirect_uri") != "https://api.example"+releaseCallbackPath {
		e.t.Fatalf("authorize URL %s", u)
	}
	e.idp.mu.Lock()
	e.idp.challenge, e.idp.nonce = q.Get("code_challenge"), q.Get("nonce")
	e.idp.extra = claims
	e.idp.mu.Unlock()
	if e.beforeCallback != nil {
		e.beforeCallback()
	}
	rec := e.send(http.MethodGet, releaseCallbackPath+"?code=z-code&state="+url.QueryEscape(q.Get("state")), ck, nil)
	form := url.Values{}
	for _, m := range basketField.FindAllStringSubmatch(rec.Body.String(), -1) {
		form.Set(m[1], html.UnescapeString(m[2]))
	}
	return rec, ck, form
}

func (e *releasePageEnv) confirm(ck *http.Cookie, form url.Values, decision string) *httptest.ResponseRecorder {
	return e.send(http.MethodPost, releaseConfirmPath, ck, url.Values{
		"challenge": {form.Get("challenge")}, "csrf": {form.Get("csrf")}, "decision": {decision},
	})
}

func (e *releasePageEnv) approval(id string) *workitems.ActionApprovalRequest {
	e.t.Helper()
	a, err := e.h.opts.WorkItems.ActionApproval(context.Background(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	return a
}

func deciderClaims() map[string]any {
	return map[string]any{"sub": "z-admin", "amr": []string{"pwd", "mfa", "user", "mfa"}}
}

func TestReleaseApprovalPage_DeciderApprovesWithEvidence(t *testing.T) {
	e := newReleasePageEnv(t)
	id, art := e.pendingRelease()
	rec, ck, form := e.signIn(id, deciderClaims())
	body := rec.Body.String()
	if rec.Code != http.StatusOK || form.Get("csrf") == "" || !strings.Contains(body, art.ImageDigest) ||
		!strings.Contains(body, art.TagCommit) || !strings.Contains(body, art.Version) {
		t.Fatalf("callback = %d %s", rec.Code, body)
	}
	if e.approval(id).State != workitems.ApprovalPending {
		t.Fatal("showing the release decided it")
	}
	got := e.confirm(ck, form, "approve")
	if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "Release approved") {
		t.Fatalf("confirm = %d %s", got.Code, got.Body.String())
	}
	a := e.approval(id)
	ev, err := workitems.ReleaseDecisionOf(a)
	if a.State != workitems.ApprovalApproved || a.DecidedByPrincipalID != basketAdminPRN || err != nil || ev == nil {
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

// ZITADEL puts the project id and the project's other client ids into aud
// next to this client's id, and names this client in azp. That is a token
// issued to this page and must be accepted (first real sign-in, 2026-11-17).
func TestReleaseApprovalPage_AcceptsZitadelAudience(t *testing.T) {
	e := newReleasePageEnv(t)
	id, art := e.pendingRelease()
	c := deciderClaims()
	c["aud"] = []string{"release-client", "369000000000000001", "deploy-client@mctl"}
	c["azp"] = "release-client"
	rec, _, form := e.signIn(id, c)
	if rec.Code != http.StatusOK || form.Get("csrf") == "" || !strings.Contains(rec.Body.String(), art.ImageDigest) {
		t.Fatalf("callback = %d %s", rec.Code, rec.Body.String())
	}
}

func TestReleaseApprovalPage_DeciderRejects(t *testing.T) {
	e := newReleasePageEnv(t)
	id, _ := e.pendingRelease()
	_, ck, form := e.signIn(id, deciderClaims())
	if got := e.confirm(ck, form, "reject"); got.Code != http.StatusOK {
		t.Fatalf("reject = %d %s", got.Code, got.Body.String())
	}
	a := e.approval(id)
	if ev, err := workitems.ReleaseDecisionOf(a); a.State != workitems.ApprovalDenied || ev == nil || err != nil {
		t.Fatalf("rejected row %+v %v %v", a, ev, err)
	}
}

// Every sign-in the page must not trust is refused at the callback, shows no
// release, and decides nothing.
func TestReleaseApprovalPage_RefusesSignIns(t *testing.T) {
	e := newReleasePageEnv(t)
	id, art := e.pendingRelease()
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
		{name: "no amr", claims: with(map[string]any{"amr": nil}), want: http.StatusForbidden, body: "amr: none"},
		{name: "password only", claims: with(map[string]any{"amr": []string{"pwd", "user"}}), want: http.StatusForbidden, body: "amr: pwd, user"},
		{name: "several audiences without azp", claims: with(map[string]any{"aud": []string{"release-client", "mcp-client"}}), want: http.StatusBadRequest},
		{name: "authorized party is another client", claims: with(map[string]any{"azp": "mcp-client"}), want: http.StatusBadRequest},
		{name: "zitadel shape minted for another client", claims: with(map[string]any{"aud": []string{"mcp-client", "release-client", "369000000000000001"}, "azp": "mcp-client"}), want: http.StatusBadRequest},
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
			if rec.Code != c.want || form.Get("csrf") != "" || strings.Contains(b, art.ImageDigest) {
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

// The release is read again at the callback and at confirm: a moved tag or
// image, or a registry that cannot be read, decides nothing.
func TestReleaseApprovalPage_ReadsTheReleaseAgain(t *testing.T) {
	e := newReleasePageEnv(t)
	moved := func(a workitems.ReleaseArtifact) *workitems.ReleaseArtifact {
		a.ImageDigest = "sha256:" + strings.Repeat("c", 64)
		return &a
	}
	t.Run("moved before the callback", func(t *testing.T) {
		id, art := e.pendingRelease()
		e.resolver.set(art.Version, moved(art), nil)
		rec, _, form := e.signIn(id, deciderClaims())
		if rec.Code != http.StatusConflict || form.Get("csrf") != "" {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("registry down at the callback", func(t *testing.T) {
		id, art := e.pendingRelease()
		e.resolver.set(art.Version, nil, fmt.Errorf("x: %w", releaseartifact.ErrUnavailable))
		rec, _, form := e.signIn(id, deciderClaims())
		if rec.Code != http.StatusServiceUnavailable || form.Get("csrf") != "" {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("moved before confirm", func(t *testing.T) {
		id, art := e.pendingRelease()
		_, ck, form := e.signIn(id, deciderClaims())
		e.resolver.set(art.Version, moved(art), nil)
		if got := e.confirm(ck, form, "approve"); got.Code != http.StatusConflict {
			t.Fatalf("confirm = %d %s", got.Code, got.Body.String())
		}
		if e.approval(id).State != workitems.ApprovalPending {
			t.Fatal("approved a release that moved")
		}
	})
	t.Run("tag gone before confirm", func(t *testing.T) {
		id, art := e.pendingRelease()
		_, ck, form := e.signIn(id, deciderClaims())
		e.resolver.set(art.Version, nil, releaseartifact.ErrNotFound)
		if got := e.confirm(ck, form, "approve"); got.Code != http.StatusConflict {
			t.Fatalf("confirm = %d %s", got.Code, got.Body.String())
		}
		if e.approval(id).State != workitems.ApprovalPending {
			t.Fatal("approved a release whose tag is gone")
		}
	})
}

// The decide form belongs to the browser that signed in, and the decider
// list is read again at confirm.
func TestReleaseApprovalPage_ConfirmIsBound(t *testing.T) {
	e := newReleasePageEnv(t)
	id, _ := e.pendingRelease()
	_, _, form := e.signIn(id, deciderClaims())
	other := &http.Cookie{Name: releasePageCookie, Value: "another-browser"}
	if got := e.confirm(other, form, "approve"); got.Code != http.StatusBadRequest {
		t.Fatalf("other browser = %d", got.Code)
	}
	id2, _ := e.pendingRelease()
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
}

// The page's own clock bounds each step to the challenge lifetime, not only
// the flow store's TTL.
func TestReleaseApprovalPage_ChallengesExpire(t *testing.T) {
	e := newReleasePageEnv(t)
	d := e.h.releaseApproval
	later := func() time.Time { return time.Now().Add(releaseChallengeTTL + time.Minute) }

	id, _ := e.pendingRelease()
	e.beforeCallback = func() { d.now = later }
	rec, _, form := e.signIn(id, deciderClaims())
	if rec.Code != http.StatusBadRequest || form.Get("csrf") != "" {
		t.Fatalf("late callback = %d %s", rec.Code, rec.Body.String())
	}
	e.beforeCallback, d.now = nil, time.Now

	id2, _ := e.pendingRelease()
	_, ck, form2 := e.signIn(id2, deciderClaims())
	d.now = later
	if got := e.confirm(ck, form2, "approve"); got.Code != http.StatusBadRequest {
		t.Fatalf("late confirm = %d %s", got.Code, got.Body.String())
	}
	d.now = time.Now
	for _, x := range []string{id, id2} {
		if e.approval(x).State != workitems.ApprovalPending {
			t.Fatal("an expired challenge decided something")
		}
	}
}

// Not a release grant: the page answers as if there were no such approval.
func TestReleaseApprovalPage_OnlyReleaseGrants(t *testing.T) {
	e := newReleasePageEnv(t)
	rec, _, _ := e.signIn("aar_"+strings.Repeat("0", 32), deciderClaims())
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown ref = %d", rec.Code)
	}
	gen, _, err := e.h.opts.WorkItems.CreateActionApproval(context.Background(), workitems.ActionApprovalInput{
		ActionIntent: workitems.ActionIntent{ExecutionID: e.tenant + "-ex", ActionKind: "service.deploy", Target: e.tenant + "/web",
			ArgsDigest: "sha256:" + strings.Repeat("1", 64), PolicyRuleID: "r", PolicyVersion: "1"},
		RequestedBy: "oidc:a", IdempotencyKey: e.tenant + "-generic", ExpiresAt: time.Now().Add(time.Hour),
		RiskLevel: "high", IntentSource: "execution:" + e.tenant + "-ex", SideEffect: "write", PolicyDecision: "require_approval", PolicyReasons: []string{"r"},
	})
	if err != nil {
		t.Fatal(err)
	}
	rec, _, form := e.signIn(gen.ID, deciderClaims())
	if rec.Code != http.StatusNotFound || form.Get("csrf") != "" || strings.Contains(rec.Body.String(), "service.deploy") {
		t.Fatalf("generic approval = %d %s", rec.Code, rec.Body.String())
	}
}

func TestReleaseApprovalPage_DarkByDefault(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	h.handleReleaseApprovalPage(rec, httptest.NewRequest(http.MethodGet, releasePagePrefix+"aar_"+strings.Repeat("0", 32), nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no page configured = %d", rec.Code)
	}
	for name, mut := range map[string]func(*ReleaseApprovalPageOptions){
		"no deciders": func(o *ReleaseApprovalPageOptions) { o.Deciders = nil },
		"no amr":      func(o *ReleaseApprovalPageOptions) { o.RequiredAMR = nil },
		"no client":   func(o *ReleaseApprovalPageOptions) { o.ClientID = "" },
	} {
		o := ReleaseApprovalPageOptions{ProviderName: "z", Issuer: "https://i", ClientID: "c", ClientSecret: "s", BaseURL: "https://b",
			Principals: &fakeSignInPrincipals{}, Authz: &auth.PrincipalAuthz{}, Flow: &flowstore.PostgresStore{},
			Deciders: []string{"p"}, RequiredAMR: []string{"mfa"}}
		if !o.enabled() {
			t.Fatalf("complete options: not enabled")
		}
		mut(&o)
		if o.enabled() {
			t.Errorf("%s: enabled", name)
		}
	}
}

func (e *releasePageEnv) asAdmin(h http.HandlerFunc, method, target string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.WithUser(req.Context(), &auth.User{ID: "test-admin", Groups: []string{"admins"}}))
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

// A request answers the page's link when the page is on, and says it cannot
// be decided when it is off.
func TestReleaseGrantRequestAnswersTheDecideLink(t *testing.T) {
	e := newReleasePageEnv(t)
	_, art := e.pendingRelease()
	body := `{"repository":"mctlhq/mctl-api","version":"` + art.Version + `"}`
	var out map[string]any
	rec := e.asAdmin(e.h.RequestReleaseGrant, http.MethodPost, "/api/v1/release/grants", body)
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code >= 300 {
		t.Fatalf("request = %d %s", rec.Code, rec.Body.String())
	}
	grant, _ := out["grant"].(map[string]any)
	approval, _ := grant["approval"].(map[string]any)
	id, _ := approval["id"].(string)
	if id == "" || out["decide_url"] != "https://api.example"+releasePagePrefix+id || out["decide_unavailable"] != nil {
		t.Fatalf("page on: %v", out)
	}
	e.h.releaseApproval = nil
	rec = e.asAdmin(e.h.RequestReleaseGrant, http.MethodPost, "/api/v1/release/grants", body)
	out = nil
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code >= 300 {
		t.Fatalf("request = %d %s", rec.Code, rec.Body.String())
	}
	if out["decide_url"] != nil || out["decide_unavailable"] == nil {
		t.Fatalf("page off: %v", out)
	}
}

// The list carries the verified evidence of a decided grant, and none for a
// pending one.
func TestReleaseGrantListCarriesTheDecision(t *testing.T) {
	e := newReleasePageEnv(t)
	id, art := e.pendingRelease()
	list := func() map[string]any {
		t.Helper()
		rec := e.asAdmin(e.h.ListReleaseGrants, http.MethodGet,
			"/api/v1/release/grants?repository=mctlhq/mctl-api&version="+art.Version, "")
		var out struct {
			Grants []map[string]any `json:"grants"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != http.StatusOK || len(out.Grants) != 1 {
			t.Fatalf("list = %d %s", rec.Code, rec.Body.String())
		}
		return out.Grants[0]
	}
	if g := list(); g["decision"] != nil {
		t.Fatalf("pending grant has a decision: %v", g)
	}
	_, ck, form := e.signIn(id, deciderClaims())
	if got := e.confirm(ck, form, "approve"); got.Code != http.StatusOK {
		t.Fatalf("confirm = %d", got.Code)
	}
	d, _ := list()["decision"].(map[string]any)
	if d["client_id"] != "release-client" || d["subject"] != "z-admin" || d["schema"] != workitems.ReleaseEvidenceSchema {
		t.Fatalf("decision = %v", d)
	}
}

// issuedToClient is checked on its own too: at the callback go-oidc already
// refuses an aud without the client id, which would hide a regression here.
func TestIssuedToClient(t *testing.T) {
	cases := []struct {
		aud, azp string
		want     bool
	}{
		{`"release-client"`, "", true},
		{`"release-client"`, "release-client", true},
		{`["release-client"]`, "", true},
		{`["release-client","369000000000000001","deploy-client@mctl"]`, "release-client", true},
		{`["release-client","mcp-client"]`, "", false},
		{`["release-client","mcp-client"]`, "mcp-client", false},
		{`"release-client"`, "mcp-client", false},
		{`["mcp-client","369000000000000001"]`, "release-client", false},
		{`"mcp-client"`, "release-client", false},
		{`[]`, "release-client", false},
		{`null`, "release-client", false},
		{`""`, "", false},
		{`{"a":1}`, "release-client", false},
	}
	for _, c := range cases {
		if got := issuedToClient(json.RawMessage(c.aud), c.azp, "release-client"); got != c.want {
			t.Errorf("issuedToClient(%s, %q) = %v, want %v", c.aud, c.azp, got, c.want)
		}
	}
	if issuedToClient(json.RawMessage(`""`), "", "") {
		t.Error("an empty client id matched an empty aud")
	}
}
