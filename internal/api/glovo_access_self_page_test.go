// Copyright 2026 MCTL Authors
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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovoconsent"
	"github.com/mctlhq/mctl-api/internal/principals"
)

// Glovo access page for the person asking (mctl-glovo#82).

const (
	selfClientID     = "self-client"
	selfClientSecret = "self-secret"
	selfBaseURL      = "https://api.example"
	// selfUsername is the preferred_username of every fake sign-in: an
	// email-shaped login, which no page, flow entry, log line or audit row
	// may carry.
	selfUsername = "new.customer@gmail.example"
	selfOtherOrg = "393497610436019469"
)

// selfEmailShaped is what the edge in front of the page rewrites.
var selfEmailShaped = regexp.MustCompile(`\S+@\S+\.\S+`)

// memFlowStore is an in-memory flowstore.Store: an atomic Take, entries that
// expire on the test's clock, and an injectable failure.
type memFlowStore struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]memFlowEntry
	err     error
	// ignoreTTL keeps expired entries readable, so a test can hold the
	// handler's own lifetime check to account.
	ignoreTTL bool
	// ttls records the lifetime of every Put, by kind.
	ttls map[string][]time.Duration
}

type memFlowEntry struct {
	payload []byte
	expires time.Time
}

func (m *memFlowStore) Put(_ context.Context, kind, key string, payload []byte, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.entries[kind+"\x00"+key] = memFlowEntry{payload: append([]byte(nil), payload...), expires: m.now().Add(ttl)}
	m.ttls[kind] = append(m.ttls[kind], ttl)
	return nil
}

func (m *memFlowStore) Take(_ context.Context, kind, key string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return nil, false, m.err
	}
	e, ok := m.entries[kind+"\x00"+key]
	if !ok {
		return nil, false, nil
	}
	delete(m.entries, kind+"\x00"+key)
	if !m.ignoreTTL && !m.now().Before(e.expires) {
		return nil, false, nil
	}
	return e.payload, true, nil
}

func (m *memFlowStore) PutOnce(context.Context, string, string, []byte, time.Duration) (bool, error) {
	return false, errors.New("not used by this page")
}

func (m *memFlowStore) GC(context.Context) error { return nil }

func (m *memFlowStore) fail(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.err = err
}

func (m *memFlowStore) payloads() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var b strings.Builder
	for k, e := range m.entries {
		b.WriteString(k + "=" + string(e.payload) + "\n")
	}
	return b.String()
}

// selfPagePrincipals resolves a ZITADEL subject to a principal and records what
// it was asked.
type selfPagePrincipals struct {
	mu    sync.Mutex
	ids   map[string]string
	err   error
	calls []auth.Identity
}

func (f *selfPagePrincipals) ResolvePrincipal(_ context.Context, id auth.Identity) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, id)
	if f.err != nil {
		return "", f.err
	}
	if p, ok := f.ids[id.Subject]; ok {
		return p, nil
	}
	return "", auth.ErrIdentityRefused
}

func (f *selfPagePrincipals) set(ids map[string]string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ids != nil {
		f.ids = ids
	}
	f.err = err
}

func (f *selfPagePrincipals) asked() []auth.Identity {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]auth.Identity(nil), f.calls...)
}

type selfEnv struct {
	t      *testing.T
	idp    *fakeIdP
	prn    *selfPagePrincipals
	cs     *memConsentStore
	as     *memAccessStore
	flow   *memFlowStore
	audit  *audit.Logger
	opts   *GlovoAccessSelfPageOptions
	router http.Handler

	mu  sync.Mutex
	now time.Time
	// bodies is every response body the page rendered in this test.
	bodies []string
}

func (e *selfEnv) clock() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.now
}

func (e *selfEnv) advance(d time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.now = e.now.Add(d)
}

// selfSetup is what a test may change before the router is built.
type selfSetup struct {
	capacity int
	opts     func(*GlovoAccessSelfPageOptions)
	routes   func(*GlovoConsentRoutes) *GlovoConsentRoutes
	mode     TenantAuthzMode
	nilOpts  bool
}

func newSelfEnv(t *testing.T, s selfSetup) *selfEnv {
	t.Helper()
	e := &selfEnv{t: t, idp: newFakeIdP(t), cs: newMemConsentStore(), as: newMemAccessStore(), audit: audit.NewLogger(),
		prn: &selfPagePrincipals{ids: map[string]string{"z-sub": consentPIDA}}, now: time.Now()}
	e.idp.clientID, e.idp.clientSecret = selfClientID, selfClientSecret
	e.idp.redirectURI = selfBaseURL + glovoAccessSelfCallbackPath
	e.idp.username = selfUsername
	e.idp.extra = googleCustomerClaims()
	e.flow = &memFlowStore{now: e.clock, entries: map[string]memFlowEntry{}, ttls: map[string][]time.Duration{}}
	if s.capacity == 0 {
		s.capacity = consentCap
	}
	g := mountedConsent(e.cs, s.capacity)
	g.Access = e.as
	if s.routes != nil {
		g = s.routes(g)
	}
	e.opts = &GlovoAccessSelfPageOptions{
		ProviderName: "zitadel", Issuer: e.idp.srv.URL, ClientID: selfClientID, ClientSecret: selfClientSecret,
		BaseURL: selfBaseURL, Principals: e.prn, Flow: e.flow,
		CustomersOrgID: testCustomersOrg, CustomersGoogleIdPID: testCustomersGoogleIdP, clock: e.clock,
	}
	if s.opts != nil {
		s.opts(e.opts)
	}
	if s.mode == "" {
		s.mode = TenantAuthzPrincipal
	}
	opts := e.opts
	if s.nilOpts {
		opts = nil
	}
	e.router = NewRouter(Options{
		AuthMiddleware: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
			})
		},
		GlovoConsent: g, AuditLog: e.audit, TenantAuthzMode: s.mode, GlovoAccessSelf: opts,
		mcpHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
	})
	return e
}

// do sends one request and holds every answer to the page's hard rule: no
// body carries anything email-shaped, the login, or an unmasked identifier.
func (e *selfEnv) do(method, target string, form url.Values, ck *http.Cookie) *httptest.ResponseRecorder {
	e.t.Helper()
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
	e.router.ServeHTTP(rec, req)
	body := rec.Body.String()
	e.bodies = append(e.bodies, body)
	if m := selfEmailShaped.FindString(body); m != "" {
		e.t.Errorf("%s %s: the body holds something email-shaped: %q", method, target, m)
	}
	for _, secret := range []string{selfUsername, "new.customer", consentPIDA, consentPIDB, testGoogleSub, "z-sub"} {
		if strings.Contains(body, secret) {
			e.t.Errorf("%s %s: the body holds %q", method, target, secret)
		}
	}
	return rec
}

func selfCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == glovoAccessSelfCookie {
			return ck
		}
	}
	t.Fatalf("no %s cookie in %v", glovoAccessSelfCookie, rec.Header())
	return nil
}

// start begins a sign-in and tells the fake IdP what the browser was sent
// with. It returns the browser cookie and the state.
func (e *selfEnv) start() (*http.Cookie, string) {
	e.t.Helper()
	rec := e.do("POST", glovoAccessSelfStartPath, url.Values{}, nil)
	if rec.Code != http.StatusSeeOther {
		e.t.Fatalf("start = %d %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil || !strings.HasPrefix(loc, e.idp.srv.URL+"/authorize") {
		e.t.Fatalf("not sent to ZITADEL: %q", loc)
	}
	q := u.Query()
	e.idp.mu.Lock()
	e.idp.challenge, e.idp.nonce = q.Get("code_challenge"), q.Get("nonce")
	e.idp.mu.Unlock()
	return selfCookie(e.t, rec), q.Get("state")
}

func (e *selfEnv) callback(ck *http.Cookie, state string) *httptest.ResponseRecorder {
	e.t.Helper()
	return e.do("GET", glovoAccessSelfCallbackPath+"?code=z-code&state="+url.QueryEscape(state), nil, ck)
}

// signIn runs a whole sign-in and returns the state page.
func (e *selfEnv) signIn() (*http.Cookie, *httptest.ResponseRecorder) {
	e.t.Helper()
	ck, state := e.start()
	return ck, e.callback(ck, state)
}

func (e *selfEnv) mustSignIn() (*http.Cookie, *httptest.ResponseRecorder) {
	e.t.Helper()
	ck, rec := e.signIn()
	if rec.Code != http.StatusOK {
		e.t.Fatalf("sign-in = %d %s", rec.Code, rec.Body.String())
	}
	return ck, rec
}

func selfForm(body string) url.Values {
	form := url.Values{}
	for _, m := range basketField.FindAllStringSubmatch(body, -1) {
		form.Set(m[1], m[2])
	}
	return form
}

var selfButton = regexp.MustCompile(`name="action" value="([a-z_]+)"`)

func selfButtons(body string) []string {
	var out []string
	for _, m := range selfButton.FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	return out
}

// act posts one action with the one-time form of page.
func (e *selfEnv) act(ck *http.Cookie, page *httptest.ResponseRecorder, action string) *httptest.ResponseRecorder {
	e.t.Helper()
	form := selfForm(page.Body.String())
	if form.Get("challenge") == "" || form.Get("csrf") == "" {
		e.t.Fatalf("the page carries no form: %d %s", page.Code, page.Body.String())
	}
	form.Set("action", action)
	return e.do("POST", glovoAccessSelfConfirmPath, form, ck)
}

func (e *selfEnv) consented() {
	e.cs.mu.Lock()
	defer e.cs.mu.Unlock()
	e.cs.active[consentPIDA] = glovoconsent.Record{ID: "gcn_" + consentPIDA, PrincipalID: consentPIDA, Version: glovoconsent.Version, RecordedAt: time.Now().UTC()}
}

func (e *selfEnv) calls() string {
	e.cs.mu.Lock()
	rc := e.cs.recordCalls
	_, consent := e.cs.active[consentPIDA]
	e.cs.mu.Unlock()
	e.as.mu.Lock()
	defer e.as.mu.Unlock()
	return fmt.Sprintf("record=%d consent=%v request=%d reject=%d rows=%d", rc, consent, e.as.reqCalls, e.as.rejectCalls, len(e.as.rows))
}

// selfEventLabels is every label pair of the consent counter the bearer
// routes and the page may write for an action.
var selfEventLabels = func() [][2]string {
	var out [][2]string
	for route, outcomes := range map[string][]string{
		"human_record":       {"recorded", "unchanged", "capacity_reached", "store_error", "store_inconsistent"},
		"human_revoke":       {"revoked", "none", "store_error"},
		"access_request":     {"opened", "unchanged", "already_approved", "store_error", "consent_required", "rate_limited"},
		"access_withdraw":    {"withdrawn", "unchanged", "store_error"},
		"access_self_signin": {"ok", "not_google", "conflict", "disabled", "unavailable", "store_error"},
		"access_self_action": {"not_valid", "conflict", "disabled", "unavailable", "store_error", "principal_changed"},
	} {
		for _, o := range outcomes {
			out = append(out, [2]string{route, o})
		}
	}
	return out
}()

func selfEvents() map[[2]string]float64 {
	out := map[[2]string]float64{}
	for _, l := range selfEventLabels {
		out[l] = testutil.ToFloat64(glovoConsentEvents.WithLabelValues(l[0], l[1]))
	}
	return out
}

// selfEventDelta is what moved since before, without the page's own
// sign-in and flow counters when actionsOnly is set.
func selfEventDelta(before map[[2]string]float64, actionsOnly bool) map[[2]string]float64 {
	out := map[[2]string]float64{}
	for l, v := range selfEvents() {
		if d := v - before[l]; d != 0 && !(actionsOnly && strings.HasPrefix(l[0], "access_self_")) {
			out[l] = d
		}
	}
	return out
}

// selfAuditRow is the part of an audit row the page must share with the
// bearer route.
type selfAuditRow struct {
	Op, Status, Risk, Refusal string
	Params                    map[string]string
}

func selfAuditRows(l *audit.Logger, from int) []selfAuditRow {
	all := l.List(0)
	var out []selfAuditRow
	for i := len(all) - 1 - from; i >= 0; i-- {
		en := all[i]
		p := map[string]string{}
		for k, v := range en.Parameters {
			if k != "surface" {
				p[k] = v
			}
		}
		out = append(out, selfAuditRow{Op: en.Operation, Status: en.Status, Risk: en.RiskLevel, Refusal: en.RefusalCode, Params: p})
	}
	return out
}

// --- the static page and the mount ----------------------------------------

func TestGlovoAccessSelfStaticPage(t *testing.T) {
	e := newSelfEnv(t, selfSetup{})
	rec := e.do("GET", glovoAccessSelfPath, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("page = %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Sign in with Google", "same Google account you connect your assistant with", "Record your consent",
		"Request access", "Wait for the approval", "consent version " + glovoconsent.Version,
		`href="https://glovo.mctl.ai/link"`, `method="post" action="` + glovoAccessSelfStartPath + `"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q:\n%s", want, body)
		}
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Errorf("the static page set a cookie: %v", rec.Header())
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("headers: %v", rec.Header())
	}
	if got := e.calls(); got != "record=0 consent=false request=0 reject=0 rows=0" || len(e.prn.asked()) != 0 || e.flow.payloads() != "" {
		t.Errorf("the static page touched state: %s, flow %q", got, e.flow.payloads())
	}
}

// Off, incomplete, outside principal mode or without the access store: every
// path of the page is the router's 404.
func TestGlovoAccessSelfUnmountedIs404(t *testing.T) {
	setups := map[string]selfSetup{
		"no options":        {nilOpts: true},
		"no provider":       {opts: func(o *GlovoAccessSelfPageOptions) { o.ProviderName = "" }},
		"no issuer":         {opts: func(o *GlovoAccessSelfPageOptions) { o.Issuer = "" }},
		"no client id":      {opts: func(o *GlovoAccessSelfPageOptions) { o.ClientID = "" }},
		"no client secret":  {opts: func(o *GlovoAccessSelfPageOptions) { o.ClientSecret = "" }},
		"no base URL":       {opts: func(o *GlovoAccessSelfPageOptions) { o.BaseURL = "" }},
		"no principals":     {opts: func(o *GlovoAccessSelfPageOptions) { o.Principals = nil }},
		"no flow store":     {opts: func(o *GlovoAccessSelfPageOptions) { o.Flow = nil }},
		"no customers org":  {opts: func(o *GlovoAccessSelfPageOptions) { o.CustomersOrgID = "" }},
		"no google idp":     {opts: func(o *GlovoAccessSelfPageOptions) { o.CustomersGoogleIdPID = "" }},
		"legacy mode":       {mode: TenantAuthzLegacy},
		"shadow mode":       {mode: TenantAuthzShadow},
		"no consent routes": {routes: func(*GlovoConsentRoutes) *GlovoConsentRoutes { return nil }},
		"consent off":       {routes: func(g *GlovoConsentRoutes) *GlovoConsentRoutes { g.Enabled = false; return g }},
		"no access store":   {routes: func(g *GlovoConsentRoutes) *GlovoConsentRoutes { g.Access = nil; return g }},
		"typed nil access store": {routes: func(g *GlovoConsentRoutes) *GlovoConsentRoutes {
			g.Access = (*memAccessStore)(nil)
			return g
		}},
	}
	for name, s := range setups {
		e := newSelfEnv(t, s)
		for _, rt := range [][2]string{
			{"GET", glovoAccessSelfPath}, {"POST", glovoAccessSelfStartPath},
			{"GET", glovoAccessSelfCallbackPath + "?code=z-code&state=s"}, {"POST", glovoAccessSelfConfirmPath},
		} {
			var form url.Values
			if rt[0] == "POST" {
				form = url.Values{"action": {"consent"}, "challenge": {"c"}, "csrf": {"x"}}
			}
			rec := e.do(rt[0], rt[1], form, &http.Cookie{Name: glovoAccessSelfCookie, Value: "b"})
			if rec.Code != http.StatusNotFound {
				t.Errorf("%s: %s %s = %d, want 404", name, rt[0], rt[1], rec.Code)
			}
		}
	}
}

// A handler reached without the mount still answers 404: the guard is in the
// handler too, not only in the router.
func TestGlovoAccessSelfHandlersGuardThemselves(t *testing.T) {
	e := newSelfEnv(t, selfSetup{})
	h := &Handlers{opts: Options{TenantAuthzMode: TenantAuthzLegacy, GlovoConsent: func() *GlovoConsentRoutes {
		g := mountedConsent(e.cs, consentCap)
		g.Access = e.as
		return g
	}()}, glovoAccessSelf: newGlovoAccessSelf(e.opts)}
	for name, fn := range map[string]http.HandlerFunc{
		"page": h.handleGlovoAccessSelfPage, "start": h.handleGlovoAccessSelfStart,
		"callback": h.handleGlovoAccessSelfCallback, "confirm": h.handleGlovoAccessSelfConfirm,
	} {
		rec := httptest.NewRecorder()
		fn(rec, httptest.NewRequest("POST", "/", nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s outside principal mode = %d, want 404", name, rec.Code)
		}
	}
}

// --- the sign-in ------------------------------------------------------------

func TestGlovoAccessSelfStartAsksForAFreshGoogleSignIn(t *testing.T) {
	e := newSelfEnv(t, selfSetup{})
	rec := e.do("POST", glovoAccessSelfStartPath, url.Values{}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("start = %d", rec.Code)
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	want := map[string]string{
		"client_id": selfClientID, "code_challenge_method": "S256", "prompt": "login", "max_age": "0",
		"redirect_uri": selfBaseURL + "/glovo/access/callback", "response_type": "code",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	if q.Get("state") == "" || q.Get("nonce") == "" || q.Get("code_challenge") == "" {
		t.Errorf("state, nonce and PKCE challenge are all needed: %v", q)
	}
	scopes := strings.Fields(q.Get("scope"))
	wantScopes := []string{"openid", "profile", auth.ScopeResourceOwner, auth.ScopeOrgIDPrefix + testCustomersOrg, auth.ScopeIdPIDPrefix + testCustomersGoogleIdP}
	if !reflect.DeepEqual(scopes, wantScopes) {
		t.Errorf("scopes = %v, want %v", scopes, wantScopes)
	}
	ck := selfCookie(t, rec)
	if !strings.HasPrefix(ck.Name, "__Host-") || !ck.Secure || !ck.HttpOnly || ck.Path != "/" || ck.SameSite != http.SameSiteLaxMode ||
		ck.MaxAge != int(releaseChallengeTTL.Seconds()) || ck.Domain != "" {
		t.Errorf("cookie = %+v", ck)
	}
	if got := e.flow.ttls[glovoAccessSelfKindStart]; len(got) != 1 || got[0] != releaseChallengeTTL {
		t.Errorf("start entry lifetimes = %v", got)
	}
}

func TestGlovoAccessSelfSignInShowsTheState(t *testing.T) {
	expiry := regexp.MustCompile(`pending, waiting for approval until \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z`)
	for name, tc := range map[string]struct {
		prepare func(e *selfEnv)
		lines   []string
		buttons []string
	}{
		"nothing yet": {func(*selfEnv) {}, []string{"Consent (version " + glovoconsent.Version + "): not recorded", "Access: not requested"}, []string{"consent"}},
		"consent only": {func(e *selfEnv) { e.consented() },
			[]string{"): recorded", "Access: not requested", "Request access to continue."}, []string{"request", "withdraw_consent"}},
		"pending": {func(e *selfEnv) { e.consented(); e.as.set(consentPIDA, glovoconsent.AccessPending) },
			[]string{"): recorded", "Access: pending, waiting for approval until "}, []string{"withdraw_request", "withdraw_consent"}},
		"approved": {func(e *selfEnv) { e.consented(); e.as.set(consentPIDA, glovoconsent.AccessApproved) },
			[]string{"Access: approved", "You have access."}, []string{"withdraw_consent"}},
		"approved without consent": {func(e *selfEnv) { e.as.set(consentPIDA, glovoconsent.AccessApproved) },
			[]string{"): not recorded", "Access: approved", "linking also needs your consent"}, []string{"consent"}},
		"rejected": {func(e *selfEnv) { e.consented(); e.as.set(consentPIDA, glovoconsent.AccessRejected) },
			[]string{"Access: rejected"}, []string{"request", "withdraw_consent"}},
		"revoked": {func(e *selfEnv) { e.consented(); e.as.set(consentPIDA, glovoconsent.AccessRevoked) },
			[]string{"Access: revoked"}, []string{"request", "withdraw_consent"}},
		"withdrawn by the person": {func(e *selfEnv) {
			e.consented()
			e.as.set(consentPIDA, glovoconsent.AccessRejected)
			row := e.as.rows[consentPIDA]
			row.DecidedBy = consentPIDA
			e.as.rows[consentPIDA] = row
		}, []string{"Access: not requested"}, []string{"request", "withdraw_consent"}},
	} {
		e := newSelfEnv(t, selfSetup{})
		tc.prepare(e)
		_, rec := e.mustSignIn()
		body := rec.Body.String()
		for _, want := range append(tc.lines, "Signed in with Google as account prn_***"+consentPIDA[len(consentPIDA)-4:]+".") {
			if !strings.Contains(body, want) {
				t.Errorf("%s: the page lacks %q:\n%s", name, want, body)
			}
		}
		if got := selfButtons(body); !reflect.DeepEqual(got, tc.buttons) {
			t.Errorf("%s: buttons = %v, want %v", name, got, tc.buttons)
		}
		if name == "pending" && !expiry.MatchString(body) {
			t.Errorf("pending must show when the request expires:\n%s", body)
		}
		if name == "withdrawn by the person" && strings.Contains(body, "rejected") {
			t.Errorf("a withdrawal must not read as a rejection:\n%s", body)
		}
		asked := e.prn.asked()
		if len(asked) != 1 || asked[0].Provider != "zitadel" || asked[0].Issuer != e.idp.srv.URL || asked[0].Subject != "z-sub" ||
			asked[0].Kind != auth.KindHuman || asked[0].Display != "" || asked[0].Customer == nil ||
			asked[0].Customer.Provider != auth.ProviderGoogle || asked[0].Customer.GoogleSub != testGoogleSub {
			t.Errorf("%s: resolver asked with %+v", name, asked)
		}
	}
}

// Every sign-in that is not a fresh Google sign-in of a customer to this
// client is refused, and the ones that fail on who the person is get one
// answer that does not tell them apart.
func TestGlovoAccessSelfSignInRefusals(t *testing.T) {
	with := func(extra map[string]any) func(e *selfEnv) {
		return func(e *selfEnv) { e.idp.extra = extra }
	}
	both := googleCustomerClaims()
	both[auth.ClaimCustomerGitHubID] = "268260640"
	refused := googleCustomerClaims()
	refused[auth.ClaimCustomerRefused] = "no_external_idp"
	badSub := googleCustomerClaims()
	badSub[auth.ClaimCustomerGoogleSub] = "not-a-subject"
	noSub := googleCustomerClaims()
	delete(noSub, auth.ClaimCustomerGoogleSub)
	type tc struct {
		prepare func(e *selfEnv)
		status  int
		generic bool
	}
	cases := map[string]tc{
		"staff or another organization": {with(map[string]any{auth.ClaimResourceOwnerID: selfOtherOrg}), http.StatusForbidden, true},
		"another organization claiming google": {func(e *selfEnv) {
			c := googleCustomerClaims()
			c[auth.ClaimResourceOwnerID] = selfOtherOrg
			e.idp.extra = c
		}, http.StatusForbidden, true},
		"github-proven customer":          {with(customerIDClaims()), http.StatusForbidden, true},
		"unproven customer":               {with(map[string]any{auth.ClaimResourceOwnerID: testCustomersOrg}), http.StatusForbidden, true},
		"refused by the hook":             {with(refused), http.StatusForbidden, true},
		"no resource owner claim":         {with(map[string]any{}), http.StatusForbidden, true},
		"resource owner of wrong shape":   {with(map[string]any{auth.ClaimResourceOwnerID: 42}), http.StatusForbidden, true},
		"claims of both providers":        {with(both), http.StatusForbidden, true},
		"malformed google subject":        {with(badSub), http.StatusForbidden, true},
		"google without a subject":        {with(noSub), http.StatusForbidden, true},
		"token for another audience":      {func(e *selfEnv) { e.idp.audOverride = "other-client" }, http.StatusBadRequest, false},
		"token for several, no azp":       {func(e *selfEnv) { e.idp.extra["aud"] = []string{selfClientID, "other"} }, http.StatusBadRequest, false},
		"token authorized to another azp": {func(e *selfEnv) { e.idp.extra["azp"] = "other-client" }, http.StatusBadRequest, false},
		"stale auth_time":                 {func(e *selfEnv) { e.idp.authTime = e.clock().Add(-10 * time.Minute) }, http.StatusBadRequest, false},
		"no auth_time":                    {func(e *selfEnv) { e.idp.omitAuthTime = true }, http.StatusBadRequest, false},
		"nonce mismatch":                  {func(e *selfEnv) { e.idp.nonceOverride = "another-nonce" }, http.StatusBadRequest, false},
	}
	var genericBody string
	for name, c := range cases {
		e := newSelfEnv(t, selfSetup{})
		e.consented()
		c.prepare(e)
		before := selfEvents()
		ck, rec := e.signIn()
		body := rec.Body.String()
		if rec.Code != c.status {
			t.Errorf("%s = %d, want %d: %s", name, rec.Code, c.status, body)
			continue
		}
		if f := selfForm(body); len(f) != 0 || len(selfButtons(body)) != 0 || strings.Contains(body, "Consent (") || strings.Contains(body, "Access:") {
			t.Errorf("%s: a refused sign-in showed state or a form:\n%s", name, body)
		}
		if len(e.prn.asked()) != 0 {
			t.Errorf("%s: the principal was resolved for a refused sign-in", name)
		}
		if got := e.calls(); got != "record=0 consent=true request=0 reject=0 rows=0" {
			t.Errorf("%s: stores touched: %s", name, got)
		}
		if strings.Contains(e.flow.payloads(), glovoAccessSelfKindAct) {
			t.Errorf("%s: an action entry was written", name)
		}
		// The start entry is spent: the same redirect cannot be replayed.
		if again := e.callback(ck, "any"); again.Code != http.StatusBadRequest {
			t.Errorf("%s: replay = %d", name, again.Code)
		}
		if !c.generic {
			continue
		}
		if !strings.Contains(body, "This page needs a Google sign-in") {
			t.Errorf("%s: body = %s", name, body)
		}
		if genericBody == "" {
			genericBody = body
		} else if body != genericBody {
			t.Errorf("%s: the refusal differs from the others, so it tells which check failed:\n%s\n---\n%s", name, body, genericBody)
		}
		if d := selfEventDelta(before, false); !reflect.DeepEqual(d, map[[2]string]float64{{"access_self_signin", "not_google"}: 1}) {
			t.Errorf("%s: counters moved %v", name, d)
		}
	}
}

func TestGlovoAccessSelfPrincipalRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		err    error
		status int
		want   string
	}{
		"conflict":        {fmt.Errorf("%w: %w", auth.ErrIdentityRefused, principals.ErrCustomerConflict), http.StatusConflict, "already tied to a different MCTL account"},
		"disabled":        {auth.ErrPrincipalDisabled, http.StatusForbidden, "This account is disabled"},
		"refused":         {auth.ErrIdentityRefused, http.StatusForbidden, "This account is disabled"},
		"store down":      {errors.New("db down"), http.StatusServiceUnavailable, "cannot look up your account"},
		"no principal id": {nil, http.StatusServiceUnavailable, "cannot look up your account"},
	} {
		e := newSelfEnv(t, selfSetup{})
		e.consented()
		if tc.err == nil {
			e.prn.set(map[string]string{"z-sub": "not-a-principal"}, nil)
		} else {
			e.prn.set(nil, tc.err)
		}
		_, rec := e.signIn()
		body := rec.Body.String()
		if rec.Code != tc.status || !strings.Contains(body, tc.want) {
			t.Errorf("%s = %d %s", name, rec.Code, body)
		}
		if len(selfForm(body)) != 0 || strings.Contains(body, "Access:") {
			t.Errorf("%s: state or a form shown:\n%s", name, body)
		}
		if got := e.calls(); got != "record=0 consent=true request=0 reject=0 rows=0" {
			t.Errorf("%s: stores touched: %s", name, got)
		}
	}
}

// A read that failed is a 503, never a page that says "not recorded" or
// "not requested".
func TestGlovoAccessSelfUnreadableStateIsNotNone(t *testing.T) {
	down := errors.New("db down")
	for name, prepare := range map[string]func(e *selfEnv){
		"consent read fails": func(e *selfEnv) { e.cs.activeErr = down },
		"access read fails":  func(e *selfEnv) { e.as.getErr = down },
		"access row of bad status": func(e *selfEnv) {
			e.as.rows[consentPIDA] = glovoconsent.Access{PrincipalID: consentPIDA, Status: "bogus"}
		},
		"access row of another principal": func(e *selfEnv) {
			e.as.set(consentPIDB, glovoconsent.AccessApproved)
			e.as.rows[consentPIDA] = e.as.rows[consentPIDB]
		},
		"consent record of another principal": func(e *selfEnv) {
			e.cs.active[consentPIDA] = glovoconsent.Record{ID: "gcn_b", PrincipalID: consentPIDB, Version: glovoconsent.Version, RecordedAt: time.Now().UTC()}
		},
		"consent record already revoked": func(e *selfEnv) {
			now := time.Now().UTC()
			e.cs.active[consentPIDA] = glovoconsent.Record{ID: "gcn_a", PrincipalID: consentPIDA, Version: glovoconsent.Version, RecordedAt: now, RevokedAt: &now}
		},
	} {
		// At the sign-in.
		e := newSelfEnv(t, selfSetup{})
		prepare(e)
		_, rec := e.signIn()
		body := rec.Body.String()
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s at sign-in = %d %s", name, rec.Code, body)
		}
		for _, bad := range []string{"not recorded", "not requested", "Access:", "Consent ("} {
			if strings.Contains(body, bad) {
				t.Errorf("%s at sign-in: an unreadable state was rendered as %q:\n%s", name, bad, body)
			}
		}
		if len(selfForm(body)) != 0 {
			t.Errorf("%s at sign-in: a form was offered", name)
		}

		// At an action, after a good sign-in.
		e = newSelfEnv(t, selfSetup{})
		ck, page := e.mustSignIn()
		prepare(e)
		rec = e.act(ck, page, glovoAccessSelfActionConsent)
		body = rec.Body.String()
		if rec.Code != http.StatusServiceUnavailable || len(selfForm(body)) != 0 || strings.Contains(body, "not requested") || strings.Contains(body, "not recorded") {
			t.Errorf("%s at an action = %d %s", name, rec.Code, body)
		}
		if e.cs.recordCalls != 0 || e.as.reqCalls != 0 || e.as.rejectCalls != 0 {
			t.Errorf("%s at an action: a store was written after an unreadable state", name)
		}
	}
}

// --- the actions ------------------------------------------------------------

// Each action does what the bearer route does: the same store call, the same
// counter and the same audit operation, with the principal as the actor.
func TestGlovoAccessSelfActionsMatchTheBearerRoutes(t *testing.T) {
	type step struct {
		name    string
		prepare func(cs *memConsentStore, as *memAccessStore)
		action  string
		bearer  [2]string
		check   func(t *testing.T, e *selfEnv)
		notice  string
		buttons []string
	}
	consent := func(cs *memConsentStore, _ *memAccessStore) {
		cs.active[consentPIDA] = glovoconsent.Record{ID: "gcn_" + consentPIDA, PrincipalID: consentPIDA, Version: glovoconsent.Version, RecordedAt: time.Now().UTC()}
	}
	for _, s := range []step{
		{name: "consent", prepare: func(*memConsentStore, *memAccessStore) {}, action: glovoAccessSelfActionConsent,
			bearer: [2]string{"PUT", consentHumanURL}, notice: "Your consent is recorded.", buttons: []string{"request", "withdraw_consent"},
			check: func(t *testing.T, e *selfEnv) {
				if _, ok := e.cs.active[consentPIDA]; !ok || e.cs.recordCalls != 1 || e.cs.lastCap != consentCap {
					t.Errorf("consent not recorded with the configured capacity: %s cap=%d", e.calls(), e.cs.lastCap)
				}
			}},
		{name: "request", prepare: consent, action: glovoAccessSelfActionRequest,
			bearer: [2]string{"PUT", accessURL}, notice: "Your request is open.", buttons: []string{"withdraw_request", "withdraw_consent"},
			check: func(t *testing.T, e *selfEnv) {
				if e.as.rows[consentPIDA].Status != glovoconsent.AccessPending || e.as.reqCalls != 1 {
					t.Errorf("request not opened: %s", e.calls())
				}
			}},
		{name: "withdraw_request", prepare: func(cs *memConsentStore, as *memAccessStore) {
			consent(cs, as)
			as.set(consentPIDA, glovoconsent.AccessPending)
		}, action: glovoAccessSelfActionWithdrawRequest,
			bearer: [2]string{"DELETE", accessURL}, notice: "Your request is withdrawn.", buttons: []string{"request", "withdraw_consent"},
			check: func(t *testing.T, e *selfEnv) {
				row := e.as.rows[consentPIDA]
				if row.Status != glovoconsent.AccessRejected || e.as.rejectCalls != 1 || e.as.lastRejectActor != consentPIDA || e.as.lastReason != glovoAccessWithdrawReason {
					t.Errorf("request not withdrawn as the person: %+v actor=%q reason=%q", row, e.as.lastRejectActor, e.as.lastReason)
				}
			}},
		{name: "withdraw_consent", prepare: consent, action: glovoAccessSelfActionWithdrawConsent,
			bearer: [2]string{"DELETE", consentHumanURL}, notice: "Your consent is withdrawn.", buttons: []string{"consent"},
			check: func(t *testing.T, e *selfEnv) {
				if _, ok := e.cs.active[consentPIDA]; ok {
					t.Error("consent still active")
				}
			}},
	} {
		// The bearer route, from the same starting state.
		be, bcs, bas := accessEnv(t, standardConsentUsers(t))
		s.prepare(bcs, bas)
		before := selfEvents()
		if rec := be.call(s.bearer[0], s.bearer[1], "alice", ""); rec.Code >= 300 {
			t.Fatalf("%s: bearer route = %d %s", s.name, rec.Code, rec.Body.String())
		}
		wantEvents := selfEventDelta(before, true)
		wantAudit := selfAuditRows(be.audit, 0)
		if len(wantEvents) != 1 || len(wantAudit) != 1 {
			t.Fatalf("%s: the bearer route wrote %v and %v", s.name, wantEvents, wantAudit)
		}

		// The page.
		e := newSelfEnv(t, selfSetup{})
		s.prepare(e.cs, e.as)
		ck, page := e.mustSignIn()
		before = selfEvents()
		rec := e.act(ck, page, s.action)
		body := rec.Body.String()
		if rec.Code != http.StatusOK || !strings.Contains(body, s.notice) {
			t.Fatalf("%s = %d %s", s.name, rec.Code, body)
		}
		s.check(t, e)
		if got := selfEventDelta(before, true); !reflect.DeepEqual(got, wantEvents) {
			t.Errorf("%s: counters moved %v, the bearer route moves %v", s.name, got, wantEvents)
		}
		if got := selfAuditRows(e.audit, 0); !reflect.DeepEqual(got, wantAudit) {
			t.Errorf("%s: audit %+v, the bearer route writes %+v", s.name, got, wantAudit)
		}
		for _, en := range e.audit.List(0) {
			if en.UserID != consentPIDA || en.PrincipalID != consentPIDA || en.Parameters["surface"] != glovoAccessSelfSurface {
				t.Errorf("%s: audit actor = %q / %q, surface %q; want the principal id", s.name, en.UserID, en.PrincipalID, en.Parameters["surface"])
			}
		}
		// The new state, with a new one-time form for the next action.
		if got := selfButtons(body); !reflect.DeepEqual(got, s.buttons) {
			t.Errorf("%s: buttons after = %v, want %v", s.name, got, s.buttons)
		}
		next, was := selfForm(body), selfForm(page.Body.String())
		if next.Get("challenge") == "" || next.Get("challenge") == was.Get("challenge") || next.Get("csrf") == was.Get("csrf") {
			t.Errorf("%s: the next form must carry a fresh challenge and CSRF token", s.name)
		}
		if len(rec.Result().Cookies()) != 0 {
			t.Errorf("%s: an action must not touch the cookie: %v", s.name, rec.Header())
		}
	}
}

// The whole path in one sign-in: each action yields the form of the next.
func TestGlovoAccessSelfChainOfActions(t *testing.T) {
	e := newSelfEnv(t, selfSetup{})
	ck, page := e.mustSignIn()
	for _, action := range []string{glovoAccessSelfActionConsent, glovoAccessSelfActionRequest, glovoAccessSelfActionWithdrawRequest, glovoAccessSelfActionWithdrawConsent} {
		page = e.act(ck, page, action)
		if page.Code != http.StatusOK {
			t.Fatalf("%s = %d %s", action, page.Code, page.Body.String())
		}
	}
	if got := selfButtons(page.Body.String()); !reflect.DeepEqual(got, []string{"consent"}) {
		t.Errorf("after the chain: %v", got)
	}
	if n := len(e.prn.asked()); n != 5 {
		t.Errorf("the principal must be resolved at the sign-in and again on every action: %d", n)
	}
}

// Soft refusals of the stores draw the state again; hard failures end the
// flow with a 503 and no claim about the state.
func TestGlovoAccessSelfStoreRefusals(t *testing.T) {
	down := errors.New("db down")
	for name, tc := range map[string]struct {
		capacity int
		consent  bool
		prepare  func(e *selfEnv)
		action   string
		status   int
		want     string
		events   map[[2]string]float64
		audit    selfAuditRow
		form     bool
	}{
		"capacity reached": {capacity: -1, action: glovoAccessSelfActionConsent, status: http.StatusConflict, want: "linking is full right now", form: true,
			events: map[[2]string]float64{{"human_record", "capacity_reached"}: 1},
			audit:  selfAuditRow{Op: "glovo.link_consent.record", Status: "refused", Refusal: gcCodeCapacityReached}},
		"consent store down": {prepare: func(e *selfEnv) { e.cs.recordErr = down }, action: glovoAccessSelfActionConsent, status: http.StatusServiceUnavailable,
			want: "could not be recorded", events: map[[2]string]float64{{"human_record", "store_error"}: 1},
			audit: selfAuditRow{Op: "glovo.link_consent.record", Status: "failed", Refusal: gcCodeUnavailable}},
		"revoke store down": {consent: true, prepare: func(e *selfEnv) { e.cs.revErr = down }, action: glovoAccessSelfActionWithdrawConsent, status: http.StatusServiceUnavailable,
			want: "could not be recorded", events: map[[2]string]float64{{"human_revoke", "store_error"}: 1},
			audit: selfAuditRow{Op: "glovo.link_consent.revoke", Status: "failed", Refusal: gcCodeUnavailable}},
		"already approved": {consent: true, prepare: func(e *selfEnv) { e.as.reqErr = glovoconsent.ErrAccessApproved }, action: glovoAccessSelfActionRequest,
			status: http.StatusConflict, want: "already approved", form: true, events: map[[2]string]float64{{"access_request", "already_approved"}: 1},
			audit: selfAuditRow{Op: "glovo.access_request.open", Status: "refused", Refusal: gcCodeAccessApproved}},
		"request store down": {consent: true, prepare: func(e *selfEnv) { e.as.reqErr = down }, action: glovoAccessSelfActionRequest,
			status: http.StatusServiceUnavailable, want: "could not be recorded", events: map[[2]string]float64{{"access_request", "store_error"}: 1},
			audit: selfAuditRow{Op: "glovo.access_request.open", Status: "failed", Refusal: gcCodeUnavailable}},
		"withdraw store down": {consent: true, prepare: func(e *selfEnv) { e.as.set(consentPIDA, glovoconsent.AccessPending); e.as.rejectErr = down },
			action: glovoAccessSelfActionWithdrawRequest, status: http.StatusServiceUnavailable, want: "could not be recorded",
			events: map[[2]string]float64{{"access_withdraw", "store_error"}: 1},
			audit:  selfAuditRow{Op: "glovo.access_request.withdraw", Status: "failed", Refusal: gcCodeUnavailable}},
	} {
		e := newSelfEnv(t, selfSetup{capacity: tc.capacity})
		if tc.consent {
			e.consented()
		}
		ck, page := e.mustSignIn()
		if tc.prepare != nil {
			tc.prepare(e)
		}
		before := selfEvents()
		rec := e.act(ck, page, tc.action)
		body := rec.Body.String()
		if rec.Code != tc.status || !strings.Contains(body, tc.want) {
			t.Errorf("%s = %d %s", name, rec.Code, body)
		}
		if got := len(selfForm(body)) != 0; got != tc.form {
			t.Errorf("%s: form offered = %v, want %v:\n%s", name, got, tc.form, body)
		}
		if !tc.form && (strings.Contains(body, "Access:") || strings.Contains(body, "Consent (")) {
			t.Errorf("%s: a failed write still claimed a state:\n%s", name, body)
		}
		if got := selfEventDelta(before, true); !reflect.DeepEqual(got, tc.events) {
			t.Errorf("%s: counters moved %v, want %v", name, got, tc.events)
		}
		rows := selfAuditRows(e.audit, 0)
		if len(rows) != 1 || rows[0].Op != tc.audit.Op || rows[0].Status != tc.audit.Status || rows[0].Refusal != tc.audit.Refusal || rows[0].Params["principal"] != consentPIDA {
			t.Errorf("%s: audit = %+v, want %+v", name, rows, tc.audit)
		}
	}
}

// The state is read again after an action; when that read fails the page
// says so instead of drawing a state.
func TestGlovoAccessSelfStateUnreadableAfterAnAction(t *testing.T) {
	e := newSelfEnv(t, selfSetup{})
	ck, page := e.mustSignIn()
	failing := &failAfterConsent{memConsentStore: e.cs}
	e.router = nil
	g := mountedConsent(failing, consentCap)
	g.Access = e.as
	e.router = NewRouter(Options{
		AuthMiddleware: func(next http.Handler) http.Handler { return next },
		GlovoConsent:   g, AuditLog: e.audit, TenantAuthzMode: TenantAuthzPrincipal, GlovoAccessSelf: e.opts,
		mcpHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
	})
	rec := e.act(ck, page, glovoAccessSelfActionConsent)
	body := rec.Body.String()
	if rec.Code != http.StatusServiceUnavailable || strings.Contains(body, "not recorded") || strings.Contains(body, "Access:") || len(selfForm(body)) != 0 {
		t.Errorf("after an action whose re-read failed = %d %s", rec.Code, body)
	}
	if e.cs.recordCalls != 1 {
		t.Errorf("the action itself must have run once: %d", e.cs.recordCalls)
	}
}

// failAfterConsent is a consent store whose reads fail once a consent was
// recorded.
type failAfterConsent struct{ *memConsentStore }

func (f *failAfterConsent) Active(ctx context.Context, pid string) (glovoconsent.Record, error) {
	f.mu.Lock()
	recorded := f.recordCalls > 0
	f.mu.Unlock()
	if recorded {
		return glovoconsent.Record{}, errors.New("db down")
	}
	return f.memConsentStore.Active(ctx, pid)
}

// The page offers only what applies, and a hand-made form is held to the
// same rule: nothing is written for an action the state does not allow.
func TestGlovoAccessSelfActionsNotValidForTheState(t *testing.T) {
	for name, tc := range map[string]struct {
		prepare func(e *selfEnv)
		action  string
		want    string
		events  map[[2]string]float64
		audited bool
	}{
		"request without consent": {func(*selfEnv) {}, glovoAccessSelfActionRequest, "Record your consent first",
			map[[2]string]float64{{"access_self_action", "not_valid"}: 1, {"access_request", "consent_required"}: 1}, true},
		"request while pending": {func(e *selfEnv) { e.consented(); e.as.set(consentPIDA, glovoconsent.AccessPending) }, glovoAccessSelfActionRequest,
			"does not apply", map[[2]string]float64{{"access_self_action", "not_valid"}: 1}, false},
		"request when approved": {func(e *selfEnv) { e.consented(); e.as.set(consentPIDA, glovoconsent.AccessApproved) }, glovoAccessSelfActionRequest,
			"does not apply", map[[2]string]float64{{"access_self_action", "not_valid"}: 1}, false},
		"withdraw a request that is not open": {func(e *selfEnv) { e.consented() }, glovoAccessSelfActionWithdrawRequest,
			"does not apply", map[[2]string]float64{{"access_self_action", "not_valid"}: 1}, false},
		"withdraw an approved access": {func(e *selfEnv) { e.consented(); e.as.set(consentPIDA, glovoconsent.AccessApproved) }, glovoAccessSelfActionWithdrawRequest,
			"does not apply", map[[2]string]float64{{"access_self_action", "not_valid"}: 1}, false},
		"consent twice": {func(e *selfEnv) { e.consented() }, glovoAccessSelfActionConsent,
			"does not apply", map[[2]string]float64{{"access_self_action", "not_valid"}: 1}, false},
		"withdraw a consent never given": {func(*selfEnv) {}, glovoAccessSelfActionWithdrawConsent,
			"does not apply", map[[2]string]float64{{"access_self_action", "not_valid"}: 1}, false},
	} {
		e := newSelfEnv(t, selfSetup{})
		tc.prepare(e)
		ck, page := e.mustSignIn()
		for _, b := range selfButtons(page.Body.String()) {
			if b == tc.action {
				t.Errorf("%s: the page offered %q", name, b)
			}
		}
		state := e.calls()
		before := selfEvents()
		rec := e.act(ck, page, tc.action)
		body := rec.Body.String()
		if rec.Code != http.StatusConflict || !strings.Contains(body, tc.want) {
			t.Errorf("%s = %d %s", name, rec.Code, body)
		}
		if got := e.calls(); got != state {
			t.Errorf("%s: stores changed: %s -> %s", name, state, got)
		}
		if got := selfEventDelta(before, false); !reflect.DeepEqual(got, tc.events) {
			t.Errorf("%s: counters moved %v, want %v", name, got, tc.events)
		}
		rows := selfAuditRows(e.audit, 0)
		if tc.audited && (len(rows) != 1 || rows[0].Op != "glovo.access_request.open" || rows[0].Status != "refused" || rows[0].Refusal != gcCodeConsentRequired) {
			t.Errorf("%s: audit = %+v", name, rows)
		}
		if !tc.audited && len(rows) != 0 {
			t.Errorf("%s: audit = %+v, want none", name, rows)
		}
		// The state is drawn again, with a form for what does apply.
		if len(selfForm(body)) == 0 && len(selfButtons(page.Body.String())) != 0 {
			t.Errorf("%s: no form after a refused action:\n%s", name, body)
		}
	}
}

func TestGlovoAccessSelfUnknownActionAndMalformedForms(t *testing.T) {
	e := newSelfEnv(t, selfSetup{})
	ck, page := e.mustSignIn()
	for _, action := range []string{"", "approve", "revoke", "CONSENT", "consent "} {
		if rec := e.act(ck, page, action); rec.Code != http.StatusBadRequest {
			t.Errorf("action %q = %d", action, rec.Code)
		}
	}
	form := selfForm(page.Body.String())
	for name, drop := range map[string]string{"no challenge": "challenge", "no csrf": "csrf"} {
		f := url.Values{"action": {"consent"}}
		for k, v := range form {
			if k != drop {
				f[k] = v
			}
		}
		if rec := e.do("POST", glovoAccessSelfConfirmPath, f, ck); rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d", name, rec.Code)
		}
	}
	form.Set("action", "consent")
	if rec := e.do("POST", glovoAccessSelfConfirmPath, form, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("no cookie = %d", rec.Code)
	}
	if got := e.calls(); got != "record=0 consent=false request=0 reject=0 rows=0" {
		t.Errorf("stores touched: %s", got)
	}
	// None of that spent the challenge: the real action still goes through.
	if rec := e.act(ck, page, glovoAccessSelfActionConsent); rec.Code != http.StatusOK {
		t.Errorf("the untouched form = %d %s", rec.Code, rec.Body.String())
	}
}

// No request field names the principal: whatever the form or the query
// carries, the action lands on the principal of the sign-in.
func TestGlovoAccessSelfTakesNoPrincipalFromTheRequest(t *testing.T) {
	e := newSelfEnv(t, selfSetup{})
	ck, page := e.mustSignIn()
	form := selfForm(page.Body.String())
	form.Set("action", glovoAccessSelfActionConsent)
	for _, k := range []string{"principal", "principal_id", "pid", "subject", "sub", "user"} {
		form.Set(k, consentPIDB)
	}
	rec := e.do("POST", glovoAccessSelfConfirmPath+"?principal_id="+consentPIDB+"&principal="+consentPIDB, form, ck)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm = %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := e.cs.active[consentPIDB]; ok {
		t.Error("the action landed on the principal named in the request")
	}
	if _, ok := e.cs.active[consentPIDA]; !ok {
		t.Error("the action did not land on the signed-in principal")
	}
}

// --- the flow ---------------------------------------------------------------

func TestGlovoAccessSelfFlowRefusals(t *testing.T) {
	t.Run("a challenge works once", func(t *testing.T) {
		e := newSelfEnv(t, selfSetup{})
		e.consented()
		ck, page := e.mustSignIn()
		if rec := e.act(ck, page, glovoAccessSelfActionRequest); rec.Code != http.StatusOK {
			t.Fatalf("first = %d", rec.Code)
		}
		// Withdrawn by other means, so the same action would apply again.
		delete(e.as.rows, consentPIDA)
		rec := e.act(ck, page, glovoAccessSelfActionRequest)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "already used") {
			t.Errorf("replay = %d %s", rec.Code, rec.Body.String())
		}
		if e.as.reqCalls != 1 {
			t.Errorf("a replayed challenge acted: %d requests", e.as.reqCalls)
		}
	})
	t.Run("another browser cannot use the form", func(t *testing.T) {
		e := newSelfEnv(t, selfSetup{})
		ck, page := e.mustSignIn()
		other := &http.Cookie{Name: glovoAccessSelfCookie, Value: "another-browser"}
		if rec := e.act(other, page, glovoAccessSelfActionConsent); rec.Code != http.StatusBadRequest {
			t.Errorf("other browser = %d", rec.Code)
		}
		if e.cs.recordCalls != 0 {
			t.Error("another browser acted")
		}
		// A wrong guess does not spend the right browser's challenge.
		if rec := e.act(ck, page, glovoAccessSelfActionConsent); rec.Code != http.StatusOK {
			t.Errorf("the right browser afterwards = %d", rec.Code)
		}
	})
	t.Run("a CSRF token of another form does not fit", func(t *testing.T) {
		e := newSelfEnv(t, selfSetup{})
		ck, page := e.mustSignIn()
		form := selfForm(page.Body.String())
		form.Set("csrf", "another-token")
		form.Set("action", glovoAccessSelfActionConsent)
		if rec := e.do("POST", glovoAccessSelfConfirmPath, form, ck); rec.Code != http.StatusBadRequest || e.cs.recordCalls != 0 {
			t.Errorf("wrong CSRF = %d, record calls %d", rec.Code, e.cs.recordCalls)
		}
	})
	t.Run("the callback needs the browser that started", func(t *testing.T) {
		e := newSelfEnv(t, selfSetup{})
		ck, state := e.start()
		for name, c := range map[string]*http.Cookie{"another browser": {Name: glovoAccessSelfCookie, Value: "another"}, "no cookie": nil} {
			if rec := e.callback(c, state); rec.Code != http.StatusBadRequest || len(selfForm(rec.Body.String())) != 0 {
				t.Errorf("%s = %d", name, rec.Code)
			}
		}
		if rec := e.callback(ck, "another-state"); rec.Code != http.StatusBadRequest {
			t.Errorf("another state = %d", rec.Code)
		}
		if len(e.prn.asked()) != 0 {
			t.Error("a sign-in was completed for the wrong browser")
		}
		if rec := e.callback(ck, state); rec.Code != http.StatusOK {
			t.Errorf("the right browser = %d", rec.Code)
		}
		// And only once.
		if rec := e.callback(ck, state); rec.Code != http.StatusBadRequest {
			t.Errorf("callback replay = %d", rec.Code)
		}
	})
	t.Run("a sign-in that took too long", func(t *testing.T) {
		e := newSelfEnv(t, selfSetup{})
		e.flow.ignoreTTL = true
		ck, state := e.start()
		e.advance(releaseChallengeTTL + time.Second)
		if rec := e.callback(ck, state); rec.Code != http.StatusBadRequest || len(e.prn.asked()) != 0 {
			t.Errorf("late callback = %d", rec.Code)
		}
	})
	t.Run("an upstream error or no code", func(t *testing.T) {
		for _, q := range []string{"error=access_denied", "x=1"} {
			e := newSelfEnv(t, selfSetup{})
			ck, state := e.start()
			rec := e.do("GET", glovoAccessSelfCallbackPath+"?state="+state+"&"+q, nil, ck)
			if rec.Code != http.StatusBadRequest || len(e.prn.asked()) != 0 {
				t.Errorf("%s = %d", q, rec.Code)
			}
		}
	})
}

// The flow lives ten minutes from the start of the sign-in, whatever is done
// in it: an action hands out a new challenge, never more time.
func TestGlovoAccessSelfLifetimeIsAbsolute(t *testing.T) {
	for name, ignoreTTL := range map[string]bool{"the handler's own check": true, "the stored lifetime": false} {
		e := newSelfEnv(t, selfSetup{})
		e.flow.ignoreTTL = ignoreTTL
		ck, page := e.mustSignIn()
		e.advance(6 * time.Minute)
		page = e.act(ck, page, glovoAccessSelfActionConsent)
		if page.Code != http.StatusOK {
			t.Fatalf("%s: inside the lifetime = %d", name, page.Code)
		}
		ttls := e.flow.ttls[glovoAccessSelfKindAct]
		if len(ttls) != 2 || ttls[0] != releaseChallengeTTL || ttls[1] != 4*time.Minute {
			t.Errorf("%s: action entries live %v, want the full lifetime then what is left of it", name, ttls)
		}
		e.advance(5 * time.Minute)
		rec := e.act(ck, page, glovoAccessSelfActionRequest)
		if rec.Code != http.StatusBadRequest || e.as.reqCalls != 0 {
			t.Errorf("%s: eleven minutes after the sign-in = %d, %d requests", name, rec.Code, e.as.reqCalls)
		}
	}
	// At the very end the state is still shown, without a form.
	e := newSelfEnv(t, selfSetup{})
	ck, page := e.mustSignIn()
	e.flow.ignoreTTL = true
	e.advance(releaseChallengeTTL - time.Second)
	page = e.act(ck, page, glovoAccessSelfActionConsent)
	if page.Code != http.StatusOK {
		t.Fatalf("last second = %d", page.Code)
	}
	e.advance(2 * time.Second)
	e.consented()
	if rec := e.act(ck, page, glovoAccessSelfActionRequest); rec.Code != http.StatusBadRequest {
		t.Errorf("after the end = %d", rec.Code)
	}
}

func TestGlovoAccessSelfFlowStoreDownIs503(t *testing.T) {
	down := errors.New("db down")
	t.Run("at start", func(t *testing.T) {
		e := newSelfEnv(t, selfSetup{})
		e.flow.fail(down)
		rec := e.do("POST", glovoAccessSelfStartPath, url.Values{}, nil)
		if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Location") != "" || len(rec.Result().Cookies()) != 0 {
			t.Errorf("start = %d %v", rec.Code, rec.Header())
		}
	})
	t.Run("at the callback read", func(t *testing.T) {
		e := newSelfEnv(t, selfSetup{})
		ck, state := e.start()
		e.flow.fail(down)
		if rec := e.callback(ck, state); rec.Code != http.StatusServiceUnavailable || len(e.prn.asked()) != 0 {
			t.Errorf("callback = %d", rec.Code)
		}
	})
	t.Run("at the callback write", func(t *testing.T) {
		e := newSelfEnv(t, selfSetup{})
		e.opts.Flow = &putFailsFor{memFlowStore: e.flow, kind: glovoAccessSelfKindAct}
		ck, state := e.start()
		rec := e.callback(ck, state)
		if rec.Code != http.StatusServiceUnavailable || len(selfForm(rec.Body.String())) != 0 {
			t.Errorf("callback = %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("at an action", func(t *testing.T) {
		e := newSelfEnv(t, selfSetup{})
		ck, page := e.mustSignIn()
		e.flow.fail(down)
		rec := e.act(ck, page, glovoAccessSelfActionConsent)
		if rec.Code != http.StatusServiceUnavailable || e.cs.recordCalls != 0 {
			t.Errorf("confirm = %d, record calls %d", rec.Code, e.cs.recordCalls)
		}
		if strings.Contains(rec.Body.String(), "already used") {
			t.Errorf("a store failure read as an unknown challenge: %s", rec.Body.String())
		}
	})
	t.Run("an unreadable entry", func(t *testing.T) {
		e := newSelfEnv(t, selfSetup{})
		ck, page := e.mustSignIn()
		e.flow.mu.Lock()
		for k, en := range e.flow.entries {
			en.payload = []byte("{")
			e.flow.entries[k] = en
		}
		e.flow.mu.Unlock()
		if rec := e.act(ck, page, glovoAccessSelfActionConsent); rec.Code != http.StatusServiceUnavailable || e.cs.recordCalls != 0 {
			t.Errorf("confirm = %d, record calls %d", rec.Code, e.cs.recordCalls)
		}
	})
}

// putFailsFor fails Put for one kind.
type putFailsFor struct {
	*memFlowStore
	kind string
}

func (p *putFailsFor) Put(ctx context.Context, kind, key string, payload []byte, ttl time.Duration) error {
	if kind == p.kind {
		return errors.New("db down")
	}
	return p.memFlowStore.Put(ctx, kind, key, payload, ttl)
}

// The principal is resolved again on every action: one disabled, conflicted,
// unreadable or re-keyed since the sign-in acts on nothing.
func TestGlovoAccessSelfPrincipalIsCheckedOnEveryAction(t *testing.T) {
	for name, tc := range map[string]struct {
		ids    map[string]string
		err    error
		status int
		event  string
	}{
		"disabled since":    {nil, auth.ErrPrincipalDisabled, http.StatusForbidden, "disabled"},
		"conflict since":    {nil, fmt.Errorf("%w: %w", auth.ErrIdentityRefused, principals.ErrCustomerConflict), http.StatusConflict, "conflict"},
		"lookup fails":      {nil, errors.New("db down"), http.StatusServiceUnavailable, "unavailable"},
		"another principal": {map[string]string{"z-sub": consentPIDB}, nil, http.StatusConflict, "principal_changed"},
	} {
		e := newSelfEnv(t, selfSetup{})
		ck, page := e.mustSignIn()
		e.prn.set(tc.ids, tc.err)
		before := selfEvents()
		rec := e.act(ck, page, glovoAccessSelfActionConsent)
		if rec.Code != tc.status || len(selfForm(rec.Body.String())) != 0 {
			t.Errorf("%s = %d %s", name, rec.Code, rec.Body.String())
		}
		if got := e.calls(); got != "record=0 consent=false request=0 reject=0 rows=0" {
			t.Errorf("%s: stores touched: %s", name, got)
		}
		if got := selfEventDelta(before, false); !reflect.DeepEqual(got, map[[2]string]float64{{"access_self_action", tc.event}: 1}) {
			t.Errorf("%s: counters moved %v", name, got)
		}
		asked := e.prn.asked()
		last := asked[len(asked)-1]
		if len(asked) != 2 || last.Subject != "z-sub" || last.Issuer != e.idp.srv.URL || last.Display != "" || last.Customer == nil || last.Customer.GoogleSub != testGoogleSub {
			t.Errorf("%s: resolver asked with %+v", name, asked)
		}
	}
}

// Three requests an hour per principal: each new one queues an owner card.
func TestGlovoAccessSelfRequestLimiter(t *testing.T) {
	e := newSelfEnv(t, selfSetup{})
	e.consented()
	ck, page := e.mustSignIn()
	for i := 1; i <= glovoAccessSelfRequestsPerHour; i++ {
		page = e.act(ck, page, glovoAccessSelfActionRequest)
		if page.Code != http.StatusOK {
			t.Fatalf("request %d = %d %s", i, page.Code, page.Body.String())
		}
		page = e.act(ck, page, glovoAccessSelfActionWithdrawRequest)
		if page.Code != http.StatusOK {
			t.Fatalf("withdraw %d = %d %s", i, page.Code, page.Body.String())
		}
	}
	before := selfEvents()
	audited := len(e.audit.List(0))
	rec := e.act(ck, page, glovoAccessSelfActionRequest)
	body := rec.Body.String()
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(body, "no new request was opened") {
		t.Fatalf("request over the limit = %d %s", rec.Code, body)
	}
	if e.as.reqCalls != glovoAccessSelfRequestsPerHour || e.as.rows[consentPIDA].Status == glovoconsent.AccessPending {
		t.Errorf("a request over the limit reached the store: %s", e.calls())
	}
	if got := selfEventDelta(before, false); !reflect.DeepEqual(got, map[[2]string]float64{{"access_request", "rate_limited"}: 1}) {
		t.Errorf("counters moved %v", got)
	}
	rows := selfAuditRows(e.audit, audited)
	if len(rows) != 1 || rows[0].Op != "glovo.access_request.open" || rows[0].Status != "refused" || rows[0].Refusal != gcCodeRateLimited {
		t.Errorf("audit = %+v", rows)
	}
	// The state is still drawn, and the other actions still work.
	if got := selfButtons(body); !reflect.DeepEqual(got, []string{"request", "withdraw_consent"}) {
		t.Errorf("buttons = %v", got)
	}
	// Another principal has a budget of its own.
	e.prn.set(map[string]string{"z-sub": consentPIDB}, nil)
	e.cs.active[consentPIDB] = glovoconsent.Record{ID: "gcn_b", PrincipalID: consentPIDB, Version: glovoconsent.Version, RecordedAt: time.Now().UTC()}
	ck2, page2 := e.mustSignIn()
	if rec := e.act(ck2, page2, glovoAccessSelfActionRequest); rec.Code != http.StatusOK {
		t.Errorf("another principal = %d %s", rec.Code, rec.Body.String())
	}
}

// A refused request (no consent, not valid) does not use up the budget.
func TestGlovoAccessSelfLimiterCountsOnlyRealRequests(t *testing.T) {
	e := newSelfEnv(t, selfSetup{})
	ck, page := e.mustSignIn()
	for i := 0; i < glovoAccessSelfRequestsPerHour+2; i++ {
		page = e.act(ck, page, glovoAccessSelfActionRequest)
		if page.Code != http.StatusConflict {
			t.Fatalf("request without consent %d = %d", i, page.Code)
		}
	}
	page = e.act(ck, page, glovoAccessSelfActionConsent)
	if rec := e.act(ck, page, glovoAccessSelfActionRequest); rec.Code != http.StatusOK || e.as.reqCalls != 1 {
		t.Errorf("first real request = %d, %d store calls", rec.Code, e.as.reqCalls)
	}
}

// --- what must never be written anywhere -----------------------------------

// The login, name and email of the person reach no page, flow entry, log
// line or audit row.
func TestGlovoAccessSelfKeepsThePersonOutOfEverything(t *testing.T) {
	logs := &lockedBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	e := newSelfEnv(t, selfSetup{})
	e.idp.extra["email"] = "new.customer@gmail.example"
	e.idp.extra["name"] = "tool@1.2.3"
	e.idp.extra["given_name"] = "New Customer"
	e.do("GET", glovoAccessSelfPath, nil, nil)
	ck, page := e.mustSignIn()
	if strings.Contains(e.flow.payloads(), "@") || strings.Contains(e.flow.payloads(), "New Customer") {
		t.Errorf("a flow entry holds the person's name or address: %s", e.flow.payloads())
	}
	for _, action := range []string{glovoAccessSelfActionRequest, glovoAccessSelfActionConsent, glovoAccessSelfActionRequest, glovoAccessSelfActionWithdrawRequest, glovoAccessSelfActionWithdrawConsent, "bogus"} {
		if next := e.act(ck, page, action); len(selfForm(next.Body.String())) != 0 {
			page = next
		}
	}
	// Refusals and failures render and log too.
	e.as.getErr = errors.New("db down")
	e.act(ck, page, glovoAccessSelfActionConsent)
	e.as.getErr = nil
	e.idp.extra = customerIDClaims()
	e.signIn()
	e.idp.extra = googleCustomerClaims()
	e.prn.set(nil, auth.ErrPrincipalDisabled)
	e.signIn()
	e.prn.set(nil, fmt.Errorf("%w: %w", auth.ErrIdentityRefused, principals.ErrCustomerConflict))
	e.signIn()

	if len(e.bodies) < 12 {
		t.Fatalf("only %d pages were rendered", len(e.bodies))
	}
	out := logs.String()
	if out == "" {
		t.Fatal("nothing was logged, so the log check proves nothing")
	}
	// The audit logger's own line names the actor, which is the principal
	// id by design; nothing else may name the person.
	for _, bad := range []string{"@", selfUsername, "new.customer", "New Customer", testGoogleSub} {
		if strings.Contains(out, bad) {
			t.Errorf("a log line holds %q:\n%s", bad, out)
		}
	}
	rows := e.audit.List(0)
	if len(rows) == 0 {
		t.Fatal("no audit rows")
	}
	for _, en := range rows {
		line := fmt.Sprintf("%+v", en)
		if strings.Contains(line, "@") || strings.Contains(line, "new.customer") || en.UserID != consentPIDA {
			t.Errorf("audit row holds the person or another actor: %s", line)
		}
	}
}

// The policy of the decision page, with Google's origin added for the
// sign-in form's redirect chain.
func TestGlovoAccessSelfContentSecurityPolicy(t *testing.T) {
	for issuer, want := range map[string]string{
		"https://auth.example":      "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://auth.example https://accounts.google.com; frame-ancestors 'none'; base-uri 'none'",
		"https://auth.example:8443": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://auth.example:8443 https://accounts.google.com; frame-ancestors 'none'; base-uri 'none'",
		"http://auth.example":       "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://accounts.google.com; frame-ancestors 'none'; base-uri 'none'",
	} {
		p := newGlovoAccessSelf(&GlovoAccessSelfPageOptions{Issuer: issuer, BaseURL: selfBaseURL})
		rec := httptest.NewRecorder()
		p.failed(rec, http.StatusBadRequest, "x")
		if got := rec.Header().Get("Content-Security-Policy"); got != want {
			t.Errorf("issuer %s: CSP = %q, want %q", issuer, got, want)
		}
	}
	e := newSelfEnv(t, selfSetup{})
	_, page := e.mustSignIn()
	for _, rec := range []*httptest.ResponseRecorder{e.do("GET", glovoAccessSelfPath, nil, nil), page} {
		csp := rec.Header().Get("Content-Security-Policy")
		if !strings.HasPrefix(csp, "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'") || !strings.HasSuffix(csp, "frame-ancestors 'none'; base-uri 'none'") {
			t.Errorf("CSP = %q", csp)
		}
		if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Frame-Options") != "DENY" {
			t.Errorf("headers = %v", rec.Header())
		}
	}
}
