package api

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-jose/go-jose/v4"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/principals"
)

// ─── fakes ────────────────────────────────────────────────────────────────

type fakeLinkStore struct {
	mu       sync.Mutex
	linkErr  error
	linked   []auth.Identity
	linkedTo []string
	unlinkFn func(pid, xid string) (*principals.ExternalIdentity, error)
	merged   [][2]string
	mergeErr error
	listErr  error
}

func (f *fakeLinkStore) Provision(_ context.Context, id auth.Identity) (*principals.Principal, error) {
	return &principals.Principal{ID: "prn_" + id.Provider + "_" + id.Subject, Kind: auth.KindHuman, Status: principals.StatusActive}, nil
}

func (f *fakeLinkStore) LinkIdentity(_ context.Context, pid string, id auth.Identity) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.linkErr != nil {
		return "", f.linkErr
	}
	f.linked = append(f.linked, id)
	f.linkedTo = append(f.linkedTo, pid)
	return principals.LinkLinked, nil
}

func (f *fakeLinkStore) UnlinkIdentity(_ context.Context, pid, xid string) (*principals.ExternalIdentity, error) {
	return f.unlinkFn(pid, xid)
}

func (f *fakeLinkStore) MergePrincipals(_ context.Context, from, into string) (principals.MergeResult, error) {
	if f.mergeErr != nil {
		return principals.MergeResult{}, f.mergeErr
	}
	for _, m := range f.merged {
		if m == [2]string{from, into} {
			return principals.MergeResult{AlreadyMerged: true}, nil
		}
	}
	f.merged = append(f.merged, [2]string{from, into})
	return principals.MergeResult{Moved: 1}, nil
}

func (f *fakeLinkStore) Identities(_ context.Context, pid string) ([]principals.ExternalIdentity, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return []principals.ExternalIdentity{{ID: "xid_1", PrincipalID: pid, Provider: "github", Subject: "42"}}, nil
}

// fakeIdP is a minimal ZITADEL: discovery, JWKS, and a token endpoint that
// checks the client secret and PKCE and signs an ID token.
type fakeIdP struct {
	t      *testing.T
	srv    *httptest.Server
	signer jose.Signer
	jwk    jose.JSONWebKey

	mu        sync.Mutex
	challenge string
	nonce     string
	// overrides for negative cases
	nonceOverride string
	authTime      time.Time
	audOverride   string
}

const testLinkClientID, testLinkClientSecret = "link-client", "link-secret"

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{t: t, jwk: jose.JSONWebKey{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}, authTime: time.Now()}
	f.signer, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "k1"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize",
			"token_endpoint": f.srv.URL + "/token", "jwks_uri": f.srv.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{f.jwk}})
	})
	mux.HandleFunc("/token", f.token)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// authorize records what the browser was sent to ZITADEL with.
func (f *fakeIdP) authorize(t *testing.T, authURL string) (state string) {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil || !strings.HasPrefix(authURL, f.srv.URL+"/authorize") {
		t.Fatalf("not sent to ZITADEL: %q", authURL)
	}
	q := u.Query()
	if q.Get("client_id") != testLinkClientID || q.Get("code_challenge_method") != "S256" || q.Get("prompt") != "login" ||
		q.Get("max_age") != "0" {
		t.Fatalf("authorize params: %v", q)
	}
	if q.Get("redirect_uri") != "https://api.example"+linkCallbackPath {
		t.Fatalf("redirect_uri = %q", q.Get("redirect_uri"))
	}
	f.mu.Lock()
	f.challenge, f.nonce = q.Get("code_challenge"), q.Get("nonce")
	f.mu.Unlock()
	return q.Get("state")
}

func (f *fakeIdP) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	_ = r.ParseForm()
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if id != testLinkClientID || secret != testLinkClientSecret || r.PostForm.Get("code") != "z-code" ||
		base64.RawURLEncoding.EncodeToString(sum[:]) != f.challenge {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}
	nonce := f.nonce
	if f.nonceOverride != "" {
		nonce = f.nonceOverride
	}
	aud := testLinkClientID
	if f.audOverride != "" {
		aud = f.audOverride
	}
	now := time.Now()
	payload, _ := json.Marshal(map[string]any{
		"iss": f.srv.URL, "sub": "z-sub", "aud": aud, "nonce": nonce,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "auth_time": f.authTime.Unix(),
		"preferred_username": "dmitrii",
	})
	sig, _ := f.signer.Sign(payload)
	idToken, _ := sig.CompactSerialize()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600, "id_token": idToken})
}

type linkHarness struct {
	t      *testing.T
	router http.Handler
	store  *fakeLinkStore
	idp    *fakeIdP
	audit  *audit.Logger
	oauth  *auth.OAuthServer

	clockMu sync.Mutex
	clock   time.Time
	// beforeProve runs inside ProveGitHub, i.e. while the GitHub callback
	// holds no lock and waits on the network.
	beforeProve func()
}

// advance moves the linker's clock forward.
func (h *linkHarness) advance(d time.Duration) {
	h.clockMu.Lock()
	h.clock = h.clock.Add(d)
	h.clockMu.Unlock()
}

func newLinkHarness(t *testing.T) *linkHarness {
	t.Helper()
	idp := newFakeIdP(t)
	store := &fakeLinkStore{}
	logger := audit.NewLogger()
	h := &linkHarness{t: t, store: store, idp: idp, audit: logger, clock: time.Now(),
		oauth: auth.NewOAuthServer("https://api.example", "gh-client", "gh-secret", []byte("test-secret"), nil, nil)}
	opts := &IdentityLinkOptions{
		Store: store, ProviderName: "zitadel", Issuer: idp.srv.URL,
		ClientID: testLinkClientID, ClientSecret: testLinkClientSecret,
		BaseURL: "https://api.example", GitHubClientID: "gh-client",
		ProveGitHub: func(_ context.Context, code, redirect string) (string, int64, error) {
			if code != "gh-code" || redirect != "https://api.example"+githubCallbackPath {
				return "", 0, errors.New("bad github code")
			}
			if h.beforeProve != nil {
				h.beforeProve()
			}
			return "mashkovd", 42, nil
		},
		clock: func() time.Time {
			h.clockMu.Lock()
			defer h.clockMu.Unlock()
			return h.clock
		},
	}
	h.router = NewRouter(Options{IdentityLink: opts, AuditLog: logger, OAuthServer: h.oauth})
	return h
}

func (h *linkHarness) do(method, target string, cookie *http.Cookie, form url.Values) *httptest.ResponseRecorder {
	var req *http.Request
	if form != nil {
		req = httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	return rec
}

// start begins a link and returns the browser cookie and GitHub state.
func (h *linkHarness) start() (*http.Cookie, string) {
	h.t.Helper()
	rec := h.do(http.MethodGet, linkStartPath, nil, nil)
	if rec.Code != http.StatusFound {
		h.t.Fatalf("start = %d %s", rec.Code, rec.Body.String())
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Host != "github.com" || loc.Query().Get("redirect_uri") != "https://api.example"+githubCallbackPath {
		h.t.Fatalf("start redirect = %s", loc)
	}
	var ck *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == linkCookieName {
			ck = c
		}
	}
	if ck == nil || !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteLaxMode {
		h.t.Fatalf("link cookie = %+v", ck)
	}
	return ck, loc.Query().Get("state")
}

// github runs the GitHub half and returns the ZITADEL state.
func (h *linkHarness) github(ck *http.Cookie, state string) string {
	h.t.Helper()
	rec := h.do(http.MethodGet, githubCallbackPath+"?code=gh-code&state="+url.QueryEscape(state), ck, nil)
	if rec.Code != http.StatusFound {
		h.t.Fatalf("github callback = %d %s", rec.Code, rec.Body.String())
	}
	return h.idp.authorize(h.t, rec.Header().Get("Location"))
}

var hiddenField = regexp.MustCompile(`name="(challenge|csrf)" value="([^"]+)"`)

// zitadel runs the ZITADEL half and returns the confirm form fields.
func (h *linkHarness) zitadel(ck *http.Cookie, zState string) (*httptest.ResponseRecorder, url.Values) {
	h.t.Helper()
	rec := h.do(http.MethodGet, linkCallbackPath+"?code=z-code&state="+url.QueryEscape(zState), ck, nil)
	form := url.Values{}
	for _, m := range hiddenField.FindAllStringSubmatch(rec.Body.String(), -1) {
		form.Set(m[1], m[2])
	}
	return rec, form
}

func (h *linkHarness) fullFlow() (*http.Cookie, url.Values) {
	ck, state := h.start()
	zState := h.github(ck, state)
	rec, form := h.zitadel(ck, zState)
	if rec.Code != http.StatusOK || form.Get("csrf") == "" {
		h.t.Fatalf("zitadel callback = %d %s", rec.Code, rec.Body.String())
	}
	return ck, form
}

// ─── browser flow ─────────────────────────────────────────────────────────

func TestIdentityLinkFlowLinksBothProvenIdentities(t *testing.T) {
	h := newLinkHarness(t)
	before := testutil.ToFloat64(identityLinksTotal.WithLabelValues("zitadel", principals.LinkLinked))
	ck, form := h.fullFlow()
	if len(h.store.linked) != 0 {
		t.Fatal("linked before the person confirmed")
	}
	rec := h.do(http.MethodPost, linkConfirmPath, ck, form)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Identities linked") {
		t.Fatalf("confirm = %d %s", rec.Code, rec.Body.String())
	}
	if len(h.store.linked) != 1 {
		t.Fatalf("links = %d, want 1", len(h.store.linked))
	}
	got, pid := h.store.linked[0], h.store.linkedTo[0]
	want := auth.Identity{Provider: "zitadel", Issuer: h.idp.srv.URL, Subject: "z-sub", Display: "dmitrii", Kind: auth.KindHuman}
	if got != want || pid != "prn_github_42" {
		t.Fatalf("linked %+v to %s; want %+v to prn_github_42", got, pid, want)
	}
	if n := testutil.ToFloat64(identityLinksTotal.WithLabelValues("zitadel", principals.LinkLinked)) - before; n != 1 {
		t.Errorf("identity_links_total{linked} moved by %v, want 1", n)
	}
	entries := h.audit.List(10)
	if len(entries) != 1 || entries[0].Operation != "identity.link" || entries[0].Status != "succeeded" ||
		entries[0].Parameters["subject"] != "z-sub" || entries[0].Parameters["github_id"] != "42" {
		t.Fatalf("audit = %+v", entries)
	}
	// Single use: the same confirm again changes nothing.
	if rec := h.do(http.MethodPost, linkConfirmPath, ck, form); rec.Code != http.StatusBadRequest || len(h.store.linked) != 1 {
		t.Fatalf("replayed confirm = %d, links = %d", rec.Code, len(h.store.linked))
	}
}

// The second half of a link started elsewhere must not land on the starter's
// principal: every step checks the browser cookie.
func TestIdentityLinkRefusesAnotherBrowser(t *testing.T) {
	h := newLinkHarness(t)
	ck, state := h.start()
	other := &http.Cookie{Name: linkCookieName, Value: "someone-else", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode}

	if rec := h.do(http.MethodGet, githubCallbackPath+"?code=gh-code&state="+url.QueryEscape(state), other, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("github callback from another browser = %d", rec.Code)
	}
	zState := h.github(ck, state)
	if rec, _ := h.zitadel(other, zState); rec.Code != http.StatusBadRequest {
		t.Fatalf("zitadel callback from another browser = %d", rec.Code)
	}

	h2 := newLinkHarness(t)
	ck2, form := h2.fullFlow()
	_ = ck2
	if rec := h2.do(http.MethodPost, linkConfirmPath, other, form); rec.Code != http.StatusBadRequest || len(h2.store.linked) != 0 {
		t.Fatalf("confirm from another browser = %d, links = %d", rec.Code, len(h2.store.linked))
	}
	if rec := h2.do(http.MethodPost, linkConfirmPath, nil, form); rec.Code != http.StatusBadRequest || len(h2.store.linked) != 0 {
		t.Fatalf("confirm without cookie = %d", rec.Code)
	}
}

func TestIdentityLinkRefusesAWrongCSRFToken(t *testing.T) {
	h := newLinkHarness(t)
	ck, form := h.fullFlow()
	form.Set("csrf", "forged")
	if rec := h.do(http.MethodPost, linkConfirmPath, ck, form); rec.Code != http.StatusBadRequest || len(h.store.linked) != 0 {
		t.Fatalf("confirm with a forged csrf = %d, links = %d", rec.Code, len(h.store.linked))
	}
}

func TestIdentityLinkRefusesAForeignNonceStaleSignInAndWrongAudience(t *testing.T) {
	cases := map[string]func(*fakeIdP){
		"nonce":    func(f *fakeIdP) { f.nonceOverride = "another-session" },
		"stale":    func(f *fakeIdP) { f.authTime = time.Now().Add(-time.Hour) },
		"audience": func(f *fakeIdP) { f.audOverride = "another-client" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			h := newLinkHarness(t)
			ck, state := h.start()
			zState := h.github(ck, state)
			h.idp.mu.Lock()
			mutate(h.idp)
			h.idp.mu.Unlock()
			rec, form := h.zitadel(ck, zState)
			if rec.Code != http.StatusBadRequest || form.Get("csrf") != "" {
				t.Fatalf("zitadel callback = %d, csrf issued = %v", rec.Code, form.Get("csrf") != "")
			}
		})
	}
}

// Owner decision A on #435: refused with an explanation, never moved.
func TestIdentityLinkExplainsAnIdentityOwnedElsewhere(t *testing.T) {
	h := newLinkHarness(t)
	h.store.linkErr = &principals.OwnedElsewhereError{PrincipalID: "prn_other"}
	ck, form := h.fullFlow()
	rec := h.do(http.MethodPost, linkConfirmPath, ck, form)
	body := rec.Body.String()
	if rec.Code != http.StatusConflict || !strings.Contains(body, "prn_other") || !strings.Contains(body, "merge") {
		t.Fatalf("confirm = %d %s", rec.Code, body)
	}
	entries := h.audit.List(10)
	if len(entries) != 1 || entries[0].Status != "failed" || entries[0].Parameters["other_principal_id"] != "prn_other" ||
		entries[0].Parameters["result"] != "refused_owned_elsewhere" {
		t.Fatalf("audit = %+v", entries)
	}
}

func TestIdentityLinkIsOffWithoutAClient(t *testing.T) {
	r := NewRouter(Options{IdentityLink: &IdentityLinkOptions{Store: &fakeLinkStore{}}})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, linkStartPath, nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("start without a client = %d, want 503", rec.Code)
	}
}

// The 10-minute TTL holds at every step, and across the unlocked network
// calls inside a step.
func TestIdentityLinkRefusesAnExpiredChallengeAtEveryStep(t *testing.T) {
	expired := linkChallengeTTL + time.Second

	t.Run("github callback", func(t *testing.T) {
		h := newLinkHarness(t)
		ck, state := h.start()
		h.advance(expired)
		if rec := h.do(http.MethodGet, githubCallbackPath+"?code=gh-code&state="+url.QueryEscape(state), ck, nil); rec.Code != http.StatusBadRequest {
			t.Fatalf("github callback after the TTL = %d, want 400", rec.Code)
		}
	})
	t.Run("expires while GitHub is verified", func(t *testing.T) {
		h := newLinkHarness(t)
		ck, state := h.start()
		h.beforeProve = func() { h.advance(expired) }
		rec := h.do(http.MethodGet, githubCallbackPath+"?code=gh-code&state="+url.QueryEscape(state), ck, nil)
		if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
			t.Fatalf("github callback whose challenge expired mid-call = %d (Location %q), want 400 and no ZITADEL redirect",
				rec.Code, rec.Header().Get("Location"))
		}
	})
	t.Run("zitadel callback", func(t *testing.T) {
		h := newLinkHarness(t)
		ck, state := h.start()
		zState := h.github(ck, state)
		h.advance(expired)
		if rec, form := h.zitadel(ck, zState); rec.Code != http.StatusBadRequest || form.Get("csrf") != "" {
			t.Fatalf("zitadel callback after the TTL = %d, csrf issued = %v", rec.Code, form.Get("csrf") != "")
		}
	})
	t.Run("confirm", func(t *testing.T) {
		h := newLinkHarness(t)
		ck, form := h.fullFlow()
		h.advance(expired)
		if rec := h.do(http.MethodPost, linkConfirmPath, ck, form); rec.Code != http.StatusBadRequest || len(h.store.linked) != 0 {
			t.Fatalf("confirm after the TTL = %d, links = %d", rec.Code, len(h.store.linked))
		}
	})
	t.Run("just inside the TTL", func(t *testing.T) {
		h := newLinkHarness(t)
		ck, form := h.fullFlow()
		h.advance(linkChallengeTTL - time.Second)
		if rec := h.do(http.MethodPost, linkConfirmPath, ck, form); rec.Code != http.StatusOK || len(h.store.linked) != 1 {
			t.Fatalf("confirm inside the TTL = %d, links = %d", rec.Code, len(h.store.linked))
		}
	})
}

// One source cannot hold linking shut: its oldest unfinished link gives way
// to its newest, and other sources are untouched.
func TestIdentityLinkCapsUnfinishedLinksPerSource(t *testing.T) {
	h := newLinkHarness(t)
	startFrom := func(ip string) (*http.Cookie, string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, linkStartPath, nil)
		req.RemoteAddr = ip + ":40000"
		rec := httptest.NewRecorder()
		h.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("start from %s = %d", ip, rec.Code)
		}
		loc, _ := url.Parse(rec.Header().Get("Location"))
		for _, c := range rec.Result().Cookies() {
			if c.Name == linkCookieName {
				return c, loc.Query().Get("state")
			}
		}
		t.Fatal("no link cookie")
		return nil, ""
	}
	otherCk, otherState := startFrom("198.51.100.9")
	var cks []*http.Cookie
	var states []string
	for i := 0; i <= linkMaxPerIP; i++ {
		h.advance(time.Second)
		ck, st := startFrom("198.51.100.1")
		cks, states = append(cks, ck), append(states, st)
	}
	if rec := h.do(http.MethodGet, githubCallbackPath+"?code=gh-code&state="+url.QueryEscape(states[0]), cks[0], nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("the source's oldest link = %d, want 400 (dropped)", rec.Code)
	}
	h.github(cks[linkMaxPerIP], states[linkMaxPerIP])
	h.github(otherCk, otherState)
}

func TestIdentityLinkCookieIsHostPrefixed(t *testing.T) {
	if !strings.HasPrefix(linkCookieName, "__Host-") {
		t.Fatalf("link cookie %q lacks the __Host- prefix", linkCookieName)
	}
}

// No index may hold a challenge byID no longer does, or an expired one: the
// linkMaxChallenges bound is checked against byID alone.
func TestIdentityLinkSweepClearsEveryIndex(t *testing.T) {
	l := newIdentityLinker(&IdentityLinkOptions{})
	now := time.Now()
	live := &linkChallenge{id: "live", githubState: "link.g1", zitadelState: "z1", expiresAt: now.Add(time.Minute)}
	expired := &linkChallenge{id: "old", githubState: "link.g2", zitadelState: "z2", expiresAt: now.Add(-time.Second)}
	orphan := &linkChallenge{id: "orphan", githubState: "link.g3", zitadelState: "z3", expiresAt: now.Add(time.Minute)}
	l.byID["live"], l.byID["old"] = live, expired
	l.byGitHub["link.g1"], l.byGitHub["link.g2"], l.byGitHub["link.g3"] = live, expired, orphan
	l.byZState["z1"], l.byZState["z2"], l.byZState["z3"] = live, expired, orphan
	l.sweepLocked(now)
	if len(l.byID) != 1 || len(l.byGitHub) != 1 || len(l.byZState) != 1 || l.byZState["z1"] != live || l.byGitHub["link.g1"] != live {
		t.Fatalf("after sweep: byID=%d byGitHub=%d byZState=%d, want only the live challenge in each", len(l.byID), len(l.byGitHub), len(l.byZState))
	}
}

// The login flow never consumes a link state: even a pending login stored
// under the very same string is left alone, because the callback hands
// link. states to linking before the OAuth server looks anything up.
func TestLoginFlowNeverConsumesALinkState(t *testing.T) {
	h := newLinkHarness(t)
	ck, state := h.start()
	h.oauth.StorePendingAuth(state, "client", "https://claude.ai/cb", "challenge")
	h.github(ck, state) // the link proceeds to ZITADEL
	if _, ok := h.oauth.LoadPendingAuth(state); !ok {
		t.Fatal("the login flow consumed a link state")
	}
	// And the link state is single-use on its own side.
	if rec := h.do(http.MethodGet, githubCallbackPath+"?code=gh-code&state="+url.QueryEscape(state), ck, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("replayed link GitHub callback = %d, want 400", rec.Code)
	}
}

// Linking never consumes a login state: it goes to the OAuth server, and
// the link handler, reached directly, finds nothing under it either.
func TestLinkFlowNeverConsumesALoginState(t *testing.T) {
	h := newLinkHarness(t)
	ck, linkState := h.start()
	ghState, err := auth.GenerateState()
	if err != nil {
		t.Fatal(err)
	}
	login := ghState + "|client-state"
	h.oauth.StorePendingAuth(login, "client", "https://claude.ai/cb", "challenge")

	// error= makes the OAuth server answer before it loads the pending entry,
	// so the entry surviving below is down to linking alone.
	rec := h.do(http.MethodGet, githubCallbackPath+"?error=access_denied&state="+url.QueryEscape(login), ck, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "GitHub auth error") {
		t.Fatalf("login callback = %d %q, want the OAuth server's answer", rec.Code, rec.Body.String())
	}
	hd := &Handlers{identityLink: newIdentityLinker(&IdentityLinkOptions{
		Store: h.store, ProviderName: "zitadel", Issuer: "https://issuer.example", ClientID: "c", ClientSecret: "s",
		BaseURL: "https://api.example", GitHubClientID: "gh-client",
		ProveGitHub: func(context.Context, string, string) (string, int64, error) {
			t.Fatal("linking acted on a login state")
			return "", 0, nil
		},
	})}
	req := httptest.NewRequest(http.MethodGet, githubCallbackPath+"?code=gh-code&state="+url.QueryEscape(login), nil)
	req.AddCookie(ck)
	direct := httptest.NewRecorder()
	hd.handleIdentityLinkGitHubCallback(direct, req)
	if direct.Code != http.StatusBadRequest {
		t.Fatalf("link handler on a login state = %d, want 400", direct.Code)
	}
	if _, ok := h.oauth.LoadPendingAuth(login); !ok {
		t.Fatal("a login state was consumed")
	}
	h.github(ck, linkState) // the link in flight is untouched
}

// mctl-api runs one replica and keeps challenges in memory. If that ever
// changes, a step that lands on a pod which did not start the link must
// fail safe: a 400 that says to start again, never a 500 or a link.
func TestIdentityLinkOnAnotherPodSaysStartAgain(t *testing.T) {
	a := newLinkHarness(t)
	ck, state := a.start()
	b := newLinkHarness(t) // the other pod: same config, its own memory
	if rec := b.do(http.MethodGet, githubCallbackPath+"?code=gh-code&state="+url.QueryEscape(state), ck, nil); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "Start again from "+linkStartPath) {
		t.Fatalf("GitHub callback on another pod = %d %s", rec.Code, rec.Body.String())
	}
	zState := a.github(ck, state)
	if rec, _ := b.zitadel(ck, zState); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Start again") {
		t.Fatalf("ZITADEL callback on another pod = %d %s", rec.Code, rec.Body.String())
	}
	_, form := a.zitadel(ck, zState)
	if rec := b.do(http.MethodPost, linkConfirmPath, ck, form); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "Start again") || len(b.store.linked) != 0 {
		t.Fatalf("confirm on another pod = %d %s", rec.Code, rec.Body.String())
	}
}

// A link state never reaches the OAuth server, and an OAuth state never
// reaches linking: '.' is outside the base64url alphabet GenerateState uses.
func TestOAuthStatesNeverLookLikeLinkStates(t *testing.T) {
	for i := 0; i < 1000; i++ {
		s, err := auth.GenerateState()
		if err != nil {
			t.Fatal(err)
		}
		if isIdentityLinkState(s) {
			t.Fatalf("OAuth state %q routed to linking", s)
		}
	}
}

// ─── API ──────────────────────────────────────────────────────────────────

type staticResolver string

func (s staticResolver) ResolvePrincipal(context.Context, auth.Identity) (string, error) {
	return string(s), nil
}

func userWithPrincipal(t *testing.T, login string, groups []string, pid string) *auth.User {
	t.Helper()
	u := auth.NewGitHubUser(login, groups)
	if err := auth.AttachPrincipal(context.Background(), staticResolver(pid), u); err != nil {
		t.Fatal(err)
	}
	return u
}

func callAs(h *Handlers, u *auth.User, method, target string, params map[string]string, fn http.HandlerFunc) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	rctx := chi.NewRouteContext()
	for k, v := range params {
		rctx.URLParams.Add(k, v)
	}
	req = req.WithContext(auth.WithUser(context.WithValue(req.Context(), chi.RouteCtxKey, rctx), u))
	rec := httptest.NewRecorder()
	fn(rec, req)
	return rec
}

func TestListIdentityLinksAnswersThePersonOnly(t *testing.T) {
	store := &fakeLinkStore{}
	h := &Handlers{identityLink: newIdentityLinker(&IdentityLinkOptions{Store: store})}
	u := userWithPrincipal(t, "mashkovd", nil, "prn_me")

	rec := callAs(h, u, http.MethodGet, "/", nil, h.ListIdentityLinks)
	var body struct {
		PrincipalID string                        `json:"principal_id"`
		Identities  []principals.ExternalIdentity `json:"identities"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); rec.Code != http.StatusOK || err != nil ||
		body.PrincipalID != "prn_me" || len(body.Identities) != 1 || body.Identities[0].PrincipalID != "prn_me" {
		t.Fatalf("list = %d %s", rec.Code, rec.Body.String())
	}

	surface := auth.NewSurfaceUser("telegram")
	for name, caller := range map[string]*auth.User{
		"surface": surface,
		"relayed": auth.NewRelayedUser("mashkovd", nil, surface),
		"service": auth.NewServiceUser(),
		"agent":   auth.NewAgentUser("implementer", auth.AgentRun{}),
	} {
		if rec := callAs(h, caller, http.MethodGet, "/", nil, h.ListIdentityLinks); rec.Code != http.StatusForbidden {
			t.Errorf("%s list = %d, want 403", name, rec.Code)
		}
		if rec := callAs(h, caller, http.MethodDelete, "/", map[string]string{"id": "xid_1"}, h.UnlinkIdentity); rec.Code != http.StatusForbidden {
			t.Errorf("%s unlink = %d, want 403", name, rec.Code)
		}
	}
	if rec := callAs(h, auth.NewGitHubUser("nobody", nil), http.MethodGet, "/", nil, h.ListIdentityLinks); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("list without a principal = %d, want 503", rec.Code)
	}
	store.listErr = errors.New("conn refused")
	if rec := callAs(h, u, http.MethodGet, "/", nil, h.ListIdentityLinks); rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), "conn refused") {
		t.Errorf("list on a store error = %d %s, want 503 without the error text", rec.Code, rec.Body.String())
	}
	// No user in the context (a route mounted outside auth) is refused, not
	// a nil dereference.
	for name, fn := range map[string]http.HandlerFunc{"list": h.ListIdentityLinks, "unlink": h.UnlinkIdentity} {
		rec := httptest.NewRecorder()
		fn(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s without a user = %d, want 403", name, rec.Code)
		}
	}
	off := &Handlers{}
	if rec := callAs(off, u, http.MethodGet, "/", nil, off.ListIdentityLinks); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("list unconfigured = %d, want 503", rec.Code)
	}
}

// forgetRecorder stands in for principals.Resolver.Forget.
type forgetRecorder struct{ calls [][]string }

func (f *forgetRecorder) forget(ids ...string) { f.calls = append(f.calls, ids) }

func TestUnlinkIdentityMapsTheStoreOutcomes(t *testing.T) {
	store := &fakeLinkStore{}
	fr := &forgetRecorder{}
	h := &Handlers{identityLink: newIdentityLinker(&IdentityLinkOptions{Store: store, ForgetPrincipals: fr.forget}), opts: Options{AuditLog: audit.NewLogger()}}
	u := userWithPrincipal(t, "mashkovd", nil, "prn_me")

	store.unlinkFn = func(pid, xid string) (*principals.ExternalIdentity, error) {
		if pid != "prn_me" {
			t.Fatalf("unlinked on %s, want the caller's principal", pid)
		}
		return nil, principals.ErrLastIdentity
	}
	if rec := callAs(h, u, http.MethodDelete, "/", map[string]string{"id": "xid_1"}, h.UnlinkIdentity); rec.Code != http.StatusConflict {
		t.Fatalf("last identity = %d, want 409", rec.Code)
	}
	store.unlinkFn = func(string, string) (*principals.ExternalIdentity, error) { return nil, principals.ErrNotFound }
	if rec := callAs(h, u, http.MethodDelete, "/", map[string]string{"id": "xid_x"}, h.UnlinkIdentity); rec.Code != http.StatusNotFound {
		t.Fatalf("foreign identity = %d, want 404", rec.Code)
	}
	now := time.Now()
	store.unlinkFn = func(_, xid string) (*principals.ExternalIdentity, error) {
		return &principals.ExternalIdentity{ID: xid, Provider: "zitadel", RevokedAt: &now}, nil
	}
	if len(fr.calls) != 0 {
		t.Fatalf("refused unlinks dropped cached answers: %v", fr.calls)
	}
	if rec := callAs(h, u, http.MethodDelete, "/", map[string]string{"id": "xid_2"}, h.UnlinkIdentity); rec.Code != http.StatusOK {
		t.Fatalf("unlink = %d, want 200", rec.Code)
	}
	if len(fr.calls) != 1 || len(fr.calls[0]) != 1 || fr.calls[0][0] != "prn_me" {
		t.Fatalf("forgot %v after an unlink, want [[prn_me]]", fr.calls)
	}
}

func TestMergePrincipalsIsForHumanAdminsOnly(t *testing.T) {
	store := &fakeLinkStore{}
	fr := &forgetRecorder{}
	h := &Handlers{identityLink: newIdentityLinker(&IdentityLinkOptions{Store: store, ForgetPrincipals: fr.forget}), opts: Options{AuditLog: audit.NewLogger()}}
	params := map[string]string{"from": "prn_q", "into": "prn_p"}

	if rec := callAs(h, auth.NewGitHubUser("someone", []string{"team"}), http.MethodPost, "/", params, h.MergePrincipals); rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin merge = %d, want 403", rec.Code)
	}
	if rec := callAs(h, auth.NewServiceUser(), http.MethodPost, "/", params, h.MergePrincipals); rec.Code != http.StatusForbidden {
		t.Fatalf("service merge = %d, want 403", rec.Code)
	}
	if len(store.merged) != 0 {
		t.Fatal("a refused merge reached the store")
	}
	admin := userWithPrincipal(t, "boss", []string{"admins"}, "prn_boss")
	// Every merge outcome is audited with the actor, the source and the target.
	auditNames := func(e audit.Entry) bool {
		return e.Operation == "principal.merge" && e.UserID == "boss" && e.Parameters["actor_principal_id"] == "prn_boss" &&
			e.Parameters["from_principal_id"] == "prn_q" && e.Parameters["into_principal_id"] == "prn_p"
	}
	rec := callAs(h, admin, http.MethodPost, "/", params, h.MergePrincipals)
	if rec.Code != http.StatusOK || len(store.merged) != 1 || store.merged[0] != [2]string{"prn_q", "prn_p"} {
		t.Fatalf("admin merge = %d, merged %v", rec.Code, store.merged)
	}
	if e := h.opts.AuditLog.List(10); len(e) != 1 || !auditNames(e[0]) || e[0].Status != "succeeded" || e[0].Parameters["moved"] != "1" {
		t.Fatalf("audit = %+v", e)
	}
	// A retry answers 200 again and says so.
	rec = callAs(h, admin, http.MethodPost, "/", params, h.MergePrincipals)
	var retry struct {
		AlreadyMerged bool   `json:"already_merged"`
		Moved         int    `json:"moved_identities"`
		Detail        string `json:"detail"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &retry); rec.Code != http.StatusOK || err != nil || !retry.AlreadyMerged || retry.Moved != 0 ||
		!strings.Contains(retry.Detail, "may differ") {
		t.Fatalf("retried merge = %d %s", rec.Code, rec.Body.String())
	}
	if e := h.opts.AuditLog.List(1); !auditNames(e[0]) || e[0].Parameters["already_merged"] != "true" {
		t.Fatalf("retry audit = %+v", e)
	}
	if len(fr.calls) == 0 || strings.Join(fr.calls[0], ",") != "prn_q,prn_p" {
		t.Fatalf("forgot %v after a merge, want [prn_q prn_p] first", fr.calls)
	}
	store.mergeErr = principals.ErrMergeConflict
	if rec := callAs(h, admin, http.MethodPost, "/", params, h.MergePrincipals); rec.Code != http.StatusConflict {
		t.Fatalf("conflicting merge = %d, want 409", rec.Code)
	}
	if e := h.opts.AuditLog.List(1); !auditNames(e[0]) || e[0].Status != "failed" || e[0].Parameters["reason"] != "merge_conflict" {
		t.Fatalf("409 audit = %+v", e)
	}
	// The audit row carries a classified reason, never the store's text.
	store.mergeErr = errors.New("dial tcp 10.0.0.7:5432: connection refused")
	if rec := callAs(h, admin, http.MethodPost, "/", params, h.MergePrincipals); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("merge on a store error = %d, want 503", rec.Code)
	}
	e := h.opts.AuditLog.List(1)
	if len(e) != 1 || e[0].Status != "failed" || e[0].Parameters["reason"] != "store_error" {
		t.Fatalf("audit = %+v", e)
	}
	for k, v := range e[0].Parameters {
		if strings.Contains(v, "10.0.0.7") {
			t.Fatalf("audit parameter %s leaks the store error: %q", k, v)
		}
	}
	if len(fr.calls) != 2 {
		t.Fatalf("forget calls = %v, want one per successful merge (2) and none for failures", fr.calls)
	}
}
