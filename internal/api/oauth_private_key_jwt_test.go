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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/auth/cimd"
	"github.com/mctlhq/mctl-api/internal/auth/refreshstore"
)

var pkjwtKey = sync.OnceValue(func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
})

const pkjwtVerifier = "verifier-verifier-verifier-verifier-verifier"

// pkjwtEnv is a server with CIMD on whose client cimdID declares
// private_key_jwt with an RS256 key set on its own host. The document, the
// key set's status and the clock can be changed by the test.
type pkjwtEnv struct {
	h          *Handlers
	o          *auth.OAuthServer
	mu         sync.Mutex
	doc        string
	docStatus  int
	jwksStatus int
	clock      time.Time
	jti        atomic.Int64
}

func pkjwtDocBody(method string) string {
	m := map[string]any{
		"client_id": cimdID, "client_name": "ChatGPT-like",
		"redirect_uris": []string{cbURL}, "token_endpoint_auth_method": method,
	}
	if method == cimd.AuthMethodPrivateKeyJWT {
		m["token_endpoint_auth_signing_alg"] = "RS256"
		m["jwks_uri"] = "https://app.example.com/jwks.json"
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func newPKJWTEnv(t *testing.T) *pkjwtEnv {
	t.Helper()
	e := &pkjwtEnv{doc: pkjwtDocBody(cimd.AuthMethodPrivateKeyJWT), clock: time.Now()}
	jwks, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &pkjwtKey().PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"},
	}})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		e.mu.Lock()
		defer e.mu.Unlock()
		if r.URL.Path == "/jwks.json" {
			if e.jwksStatus != 0 {
				w.WriteHeader(e.jwksStatus)
				return
			}
			_, _ = w.Write(jwks)
			return
		}
		if e.docStatus != 0 {
			w.WriteHeader(e.docStatus)
			return
		}
		_, _ = w.Write([]byte(e.doc))
	}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	cl := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
			DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, n, srv.Listener.Addr().String())
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	e.o = auth.NewOAuthServer("https://api.mctl.ai", "gh", "sec", []byte("secret"),
		[]string{"https://claude.ai/api/mcp/auth_callback"}, nil)
	e.o.CIMD = cimd.NewResolver(cimd.Options{AllowedHosts: []string{"app.example.com"}, HTTPClient: cl, Now: e.now})
	e.h = &Handlers{opts: Options{OAuthServer: e.o}}
	return e
}

func (e *pkjwtEnv) now() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.clock
}

func (e *pkjwtEnv) setDoc(body string, advance time.Duration) {
	e.mu.Lock()
	e.doc = body
	e.clock = e.clock.Add(advance)
	e.mu.Unlock()
}

func (e *pkjwtEnv) code(t *testing.T) string {
	t.Helper()
	sum := sha256.Sum256([]byte(pkjwtVerifier))
	code, err := e.o.IssueCode(context.Background(), "alice", testPRN, cimdID, cbURL,
		base64.RawURLEncoding.EncodeToString(sum[:]), nil)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func (e *pkjwtEnv) assertion(t *testing.T, aud string) string {
	t.Helper()
	now := e.now()
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: pkjwtKey()},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := jwt.Signed(s).Claims(jwt.Claims{
		Issuer: cimdID, Subject: cimdID, Audience: jwt.Audience{aud},
		Expiry: jwt.NewNumericDate(now.Add(time.Minute)), IssuedAt: jwt.NewNumericDate(now),
		ID: fmt.Sprintf("jti-%d", e.jti.Add(1)),
	}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func withAssertion(v url.Values, assertion string) url.Values {
	v.Set("client_assertion_type", auth.ClientAssertionTypeJWT)
	v.Set("client_assertion", assertion)
	return v
}

func codeGrant(code string) url.Values {
	return url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {pkjwtVerifier},
		"client_id": {cimdID}, "redirect_uri": {cbURL},
	}
}

func tokenRequest(h *Handlers, v url.Values) (*httptest.ResponseRecorder, map[string]any) {
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.handleOAuthToken(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec, body
}

func wantInvalidClient(t *testing.T, rec *httptest.ResponseRecorder, body map[string]any) {
	t.Helper()
	if rec.Code != http.StatusUnauthorized || body["error"] != "invalid_client" {
		t.Fatalf("want 401 invalid_client, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestPrivateKeyJWTCodeAndRefresh(t *testing.T) {
	e := newPKJWTEnv(t)
	rec, body := tokenRequest(e.h, withAssertion(codeGrant(e.code(t)), e.assertion(t, "https://api.mctl.ai")))
	if rec.Code != http.StatusOK || body["refresh_token"] == "" {
		t.Fatalf("code grant: %d %s", rec.Code, rec.Body.String())
	}
	refresh := body["refresh_token"].(string)

	// Refresh needs its own assertion; without one the session is untouched.
	before := testutil.ToFloat64(oauthClientAuthFailures.WithLabelValues("refresh_token", "absent"))
	rec, body = tokenRequest(e.h, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {cimdID}})
	wantInvalidClient(t, rec, body)
	if got := testutil.ToFloat64(oauthClientAuthFailures.WithLabelValues("refresh_token", "absent")); got != before+1 {
		t.Fatalf("metric %v -> %v", before, got)
	}
	rec, _ = tokenRequest(e.h, withAssertion(url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {cimdID},
	}, e.assertion(t, "https://api.mctl.ai/oauth/token")))
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh: %d %s", rec.Code, rec.Body.String())
	}
}

// pkjwtRefreshStore is a refreshstore.Store that carries a session's auth
// method through rotation as PostgresStore does (its own tests prove that),
// so the store-backed refresh path runs without a database.
type pkjwtRefreshStore struct {
	mu      sync.Mutex
	rows    map[string]refreshstore.Session
	family  map[string]string
	revoked map[string]bool
	rotated map[string]bool
	reasons []string
}

func newPKJWTRefreshStore() *pkjwtRefreshStore {
	return &pkjwtRefreshStore{rows: map[string]refreshstore.Session{}, family: map[string]string{},
		revoked: map[string]bool{}, rotated: map[string]bool{}}
}

func (f *pkjwtRefreshStore) Insert(raw, _ string, sess refreshstore.Session, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rows[raw], f.family[raw] = sess, raw
	return nil
}

func (f *pkjwtRefreshStore) RotateIf(old, next, _ string, _ time.Time, accept func(refreshstore.Session) error) (refreshstore.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	sess, ok := f.rows[old]
	if !ok || f.revoked[f.family[old]] || f.rotated[old] {
		return refreshstore.Session{}, refreshstore.ErrInvalidToken
	}
	if accept != nil {
		if err := accept(sess); err != nil {
			return refreshstore.Session{}, err
		}
	}
	f.rotated[old] = true
	f.rows[next], f.family[next] = sess, f.family[old]
	return sess, nil
}

func (f *pkjwtRefreshStore) RevokeFamily(raw, _, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked[f.family[raw]] = true
	f.reasons = append(f.reasons, reason)
	return nil
}

func (f *pkjwtRefreshStore) RevokePrincipal(string, string) (int64, error) { return 0, nil }
func (f *pkjwtRefreshStore) GC() error                                     { return nil }

// A session issued under private_key_jwt is not refreshed with none after
// the client's document drops to none, in either refresh path, and the
// refused token is spent.
func TestPrivateKeyJWTRefreshNoDowngrade(t *testing.T) {
	for _, tc := range []struct {
		name  string
		store *pkjwtRefreshStore
	}{{"memory", nil}, {"store", newPKJWTRefreshStore()}} {
		t.Run(tc.name, func(t *testing.T) {
			e := newPKJWTEnv(t)
			if tc.store != nil {
				e.o.RefreshStore = tc.store
			}
			rec, body := tokenRequest(e.h, withAssertion(codeGrant(e.code(t)), e.assertion(t, "https://api.mctl.ai")))
			if rec.Code != http.StatusOK {
				t.Fatalf("exchange: %d %s", rec.Code, rec.Body.String())
			}
			// One rotation first, so the binding is checked on a successor.
			grant := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {body["refresh_token"].(string)}, "client_id": {cimdID}}
			rec, body = tokenRequest(e.h, withAssertion(grant, e.assertion(t, "https://api.mctl.ai")))
			if rec.Code != http.StatusOK {
				t.Fatalf("refresh: %d %s", rec.Code, rec.Body.String())
			}
			e.setDoc(pkjwtDocBody(cimd.AuthMethodNone), 2*time.Hour)
			grant = url.Values{"grant_type": {"refresh_token"}, "refresh_token": {body["refresh_token"].(string)}, "client_id": {cimdID}}
			rec, body = tokenRequest(e.h, grant)
			wantInvalidClient(t, rec, body)
			if tc.store != nil && (len(tc.store.reasons) != 1 || tc.store.reasons[0] != "auth_method_downgrade") {
				t.Fatalf("family not revoked: %v", tc.store.reasons)
			}
			if rec, _ := tokenRequest(e.h, grant); rec.Code == http.StatusOK {
				t.Fatal("refused refresh token still works")
			}
			// A session issued under none refreshes with none.
			rec, body = tokenRequest(e.h, codeGrant(e.code(t)))
			if rec.Code != http.StatusOK {
				t.Fatalf("none exchange: %d %s", rec.Code, rec.Body.String())
			}
			grant.Set("refresh_token", body["refresh_token"].(string))
			if rec, _ := tokenRequest(e.h, grant); rec.Code != http.StatusOK {
				t.Fatalf("none refresh: %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// mctl-api#851: the auth-method check runs before the resource check, so a
// private_key_jwt session refreshed with none (the client's document dropped
// to none) and a mismatched or unknown resource is still a downgrade:
// invalid_client, the token spent and, with a store, the family revoked.
// Not invalid_target.
func TestPrivateKeyJWTRefreshDowngradeBeatsResource(t *testing.T) {
	for _, resource := range []string{"https://support.mctl.ai", "https://evil.example"} {
		for _, tc := range []struct {
			name  string
			store *pkjwtRefreshStore
		}{{"memory", nil}, {"store", newPKJWTRefreshStore()}} {
			t.Run(tc.name+" "+resource, func(t *testing.T) {
				e := newPKJWTEnv(t)
				e.o.SupportResource = "https://support.mctl.ai"
				if tc.store != nil {
					e.o.RefreshStore = tc.store
				}
				rec, body := tokenRequest(e.h, withAssertion(codeGrant(e.code(t)), e.assertion(t, "https://api.mctl.ai")))
				if rec.Code != http.StatusOK {
					t.Fatalf("exchange: %d %s", rec.Code, rec.Body.String())
				}
				e.setDoc(pkjwtDocBody(cimd.AuthMethodNone), 2*time.Hour)
				grant := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {body["refresh_token"].(string)}, "client_id": {cimdID}, "resource": {resource}}
				rec, body = tokenRequest(e.h, grant)
				wantInvalidClient(t, rec, body)
				if tc.store != nil && (len(tc.store.reasons) != 1 || tc.store.reasons[0] != "auth_method_downgrade") {
					t.Fatalf("family not revoked: %v", tc.store.reasons)
				}
				grant.Del("resource")
				if rec, _ := tokenRequest(e.h, grant); rec.Code == http.StatusOK {
					t.Fatal("refused refresh token still works")
				}
			})
		}
	}
}

// A key set that cannot be fetched observed nothing about the client: the
// token request is a retryable server error, never invalid_client, and the
// code is kept.
func TestPrivateKeyJWTKeySetFetchFailureIsServerError(t *testing.T) {
	e := newPKJWTEnv(t)
	code := e.code(t)
	e.mu.Lock()
	e.jwksStatus = http.StatusServiceUnavailable
	e.mu.Unlock()
	rec, body := tokenRequest(e.h, withAssertion(codeGrant(code), e.assertion(t, "https://api.mctl.ai")))
	if rec.Code != http.StatusInternalServerError || body["error"] != "server_error" {
		t.Fatalf("want 500 server_error, got %d %s", rec.Code, rec.Body.String())
	}
	e.mu.Lock()
	e.jwksStatus = 0
	e.mu.Unlock()
	// The failure is cached for minTTL; past it the same code redeems.
	e.setDoc(pkjwtDocBody(cimd.AuthMethodPrivateKeyJWT), time.Minute)
	if rec, _ := tokenRequest(e.h, withAssertion(codeGrant(code), e.assertion(t, "https://api.mctl.ai"))); rec.Code != http.StatusOK {
		t.Fatalf("after recovery: %d %s", rec.Code, rec.Body.String())
	}
}

// The method read from the document at consent binds the code: approval
// does not fetch the document again, and a document that drops to none by
// the time of the exchange does not unbind it.
func TestConsentCarriesAuthMethodToCode(t *testing.T) {
	e := newPKJWTEnv(t)
	c := completion(cimdID)
	sum := sha256.Sum256([]byte(pkjwtVerifier))
	c.CodeChallenge = base64.RawURLEncoding.EncodeToString(sum[:])
	token, cookie, _ := requestConsentFor(t, e.h, c)
	// Unreachable at approval: a re-resolve there would fail the grant.
	e.setDoc("not json", 2*time.Hour)
	rec := postConsent(e.h, token, "approve", cookie)
	loc, err := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || err != nil || loc.Query().Get("code") == "" {
		t.Fatalf("approve: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	e.setDoc(pkjwtDocBody(cimd.AuthMethodNone), 2*time.Hour)
	rec, body := tokenRequest(e.h, codeGrant(loc.Query().Get("code")))
	wantInvalidClient(t, rec, body)
}

// A request that fails client authentication does not consume the code.
func TestPrivateKeyJWTMissingAssertionKeepsCode(t *testing.T) {
	e := newPKJWTEnv(t)
	code := e.code(t)
	for name, v := range map[string]url.Values{
		"none":       codeGrant(code),
		"wrong type": withAssertion(codeGrant(code), e.assertion(t, "https://api.mctl.ai")),
		"wrong aud":  withAssertion(codeGrant(code), e.assertion(t, "https://evil.example.com")),
	} {
		if name == "wrong type" {
			v.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:saml2-bearer")
		}
		rec, body := tokenRequest(e.h, v)
		if rec.Code != http.StatusUnauthorized || body["error"] != "invalid_client" {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	if rec, _ := tokenRequest(e.h, withAssertion(codeGrant(code), e.assertion(t, "https://api.mctl.ai"))); rec.Code != http.StatusOK {
		t.Fatalf("code consumed by a failed authentication: %d %s", rec.Code, rec.Body.String())
	}
}

func TestPrivateKeyJWTAssertionIsSingleUse(t *testing.T) {
	e := newPKJWTEnv(t)
	as := e.assertion(t, "https://api.mctl.ai")
	if rec, _ := tokenRequest(e.h, withAssertion(codeGrant(e.code(t)), as)); rec.Code != http.StatusOK {
		t.Fatalf("first use: %d %s", rec.Code, rec.Body.String())
	}
	rec, body := tokenRequest(e.h, withAssertion(codeGrant(e.code(t)), as))
	wantInvalidClient(t, rec, body)
}

// RFC 7521 section 4.2: with an assertion, client_id may be omitted.
func TestPrivateKeyJWTClientIDFromAssertion(t *testing.T) {
	e := newPKJWTEnv(t)
	v := withAssertion(codeGrant(e.code(t)), e.assertion(t, "https://api.mctl.ai"))
	v.Del("client_id")
	if rec, _ := tokenRequest(e.h, v); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

// A code issued while the client declared private_key_jwt is not redeemed
// as none after its document changes.
func TestPrivateKeyJWTCodeSurvivesNoDowngrade(t *testing.T) {
	e := newPKJWTEnv(t)
	code := e.code(t)
	e.setDoc(pkjwtDocBody(cimd.AuthMethodNone), 2*time.Hour)
	rec, body := tokenRequest(e.h, codeGrant(code))
	wantInvalidClient(t, rec, body)
	// The none document itself is served as none for a fresh code.
	if rec, _ := tokenRequest(e.h, codeGrant(e.code(t))); rec.Code != http.StatusOK {
		t.Fatalf("none client: %d %s", rec.Code, rec.Body.String())
	}
}

// A public client must not send a client assertion, and a none CIMD client
// neither.
func TestAssertionFromPublicClientRefused(t *testing.T) {
	h, _ := cimdEnv(t, cimdDoc(cbURL))
	o := h.opts.OAuthServer
	sum := sha256.Sum256([]byte(pkjwtVerifier))
	dcr := o.RegisterClient("test", []string{"https://claude.ai/api/mcp/auth_callback"}).ClientID
	for _, c := range []struct{ id, redirect string }{
		{cimdID, cbURL}, // CIMD client declaring none
		{dcr, "https://claude.ai/api/mcp/auth_callback"},
	} {
		code, err := o.IssueCode(context.Background(), "alice", testPRN, c.id, c.redirect, base64.RawURLEncoding.EncodeToString(sum[:]), nil)
		if err != nil {
			t.Fatal(err)
		}
		v := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {pkjwtVerifier}, "client_id": {c.id}, "redirect_uri": {c.redirect}}
		rec, body := tokenRequest(h, withAssertion(v, "x.y.z"))
		wantInvalidClient(t, rec, body)
		v.Del("client_assertion")
		v.Del("client_assertion_type")
		if rec, _ := tokenRequest(h, v); rec.Code != http.StatusOK {
			t.Fatalf("%s without assertion: %d %s", c.id, rec.Code, rec.Body.String())
		}
	}
}

// With CIMD off a CIMD client_id cannot reach a grant: its required method
// is unknown, and unknown is not none.
func TestCIMDClientIDRefusedAtTokenWhileOff(t *testing.T) {
	e := newPKJWTEnv(t)
	code := e.code(t)
	e.o.CIMD = nil
	rec, body := tokenRequest(e.h, codeGrant(code))
	wantInvalidClient(t, rec, body)
	rec, body = tokenRequest(e.h, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"r"}, "client_id": {cimdID}})
	wantInvalidClient(t, rec, body)
}

func TestMetadataListsPrivateKeyJWTOnlyWithCIMD(t *testing.T) {
	e := newPKJWTEnv(t)
	meta := func() map[string]any {
		rec := httptest.NewRecorder()
		e.h.handleOAuthMeta(rec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
		var m map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		return m
	}
	m := meta()
	if fmt.Sprint(m["token_endpoint_auth_methods_supported"]) != "[none private_key_jwt]" ||
		fmt.Sprint(m["token_endpoint_auth_signing_alg_values_supported"]) != "[RS256 ES256]" {
		t.Fatalf("on: %v", m)
	}
	e.o.CIMD = nil
	m = meta()
	if _, ok := m["token_endpoint_auth_signing_alg_values_supported"]; ok || fmt.Sprint(m["token_endpoint_auth_methods_supported"]) != "[none]" {
		t.Fatalf("off: %v", m)
	}
}

// A document that cannot be fetched at the token endpoint is a retryable
// server error, remembered only for the fetch floor, so the client's
// refresh works again 30 s after its host recovers (mctl-api#702).
func TestDocumentFetchFailureAtTokenEndpointRecovers(t *testing.T) {
	e := newPKJWTEnv(t)
	rec, body := tokenRequest(e.h, withAssertion(codeGrant(e.code(t)), e.assertion(t, "https://api.mctl.ai")))
	if rec.Code != http.StatusOK {
		t.Fatalf("exchange: %d %s", rec.Code, rec.Body.String())
	}
	grant := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {body["refresh_token"].(string)}, "client_id": {cimdID}}
	e.mu.Lock()
	e.docStatus = http.StatusServiceUnavailable
	e.mu.Unlock()
	e.setDoc(pkjwtDocBody(cimd.AuthMethodPrivateKeyJWT), 2*time.Hour)
	rec, body = tokenRequest(e.h, withAssertion(grant, e.assertion(t, "https://api.mctl.ai")))
	if rec.Code != http.StatusInternalServerError || body["error"] != "server_error" {
		t.Fatalf("want 500 server_error, got %d %s", rec.Code, rec.Body.String())
	}
	e.mu.Lock()
	e.docStatus = 0
	e.mu.Unlock()
	e.setDoc(pkjwtDocBody(cimd.AuthMethodPrivateKeyJWT), time.Minute)
	if rec, _ := tokenRequest(e.h, withAssertion(grant, e.assertion(t, "https://api.mctl.ai"))); rec.Code != http.StatusOK {
		t.Fatalf("after recovery: %d %s", rec.Code, rec.Body.String())
	}
}
