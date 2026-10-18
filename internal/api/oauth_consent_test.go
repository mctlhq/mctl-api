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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/auth/cimd"
)

const (
	cimdID  = "https://app.example.com/client.json"
	testPRN = "prn_01JBBBBBBBBBBBBBBBBBBBBBBB"
	cbURL   = "https://app.example.com/cb"
)

// cimdEnv serves the CIMD document for cimdID and returns Handlers with CIMD
// enabled, plus the audit log.
func cimdEnv(t *testing.T, docBody string) (*Handlers, *audit.Logger) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(docBody))
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
	o := auth.NewOAuthServer("https://api.mctl.ai", "gh", "sec", []byte("secret"),
		[]string{"https://claude.ai/api/mcp/auth_callback"}, nil)
	o.CIMD = cimd.NewResolver(cimd.Options{AllowedHosts: []string{"app.example.com"}, HTTPClient: cl})
	log := audit.NewLogger()
	return &Handlers{opts: Options{OAuthServer: o, AuditLog: log}}, log
}

func cimdDoc(redirects ...string) string {
	b, _ := json.Marshal(map[string]any{
		"client_id": cimdID, "client_name": "<b>Evil</b> Co",
		"redirect_uris": redirects, "token_endpoint_auth_method": "none",
	})
	return string(b)
}

func authorize(h *Handlers, clientID, redirect string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	q := url.Values{"client_id": {clientID}, "redirect_uri": {redirect}, "response_type": {"token"}, "state": {"s"}}
	h.handleOAuthAuthorize(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
	return rec
}

func TestCIMDRedirectDecidedByDocumentAlone(t *testing.T) {
	h, _ := cimdEnv(t, cimdDoc(cbURL, "http://127.0.0.1:1/cb"))
	// Listed: reaches the next check (response_type), reported through the URI.
	if rec := authorize(h, cimdID, cbURL); rec.Code != http.StatusFound {
		t.Fatalf("listed redirect: %d", rec.Code)
	}
	if rec := authorize(h, cimdID, "http://127.0.0.1:55555/cb"); rec.Code != http.StatusFound {
		t.Fatalf("listed loopback on another port: %d", rec.Code)
	}
	// Unlisted: refused even when on the global allowlist or loopback.
	for _, u := range []string{"https://claude.ai/api/mcp/auth_callback", "http://127.0.0.1:1/other", "http://localhost:1/cb", "https://evil.com/cb"} {
		rec := authorize(h, cimdID, u)
		if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
			t.Errorf("%s: %d Location=%q", u, rec.Code, rec.Header().Get("Location"))
		}
	}
}

// A refused redirect_uri is logged clipped: /authorize takes it from the query
// before any other check, so one request must not write an unbounded record.
func TestCIMDRefusedRedirectIsLoggedClipped(t *testing.T) {
	h, _ := cimdEnv(t, cimdDoc(cbURL, "http://localhost/callback"))
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	long := "https://evil.example.com/" + strings.Repeat("a", 100_000)
	if rec := authorize(h, cimdID, long); rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d", rec.Code)
	}
	out := buf.String()
	if !strings.Contains(out, "redirect_uri not in the client metadata document") || !strings.Contains(out, "http://localhost/callback") {
		t.Fatalf("missing log line or dropped entry: %.300s", out)
	}
	if len(out) > 4096 {
		t.Fatalf("log output is %d bytes; the redirect_uri was not clipped", len(out))
	}
}

func TestCIMDFetchFailureIsDirect400(t *testing.T) {
	h, _ := cimdEnv(t, `not json`)
	rec := authorize(h, cimdID, cbURL)
	if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("Location"))
	}
	// A host off the allowlist is refused too, never falling back to the
	// global allowlist or loopback.
	rec = authorize(h, "https://other.example.org/c.json", "http://127.0.0.1:1/cb")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("off-allowlist: %d", rec.Code)
	}
}

func TestCIMDDisabledBehavesAsBefore(t *testing.T) {
	h, _ := cimdEnv(t, cimdDoc(cbURL))
	h.opts.OAuthServer.CIMD = nil
	// An https client_id is an ordinary client: the global allowlist and the
	// loopback rule apply, the document is never consulted.
	if rec := authorize(h, cimdID, "https://claude.ai/api/mcp/auth_callback"); rec.Code != http.StatusFound {
		t.Fatalf("allowlisted: %d", rec.Code)
	}
	if rec := authorize(h, cimdID, "http://127.0.0.1:9/cb"); rec.Code != http.StatusFound {
		t.Fatalf("loopback: %d", rec.Code)
	}
	if rec := authorize(h, cimdID, cbURL); rec.Code != http.StatusBadRequest {
		t.Fatalf("document redirect must not count when disabled: %d", rec.Code)
	}
}

// Discovery announces CIMD only while it is both accepted and advertised:
// accepting alone keeps it out of discovery, so clients that prefer CIMD do
// not switch to it (mctl-api#693).
func TestMetadataAdvertisesCIMDOnlyWhenAcceptedAndAdvertised(t *testing.T) {
	h, _ := cimdEnv(t, cimdDoc(cbURL))
	h.opts.OAuthServer.CIMDAdvertise = true
	get := func() map[string]any {
		rec := httptest.NewRecorder()
		h.handleOAuthMeta(rec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
		var m map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		return m
	}
	if get()["client_id_metadata_document_supported"] != true {
		t.Fatal("must advertise when accepted and advertised")
	}
	h.opts.OAuthServer.CIMDAdvertise = false
	if _, ok := get()["client_id_metadata_document_supported"]; ok {
		t.Fatal("must omit when accepted but not advertised")
	}
	// Accept-only still resolves a document: the flag only hides discovery.
	if rec := authorize(h, cimdID, cbURL); rec.Code != http.StatusFound {
		t.Fatalf("accept-only must still resolve the document: %d", rec.Code)
	}
	h.opts.OAuthServer.CIMDAdvertise = true
	h.opts.OAuthServer.CIMD = nil
	if _, ok := get()["client_id_metadata_document_supported"]; ok {
		t.Fatal("must omit when not accepted, whatever CIMDAdvertise says")
	}
}

func completion(clientID string) authzCompletion {
	return authzCompletion{
		Login: "alice", PrincipalID: testPRN, ClientID: clientID, RedirectURI: cbURL,
		CodeChallenge: "chal", ClientState: "st", Upstream: auth.UpstreamZitadel,
	}
}

func requestConsent(t *testing.T, h *Handlers) (token string, cookie *http.Cookie, body string) {
	t.Helper()
	return requestConsentFor(t, h, completion(cimdID))
}

func requestConsentFor(t *testing.T, h *Handlers, c authzCompletion) (token string, cookie *http.Cookie, body string) {
	t.Helper()
	rec := httptest.NewRecorder()
	if res := h.finishAuthorization(rec, httptest.NewRequest(http.MethodGet, "/cb", nil), c); res != "consent_required" {
		t.Fatalf("result %q, body %s", res, rec.Body.String())
	}
	if rec.Header().Get("Location") != "" {
		t.Fatal("no code before consent")
	}
	body = rec.Body.String()
	marker := `name="token" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatal("consent token marker missing")
	}
	token = body[i+len(marker):]
	j := strings.Index(token, `"`)
	if j < 0 {
		t.Fatal("consent token not terminated")
	}
	token = token[:j]
	for _, c := range rec.Result().Cookies() {
		if strings.HasPrefix(c.Name, consentCookie) {
			cookie = c
		}
	}
	if cookie == nil || !strings.HasPrefix(cookie.Name, "__Host-") || !cookie.Secure || !cookie.HttpOnly ||
		cookie.Path != "/" || cookie.Domain != "" || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie: %+v", cookie)
	}
	return
}

// postConsent posts a decision with the cookies a browser would send.
func postConsent(h *Handlers, token, decision string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/oauth/consent", strings.NewReader(url.Values{"token": {token}, "decision": {decision}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		if c != nil {
			req.AddCookie(c)
		}
	}
	rec := httptest.NewRecorder()
	h.handleOAuthConsent(rec, req)
	return rec
}

func TestConsentApproveIssuesCodeAndAudits(t *testing.T) {
	h, log := cimdEnv(t, cimdDoc(cbURL))
	token, cookie, body := requestConsent(t, h)
	if strings.Contains(body, "<b>Evil") || !strings.Contains(body, "&lt;b&gt;Evil") {
		t.Fatalf("client_name must be HTML-escaped: %s", body)
	}
	for _, want := range []string{cimdID, "app.example.com", "alice"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	rec := postConsent(h, token, "approve", cookie)
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || !strings.HasPrefix(loc, cbURL+"?") || !strings.Contains(loc, "code=") || !strings.Contains(loc, "state=st") {
		t.Fatalf("%d %q", rec.Code, loc)
	}
	entries := log.List(10)
	if len(entries) != 1 {
		t.Fatalf("want one audit entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Operation != "oauth.grant_issued" || e.PrincipalID != testPRN || e.UserID != "alice" ||
		e.Parameters["client_kind"] != "cimd" || e.Parameters["client_id"] != cimdID ||
		e.Parameters["redirect_host"] != "app.example.com" || e.Parameters["upstream"] != auth.UpstreamZitadel {
		t.Fatalf("%+v", e)
	}
	// Replay of the token is refused.
	if rec := postConsent(h, token, "approve", cookie); rec.Code != http.StatusBadRequest {
		t.Fatalf("replay: %d", rec.Code)
	}
}

func TestConsentDeny(t *testing.T) {
	h, log := cimdEnv(t, cimdDoc(cbURL))
	token, cookie, _ := requestConsent(t, h)
	rec := postConsent(h, token, "deny", cookie)
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "error=access_denied") || strings.Contains(loc, "code=") {
		t.Fatalf("%q", loc)
	}
	if len(log.List(10)) != 0 {
		t.Fatal("a denial issues nothing")
	}
}

func TestConsentCookieBinding(t *testing.T) {
	h, _ := cimdEnv(t, cimdDoc(cbURL))
	token, cookie, _ := requestConsent(t, h)
	other, otherCookie, _ := requestConsent(t, h)
	bad := *cookie
	bad.Value = "0000"
	for name, cookies := range map[string][]*http.Cookie{
		"missing cookie":          nil,
		"mismatched value":        {&bad},
		"another flow's cookie":   {otherCookie},
		"cookie under other name": {{Name: consentCookie, Value: cookie.Value}},
	} {
		if rec := postConsent(h, token, "approve", cookies...); rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
			t.Fatalf("%s: %d", name, rec.Code)
		}
	}
	if rec := postConsent(h, "unknown", "approve", cookie); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown token: %d", rec.Code)
	}
	if rec := postConsent(h, token, "maybe", cookie); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad decision: %d", rec.Code)
	}
	// None of the refused attempts spent the token: the cookie is checked
	// first, so the browser that signed in can still decide.
	rec := postConsent(h, token, "approve", cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("the refused attempts must not spend the token: %d", rec.Code)
	}
	cleared := func(rec *httptest.ResponseRecorder) bool {
		for _, c := range rec.Result().Cookies() {
			if c.Name == cookie.Name && c.MaxAge < 0 {
				return true
			}
		}
		return false
	}
	if !cleared(rec) {
		t.Error("the decision must clear its flow cookie")
	}
	if rec := postConsent(h, token, "approve", cookie); rec.Code != http.StatusBadRequest || !cleared(rec) {
		t.Fatalf("a replay is refused and clears the cookie it carried: %d", rec.Code)
	}
	if rec := postConsent(h, other, "deny", otherCookie); rec.Code != http.StatusFound {
		t.Fatalf("the other flow is untouched: %d", rec.Code)
	}
}

// Two consent pages open in one browser: the second flow's cookie must not
// overwrite the first one's binding.
func TestConcurrentConsentFlowsInOneBrowser(t *testing.T) {
	h, _ := cimdEnv(t, cimdDoc(cbURL))
	jar := map[string]*http.Cookie{} // a browser keeps one cookie per name
	var tokens []string
	for i := 0; i < 2; i++ {
		token, cookie, _ := requestConsent(t, h)
		jar[cookie.Name] = cookie
		tokens = append(tokens, token)
	}
	var all []*http.Cookie
	for _, c := range jar {
		all = append(all, c)
	}
	for i, token := range tokens {
		if rec := postConsent(h, token, "approve", all...); rec.Code != http.StatusFound {
			t.Fatalf("tab %d: %d %s", i+1, rec.Code, rec.Body.String())
		}
	}
}

func TestConsentDecisionMetrics(t *testing.T) {
	h, _ := cimdEnv(t, cimdDoc(cbURL))
	count := func(result string) float64 {
		return testutil.ToFloat64(oauthConsentDecisions.WithLabelValues(result))
	}
	before := map[string]float64{}
	for _, r := range []string{"approve", "deny", "invalid_request", "wrong_browser", "invalid_token"} {
		before[r] = count(r)
	}
	token, cookie, _ := requestConsent(t, h)
	postConsent(h, token, "maybe", cookie)
	postConsent(h, token, "approve")
	postConsent(h, token, "approve", cookie)
	postConsent(h, token, "approve", cookie)
	token, cookie, _ = requestConsent(t, h)
	postConsent(h, token, "deny", cookie)
	for r, want := range map[string]float64{"approve": 1, "deny": 1, "invalid_request": 1, "wrong_browser": 1, "invalid_token": 1} {
		if got := count(r) - before[r]; got != want {
			t.Errorf("%s: %v, want %v", r, got, want)
		}
	}
}

// The consent page is drawn in the page shell, and a sign-in with no GitHub
// login (a customer, or a ZITADEL-only human in principal mode) names the
// principal rather than an empty account.
func TestConsentPageInShellNamesPrincipalWithoutLogin(t *testing.T) {
	h, _ := cimdEnv(t, cimdDoc(cbURL))
	c := completion(cimdID)
	c.Login = ""
	rec := httptest.NewRecorder()
	if res := h.finishAuthorization(rec, httptest.NewRequest(http.MethodGet, "/cb", nil), c); res != "consent_required" {
		t.Fatalf("result %q", res)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `data-shell="mctl"`) || !strings.Contains(body, `name="decision" value="deny"`) {
		t.Fatalf("consent page not drawn in the shell:\n%s", body)
	}
	if !strings.Contains(body, "signed in as "+testPRN+".") {
		t.Errorf("page does not name the principal:\n%s", body)
	}
	if h := rec.Header().Get("Content-Security-Policy"); !strings.Contains(h, "form-action 'self' https://app.example.com;") {
		t.Errorf("CSP %q does not allow the consent form and its redirect to the client", h)
	}
}

// The decision is a 302 to the client, and browsers hold that redirect to
// form-action: the page must allow exactly the redirect's origin, and
// nothing when the URI is not a plain origin.
func TestConsentFormTarget(t *testing.T) {
	for raw, want := range map[string]string{
		"https://chatgpt.com/connector/oauth/O5rDjGVhvXke": " https://chatgpt.com",
		"http://127.0.0.1:33418/callback":                  " http://127.0.0.1:33418",
		"HTTPS://Example.COM/cb":                           " https://Example.COM",
		"cursor://anysphere.cursor-mcp/oauth/callback":     " cursor:",
		"https://a.example/cb;x":                           " https://a.example",
		"/relative":                                        "",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("%q: %v", raw, err)
		}
		if got := consentFormTarget(u); got != want {
			t.Errorf("consentFormTarget(%q) = %q, want %q", raw, got, want)
		}
	}
	if got := consentFormTarget(&url.URL{Scheme: "https", Host: "a.example; script-src *"}); got != "" {
		t.Errorf("a host with policy syntax got %q, want nothing", got)
	}
}

func TestConsentShownEveryTime(t *testing.T) {
	h, _ := cimdEnv(t, cimdDoc(cbURL))
	for i := 0; i < 2; i++ {
		token, cookie, _ := requestConsent(t, h)
		if rec := postConsent(h, token, "approve", cookie); rec.Code != http.StatusFound {
			t.Fatalf("round %d: %d", i, rec.Code)
		}
	}
}

func TestNonCIMDClientsSkipConsentAndAreAuditedByKind(t *testing.T) {
	h, log := cimdEnv(t, cimdDoc(cbURL))
	o := h.opts.OAuthServer
	if err := o.AddPreregisteredClient("portal", "Portal", []string{"https://portal.example/cb"}); err != nil {
		t.Fatal(err)
	}
	dcr := o.RegisterClient("dcr", []string{"http://127.0.0.1:1/cb"})
	for _, tc := range []struct{ id, kind, redirect, principal string }{
		{"portal", "static", "https://portal.example/cb", "prn_01JCCCCCCCCCCCCCCCCCCCCCCC"},
		{dcr.ClientID, "dcr", "http://127.0.0.1:1/cb", "prn_01JDDDDDDDDDDDDDDDDDDDDDDD"},
		{"plain-client", "allowlisted", "https://claude.ai/api/mcp/auth_callback", "prn_01JEEEEEEEEEEEEEEEEEEEEEEE"},
	} {
		c := completion(tc.id)
		c.RedirectURI = tc.redirect
		c.PrincipalID = tc.principal
		rec := httptest.NewRecorder()
		if res := h.finishAuthorization(rec, httptest.NewRequest(http.MethodGet, "/cb", nil), c); res != "issued" {
			t.Fatalf("%s: %q", tc.kind, res)
		}
		if loc := rec.Header().Get("Location"); !strings.Contains(loc, "code=") || strings.Contains(rec.Body.String(), "<form") {
			t.Fatalf("%s: %q", tc.kind, loc)
		}
		e := log.List(1)[0]
		// The principal recorded is the one the sign-in produced, varied per
		// row, never a fixed value or anything the client supplied.
		if e.Parameters["client_kind"] != tc.kind || e.PrincipalID != tc.principal || e.Parameters["client_id"] != tc.id {
			t.Fatalf("%s: %+v", tc.kind, e)
		}
	}
	if n := len(log.List(10)); n != 3 {
		t.Fatalf("one entry per issued code, got %d", n)
	}
}

// A4: the principal of a CIMD grant is the one the upstream sign-in produced.
// A document naming a principal, subject or login changes nothing.
func TestConsentPrincipalComesFromSignIn(t *testing.T) {
	b, _ := json.Marshal(map[string]any{
		"client_id": cimdID, "redirect_uris": []string{cbURL}, "token_endpoint_auth_method": "none",
		"principal_id": testPRN, "sub": testPRN, "login": "mallory",
	})
	h, log := cimdEnv(t, string(b))
	for _, signedIn := range []struct{ login, principal string }{
		{"bob", "prn_01JFFFFFFFFFFFFFFFFFFFFFFF"},
		{"", "prn_01JGGGGGGGGGGGGGGGGGGGGGGG"},
	} {
		c := completion(cimdID)
		c.Login, c.PrincipalID = signedIn.login, signedIn.principal
		token, cookie, _ := requestConsentFor(t, h, c)
		if rec := postConsent(h, token, "approve", cookie); rec.Code != http.StatusFound {
			t.Fatalf("%s: %d", signedIn.principal, rec.Code)
		}
		e := log.List(1)[0]
		if e.PrincipalID != signedIn.principal || e.UserID != signedIn.login {
			t.Fatalf("want %s/%q from the sign-in, got %s/%q", signedIn.principal, signedIn.login, e.PrincipalID, e.UserID)
		}
	}
}

// A pre-registered client whose client_id is URL-shaped stays static: its own
// list decides, exactly, port included, and its document is never consulted.
func TestStaticClientBeatsCIMD(t *testing.T) {
	h, log := cimdEnv(t, cimdDoc(cbURL, "http://127.0.0.1:8000/cb"))
	o := h.opts.OAuthServer
	if err := o.AddPreregisteredClient(cimdID, "Portal", []string{"http://127.0.0.1:8000/cb"}); err != nil {
		t.Fatal(err)
	}
	if o.IsCIMDClient(cimdID) || o.ClientKind(cimdID) != auth.ClientKindStatic {
		t.Fatalf("a static client must not be handled as CIMD: kind %q", o.ClientKind(cimdID))
	}
	if rec := authorize(h, cimdID, "http://127.0.0.1:8000/cb"); rec.Code != http.StatusFound {
		t.Fatalf("registered redirect: %d", rec.Code)
	}
	// The document lists cbURL, and its loopback entry would match on any
	// port; neither counts for a static client.
	for _, u := range []string{cbURL, "http://127.0.0.1:9000/cb"} {
		if rec := authorize(h, cimdID, u); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", u, rec.Code)
		}
	}
	c := completion(cimdID)
	c.RedirectURI = "http://127.0.0.1:8000/cb"
	rec := httptest.NewRecorder()
	if res := h.finishAuthorization(rec, httptest.NewRequest(http.MethodGet, "/cb", nil), c); res != "issued" {
		t.Fatalf("a static client gets no consent page: %q", res)
	}
	if e := log.List(1)[0]; e.Parameters["client_kind"] != auth.ClientKindStatic {
		t.Fatalf("%+v", e)
	}
}
