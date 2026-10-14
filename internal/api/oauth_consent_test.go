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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

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

func TestMetadataAdvertisesCIMDOnlyWhenEnabled(t *testing.T) {
	h, _ := cimdEnv(t, cimdDoc(cbURL))
	get := func() map[string]any {
		rec := httptest.NewRecorder()
		h.handleOAuthMeta(rec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
		var m map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		return m
	}
	if get()["client_id_metadata_document_supported"] != true {
		t.Fatal("must advertise when enabled")
	}
	h.opts.OAuthServer.CIMD = nil
	if _, ok := get()["client_id_metadata_document_supported"]; ok {
		t.Fatal("must omit when disabled")
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
	rec := httptest.NewRecorder()
	if res := h.finishAuthorization(rec, httptest.NewRequest(http.MethodGet, "/cb", nil), completion(cimdID)); res != "consent_required" {
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
		if c.Name == consentCookie {
			cookie = c
		}
	}
	if cookie == nil || !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" {
		t.Fatalf("cookie: %+v", cookie)
	}
	return
}

func postConsent(h *Handlers, token, decision string, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/oauth/consent", strings.NewReader(url.Values{"token": {token}, "decision": {decision}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		req.AddCookie(cookie)
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
	if rec := postConsent(h, token, "approve", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing cookie: %d", rec.Code)
	}
	// The token is spent by the refused attempt.
	if rec := postConsent(h, token, "approve", cookie); rec.Code != http.StatusBadRequest {
		t.Fatalf("spent token: %d", rec.Code)
	}
	token, cookie, _ = requestConsent(t, h)
	bad := *cookie
	bad.Value = "0000"
	if rec := postConsent(h, token, "approve", &bad); rec.Code != http.StatusBadRequest {
		t.Fatalf("mismatched cookie: %d", rec.Code)
	}
	if rec := postConsent(h, "unknown", "approve", cookie); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown token: %d", rec.Code)
	}
	if rec := postConsent(h, token, "maybe", cookie); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad decision: %d", rec.Code)
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
	for _, tc := range []struct{ id, kind, redirect string }{
		{"portal", "static", "https://portal.example/cb"},
		{dcr.ClientID, "dcr", "http://127.0.0.1:1/cb"},
		{"plain-client", "allowlisted", "https://claude.ai/api/mcp/auth_callback"},
	} {
		c := completion(tc.id)
		c.RedirectURI = tc.redirect
		rec := httptest.NewRecorder()
		if res := h.finishAuthorization(rec, httptest.NewRequest(http.MethodGet, "/cb", nil), c); res != "issued" {
			t.Fatalf("%s: %q", tc.kind, res)
		}
		if loc := rec.Header().Get("Location"); !strings.Contains(loc, "code=") || strings.Contains(rec.Body.String(), "<form") {
			t.Fatalf("%s: %q", tc.kind, loc)
		}
		e := log.List(1)[0]
		// A4: the same human resolves to the same principal whatever the client.
		if e.Parameters["client_kind"] != tc.kind || e.PrincipalID != testPRN || e.Parameters["client_id"] != tc.id {
			t.Fatalf("%s: %+v", tc.kind, e)
		}
	}
	if n := len(log.List(10)); n != 3 {
		t.Fatalf("one entry per issued code, got %d", n)
	}
}
