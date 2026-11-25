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
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/principals"
)

// The Google-only guard on the Glovo resources, shadow mode (stage D).

const (
	googleOnlyShadowMsg = "oauth: glovo google-only shadow"
	// Two principals with different endings, so a masked value proves which
	// one the line is about.
	googleOnlyCustomerPRN = "prn_01JCCCCCCCCCCCCCCCCCCCCC7Q"
	googleOnlyStaffPRN    = "prn_01JTESTAAAAAAAAAAAAAAAAAAA"
	googleOnlyOtherOrg    = "395272528420930001"
)

func TestParseGlovoGoogleOnlyMode(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want GlovoGoogleOnlyMode
	}{{"", GlovoGoogleOnlyOff}, {"off", GlovoGoogleOnlyOff}, {"shadow", GlovoGoogleOnlyShadow}} {
		if got, err := ParseGlovoGoogleOnlyMode(tc.in); err != nil || got != tc.want {
			t.Errorf("ParseGlovoGoogleOnlyMode(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	// enforce is reserved and not implemented: it must stop the boot, and
	// so must every spelling that could be mistaken for a mode.
	for _, in := range []string{"enforce", "Enforce", "ENFORCE", "SHADOW", "Shadow", "on", "true", "1", "shadow ", "shadow,enforce", "audit"} {
		got, err := ParseGlovoGoogleOnlyMode(in)
		if err == nil || !strings.Contains(err.Error(), "GLOVO_GOOGLE_ONLY_MODE") {
			t.Errorf("ParseGlovoGoogleOnlyMode(%q) = %q, %v; want an error naming GLOVO_GOOGLE_ONLY_MODE", in, got, err)
		}
		if got != "" {
			t.Errorf("ParseGlovoGoogleOnlyMode(%q) returned mode %q beside its error", in, got)
		}
	}
	if _, err := ParseGlovoGoogleOnlyMode("enforce"); err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Errorf("enforce: %v, want an error saying it is not implemented", err)
	}
}

// The classification, both ways: Google is the only pass, every other known
// kind is a refusal, and what could not be observed is neither.
func TestGlovoGoogleOnlyClassification(t *testing.T) {
	for _, tc := range []struct {
		name         string
		org          string
		customer     *auth.CustomerProof
		provider     string
		wouldRefuse  string
		explainsWhat string
	}{
		{"google customer", testCustomersOrg, &auth.CustomerProof{Provider: auth.ProviderGoogle, GoogleSub: testGoogleSub}, "google", "false", ""},
		{"github customer", testCustomersOrg, &auth.CustomerProof{Provider: auth.ProviderGitHub, GitHubID: "42", GitHubLogin: "someone"}, "github", "true", ""},
		{"another organization", testCustomersOrg, nil, "staff", "true", ""},
		{"no customers organization configured", "", nil, "unknown", "unknown", "the organization was never read"},
		{"google proof without a configured organization", "", &auth.CustomerProof{Provider: auth.ProviderGoogle, GoogleSub: testGoogleSub}, "unknown", "unknown", "a proof nothing could have verified"},
		{"proof of an unlisted provider", testCustomersOrg, &auth.CustomerProof{Provider: "gitlab"}, "unknown", "unknown", ""},
		{"proof with no provider", testCustomersOrg, &auth.CustomerProof{}, "unknown", "unknown", ""},
	} {
		provider := zitadelSigninProviderKind(tc.org, tc.customer)
		if provider != tc.provider {
			t.Errorf("%s: provider = %q, want %q %s", tc.name, provider, tc.provider, tc.explainsWhat)
		}
		if got := glovoGoogleOnlyWouldRefuse(provider); got != tc.wouldRefuse {
			t.Errorf("%s: would_refuse = %q, want %q", tc.name, got, tc.wouldRefuse)
		}
	}
	for provider, want := range map[string]string{
		glovoSigninGoogle: "false", glovoSigninGitHub: "true", glovoSigninStaff: "true", glovoSigninGitHubLegacy: "true",
		glovoSigninUnknown: "unknown", "": "unknown", "Google": "unknown", "password": "unknown",
	} {
		if got := glovoGoogleOnlyWouldRefuse(provider); got != want {
			t.Errorf("glovoGoogleOnlyWouldRefuse(%q) = %q, want %q", provider, got, want)
		}
	}
}

func TestMaskedPrincipalID(t *testing.T) {
	for in, want := range map[string]string{
		googleOnlyCustomerPRN:    "prn_***CC7Q",
		googleOnlyStaffPRN:       "prn_***AAAA",
		"":                       "none",
		"someone@example.com":    "invalid",
		"prn_short":              "invalid",
		"109876543210987654321":  "invalid",
		googleOnlyStaffPRN + "X": "invalid",
	} {
		got := maskedPrincipalID(in)
		if got != want {
			t.Errorf("maskedPrincipalID(%q) = %q, want %q", in, got, want)
		}
		if in != "" && strings.Contains(got, in) {
			t.Errorf("maskedPrincipalID(%q) = %q echoes its input", in, got)
		}
	}
}

// captureShadowLogs redirects slog and returns a reader of the shadow lines
// written so far, each decoded, plus everything that was logged.
func captureShadowLogs(t *testing.T) (lines func() []map[string]any, all func() string) {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	lines = func() []map[string]any {
		t.Helper()
		var out []map[string]any
		for _, raw := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			if raw == "" {
				continue
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(raw), &m); err != nil {
				t.Fatalf("log line is not JSON: %q", raw)
			}
			if m["msg"] == googleOnlyShadowMsg {
				m["_raw"] = raw
				out = append(out, m)
			}
		}
		return out
	}
	return lines, buf.String
}

// googleOnlySignin describes one way of signing in.
type googleOnlySignin struct {
	name string
	// customersOrg is the configured customers organization ("" for none).
	customersOrg string
	// upstream is the chooser entry, "" where there is no chooser.
	upstream string
	claims   map[string]any
	store    *fakeLinkedStore
	resolver auth.PrincipalResolver
	// what the shadow line must say
	provider, wouldRefuse, principal string
	// secrets are values of this sign-in that must never be logged.
	secrets []string
}

func googleOnlySignins() []googleOnlySignin {
	otherOrg := func() map[string]any { return map[string]any{auth.ClaimResourceOwnerID: googleOnlyOtherOrg} }
	return []googleOnlySignin{
		{
			name: "google customer", customersOrg: testCustomersOrg, upstream: oauthUpstreamCustomerGoogle,
			claims: googleCustomerClaims(), store: &fakeLinkedStore{err: principals.ErrNotFound},
			resolver: signinResolver{prn: googleOnlyCustomerPRN},
			provider: "google", wouldRefuse: "false", principal: "prn_***CC7Q",
			secrets: []string{googleOnlyCustomerPRN, testGoogleSub},
		},
		{
			name: "github customer", customersOrg: testCustomersOrg, upstream: oauthUpstreamCustomer,
			claims: customerIDClaims(), store: &fakeLinkedStore{err: principals.ErrNotFound},
			resolver: signinResolver{prn: googleOnlyCustomerPRN},
			provider: "github", wouldRefuse: "true", principal: "prn_***CC7Q",
			secrets: []string{googleOnlyCustomerPRN, "268260640", "mctl-reviewer"},
		},
		{
			// A staff or partner account with a linked GitHub login.
			name: "staff", customersOrg: testCustomersOrg, upstream: auth.UpstreamZitadel,
			claims: otherOrg(), store: linkedTo("mashkovd"),
			provider: "staff", wouldRefuse: "true", principal: "prn_***AAAA",
			secrets: []string{googleOnlyStaffPRN, "mashkovd"},
		},
		{
			// A ZITADEL-only account of another organization: it has no
			// external IdP at all, which is what a password sign-in is.
			name: "password", customersOrg: testCustomersOrg, upstream: auth.UpstreamZitadel,
			claims: otherOrg(), store: &fakeLinkedStore{err: principals.ErrNotFound},
			resolver: signinResolver{prn: googleOnlyCustomerPRN},
			provider: "staff", wouldRefuse: "true", principal: "prn_***CC7Q",
			secrets: []string{googleOnlyCustomerPRN},
		},
		{
			// No customers organization: the token's organization is never
			// read, so the provider was not observed.
			name: "unknown provider", customersOrg: "", upstream: "",
			claims: googleCustomerClaims(), store: linkedTo("mashkovd"),
			provider: "unknown", wouldRefuse: "unknown", principal: "prn_***AAAA",
			secrets: []string{googleOnlyStaffPRN, testGoogleSub},
		},
	}
}

func newGoogleOnlyHarness(t *testing.T, mode GlovoGoogleOnlyMode, s googleOnlySignin) *upstreamHarness {
	t.Helper()
	h := newUpstreamHarness(t, OAuthUpstreamZitadel, s.store)
	h.idp.extra = s.claims
	h.idp.authTime = time.Now()
	makeLinkReady(h.oauth, linkTestRes)
	zopts := &OAuthZitadelOptions{ProviderName: "zitadel", Issuer: h.idp.srv.URL, ClientID: testOAuthZClientID,
		ClientSecret: testOAuthZClientSecret, Store: s.store, CustomersOrgID: s.customersOrg}
	if s.customersOrg != "" {
		zopts.CustomersGitHubIdPID, zopts.CustomersGoogleIdPID = testCustomersGitHubIdP, testCustomersGoogleIdP
	}
	h.router = NewRouter(Options{OAuthServer: h.oauth, OAuthUpstream: OAuthUpstreamZitadel, OAuthZitadel: zopts,
		Principals: s.resolver, TenantAuthzMode: TenantAuthzPrincipal, GlovoGoogleOnly: mode})
	return h
}

// signIn runs authorize and the ZITADEL callback for resource and returns
// the callback's response.
func (h *upstreamHarness) signIn(upstream, resource string) *httptest.ResponseRecorder {
	h.t.Helper()
	extra := ""
	if resource != "" {
		extra += "&resource=" + url.QueryEscape(resource)
	}
	if upstream != "" {
		extra += "&" + oauthUpstreamParam + "=" + url.QueryEscape(upstream)
	}
	rec := h.get(authorizeQuery(extra))
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || !strings.HasPrefix(loc, h.idp.srv.URL+"/authorize") {
		h.t.Fatalf("authorize = %d Location=%q, want a redirect to ZITADEL: %s", rec.Code, loc, rec.Body.String())
	}
	u, _ := url.Parse(loc)
	q := u.Query()
	h.idp.mu.Lock()
	h.idp.challenge, h.idp.nonce = q.Get("code_challenge"), q.Get("nonce")
	h.idp.mu.Unlock()
	return h.callback(q.Get("state"))
}

var (
	// The per-request values of a consent page and of an issued code.
	googleOnlyTokenRe = regexp.MustCompile(`[A-Za-z0-9_-]{32,}`)
	googleOnlyCodeRe  = regexp.MustCompile(`code=[^&"]+`)
)

// responseShape is a response with its per-request random values blanked,
// so two runs of the same sign-in compare equal exactly when the guard left
// the response alone.
func responseShape(rec *httptest.ResponseRecorder) string {
	blank := func(s string) string {
		return googleOnlyTokenRe.ReplaceAllString(googleOnlyCodeRe.ReplaceAllString(s, "code=X"), "X")
	}
	var names []string
	for name := range rec.Header() {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString(http.StatusText(rec.Code) + "\n")
	for _, name := range names {
		v := strings.Join(rec.Header().Values(name), ",")
		if name == "Set-Cookie" {
			// Only the cookie's name and attributes: its value is random.
			v = regexp.MustCompile(`=[^;]*`).ReplaceAllString(v, "=X")
		}
		if name == "X-Ratelimit-Reset" {
			// Window end is wall-clock. Two sign-ins that straddle a minute
			// boundary differ by 60s even when the guard left the response alone.
			v = "X"
		}
		b.WriteString(name + ": " + blank(v) + "\n")
	}
	b.WriteString(blank(rec.Body.String()))
	return b.String()
}

func TestResponseShapeIgnoresRateLimitWindow(t *testing.T) {
	off := httptest.NewRecorder()
	shadow := httptest.NewRecorder()
	off.Header().Set("X-Ratelimit-Limit", "60")
	shadow.Header().Set("X-Ratelimit-Limit", "60")
	off.Header().Set("X-Ratelimit-Remaining", "58")
	shadow.Header().Set("X-Ratelimit-Remaining", "58")
	off.Header().Set("X-Ratelimit-Reset", "1795628040")
	shadow.Header().Set("X-Ratelimit-Reset", "1795628100")
	off.Header().Set("Location", "https://claude.ai/api/mcp/auth_callback?code=abc&state=client-state")
	shadow.Header().Set("Location", "https://claude.ai/api/mcp/auth_callback?code=xyz&state=client-state")
	off.WriteHeader(http.StatusFound)
	shadow.WriteHeader(http.StatusFound)
	if a, b := responseShape(off), responseShape(shadow); a != b {
		t.Fatalf("clock-only rate-limit reset changed the shape\noff:\n%s\nshadow:\n%s", a, b)
	}
}

// Every kind of sign-in on each Glovo resource writes exactly one shadow
// line with its decision, and gets the response it gets with the mode off.
func TestGlovoGoogleOnlyShadowLogsAndRefusesNothing(t *testing.T) {
	resources := []struct{ kind, resource string }{{"mcp", auth.GlovoResourceIntended}, {"link", linkTestRes}}
	for _, s := range googleOnlySignins() {
		for _, res := range resources {
			t.Run(s.name+"/"+res.kind, func(t *testing.T) {
				lines, _ := captureShadowLogs(t)
				off := newGoogleOnlyHarness(t, GlovoGoogleOnlyOff, s).signIn(s.upstream, res.resource)
				if got := lines(); len(got) != 0 {
					t.Fatalf("mode off logged %d shadow lines: %v", len(got), got)
				}
				// A page, not a refusal: both Glovo resources stop at a
				// consent page before any code.
				if off.Code != http.StatusOK || off.Header().Get("Location") != "" {
					t.Fatalf("mode off: callback = %d Location=%q, want the consent page: %s", off.Code, off.Header().Get("Location"), off.Body.String())
				}

				before := testutil.ToFloat64(glovoGoogleOnlyShadow.WithLabelValues(res.kind, s.provider, s.wouldRefuse))
				shadow := newGoogleOnlyHarness(t, GlovoGoogleOnlyShadow, s).signIn(s.upstream, res.resource)
				if a, b := responseShape(off), responseShape(shadow); a != b {
					t.Fatalf("shadow mode changed the response.\noff:\n%s\nshadow:\n%s", a, b)
				}
				got := lines()
				if len(got) != 1 {
					t.Fatalf("shadow mode logged %d lines, want exactly 1: %v", len(got), got)
				}
				line := got[0]
				raw, _ := line["_raw"].(string)
				delete(line, "_raw")
				delete(line, "time")
				want := map[string]any{"level": "INFO", "msg": googleOnlyShadowMsg, "mode": "shadow",
					"would_refuse": s.wouldRefuse, "provider": s.provider, "resource": res.kind, "principal": s.principal}
				if len(line) != len(want) {
					t.Fatalf("shadow line fields = %v, want exactly %v", line, want)
				}
				for k, v := range want {
					if line[k] != v {
						t.Errorf("shadow line %s = %v, want %v (line %v)", k, line[k], v, line)
					}
				}
				for _, secret := range append(s.secrets, "dmitrii", "z-code", res.resource) {
					if strings.Contains(raw, secret) {
						t.Errorf("shadow line carries %q: %s", secret, raw)
					}
				}
				if n := testutil.ToFloat64(glovoGoogleOnlyShadow.WithLabelValues(res.kind, s.provider, s.wouldRefuse)) - before; n != 1 {
					t.Errorf("counter {%s,%s,%s} +%v, want +1", res.kind, s.provider, s.wouldRefuse, n)
				}
			})
		}
	}
}

// A resource that is not a Glovo resource is not evaluated at all: no line,
// no counter, and the code is issued as with the mode off.
func TestGlovoGoogleOnlyShadowIgnoresOtherResources(t *testing.T) {
	for _, s := range googleOnlySignins() {
		for _, res := range []struct{ name, resource string }{{"default", ""}, {"support", "https://support.mctl.ai"}} {
			t.Run(s.name+"/"+res.name, func(t *testing.T) {
				lines, all := captureShadowLogs(t)
				off := newGoogleOnlyHarness(t, GlovoGoogleOnlyOff, s).signIn(s.upstream, res.resource)
				offLog := all()
				before := testutil.CollectAndCount(glovoGoogleOnlyShadow)
				shadow := newGoogleOnlyHarness(t, GlovoGoogleOnlyShadow, s).signIn(s.upstream, res.resource)
				loc, _ := url.Parse(shadow.Header().Get("Location"))
				if shadow.Code != http.StatusFound || loc.Query().Get("code") == "" {
					t.Fatalf("callback = %d %q, want a code: %s", shadow.Code, loc, shadow.Body.String())
				}
				if a, b := responseShape(off), responseShape(shadow); a != b {
					t.Fatalf("shadow mode changed the response.\noff:\n%s\nshadow:\n%s", a, b)
				}
				if got := lines(); len(got) != 0 {
					t.Fatalf("a non-Glovo resource logged %d shadow lines: %v", len(got), got)
				}
				if strings.Contains(strings.TrimPrefix(all(), offLog), "google-only") {
					t.Fatalf("a non-Glovo resource mentions the guard in its logs: %s", all())
				}
				if after := testutil.CollectAndCount(glovoGoogleOnlyShadow); after != before {
					t.Fatalf("a non-Glovo resource added %d counter series", after-before)
				}
			})
		}
	}
}

// The direct GitHub upstream never passes through ZITADEL; it is observed
// at its own callback as a refusal the guard would make. Its callback talks
// to github.com, so the observation is exercised directly.
func TestGlovoGoogleOnlyShadowObservation(t *testing.T) {
	o := auth.NewOAuthServer("https://api.example", "gh-client", "gh-secret", []byte("test-secret"), []string{testClientRedirect}, nil)
	makeLinkReady(o, linkTestRes)
	shadow := &Handlers{opts: Options{OAuthServer: o, GlovoGoogleOnly: GlovoGoogleOnlyShadow}}

	lines, _ := captureShadowLogs(t)
	shadow.observeGlovoGoogleOnly(auth.GlovoResourceIntended, glovoSigninGitHubLegacy, googleOnlyStaffPRN)
	got := lines()
	if len(got) != 1 || got[0]["provider"] != "github_legacy" || got[0]["would_refuse"] != "true" ||
		got[0]["resource"] != "mcp" || got[0]["principal"] != "prn_***AAAA" {
		t.Fatalf("legacy GitHub on the MCP resource: %v", got)
	}

	// A principal that is missing or malformed is named as such, never
	// echoed, and still does not turn the decision into a pass.
	shadow.observeGlovoGoogleOnly(linkTestRes, glovoSigninGitHub, "")
	shadow.observeGlovoGoogleOnly(linkTestRes, glovoSigninGitHub, "someone@example.com")
	got = lines()
	if len(got) != 3 || got[1]["principal"] != "none" || got[2]["principal"] != "invalid" ||
		got[1]["would_refuse"] != "true" || got[2]["would_refuse"] != "true" {
		t.Fatalf("missing and malformed principals: %v", got)
	}
	if raw, _ := got[2]["_raw"].(string); strings.Contains(raw, "example.com") {
		t.Fatalf("a malformed principal was echoed: %s", raw)
	}

	// Nothing for other resources, for a Glovo resource that is not
	// configured, or with the mode off (the zero value included).
	shadow.observeGlovoGoogleOnly("", glovoSigninGitHub, googleOnlyStaffPRN)
	shadow.observeGlovoGoogleOnly("https://support.mctl.ai", glovoSigninGitHub, googleOnlyStaffPRN)
	shadow.observeGlovoGoogleOnly("https://glovo.mctl.ai/other", glovoSigninGitHub, googleOnlyStaffPRN)
	bare := auth.NewOAuthServer("https://api.example", "gh-client", "gh-secret", []byte("test-secret"), []string{testClientRedirect}, nil)
	(&Handlers{opts: Options{OAuthServer: bare, GlovoGoogleOnly: GlovoGoogleOnlyShadow}}).observeGlovoGoogleOnly(auth.GlovoResourceIntended, glovoSigninGitHub, googleOnlyStaffPRN)
	(&Handlers{opts: Options{OAuthServer: bare, GlovoGoogleOnly: GlovoGoogleOnlyShadow}}).observeGlovoGoogleOnly("", glovoSigninGitHub, googleOnlyStaffPRN)
	for _, mode := range []GlovoGoogleOnlyMode{"", GlovoGoogleOnlyOff, "enforce"} {
		(&Handlers{opts: Options{OAuthServer: o, GlovoGoogleOnly: mode}}).observeGlovoGoogleOnly(auth.GlovoResourceIntended, glovoSigninGitHub, googleOnlyStaffPRN)
	}
	if got = lines(); len(got) != 3 {
		t.Fatalf("%d shadow lines, want still 3: %v", len(got), got)
	}
}
