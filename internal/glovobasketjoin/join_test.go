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

package glovobasketjoin

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/auth/teamgrant"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/scope"
	"github.com/mctlhq/mctl-api/internal/glovobasket"
	"github.com/mctlhq/mctl-api/internal/glovojoin"
)

const (
	prnA   = "prn_01JBBBBBBBBBBBBBBBBBBBBBBB"
	res    = "https://glovo.mctl.ai/mcp"
	base   = "https://api.mctl.ai"
	client = "client-1"
	secret = "basket-join-test-secret"
	bskID  = "gbk_ABCDEFGHIJKLMNOPQRSTUVWXYZ"

	minimalBasket = `{"v":"mctl-approval-basket/v1","store_ref":"pst_0123456789abcdef0123","currency":"EUR","lines":[{"item_code":"FAKE-1","quantity":1,"unit_price_minor":500}],"subtotal_minor":500,"delivery_fee_minor":199,"service_fee_minor":50,"discount_minor":0,"total_minor":749}`
	minimalFP     = "sha256:662ad98455b98d60da709cb520e7b519b94ee5125e8743b47952b02553666d96"
)

type fakeGrants struct {
	g   teamgrant.Grant
	err error
}

func (f *fakeGrants) Check(_ context.Context, id, prn, cl, r string) (teamgrant.Grant, error) {
	if f.err != nil {
		return teamgrant.Grant{}, f.err
	}
	if id != f.g.ID || prn != f.g.PrincipalID || cl != f.g.ClientID || r != f.g.Resource || f.g.State != teamgrant.StateActive {
		return teamgrant.Grant{}, teamgrant.ErrGrantInvalid
	}
	return f.g, nil
}

type fakeMembership struct{ roles map[string][][]string }

func (f *fakeMembership) TryNamespacesForPrincipal(string) (gitops.PrincipalMembership, bool, error) {
	return gitops.PrincipalMembership{}, true, nil
}

func (f *fakeMembership) MemberRolesForPrincipal(tenant, prn string) ([][]string, error) {
	return f.roles[tenant+"|"+prn], nil
}

type fakeAllow struct {
	rows map[string]bool
	err  error
}

func (f *fakeAllow) IsAllowlisted(_ context.Context, tenant, prn string) (bool, error) {
	return f.rows[tenant+"|"+prn], f.err
}

// fakePrincipals is the principal store: CheckPrincipal answers err.
type fakePrincipals struct{ err error }

func (f *fakePrincipals) ResolvePrincipal(context.Context, auth.Identity) (string, error) {
	return "", errors.New("not used")
}

func (f *fakePrincipals) CheckPrincipal(context.Context, string) error { return f.err }

type fakeApprovals struct {
	calls []struct {
		o  glovobasket.Owner
		in glovobasket.SnapshotApprovalInput
	}
	out *glovobasket.ApprovalRequest
	err error
}

func (f *fakeApprovals) RequestApprovalFromSnapshot(_ context.Context, o glovobasket.Owner, in glovobasket.SnapshotApprovalInput, _ time.Duration) (*glovobasket.ApprovalRequest, error) {
	f.calls = append(f.calls, struct {
		o  glovobasket.Owner
		in glovobasket.SnapshotApprovalInput
	}{o, in})
	if f.err != nil {
		return nil, f.err
	}
	out := *f.out
	out.Fingerprint = in.Snapshot.Fingerprint
	return &out, nil
}

type env struct {
	t        *testing.T
	svc      *Service
	oauth    *auth.OAuthServer
	grants   *fakeGrants
	members  *fakeMembership
	allow    *fakeAllow
	pr       *fakePrincipals
	ap       *fakeApprovals
	refusals []Refused
	h        http.Handler
}

func newEnv(t *testing.T) *env {
	t.Helper()
	o := auth.NewOAuthServer(base, "gh", "sec", []byte(secret), nil, nil)
	o.GlovoResource, o.PrincipalMode = res, true
	e := &env{t: t, oauth: o,
		grants:  &fakeGrants{g: teamgrant.Grant{ID: "tgr_1", PrincipalID: prnA, Tenant: "alpha", ClientID: client, Resource: res, State: teamgrant.StateActive}},
		members: &fakeMembership{roles: map[string][][]string{"alpha|" + prnA: {{"developer"}}}},
		allow:   &fakeAllow{rows: map[string]bool{"alpha|" + prnA: true}},
		pr:      &fakePrincipals{},
		ap: &fakeApprovals{out: &glovobasket.ApprovalRequest{ApprovalRef: "aar_0123456789abcdef0123456789abcdef", BasketID: bskID, Revision: 2,
			State: "pending", ExpiresAt: time.Now().Add(time.Hour).UTC(), Created: true}},
	}
	r := &scope.Resolver{Grants: e.grants, Elig: &scope.Eligibility{Membership: e.members, Allowlist: e.allow, NonSelectable: scope.NonSelectable("admins")},
		Resource: res, Ready: func() bool { return true }}
	e.svc = &Service{Tokens: o, Principals: e.pr, Resolver: r, Approvals: e.ap, ApprovalPageBaseURL: base,
		OnRefused: func(rf Refused) { e.refusals = append(e.refusals, rf) }}
	if err := e.svc.Validate(); err != nil {
		t.Fatal(err)
	}
	e.h = e.svc.Handler()
	return e
}

// token signs a subject token; extra overrides claims.
func (e *env) token(extra map[string]any) string {
	e.t.Helper()
	enc := base64.RawURLEncoding
	hdr, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	claims := map[string]any{"iss": base, "sub": prnA, "pid": prnA, "aud": res, "client_id": client, "groups": []string{},
		"tgr": "tgr_1", "stn": "alpha", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
	for k, v := range extra {
		claims[k] = v
	}
	body, _ := json.Marshal(claims)
	in := enc.EncodeToString(hdr) + "." + enc.EncodeToString(body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(in))
	return in + "." + enc.EncodeToString(mac.Sum(nil))
}

type result struct {
	code int
	body map[string]any
	raw  string
}

func (e *env) call(path, tok, body string) result {
	e.t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if tok != "" {
		req.Header.Set(glovojoin.SubjectTokenHeader, tok)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	out := result{code: rec.Code, raw: rec.Body.String()}
	_ = json.Unmarshal(rec.Body.Bytes(), &out.body)
	return out
}

func (r result) errCode() string {
	if c, ok := r.body["code"].(string); ok {
		return c
	}
	s, _ := r.body["error"].(string)
	return s
}

func approvalBody(fp string) string {
	b := map[string]any{"basket_id": bskID, "revision": 2, "basket": json.RawMessage(minimalBasket), "item_names": map[string]string{"FAKE-1": "Fake coffee"}}
	if fp != "" {
		b["basket_fingerprint"] = fp
	}
	raw, _ := json.Marshal(b)
	return string(raw)
}

func TestResolveReturnsTheResolvedScope(t *testing.T) {
	e := newEnv(t)
	res := e.call(PathResolve, e.token(nil), "{}")
	if res.code != http.StatusOK || res.body["principal_id"] != prnA || res.body["tenant"] != "alpha" || res.body["role"] != "developer" || res.body["can_decide"] != true {
		t.Fatalf("resolve = %d %s", res.code, res.raw)
	}
	if _, leaked := res.body["grant_id"]; leaked {
		t.Fatalf("grant id leaked: %s", res.raw)
	}
	// A viewer is resolved but cannot decide.
	e.members.roles["alpha|"+prnA] = [][]string{{"viewer"}}
	if res := e.call(PathResolve, e.token(nil), ""); res.code != http.StatusOK || res.body["can_decide"] != false {
		t.Fatalf("viewer = %d %s", res.code, res.raw)
	}
}

// Every request re-resolves: a grant revoked or an allowlist row removed
// after a successful call refuses the very next one. Nothing is cached.
func TestEveryRequestReResolves(t *testing.T) {
	for name, revoke := range map[string]func(e *env){
		"revoked grant":         func(e *env) { e.grants.g.State = teamgrant.StateRevoked },
		"removed allowlist row": func(e *env) { delete(e.allow.rows, "alpha|"+prnA) },
		"membership removed":    func(e *env) { delete(e.members.roles, "alpha|"+prnA) },
	} {
		for _, path := range []string{PathResolve, PathApprovals} {
			e := newEnv(t)
			body := "{}"
			if path == PathApprovals {
				body = approvalBody("")
			}
			if res := e.call(path, e.token(nil), body); res.code/100 != 2 {
				t.Fatalf("%s %s: control = %d %s", name, path, res.code, res.raw)
			}
			calls := len(e.ap.calls)
			revoke(e)
			res := e.call(path, e.token(nil), body)
			if res.code/100 == 2 || res.code == http.StatusServiceUnavailable {
				t.Fatalf("%s %s: after revocation = %d %s", name, path, res.code, res.raw)
			}
			if len(e.ap.calls) != calls {
				t.Fatalf("%s %s: the ledger was reached after revocation", name, path)
			}
		}
	}
}

// The subject token is a Glovo-audience access token of a principal, sent
// in the header only; anything else is 401 and reaches no resolver.
func TestSubjectTokenRefusals(t *testing.T) {
	e := newEnv(t)
	for name, tok := range map[string]string{
		"missing":        "",
		"wrong audience": e.token(map[string]any{"aud": base}),
		"two audiences":  e.token(map[string]any{"aud": []string{res, base}}),
		"expired":        e.token(map[string]any{"exp": time.Now().Add(-time.Minute).Unix()}),
		"bad signature":  e.token(nil) + "x",
		"no principal":   e.token(map[string]any{"pid": ""}),
	} {
		if res := e.call(PathResolve, tok, "{}"); res.code != http.StatusUnauthorized || res.errCode() != string(glovo.CodeNotAuthorized) {
			t.Errorf("%s = %d %s", name, res.code, res.raw)
		}
	}
	// A token in the query string is refused, never read.
	if res := e.call(PathResolve+"?access_token="+e.token(nil), "", "{}"); res.code != http.StatusUnauthorized {
		t.Errorf("query token = %d %s", res.code, res.raw)
	}
	if len(e.ap.calls) != 0 {
		t.Fatal("a refused subject reached the ledger")
	}
}

// The principal store decides like the auth middleware: a disabled
// principal is 401; a store that does not answer is 503, never a refusal
// and never "no principal".
func TestPrincipalCheck(t *testing.T) {
	e := newEnv(t)
	e.pr.err = auth.ErrPrincipalDisabled
	if res := e.call(PathResolve, e.token(nil), "{}"); res.code != http.StatusUnauthorized {
		t.Fatalf("disabled principal = %d %s", res.code, res.raw)
	}
	e.pr.err = errors.New("db down")
	if res := e.call(PathResolve, e.token(nil), "{}"); res.code != http.StatusServiceUnavailable || res.errCode() != string(glovo.CodeUnavailable) {
		t.Fatalf("principal store down = %d %s", res.code, res.raw)
	}
	// A failed resolver read is 503 too.
	e.pr.err = nil
	e.allow.err = errors.New("allowlist down")
	if res := e.call(PathResolve, e.token(nil), "{}"); res.code != http.StatusServiceUnavailable {
		t.Fatalf("allowlist down = %d %s", res.code, res.raw)
	}
}

// mctl-api computes the fingerprint from the basket it froze; a caller
// fingerprint is passed on only to be compared, never as the snapshot's.
func TestApprovalFingerprintIsComputedHere(t *testing.T) {
	e := newEnv(t)
	forged := "sha256:" + strings.Repeat("0", 64)
	res := e.call(PathApprovals, e.token(nil), approvalBody(forged))
	if res.code != http.StatusCreated {
		t.Fatalf("approvals = %d %s", res.code, res.raw)
	}
	if len(e.ap.calls) != 1 {
		t.Fatalf("%d ledger calls", len(e.ap.calls))
	}
	c := e.ap.calls[0]
	if c.in.Snapshot.Fingerprint != minimalFP || c.in.BasketFingerprint != forged || c.in.BasketID != bskID || c.in.Revision != 2 {
		t.Fatalf("ledger input: fp %s caller %s", c.in.Snapshot.Fingerprint, c.in.BasketFingerprint)
	}
	if c.o != (glovobasket.Owner{Tenant: "alpha", PrincipalID: prnA}) {
		t.Fatalf("owner %+v", c.o)
	}
	if res.body["basket_fingerprint"] != minimalFP || res.body["approval_url"] != base+glovobasket.ApprovalPagePath+"aar_0123456789abcdef0123456789abcdef" {
		t.Fatalf("response %s", res.raw)
	}
}

// The body names no tenant or owner, and a malformed basket is refused
// before the ledger.
func TestApprovalBodyRefusals(t *testing.T) {
	e := newEnv(t)
	for name, body := range map[string]string{
		"tenant field":   strings.Replace(approvalBody(""), `{`, `{"tenant":"beta",`, 1),
		"owner field":    strings.Replace(approvalBody(""), `{`, `{"owner_principal_id":"prn_x",`, 1),
		"bad basket":     strings.Replace(approvalBody(""), `"total_minor":749`, `"total_minor":1`, 1),
		"missing names":  strings.Replace(approvalBody(""), `"FAKE-1":"Fake coffee"`, ``, 1),
		"no basket":      `{"basket_id":"` + bskID + `","revision":2}`,
		"trailing value": approvalBody("") + "{}",
	} {
		if res := e.call(PathApprovals, e.token(nil), body); res.code != http.StatusBadRequest {
			t.Errorf("%s = %d %s", name, res.code, res.raw)
		}
	}
	if len(e.ap.calls) != 0 {
		t.Fatal("a refused body reached the ledger")
	}
	// A ledger that does not answer is 503.
	e.ap.err = errors.New("db down")
	if res := e.call(PathApprovals, e.token(nil), approvalBody("")); res.code != http.StatusServiceUnavailable {
		t.Fatalf("ledger down = %d %s", res.code, res.raw)
	}
}

func TestUnconfiguredServiceIsNotReady(t *testing.T) {
	s := &Service{}
	if s.Validate() == nil {
		t.Fatal("an empty service validated")
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, PathResolve, strings.NewReader("{}")))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured = %d", rec.Code)
	}
	if (&Service{ApprovalPageBaseURL: "http://api.mctl.ai", Tokens: auth.NewOAuthServer(base, "", "", []byte("x"), nil, nil),
		Principals: &fakePrincipals{}, Resolver: &scope.Resolver{}, Approvals: &fakeApprovals{}}).Validate() == nil {
		t.Fatal("a non-https page origin validated")
	}
}

// The decider role the resolve answer reports is the approval page's.
func TestCanDecideNeedsDeveloper(t *testing.T) {
	if DeciderRole != "developer" {
		t.Fatalf("DeciderRole = %s", DeciderRole)
	}
}

// The per-subject and write ceilings answer 429 with Retry-After, and a
// refused write never reaches the ledger.
func TestRateLimits(t *testing.T) {
	e := newEnv(t)
	svc := &Service{Tokens: e.svc.Tokens, Principals: e.svc.Principals, Resolver: e.svc.Resolver, Approvals: e.ap,
		PerSubject: 3, Writes: 1, OnRefused: e.svc.OnRefused}
	e.h = svc.Handler()
	if res := e.call(PathApprovals, e.token(nil), approvalBody("")); res.code != http.StatusCreated {
		t.Fatalf("first write = %d %s", res.code, res.raw)
	}
	req := httptest.NewRequest(http.MethodPost, PathApprovals, strings.NewReader(approvalBody("")))
	req.Header.Set(glovojoin.SubjectTokenHeader, e.token(nil))
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "60" || len(e.ap.calls) != 1 {
		t.Fatalf("second write = %d retry %q, %d ledger calls", rec.Code, rec.Header().Get("Retry-After"), len(e.ap.calls))
	}
	// Reads have their own, higher ceiling: one left of three.
	if res := e.call(PathResolve, e.token(nil), "{}"); res.code != http.StatusOK {
		t.Fatalf("read under the ceiling = %d %s", res.code, res.raw)
	}
	if res := e.call(PathResolve, e.token(nil), "{}"); res.code != http.StatusTooManyRequests {
		t.Fatalf("read over the ceiling = %d %s", res.code, res.raw)
	}
	if n := len(e.refusals); n != 2 || e.refusals[0].Code != glovo.CodeRateLimited {
		t.Fatalf("refusals %+v", e.refusals)
	}
}
