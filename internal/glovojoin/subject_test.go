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

package glovojoin

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/scope"
)

const (
	subjBase      = "https://api.example"
	subjResource  = auth.GlovoResourceIntended
	subjPrincipal = "prn_0123456789abcdef"
)

var subjSecret = []byte("subject-test-secret")

// forgeSubject signs an HS256 access token. aud is a string or a []string.
func forgeSubject(t *testing.T, aud any, exp time.Time, extra map[string]any) string {
	t.Helper()
	enc := base64.RawURLEncoding
	hdr, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	claims := map[string]any{"iss": subjBase, "sub": "dan", "aud": aud, "groups": []string{},
		"iat": time.Now().Unix(), "exp": exp.Unix()}
	for k, v := range extra {
		claims[k] = v
	}
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	in := enc.EncodeToString(hdr) + "." + enc.EncodeToString(body)
	mac := hmac.New(sha256.New, subjSecret)
	mac.Write([]byte(in))
	return in + "." + enc.EncodeToString(mac.Sum(nil))
}

func glovoToken(t *testing.T, exp time.Time) string {
	return forgeSubject(t, subjResource, exp, map[string]any{"tgr": "tgr_1", "stn": "acme"})
}

func newOAuth() *auth.OAuthServer {
	o := auth.NewOAuthServer(subjBase, "gh-client", "gh-secret", subjSecret, []string{"https://client.example/cb"}, auth.NewGitHubValidator(nil))
	o.GlovoResource = subjResource
	return o
}

type fakeResolver struct {
	sc    scope.Scope
	err   *glovo.Error
	calls int
}

func (f *fakeResolver) Resolve(_ context.Context, u *auth.User) (scope.Scope, *glovo.Error) {
	f.calls++
	if f.err != nil {
		return scope.Scope{}, f.err
	}
	return f.sc, nil
}

type fakeInstalls struct {
	inst *glovo.Install
	err  error
}

func (f *fakeInstalls) GetInstall(context.Context, string) (*glovo.Install, error) {
	return f.inst, f.err
}

func newVerifier() (*SubjectVerifier, *fakeResolver, *fakeInstalls) {
	r := &fakeResolver{sc: scope.Scope{PrincipalID: subjPrincipal, Tenant: "acme", Role: "admin", GrantID: "tgr_1", RefreshFamilyID: "fam_1"}}
	i := &fakeInstalls{inst: &glovo.Install{InstallID: "gin_abc", TenantID: "acme", InstallRevision: 3}}
	return &SubjectVerifier{Tokens: newOAuth(), Resolver: r, Installs: i}, r, i
}

func subjReq(path, token string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set(SubjectTokenHeader, token)
	}
	return req
}

func TestSubjectVerifierAcceptsAGlovoAudienceToken(t *testing.T) {
	v, r, _ := newVerifier()
	tok := glovoToken(t, time.Now().Add(time.Hour))
	req := subjReq("/connection", tok)
	sub, ref := v.Verify(req)
	if ref != nil {
		t.Fatalf("refused: %v", ref)
	}
	if sub.PrincipalID != subjPrincipal || sub.Tenant != "acme" || sub.GrantID != "tgr_1" || sub.FamilyID != "fam_1" ||
		sub.InstallID != "gin_abc" || sub.InstallRevision != 3 || r.calls != 1 {
		t.Fatalf("subject = %+v", sub)
	}
	sum := sha256.Sum256([]byte(tok))
	if sub.TokenHash != hex.EncodeToString(sum[:]) {
		t.Fatalf("token hash %q", sub.TokenHash)
	}
	if !sub.HasScope(ScopeRead) || !sub.HasScope(ScopeBasketPrepare) || sub.HasScope("glovo:admin") {
		t.Fatalf("scopes = %v", sub.Scopes)
	}
	// The raw token is deleted from the request and is nowhere in the subject.
	if req.Header.Get(SubjectTokenHeader) != "" {
		t.Fatal("the subject header survived verification")
	}
	sub.User = nil
	if strings.Contains(fmt.Sprintf("%+v", sub), tok) {
		t.Fatal("the raw token is reachable from the subject")
	}
}

func TestSubjectVerifierRefusesWith401(t *testing.T) {
	future := time.Now().Add(time.Hour)
	for name, c := range map[string]struct {
		req    func() *http.Request
		reason string
	}{
		"missing header": {func() *http.Request { return subjReq("/connection", "") }, "subject_token_invalid:header"},
		"two headers": {func() *http.Request {
			r := subjReq("/connection", glovoToken(t, future))
			r.Header.Add(SubjectTokenHeader, glovoToken(t, future))
			return r
		}, "subject_token_invalid:header"},
		"garbage": {func() *http.Request { return subjReq("/connection", "not-a-jwt") }, "subject_token_invalid:verify"},
		"bad signature": {func() *http.Request {
			return subjReq("/connection", glovoToken(t, future)+"x")
		}, "subject_token_invalid:verify"},
		"expired": {func() *http.Request {
			return subjReq("/connection", glovoToken(t, time.Now().Add(-time.Minute)))
		}, "subject_token_invalid:verify"},
		"api audience": {func() *http.Request {
			return subjReq("/connection", forgeSubject(t, subjBase, future, nil))
		}, "subject_token_invalid:audience"},
		"mixed audience": {func() *http.Request {
			return subjReq("/connection", forgeSubject(t, []string{subjResource, subjBase}, future, map[string]any{"tgr": "tgr_1", "stn": "acme"}))
		}, "subject_token_invalid:verify"},
		"wrong issuer": {func() *http.Request {
			return subjReq("/connection", forgeSubject(t, subjResource, future, map[string]any{"iss": "https://evil.example"}))
		}, "subject_token_invalid:verify"},
		"token in the query": {func() *http.Request {
			return subjReq("/connection?subject_token="+glovoToken(t, future), "")
		}, "subject_token_invalid:in_query"},
		"token in the query beside a header": {func() *http.Request {
			return subjReq("/connection?access_token=x", glovoToken(t, future))
		}, "subject_token_invalid:in_query"},
	} {
		t.Run(name, func(t *testing.T) {
			v, r, _ := newVerifier()
			req := c.req()
			_, ref := v.Verify(req)
			if ref == nil || !ref.Unauthenticated || ref.Err.Code != glovo.CodeNotAuthorized || ref.Reason != c.reason {
				t.Fatalf("refusal = %+v, want 401 %s", ref, c.reason)
			}
			if r.calls != 0 {
				t.Fatal("the resolver ran for an unverified token")
			}
			if req.Header.Get(SubjectTokenHeader) != "" {
				t.Fatal("the subject header survived a refusal")
			}
		})
	}
}

func TestSubjectVerifierSelectedTenantHeaderIsCompareOnly(t *testing.T) {
	v, _, _ := newVerifier()
	tok := glovoToken(t, time.Now().Add(time.Hour))
	req := subjReq("/connection", tok)
	req.Header.Set(SelectedTenantHeader, "other")
	if _, ref := v.Verify(req); ref == nil || ref.Unauthenticated || ref.Err.Code != glovo.CodeNotAuthorized || ref.Reason != "tenant_mismatch" {
		t.Fatalf("a different selected tenant = %+v", ref)
	}
	req = subjReq("/connection", tok)
	req.Header.Set(SelectedTenantHeader, "acme")
	if sub, ref := v.Verify(req); ref != nil || sub.Tenant != "acme" {
		t.Fatalf("a matching selected tenant = %+v, %v", sub, ref)
	}
	// Absent is fine, and a header never supplies the tenant the token lacks.
	v2, _, _ := newVerifier()
	noStn := forgeSubject(t, subjResource, time.Now().Add(time.Hour), nil)
	req = subjReq("/connection", noStn)
	req.Header.Set(SelectedTenantHeader, "acme")
	v2.Resolver = &fakeResolver{err: glovo.Refuse(glovo.CodeAmbiguousTenant)}
	if _, ref := v2.Verify(req); ref == nil || ref.Err.Code != glovo.CodeAmbiguousTenant || ref.Unauthenticated {
		t.Fatalf("a token without a team grant = %+v", ref)
	}
}

func TestSubjectVerifierPassesResolverAndInstallRefusalsUnchanged(t *testing.T) {
	tok := glovoToken(t, time.Now().Add(time.Hour))
	for _, c := range []glovo.Code{glovo.CodeAmbiguousTenant, glovo.CodeNoTenant, glovo.CodeNotInPilot, glovo.CodeUnavailable, glovo.CodeNotReady} {
		v, r, _ := newVerifier()
		r.err = glovo.Refuse(c)
		if _, ref := v.Verify(subjReq("/connection", tok)); ref == nil || ref.Err.Code != c || ref.Unauthenticated {
			t.Fatalf("resolver %s -> %+v", c, ref)
		}
	}
	v, _, i := newVerifier()
	i.err = glovo.Refuse(glovo.CodeNoInstall)
	if _, ref := v.Verify(subjReq("/connection", tok)); ref == nil || ref.Err.Code != glovo.CodeNoInstall {
		t.Fatalf("no install -> %+v", ref)
	}
	// A failed install read is unavailable, never "no install".
	i.err = errors.New("pool closed")
	if _, ref := v.Verify(subjReq("/connection", tok)); ref == nil || ref.Err.Code != glovo.CodeUnavailable {
		t.Fatalf("failed install read -> %+v", ref)
	}
	// A resolver answer without a refresh family cannot bind a ref.
	v, r, _ := newVerifier()
	r.sc.RefreshFamilyID = ""
	if _, ref := v.Verify(subjReq("/connection", tok)); ref == nil || ref.Err.Code != glovo.CodeUnavailable {
		t.Fatalf("no family -> %+v", ref)
	}
	if _, ref := (&SubjectVerifier{}).Verify(subjReq("/connection", tok)); ref == nil || ref.Err.Code != glovo.CodeNotReady {
		t.Fatalf("an unwired verifier -> %+v", ref)
	}
}
