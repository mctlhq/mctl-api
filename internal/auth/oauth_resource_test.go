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

package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth/refreshstore"
)

const (
	testRedirect   = "https://client.example/callback"
	testSupportRes = "https://support.mctl.ai"
)

func newResourceServer(t *testing.T) *OAuthServer {
	t.Helper()
	o := newTestOAuthServer(t)
	o.SupportResource = testSupportRes
	return o
}

func TestResolveResource(t *testing.T) {
	o := newResourceServer(t)
	for _, tc := range []struct {
		name   string
		values []string
		want   string
		err    bool
	}{
		{"none", nil, o.BaseURL, false},
		{"base", []string{o.BaseURL}, o.BaseURL, false},
		{"base slash", []string{o.BaseURL + "/"}, o.BaseURL, false},
		{"mcp", []string{o.BaseURL + "/mcp"}, o.BaseURL, false},
		{"support", []string{testSupportRes}, testSupportRes, false},
		{"support slash", []string{testSupportRes + "/"}, testSupportRes, false},
		{"unknown", []string{"https://evil.example"}, "", true},
		{"two", []string{o.BaseURL, testSupportRes}, "", true},
		{"fragment", []string{testSupportRes + "#x"}, "", true},
		{"http", []string{"http://support.mctl.ai"}, "", true},
		{"relative", []string{"support"}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := o.ResolveResource(tc.values)
			if tc.err {
				if !errors.Is(err, ErrInvalidTarget) {
					t.Fatalf("err = %v, want ErrInvalidTarget", err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	o.SupportResource = ""
	if _, err := o.ResolveResource([]string{testSupportRes}); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("disabled support resource: err = %v, want ErrInvalidTarget", err)
	}
}

// mctl-api#851: a local run's own http base URL and /mcp endpoint resolve to
// the default audience; any other http resource is still invalid_target.
func TestResolveResource_LocalHTTPBase(t *testing.T) {
	o := NewOAuthServer("http://localhost:8080", "gh-client", "gh-secret", []byte("jwt-secret"), nil, NewGitHubValidator(nil))
	o.SupportResource = testSupportRes
	for _, v := range []string{"http://localhost:8080", "http://localhost:8080/", "http://localhost:8080/mcp"} {
		if got, err := o.ResolveResource([]string{v}); err != nil || got != "http://localhost:8080" {
			t.Errorf("%s: got %q, %v", v, got, err)
		}
	}
	for _, v := range []string{"http://localhost:9090", "http://support.mctl.ai", "http://localhost:8080/mcp#x"} {
		if _, err := o.ResolveResource([]string{v}); !errors.Is(err, ErrInvalidTarget) {
			t.Errorf("%s: err = %v, want ErrInvalidTarget", v, err)
		}
	}
}

func audOf(t *testing.T, o *OAuthServer, tok string) audience {
	t.Helper()
	p, err := o.verifyAccessToken(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return p.Audience
}

func codeFor(t *testing.T, o *OAuthServer, resource string) string {
	t.Helper()
	code, err := o.IssueCodeWithAuthMethod(context.Background(), "alice", "", "c", testRedirect,
		testPKCEChallenge(t, "v"), nil, "", resource)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// T2/T3: the code carries its resource; an unknown or different resource is
// invalid_target and, when unknown, does not burn the code.
func TestExchangeCodeResource(t *testing.T) {
	ctx := context.Background()
	o := newResourceServer(t)

	code := codeFor(t, o, testSupportRes)
	if _, _, err := o.ExchangeCodeForResource(ctx, code, "v", "c", testRedirect, ClientAssertion{}, []string{"https://evil.example"}); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("unknown resource: %v", err)
	}
	// Not consumed: still redeems, without a resource, for the support resource.
	access, _, err := o.ExchangeCodeForResource(ctx, code, "v", "c", testRedirect, ClientAssertion{}, nil)
	if err != nil {
		t.Fatalf("code was burned by an invalid_target: %v", err)
	}
	if aud := audOf(t, o, access); len(aud) != 1 || aud[0] != testSupportRes {
		t.Fatalf("aud = %v, want exactly [%s]", aud, testSupportRes)
	}

	// A resource differing from the authorized one mints nothing.
	code = codeFor(t, o, testSupportRes)
	if _, _, err := o.ExchangeCodeForResource(ctx, code, "v", "c", testRedirect, ClientAssertion{}, []string{o.BaseURL}); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("different resource: %v", err)
	}
	code = codeFor(t, o, "")
	if _, _, err := o.ExchangeCodeForResource(ctx, code, "v", "c", testRedirect, ClientAssertion{}, []string{testSupportRes}); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("api code redeemed for support: %v", err)
	}

	// No resource: the default audience, as before.
	code = codeFor(t, o, "")
	access, _, err = o.ExchangeCodeForResource(ctx, code, "v", "c", testRedirect, ClientAssertion{}, []string{o.BaseURL + "/mcp"})
	if err != nil {
		t.Fatal(err)
	}
	if aud := audOf(t, o, access); len(aud) != 1 || aud[0] != o.accessAudience() {
		t.Fatalf("aud = %v, want [%s]", aud, o.accessAudience())
	}
}

// T4: refresh keeps the resource, in memory and through a RotateIf store.
func TestRefreshKeepsResource(t *testing.T) {
	for name, store := range map[string]refreshstore.Store{"memory": nil, "store": newFakeRefreshStore()} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			o := newResourceServer(t)
			if store != nil {
				o.RefreshStore = store
			}
			code := codeFor(t, o, testSupportRes)
			_, refresh, err := o.ExchangeCodeForResource(ctx, code, "v", "c", testRedirect, ClientAssertion{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			// A mismatching resource is refused and the token still works.
			if _, _, err := o.RefreshAccessTokenForResource(ctx, refresh, "c", ClientAssertion{}, []string{o.BaseURL}); !errors.Is(err, ErrInvalidTarget) {
				t.Fatalf("mismatching refresh: %v", err)
			}
			for i := 0; i < 2; i++ { // the session, then its successor
				var access string
				access, refresh, err = o.RefreshAccessTokenForResource(ctx, refresh, "c", ClientAssertion{}, nil)
				if err != nil {
					t.Fatalf("refresh %d: %v", i, err)
				}
				if aud := audOf(t, o, access); len(aud) != 1 || aud[0] != testSupportRes {
					t.Fatalf("refresh %d: aud = %v, want [%s]", i, aud, testSupportRes)
				}
			}
			// A session that predates the resource is the default API one.
			plain := codeFor(t, o, "")
			_, refresh, err = o.ExchangeCodeForResource(ctx, plain, "v", "c", testRedirect, ClientAssertion{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			access, _, err := o.RefreshAccessTokenForResource(ctx, refresh, "c", ClientAssertion{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if aud := audOf(t, o, access); aud[0] != o.accessAudience() {
				t.Fatalf("aud = %v, want the default", aud)
			}
		})
	}
}

// T8, T10: verification and classification, through the legacy chain
// (ValidateJWT) and the federation provider.
func TestSupportAudienceVerification(t *testing.T) {
	o := newResourceServer(t)
	mint := func(aud string) string {
		tok, err := o.issueJWTFor("alice", "", nil, aud, "")
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	support := mint(testSupportRes)
	u, err := o.ValidateJWT(support)
	if err != nil || !u.IsSupportAudience() {
		t.Fatalf("ValidateJWT support token: %v, support=%v", err, u != nil && u.IsSupportAudience())
	}
	if aud, ok := u.TokenAudience(); !ok || len(aud) != 1 || aud[0] != testSupportRes {
		t.Fatalf("TokenAudience = %v, %v", aud, ok)
	}
	v, err := newLocalOAuthProvider(o).Verify(context.Background(), support)
	if err != nil {
		t.Fatal(err)
	}
	if fu := userFromVerified(v); !fu.IsSupportAudience() {
		t.Fatal("registry path lost the support audience")
	}

	api, err := o.ValidateJWT(mint(""))
	if err != nil || api.IsSupportAudience() {
		t.Fatalf("api token: %v, support=%v", err, api != nil && api.IsSupportAudience())
	}
	if aud, _ := api.TokenAudience(); len(aud) != 1 || aud[0] != o.accessAudience() {
		t.Fatalf("api TokenAudience = %v", aud)
	}
	v, _ = newLocalOAuthProvider(o).Verify(context.Background(), mint(""))
	if userFromVerified(v).IsSupportAudience() {
		t.Fatal("api token classified as support")
	}

	if _, err := o.ValidateJWT(mint("https://other.example")); err == nil {
		t.Fatal("unknown aud accepted")
	}
	o.SupportResource = ""
	if _, err := o.ValidateJWT(support); err == nil {
		t.Fatal("support aud accepted with the support resource disabled")
	}
}

// An aud naming both the API and the support resource is restricted.
func TestSupportAudienceWinsOverAPI(t *testing.T) {
	o := newResourceServer(t)
	tok, err := signJWT(jwtPayload{Issuer: o.BaseURL, Subject: "alice", Audience: audience{o.BaseURL, testSupportRes},
		ExpiresAt: time.Now().Add(time.Hour).Unix()}, o.JWTSecret)
	if err != nil {
		t.Fatal(err)
	}
	u, err := o.ValidateJWT(tok)
	if err != nil || !u.IsSupportAudience() {
		t.Fatalf("both-aud token: %v, support=%v", err, u != nil && u.IsSupportAudience())
	}
}

// The resource rides the pending authorization through the shared store.
func TestPendingAndCodeCarryResource(t *testing.T) {
	a, b, _ := twoReplicas(t)
	a.SupportResource, b.SupportResource = testSupportRes, testSupportRes
	ctx := context.Background()
	if err := a.StorePendingAuth(ctx, "s", "c", testRedirect, "ch", testSupportRes); err != nil {
		t.Fatal(err)
	}
	p, ok, err := b.LoadPendingAuth(ctx, "s")
	if err != nil || !ok || p.Resource != testSupportRes {
		t.Fatalf("pending = %+v, %v, %v", p, ok, err)
	}
	code := codeFor(t, a, testSupportRes)
	access, _, err := b.ExchangeCodeForResource(ctx, code, "v", "c", testRedirect, ClientAssertion{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if aud := audOf(t, b, access); aud[0] != testSupportRes {
		t.Fatalf("aud = %v", aud)
	}
}
