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
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth/refreshstore"
)

const (
	testTGRes    = "https://tg.mctl.ai/mcp"
	testAliceRes = "https://alice.mctl.ai/mcp"
	testAdminPID = "prn_01JZZZZZZZZZZZZZZZZZZZZZZZ"
	testUserPID  = "prn_01JBBBBBBBBBBBBBBBBBBBBBBB"
)

// newDownstreamServer is an EdDSA-signing server with tg (any principal)
// and alice (admins only) registered, and testAdminPID as the one admin.
func newDownstreamServer(t *testing.T) (*OAuthServer, map[string]bool) {
	t.Helper()
	_, edPriv, _ := genKeys(t)
	o := newSigner(t, JWTAlgEdDSA, keysJSON(t, signingKeysDoc{Active: "k1", Keys: []signingKeyEntry{
		{Kid: "k1", Alg: JWTAlgEdDSA, PrivateKeyPEM: pemPriv(t, edPriv)}}}))
	o.SupportResource = testSupportRes
	admins := map[string]bool{testAdminPID: true}
	o.IsAdminPrincipal = func(pid string) bool { return admins[pid] }
	o.DownstreamResources = []DownstreamResource{{Resource: testTGRes}, {Resource: testAliceRes, AdminOnly: true}}
	if err := o.ValidateDownstreamResources(); err != nil {
		t.Fatal(err)
	}
	return o, admins
}

func downstreamCode(t *testing.T, o *OAuthServer, pid, resource string) (string, error) {
	t.Helper()
	return o.IssueCodeWithAuthMethod(context.Background(), "alice", pid, "c", testRedirect,
		testPKCEChallenge(t, "v"), []string{"admins"}, "", resource)
}

// claimsOf decodes the payload without verifying it: what a downstream
// would read after its own JWKS check.
func claimsOf(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %q", tok)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestParseDownstreamResources(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		want      []DownstreamResource
		err       bool
	}{
		{"unset", "", nil, false},
		{"blank", "  \n", nil, false},
		{"two", `[{"resource":" https://tg.mctl.ai/mcp "},{"resource":"https://alice.mctl.ai/mcp","admin_only":true}]`,
			[]DownstreamResource{{Resource: testTGRes}, {Resource: testAliceRes, AdminOnly: true}}, false},
		{"typo field", `[{"resource":"https://alice.mctl.ai/mcp","adminOnly":true}]`, nil, true},
		{"object", `{"resource":"https://tg.mctl.ai/mcp"}`, nil, true},
		{"trailing", `[] []`, nil, true},
		{"garbage", `tg`, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseDownstreamResources(tc.raw)
			if tc.err {
				if err == nil {
					t.Fatalf("accepted %q as %v", tc.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("entry %d = %v, want %v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestValidateDownstreamResources(t *testing.T) {
	o, _ := newDownstreamServer(t)
	o.GlovoResource = GlovoResourceIntended
	for _, tc := range []struct {
		name string
		res  []DownstreamResource
	}{
		{"http", []DownstreamResource{{Resource: "http://tg.mctl.ai/mcp"}}},
		{"relative", []DownstreamResource{{Resource: "tg/mcp"}}},
		{"empty", []DownstreamResource{{Resource: ""}}},
		{"fragment", []DownstreamResource{{Resource: testTGRes + "#x"}}},
		{"this api", []DownstreamResource{{Resource: o.BaseURL + "/mcp"}}},
		{"support", []DownstreamResource{{Resource: testSupportRes}}},
		{"glovo", []DownstreamResource{{Resource: GlovoResourceIntended}}},
		{"duplicate", []DownstreamResource{{Resource: testTGRes}, {Resource: testTGRes + "/"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o.DownstreamResources = tc.res
			if err := o.ValidateDownstreamResources(); err == nil {
				t.Fatalf("accepted %v", tc.res)
			}
		})
	}

	// admin_only needs an admin predicate.
	o.DownstreamResources = []DownstreamResource{{Resource: testAliceRes, AdminOnly: true}}
	o.IsAdminPrincipal = nil
	if err := o.ValidateDownstreamResources(); err == nil {
		t.Fatal("admin_only accepted with no admins configured")
	}

	// Downstreams verify through the JWKS, so HS256 cannot serve them.
	hs := newTestOAuthServer(t)
	hs.DownstreamResources = []DownstreamResource{{Resource: testTGRes}}
	if err := hs.ValidateDownstreamResources(); err == nil {
		t.Fatal("registry accepted with HS256 signing")
	}
	hs.DownstreamResources = nil
	if err := hs.ValidateDownstreamResources(); err != nil {
		t.Fatalf("empty registry refused: %v", err)
	}
}

func TestResolveDownstreamResource(t *testing.T) {
	o, _ := newDownstreamServer(t)
	for _, v := range []string{testTGRes, testTGRes + "/"} {
		got, err := o.ResolveResource([]string{v})
		if err != nil || got != testTGRes {
			t.Fatalf("ResolveResource(%q) = %q, %v", v, got, err)
		}
	}
	if _, err := o.ResolveResource([]string{"https://tg.mctl.ai/other"}); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("unregistered path resolved: %v", err)
	}
	o.DownstreamResources = nil
	if _, err := o.ResolveResource([]string{testTGRes}); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("removed entry still resolves: %v", err)
	}
}

// The token a downstream receives: aud exactly its resource, sub the
// principal, no login and no groups.
func TestDownstreamTokenClaims(t *testing.T) {
	ctx := context.Background()
	o, _ := newDownstreamServer(t)
	code, err := downstreamCode(t, o, testUserPID, testTGRes)
	if err != nil {
		t.Fatal(err)
	}
	access, refresh, err := o.ExchangeCodeForResource(ctx, code, "v", "c", testRedirect, ClientAssertion{}, []string{testTGRes})
	if err != nil {
		t.Fatal(err)
	}
	c := claimsOf(t, access)
	// A single aud is serialized as a string (RFC 7519 section 4.1.3).
	if c["aud"] != testTGRes {
		t.Fatalf("aud = %v, want exactly [%s]", c["aud"], testTGRes)
	}
	if c["sub"] != testUserPID || c["pid"] != testUserPID {
		t.Fatalf("sub = %v, pid = %v, want the principal", c["sub"], c["pid"])
	}
	if g, ok := c["groups"]; ok && g != nil {
		t.Fatalf("groups leaked to the downstream: %v", g)
	}
	if strings.Contains(string(mustJSON(t, c)), `"alice"`) {
		t.Fatal("login leaked to the downstream")
	}

	// Refresh keeps the resource and the same claim shape.
	access, _, err = o.RefreshAccessTokenForResource(ctx, refresh, "c", ClientAssertion{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c := claimsOf(t, access); c["sub"] != testUserPID {
		t.Fatalf("refreshed sub = %v", c["sub"])
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A downstream token is never an API token, alone or mixed with the API aud.
func TestDownstreamTokenRefusedByAPI(t *testing.T) {
	o, _ := newDownstreamServer(t)
	tok, err := o.issueJWTFor("alice", testUserPID, nil, testTGRes, "c")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.ValidateJWT(tok); err == nil {
		t.Fatal("API accepted a token minted for tg")
	}
	if _, err := newLocalOAuthProvider(o).Verify(context.Background(), tok); err == nil {
		t.Fatal("registry path accepted a token minted for tg")
	}
	// Signed like a real API token (a login as sub), so the aud is the only
	// reason left to refuse it; the first entry is the control.
	mint := func(aud audience) string {
		tok, err := signJWTAsymmetric(jwtPayload{Issuer: o.BaseURL, Subject: "alice", PID: testUserPID,
			Audience: aud, IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix()}, o.keys.active)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	if _, err := o.ValidateJWT(mint(audience{o.accessAudience()})); err != nil {
		t.Fatalf("control API token refused: %v", err)
	}
	for _, aud := range []audience{{o.accessAudience(), testTGRes}, {testTGRes, o.accessAudience()}, {testSupportRes, testTGRes}} {
		if _, err := o.ValidateJWT(mint(aud)); err == nil {
			t.Fatalf("API accepted aud %v", aud)
		}
	}
	// Control: an API token from the same server still verifies.
	api, err := o.issueJWTFor("alice", testUserPID, nil, "", "c")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.ValidateJWT(api); err != nil {
		t.Fatalf("API token refused: %v", err)
	}
}

func TestDownstreamNeedsPrincipal(t *testing.T) {
	o, _ := newDownstreamServer(t)
	if _, err := downstreamCode(t, o, "", testTGRes); !errors.Is(err, ErrDownstreamPrincipal) {
		t.Fatalf("code without a principal: %v", err)
	}
	if _, err := o.issueJWTFor("alice", "", nil, testTGRes, "c"); !errors.Is(err, ErrDownstreamPrincipal) {
		t.Fatalf("token without a principal: %v", err)
	}
	// The API resource keeps working for a login-only caller.
	if _, err := downstreamCode(t, o, "", ""); err != nil {
		t.Fatalf("API code refused: %v", err)
	}
}

func TestDownstreamAdminOnly(t *testing.T) {
	for name, store := range map[string]refreshstore.Store{"memory": nil, "store": newFakeRefreshStore()} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			o, admins := newDownstreamServer(t)
			if store != nil {
				o.RefreshStore = store
			}
			if _, err := downstreamCode(t, o, testUserPID, testAliceRes); !errors.Is(err, ErrDownstreamPrincipal) {
				t.Fatalf("non-admin got an alice code: %v", err)
			}
			if _, err := o.issueJWTFor("alice", testUserPID, nil, testAliceRes, "c"); !errors.Is(err, ErrDownstreamPrincipal) {
				t.Fatalf("non-admin got an alice token: %v", err)
			}
			// tg is open to the same non-admin.
			if _, err := downstreamCode(t, o, testUserPID, testTGRes); err != nil {
				t.Fatalf("non-admin refused for tg: %v", err)
			}

			code, err := downstreamCode(t, o, testAdminPID, testAliceRes)
			if err != nil {
				t.Fatal(err)
			}
			_, refresh, err := o.ExchangeCodeForResource(ctx, code, "v", "c", testRedirect, ClientAssertion{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			// Removed from the admins: the next refresh mints nothing.
			delete(admins, testAdminPID)
			if _, _, err := o.RefreshAccessTokenForResource(ctx, refresh, "c", ClientAssertion{}, nil); !errors.Is(err, ErrDownstreamPrincipal) {
				t.Fatalf("refresh after admin removal: %v", err)
			}
		})
	}
}

// A session outlives its resource: removing the entry (or disabling the
// support resource) stops the next refresh and an unredeemed code from
// minting, instead of minting a token for a resource no longer served.
func TestSessionResourceRemoved(t *testing.T) {
	for name, store := range map[string]refreshstore.Store{"memory": nil, "store": newFakeRefreshStore()} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			o, _ := newDownstreamServer(t)
			if store != nil {
				o.RefreshStore = store
			}
			code, err := downstreamCode(t, o, testUserPID, testTGRes)
			if err != nil {
				t.Fatal(err)
			}
			_, refresh, err := o.ExchangeCodeForResource(ctx, code, "v", "c", testRedirect, ClientAssertion{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			pending, err := downstreamCode(t, o, testUserPID, testTGRes)
			if err != nil {
				t.Fatal(err)
			}
			o.DownstreamResources = []DownstreamResource{{Resource: testAliceRes, AdminOnly: true}}
			if _, _, err := o.RefreshAccessTokenForResource(ctx, refresh, "c", ClientAssertion{}, nil); !errors.Is(err, ErrInvalidTarget) {
				t.Fatalf("refresh for a removed resource: %v", err)
			}
			if _, _, err := o.ExchangeCodeForResource(ctx, pending, "v", "c", testRedirect, ClientAssertion{}, nil); !errors.Is(err, ErrInvalidTarget) {
				t.Fatalf("code for a removed resource: %v", err)
			}

			// The same rule for the support resource once it is disabled.
			support := codeFor(t, o, testSupportRes)
			_, refresh, err = o.ExchangeCodeForResource(ctx, support, "v", "c", testRedirect, ClientAssertion{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			o.SupportResource = ""
			if _, _, err := o.RefreshAccessTokenForResource(ctx, refresh, "c", ClientAssertion{}, nil); !errors.Is(err, ErrInvalidTarget) {
				t.Fatalf("refresh with the support resource disabled: %v", err)
			}
		})
	}
}
