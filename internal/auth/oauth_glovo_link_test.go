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

const testLinkRes = "https://glovo.mctl.ai/link"

func newLinkEnv(t *testing.T) *glovoEnv {
	t.Helper()
	e := newGlovoEnv(t)
	e.o.GlovoLinkResource = testLinkRes
	return e
}

func tokenClaims(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
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

func (e *glovoEnv) linkCode(t *testing.T, authTime int64) string {
	t.Helper()
	code, err := e.o.IssueCodeForLink(context.Background(), "", tgPRN, tgClient, tgRedir, challenge(), nil, "", testLinkRes, authTime)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestLinkResourceIsDarkUnlessConfiguredAndReady(t *testing.T) {
	// Unset: invalid_target, as for any unknown resource.
	e := newGlovoEnv(t)
	if _, err := e.o.ResolveResource([]string{testLinkRes}); !errors.Is(err, ErrInvalidTarget) || errors.Is(err, ErrGlovoNotReady) {
		t.Fatalf("unset link resource: %v, want plain invalid_target", err)
	}
	// Set and ready: admitted as itself.
	e = newLinkEnv(t)
	if got, err := e.o.ResolveResource([]string{testLinkRes}); err != nil || got != testLinkRes {
		t.Fatalf("ready: %q %v", got, err)
	}
	// Set but not ready: refused.
	e.o.GlovoEnabled = false
	if _, err := e.o.ResolveResource([]string{testLinkRes}); !errors.Is(err, ErrGlovoNotReady) {
		t.Fatalf("not ready: %v, want ErrGlovoNotReady", err)
	}
	if _, err := e.o.IssueCodeForLink(context.Background(), "", tgPRN, tgClient, tgRedir, "c", nil, "", testLinkRes, 1); !errors.Is(err, ErrGlovoNotReady) {
		t.Fatalf("code issued while not ready: %v", err)
	}
}

func TestValidateGlovoLinkResource(t *testing.T) {
	for name, tc := range map[string]struct {
		res string
		ok  bool
	}{
		"empty":     {"", true},
		"valid":     {testLinkRes, true},
		"http":      {"http://glovo.mctl.ai/link", false},
		"fragment":  {testLinkRes + "#x", false},
		"mcp":       {GlovoResourceIntended, false},
		"mcp slash": {GlovoResourceIntended + "/", false},
		"support":   {testSupportRes, false},
		"api":       {"https://api.example", false},
	} {
		t.Run(name, func(t *testing.T) {
			e := newGlovoEnv(t)
			e.o.BaseURL = "https://api.example"
			e.o.GlovoLinkResource = tc.res
			if err := e.o.ValidateGlovoLinkResource(); (err == nil) != tc.ok {
				t.Fatalf("%q: %v, want ok=%v", tc.res, err, tc.ok)
			}
		})
	}
	e := newGlovoEnv(t)
	e.o.DownstreamResources = []DownstreamResource{{Resource: "https://down.example/mcp"}}
	e.o.GlovoLinkResource = "https://down.example/mcp"
	if err := e.o.ValidateGlovoLinkResource(); err == nil {
		t.Fatal("a downstream resource accepted as the link resource")
	}
}

func TestLinkTokenHasAuthTimeAndLinkAudienceOnly(t *testing.T) {
	e := newLinkEnv(t)
	const at = int64(1_700_000_000)
	access, refresh, err := e.o.ExchangeCodeForResource(context.Background(), e.linkCode(t, at), tgVerif, tgClient, tgRedir, ClientAssertion{}, []string{testLinkRes})
	if err != nil {
		t.Fatal(err)
	}
	if refresh != "" || e.store.Live() != 0 {
		t.Fatalf("refresh token %q / live %d: a link session must have none", refresh, e.store.Live())
	}
	c := tokenClaims(t, access)
	if c["aud"] != testLinkRes {
		t.Fatalf("aud = %v, want exactly the link resource", c["aud"])
	}
	if got, _ := c["auth_time"].(float64); int64(got) != at {
		t.Fatalf("auth_time = %v, want %d", c["auth_time"], at)
	}
	if _, has := c["tgr"]; has {
		t.Fatalf("link token carries a grant: %v", c)
	}

	// The default (MCP) token never carries auth_time.
	mcp, err := e.o.IssueJWT("", tgPRN, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, has := tokenClaims(t, mcp)["auth_time"]; has {
		t.Fatal("MCP token carries auth_time")
	}
	// Nor does the Glovo MCP token.
	code, g := e.codeFor(t, "alpha")
	gt, _, err := e.exchange(code)
	if err != nil {
		t.Fatal(err)
	}
	_ = g
	if _, has := tokenClaims(t, gt)["auth_time"]; has {
		t.Fatal("Glovo MCP token carries auth_time")
	}
}

func TestLinkCodeNeedsAuthTimeAndOnlyLinkMayCarryOne(t *testing.T) {
	e := newLinkEnv(t)
	ctx := context.Background()
	for _, at := range []int64{0, -5} {
		if _, err := e.o.IssueCodeForLink(ctx, "", tgPRN, tgClient, tgRedir, "c", nil, "", testLinkRes, at); err == nil {
			t.Fatalf("link code issued with auth_time %d", at)
		}
	}
	if _, err := e.o.IssueCodeForLink(ctx, "", tgPRN, tgClient, tgRedir, "c", nil, "", "", 1); err == nil {
		t.Fatal("default-resource code issued with an auth_time")
	}
	// A link JWT cannot be minted without one either.
	if _, err := e.o.issueJWTAt("", tgPRN, nil, testLinkRes, tgClient, "", "", false, 0); err == nil {
		t.Fatal("link token minted without auth_time")
	}
	// auth_time is never minted for another audience.
	tok, err := e.o.issueJWTAt("", tgPRN, nil, "", tgClient, "", "", false, 99)
	if err != nil {
		t.Fatal(err)
	}
	if _, has := tokenClaims(t, tok)["auth_time"]; has {
		t.Fatal("auth_time minted for the default audience")
	}
}

func TestRefreshForLinkResourceIsRefused(t *testing.T) {
	e := newLinkEnv(t)
	// No path issues one...
	if _, err := e.o.issueRefreshToken("", tgPRN, nil, tgClient, "", testLinkRes); err == nil {
		t.Fatal("refresh token issued for the link resource")
	}
	// ...but a session that nevertheless exists is not refreshed.
	if err := e.store.Insert("rt-link", tgClient, refreshstore.Session{PrincipalID: tgPRN, Resource: testLinkRes}, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	_, _, err := e.o.RefreshAccessTokenForResource(context.Background(), "rt-link", tgClient, ClientAssertion{}, nil)
	if !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("refresh of a link session = %v, want invalid_target", err)
	}
}

func TestLinkTokenIsRefusedByVerification(t *testing.T) {
	e := newLinkEnv(t)
	access, _, err := e.o.ExchangeCodeForResource(context.Background(), e.linkCode(t, 1_700_000_000), tgVerif, tgClient, tgRedir, ClientAssertion{}, []string{testLinkRes})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.o.verifyAccessToken(access); err == nil {
		t.Fatal("verification accepted a link token")
	}
	if _, err := e.o.ValidateJWT(access); err == nil {
		t.Fatal("ValidateJWT accepted a link token")
	}
	// A mixed aud naming the API as well is refused too.
	mixed, err := e.o.signAccessToken(jwtPayload{Issuer: e.o.BaseURL, Subject: "x", PID: tgPRN,
		Audience: audience{e.o.accessAudience(), testLinkRes}, IssuedAt: 1, ExpiresAt: 1 << 40})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.o.verifyAccessToken(mixed); err == nil {
		t.Fatal("verification accepted [api, link]")
	}
	// A default token still verifies.
	ok, err := e.o.IssueJWT("", tgPRN, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.o.verifyAccessToken(ok); err != nil {
		t.Fatalf("default token refused: %v", err)
	}
}
