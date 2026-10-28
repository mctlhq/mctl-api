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
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

const testSupportPID = "prn_01ARZ3NDEKTSV4RRFFQ69G5FAV"

func jwtClaims(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a jwt: %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestIssueSupportToken(t *testing.T) {
	o := newResourceServer(t)
	u := &User{ID: "alice", githubLogin: true, principalID: testSupportPID}
	st, err := o.IssueSupportToken(u, 11*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	c := jwtClaims(t, st.Token)
	if c["aud"] != testSupportRes { // a single string, not an array
		t.Fatalf("aud = %v", c["aud"])
	}
	if c["pid"] != testSupportPID || c["jti"] != st.JTI || st.JTI == "" {
		t.Fatalf("claims = %v", c)
	}
	if g, _ := c["groups"].([]any); len(g) != 0 {
		t.Fatalf("groups = %v", c["groups"])
	}
	if d := c["exp"].(float64) - c["iat"].(float64); d > 11*60 || d < 11*60-1 {
		t.Fatalf("lifetime = %v", d)
	}
	vu, err := o.ValidateJWT(st.Token)
	if err != nil || !vu.IsSupportAudience() {
		t.Fatalf("ValidateJWT: %v support=%v", err, vu != nil && vu.IsSupportAudience())
	}
	st2, _ := o.IssueSupportToken(u, time.Minute)
	if st2.JTI == st.JTI {
		t.Fatal("jti reused")
	}
}

func TestIssueSupportToken_Refusals(t *testing.T) {
	o := newResourceServer(t)
	good := func() *User { return &User{ID: "alice", githubLogin: true, principalID: testSupportPID} }
	agent := good()
	agent.agent = "implementer"
	svc := good()
	svc.service = true
	relayed := good()
	relayed.viaPrincipalID = testSupportPID
	unresolved := good()
	unresolved.principalUnresolved = true
	support := good()
	support.supportAudience = true
	nopid := good()
	nopid.principalID = ""
	for name, u := range map[string]*User{
		"nil": nil, "agent": agent, "service": svc, "surface": NewSurfaceUser("telegram"),
		"relayed": relayed, "unresolved": unresolved, "support": support, "nopid": nopid,
	} {
		if _, err := o.IssueSupportToken(u, time.Minute); !errors.Is(err, ErrSupportTokenRefused) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	for _, ttl := range []time.Duration{0, MaxSupportTokenTTL + time.Second} {
		if _, err := o.IssueSupportToken(good(), ttl); err == nil {
			t.Errorf("ttl %s accepted", ttl)
		}
	}
	o.SupportResource = ""
	if _, err := o.IssueSupportToken(good(), time.Minute); !errors.Is(err, ErrSupportResourceDisabled) {
		t.Errorf("disabled: %v", err)
	}
}

func TestIssueJWT_HasNoJTI(t *testing.T) {
	o := newResourceServer(t)
	tok, err := o.IssueJWT("alice", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := jwtClaims(t, tok)["jti"]; ok {
		t.Fatal("ordinary access token carries jti")
	}
}

// T2: a disabled principal is refused at mint time and nothing is signed.
func TestIssueSupportToken_DisabledPrincipal(t *testing.T) {
	o := newResourceServer(t)
	c := &checkOnly{err: errors.New("principal disabled")}
	o.TokenPrincipalChecker = c
	st, err := o.IssueSupportToken(&User{ID: "alice", githubLogin: true, principalID: testSupportPID}, time.Minute)
	if err == nil || st.Token != "" {
		t.Fatalf("disabled principal minted: err=%v", err)
	}
	if !slices.Equal(c.checked, []string{testSupportPID}) {
		t.Fatalf("checked = %v", c.checked)
	}
}

// T1 under EdDSA: the minted token verifies as a support-audience token with
// the asymmetric signer too.
func TestIssueSupportToken_EdDSA(t *testing.T) {
	_, edPriv, _ := genKeys(t)
	o := newSigner(t, JWTAlgEdDSA, keysJSON(t, signingKeysDoc{Active: "k1", Keys: []signingKeyEntry{
		{Kid: "k1", Alg: JWTAlgEdDSA, PrivateKeyPEM: pemPriv(t, edPriv)}}}))
	o.SupportResource = testSupportRes
	st, err := o.IssueSupportToken(&User{ID: "alice", githubLogin: true, principalID: testSupportPID}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	vu, err := o.ValidateJWT(st.Token)
	if err != nil || !vu.IsSupportAudience() {
		t.Fatalf("ValidateJWT: %v", err)
	}
	if c := jwtClaims(t, st.Token); c["pid"] != testSupportPID || c["jti"] != st.JTI {
		t.Fatalf("claims = %v", c)
	}
}

// T13: a token minted with the default SUPPORT_TOKEN_TTL (11m) still verifies
// at +10m, which covers mctl-support's 600s task ceiling, and is rejected at
// +12m.
func TestIssueSupportToken_Lifetime(t *testing.T) {
	// Built outside the bubble: its GC goroutines would never exit inside it.
	o := newResourceServer(t)
	synctest.Test(t, func(t *testing.T) {
		st, err := o.IssueSupportToken(&User{ID: "alice", githubLogin: true, principalID: testSupportPID}, 11*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Minute)
		if _, err := o.ValidateJWT(st.Token); err != nil {
			t.Fatalf("rejected at +10m: %v", err)
		}
		time.Sleep(2 * time.Minute)
		if _, err := o.ValidateJWT(st.Token); err == nil {
			t.Fatal("accepted at +12m")
		}
	})
}

type staticMembers map[string][]string

func (m staticMembers) PrincipalTenants(pid string) ([]string, []string, error) {
	return m[pid], nil, nil
}

// T12: what mctl-support learns from whoami with the minted token is what the
// caller's own API token says: same id, principal, admin bit and tenants,
// although the support token carries no groups claim. Both authorization
// modes are covered: principal mode (PrincipalAuthz, as in production) and
// legacy mode, where groups are re-resolved from the login on every
// validation.
func TestIssueSupportToken_WhoamiParity(t *testing.T) {
	check := func(t *testing.T, api, sup *User) {
		t.Helper()
		if api.ID != sup.ID || api.PrincipalID() != sup.PrincipalID() || api.IsAdmin() != sup.IsAdmin() ||
			!slices.Equal(api.Groups, sup.Groups) {
			t.Fatalf("api = %s/%s admin=%v %v; support = %s/%s admin=%v %v",
				api.ID, api.PrincipalID(), api.IsAdmin(), api.Groups, sup.ID, sup.PrincipalID(), sup.IsAdmin(), sup.Groups)
		}
		if len(api.Groups) == 0 || api.IsSupportAudience() || !sup.IsSupportAudience() {
			t.Fatalf("bad fixture: groups=%v", api.Groups)
		}
	}
	mint := func(t *testing.T, o *OAuthServer, caller *User) *User {
		t.Helper()
		st, err := o.IssueSupportToken(caller, 11*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if g := jwtClaims(t, st.Token)["groups"]; g != nil {
			t.Fatalf("support token carries groups %v", g)
		}
		u, err := o.ValidateJWT(st.Token)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}

	t.Run("principal", func(t *testing.T) {
		o := newResourceServer(t)
		o.PrincipalMode = true
		authz := &PrincipalAuthz{Members: staticMembers{testSupportPID: {"karabu", "labs"}}, Admins: map[string]bool{testSupportPID: true}}
		tok, err := o.IssueJWT("alice", testSupportPID, nil)
		if err != nil {
			t.Fatal(err)
		}
		api, err := o.ValidateJWT(tok)
		if err != nil {
			t.Fatal(err)
		}
		if err := authz.Apply(api); err != nil {
			t.Fatal(err)
		}
		sup := mint(t, o, api)
		if err := authz.Apply(sup); err != nil {
			t.Fatal(err)
		}
		check(t, api, sup)
	})

	t.Run("legacy", func(t *testing.T) {
		o := newResourceServer(t)
		r := &stubTenantResolver{}
		r.setTenants("alice", []string{"karabu"})
		o.TenantResolver = r
		tok, err := o.IssueJWT("alice", testSupportPID, []string{"karabu"})
		if err != nil {
			t.Fatal(err)
		}
		api, err := o.ValidateJWT(tok)
		if err != nil {
			t.Fatal(err)
		}
		api.principalID = testSupportPID // attached by the middleware's principal resolver
		sup := mint(t, o, api)
		sup.principalID = testSupportPID
		check(t, api, sup)
	})
}
