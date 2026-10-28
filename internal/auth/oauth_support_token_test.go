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
	"strings"
	"testing"
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
	if c["aud"] != testSupportRes && !(len(c["aud"].([]any)) == 1 && c["aud"].([]any)[0] == testSupportRes) {
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
