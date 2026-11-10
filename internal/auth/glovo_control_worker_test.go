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
	"strings"
	"testing"
	"time"
)

const glovoControlWorkerJSON = `{"issuer":"https://issuer.example.com","subject":"temporal-control","audience":"mctl-api-glovo-control","tenants":["acme"]}`

func TestParseGlovoControlWorkerRefusesMalformedConfig(t *testing.T) {
	if c, err := ParseGlovoControlWorker(""); c != nil || err != nil {
		t.Fatalf("empty input is no configuration, got %v %v", c, err)
	}
	c, err := ParseGlovoControlWorker(glovoControlWorkerJSON)
	if err != nil || c == nil || len(c.Tenants) != 1 || c.Tenants[0] != "acme" {
		t.Fatalf("valid config: %v %v", c, err)
	}
	bad := map[string]string{
		"no tenants":     `{"issuer":"https://i.example.com","subject":"s","audience":"mctl-api-glovo-control"}`,
		"empty tenants":  `{"issuer":"https://i.example.com","subject":"s","audience":"mctl-api-glovo-control","tenants":[]}`,
		"blank tenant":   `{"issuer":"https://i.example.com","subject":"s","audience":"mctl-api-glovo-control","tenants":[" "]}`,
		"wrong audience": `{"issuer":"https://i.example.com","subject":"s","audience":"mctl-api-bridge","tenants":["a"]}`,
		"http issuer":    `{"issuer":"http://i.example.com","subject":"s","audience":"mctl-api-glovo-control","tenants":["a"]}`,
		"no subject":     `{"issuer":"https://i.example.com","subject":" ","audience":"mctl-api-glovo-control","tenants":["a"]}`,
		"unknown field":  `{"issuer":"https://i.example.com","subject":"s","audience":"mctl-api-glovo-control","tenants":["a"],"admin":true}`,
		"trailing data":  glovoControlWorkerJSON + ` {}`,
		"not json":       `nope`,
	}
	for name, raw := range bad {
		if c, err := ParseGlovoControlWorker(raw); err == nil || c != nil {
			t.Errorf("%s: must be refused, got %v %v", name, c, err)
		}
	}
	t.Setenv(glovoControlWorkerEnv, bad["no tenants"])
	if LoadGlovoControlWorker() != nil {
		t.Fatal("a half-configured value must disable the mapping")
	}
	t.Setenv(glovoControlWorkerEnv, glovoControlWorkerJSON)
	if LoadGlovoControlWorker() == nil {
		t.Fatal("a complete value must load")
	}
}

func TestGlovoControlPinClaimsFailsClosed(t *testing.T) {
	c, err := ParseGlovoControlWorker(glovoControlWorkerJSON)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	aud := []string{GlovoControlAudience}
	ok := func(iss string, a []string, sub string, exp, nbf time.Time) error {
		return c.PinClaims(iss, a, sub, exp, nbf, now)
	}
	if err := ok(c.Issuer, aud, c.Subject, now.Add(time.Minute), time.Time{}); err != nil {
		t.Fatalf("a matching token must pass: %v", err)
	}
	if err := ok(c.Issuer, append([]string{"other"}, aud...), c.Subject, now.Add(time.Minute), now.Add(-time.Minute)); err != nil {
		t.Fatalf("a multi-audience token that carries the pin must pass: %v", err)
	}
	cases := map[string]error{
		"wrong issuer":  ok("https://evil.example.com", aud, c.Subject, now.Add(time.Minute), time.Time{}),
		"empty issuer":  ok("", aud, c.Subject, now.Add(time.Minute), time.Time{}),
		"wrong subject": ok(c.Issuer, aud, "someone-else", now.Add(time.Minute), time.Time{}),
		"empty subject": ok(c.Issuer, aud, "", now.Add(time.Minute), time.Time{}),
		"wrong aud":     ok(c.Issuer, []string{"mctl-api-bridge"}, c.Subject, now.Add(time.Minute), time.Time{}),
		"no aud":        ok(c.Issuer, nil, c.Subject, now.Add(time.Minute), time.Time{}),
		"expired":       ok(c.Issuer, aud, c.Subject, now.Add(-time.Second), time.Time{}),
		"no exp":        ok(c.Issuer, aud, c.Subject, time.Time{}, time.Time{}),
		"not yet valid": ok(c.Issuer, aud, c.Subject, now.Add(time.Hour), now.Add(time.Minute)),
	}
	for name, err := range cases {
		if err == nil {
			t.Errorf("%s: must fail closed", name)
		}
	}
}

func TestGlovoControlWorkerIsNarrowAndDistinct(t *testing.T) {
	u := NewGlovoControlWorkerUser()
	if !u.IsGlovoControlWorker() || u.ID != "service:glovo-control-worker" {
		t.Fatalf("principal = %+v", u)
	}
	if !u.HasPermission(PermissionGlovoControlDispatch) || u.IsAdmin() || u.HasPermission(PermissionBridgeProvider) ||
		u.HasPermission(PermissionUsageWrite) || u.HasPermission(PermissionSecurityIngest) {
		t.Fatal("the control worker holds more than its one permission")
	}
	if u.IsGlovoWorker() || u.IsGlovoAudience() || u.BridgeProviderRef() != "" || u.IsService() || u.IsAgent() || u.IsCI() {
		t.Fatal("the control worker must not be any other principal type")
	}
	if id, ok := u.Identity(); !ok || id.Kind != KindService || id.Subject != u.ID {
		t.Fatalf("identity = %+v", id)
	}
	others := map[string]*User{
		"nil":             nil,
		"service":         NewServiceUser(),
		"bridge provider": NewBridgeProviderUser("glovo"),
		"glovo worker":    NewGlovoWorkerUser(),
		"usage writer":    NewUsageWriterUser(),
		"surface":         NewSurfaceUser("telegram"),
		"ci":              NewCIUser("mctlhq/x", "1"),
		"github human":    NewGitHubUser("someone", []string{"admins"}),
	}
	for name, o := range others {
		if o.IsGlovoControlWorker() || o.HasPermission(PermissionGlovoControlDispatch) {
			t.Errorf("%s must not be or hold the control-worker permission", name)
		}
	}
}

// TestNoProductionVerifierMapsToTheControlWorker pins the release posture:
// with the control worker fully configured and every other credential set, no
// token and no verified identity yields the principal (mctl-gitops#2506).
func TestNoProductionVerifierMapsToTheControlWorker(t *testing.T) {
	t.Setenv("AUTH_REQUIRED", "true")
	t.Setenv("MCTL_AGENT_SERVICE_TOKEN", "svc-token-123")
	t.Setenv(glovoControlWorkerEnv, glovoControlWorkerJSON)
	t.Setenv("MCTL_BRIDGE_PROVIDERS", bridgeProvidersJSON)
	t.Setenv("MCTL_BRIDGE_PROVIDER_TOKENS", "glovo="+bridgeTestToken)
	for _, token := range []string{"svc-token-123", bridgeTestToken, GlovoControlWorkerUserID, "temporal-control", strings.Repeat("x", 40)} {
		if u := authAs(t, token); u.IsGlovoControlWorker() {
			t.Fatalf("token %q mapped to the control worker", token)
		}
	}
	for _, v := range []*Verified{
		{Identity: Identity{Provider: ProviderService, Subject: GlovoControlWorkerUserID, Kind: KindService}},
		{Identity: Identity{Provider: ProviderDex, Subject: GlovoControlWorkerUserID, Kind: KindService}},
	} {
		if u := userFromVerified(v); u.IsGlovoControlWorker() {
			t.Fatalf("a verified identity %+v mapped to the control worker", v.Identity)
		}
	}
}
