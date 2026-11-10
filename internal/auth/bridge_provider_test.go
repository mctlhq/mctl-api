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
	"testing"
	"time"
)

//nolint:gosec // test fixtures, not credentials
const (
	bridgeTestToken     = "bridge-provider-token-0123456789abcdef"
	bridgeProvidersJSON = `[{"ref":"glovo","issuer":"https://issuer.example.test","subject":"system:serviceaccount:p:glovo","audience":"mctl-api-bridge","tenants":["acme"]}]`
)

func TestParseBridgeProvidersRefusesMalformedConfig(t *testing.T) {
	good, err := ParseBridgeProviders(bridgeProvidersJSON)
	if err != nil || len(good) != 1 || good[0].Ref != "glovo" {
		t.Fatalf("good config: %v %+v", err, good)
	}
	if got, err := ParseBridgeProviders(""); err != nil || got != nil {
		t.Fatalf("empty config: %v %v", err, got)
	}
	entry := `{"ref":"glovo","issuer":"https://i.test","subject":"s","audience":"mctl-api-bridge","tenants":["a"]}`
	bad := map[string]string{
		"not json":       `[{"ref"`,
		"unknown field":  `[{"ref":"glovo","issuer":"https://i.test","subject":"s","audience":"mctl-api-bridge","tenants":["a"],"extra":1}]`,
		"trailing data":  bridgeProvidersJSON + "x",
		"bad ref":        `[{"ref":"Glovo!","issuer":"https://i.test","subject":"s","audience":"mctl-api-bridge","tenants":["a"]}]`,
		"http issuer":    `[{"ref":"glovo","issuer":"http://i.test","subject":"s","audience":"mctl-api-bridge","tenants":["a"]}]`,
		"no subject":     `[{"ref":"glovo","issuer":"https://i.test","subject":"","audience":"mctl-api-bridge","tenants":["a"]}]`,
		"wrong audience": `[{"ref":"glovo","issuer":"https://i.test","subject":"s","audience":"mctl-api","tenants":["a"]}]`,
		"no tenants":     `[{"ref":"glovo","issuer":"https://i.test","subject":"s","audience":"mctl-api-bridge","tenants":[]}]`,
		"duplicate ref":  "[" + entry + "," + entry + "]",
	}
	for name, raw := range bad {
		if _, err := ParseBridgeProviders(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestBridgePinClaimsFailsClosed(t *testing.T) {
	cfg := BridgeProviderConfig{Ref: "glovo", Issuer: "https://issuer.example.test", Subject: "sub", Audience: BridgeAudience}
	now := time.Now()
	check := func(iss string, aud []string, sub string, exp, nbf time.Time) error {
		return cfg.PinClaims(iss, aud, sub, exp, nbf, now)
	}
	aud := []string{BridgeAudience}
	if err := check(cfg.Issuer, aud, "sub", now.Add(time.Minute), now.Add(-time.Minute)); err != nil {
		t.Fatalf("pinned token refused: %v", err)
	}
	cases := map[string]error{
		"wrong issuer":   check("https://other.test", aud, "sub", now.Add(time.Minute), time.Time{}),
		"wrong audience": check(cfg.Issuer, []string{"mctl-api"}, "sub", now.Add(time.Minute), time.Time{}),
		"wrong subject":  check(cfg.Issuer, aud, "other", now.Add(time.Minute), time.Time{}),
		"expired":        check(cfg.Issuer, aud, "sub", now.Add(-time.Second), time.Time{}),
		"no exp":         check(cfg.Issuer, aud, "sub", time.Time{}, time.Time{}),
		"not yet valid":  check(cfg.Issuer, aud, "sub", now.Add(time.Minute), now.Add(time.Minute)),
	}
	for name, err := range cases {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestBridgeProviderTokenMintsANarrowPrincipal(t *testing.T) {
	t.Setenv("AUTH_REQUIRED", "true")
	t.Setenv("MCTL_AGENT_SERVICE_TOKEN", "svc-token-123")
	t.Setenv("MCTL_BRIDGE_PROVIDERS", bridgeProvidersJSON)
	t.Setenv("MCTL_BRIDGE_PROVIDER_TOKENS", "glovo="+bridgeTestToken)

	u := authAs(t, bridgeTestToken)
	if u == nil || u.BridgeProviderRef() != "glovo" || u.ID != "service:bridge-provider:glovo" {
		t.Fatalf("bridge token: %+v", u)
	}
	if !u.HasPermission(PermissionBridgeProvider) || u.IsAdmin() || u.HasPermission(PermissionSecurityIngest) || u.HasPermission(PermissionUsageWrite) {
		t.Fatal("bridge provider holds more than its one permission")
	}
	if id, ok := u.Identity(); !ok || id.Kind != KindService || id.Subject != u.ID {
		t.Fatalf("identity = %+v", id)
	}
	if svc := authAs(t, "svc-token-123"); svc == nil || svc.BridgeProviderRef() != "" || svc.HasPermission(PermissionBridgeProvider) {
		t.Fatalf("service principal = %+v", svc)
	}
	if got := authAs(t, bridgeTestToken+"x"); got != nil {
		t.Fatalf("wrong token authenticated: %+v", got)
	}
}

func TestBridgeProviderTokenThatCouldBeConfusedIsRefused(t *testing.T) {
	cases := []struct{ name, tokens, evidence, providers string }{
		{"too short", "glovo=short", "", bridgeProvidersJSON},
		{"equal to another principal's token", "glovo=" + bridgeTestToken, bridgeTestToken, bridgeProvidersJSON},
		{"no entry", "ghost=" + bridgeTestToken, "", bridgeProvidersJSON},
		{"malformed config", "glovo=" + bridgeTestToken, "", `[{"ref":"glovo"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("AUTH_REQUIRED", "true")
			t.Setenv("MCTL_AGENT_SERVICE_TOKEN", "svc-token-123")
			t.Setenv("MCTL_EVIDENCE_WRITER_TOKEN", c.evidence)
			t.Setenv("MCTL_BRIDGE_PROVIDERS", c.providers)
			t.Setenv("MCTL_BRIDGE_PROVIDER_TOKENS", c.tokens)
			if u := authAs(t, bridgeTestToken); u != nil && u.BridgeProviderRef() != "" {
				t.Fatalf("minted a bridge principal: %+v", u)
			}
		})
	}
}

func TestParseBridgeProvidersSupportedVersions(t *testing.T) {
	entry := func(v string) string {
		return `[{"ref":"glovo","issuer":"https://issuer.example","subject":"s","audience":"mctl-api-bridge","tenants":["acme"]` + v + `}]`
	}
	got, err := ParseBridgeProviders(entry(""))
	if err != nil {
		t.Fatal(err)
	}
	if v := got[0].WireVersions(); len(v) != 1 || v[0] != BridgeWireV1alpha1 {
		t.Fatalf("absent key must mean [v1alpha1], got %v", v)
	}
	got, err = ParseBridgeProviders(entry(`,"supported_versions":["bridge.mctl.ai/v1alpha1","bridge.mctl.ai/v1alpha2"]`))
	if err != nil {
		t.Fatal(err)
	}
	if v := got[0].WireVersions(); len(v) != 2 || v[1] != BridgeWireV1alpha2 {
		t.Fatalf("versions = %v", v)
	}
	for name, bad := range map[string]string{
		"unknown":       `,"supported_versions":["bridge.mctl.ai/v1alpha1","bridge.mctl.ai/v9"]`,
		"duplicate":     `,"supported_versions":["bridge.mctl.ai/v1alpha1","bridge.mctl.ai/v1alpha1"]`,
		"empty":         `,"supported_versions":[]`,
		"without v1":    `,"supported_versions":["bridge.mctl.ai/v1alpha2"]`,
		"empty element": `,"supported_versions":[""]`,
	} {
		if _, err := ParseBridgeProviders(entry(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
