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

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// mctl-api#851: an OAUTH_SUPPORT_RESOURCE that names this API, or that is
// not an https URL, refuses the boot; unset is the default, empty disables.
func TestConfigureSupportResource(t *testing.T) {
	const base = "https://api.example"
	for name, tc := range map[string]struct {
		env     *string
		want    string
		refused bool
	}{
		"unset":      {nil, auth.DefaultSupportResource, false},
		"empty":      {ptr(""), "", false},
		"other host": {ptr(" https://support.example "), "https://support.example", false},
		"base url":   {ptr(base), "", true},
		"base slash": {ptr(base + "/"), "", true},
		"mcp":        {ptr(base + "/mcp"), "", true},
		"audience":   {ptr("https://aud.example"), "", true},
		"http":       {ptr("http://support.example"), "", true},
		"relative":   {ptr("support"), "", true},
		"fragment":   {ptr("https://support.example#x"), "", true},
		"no host":    {ptr("https://"), "", true},
	} {
		t.Run(name, func(t *testing.T) {
			o := auth.NewOAuthServer(base, "id", "secret", []byte("jwt-secret"), nil, auth.NewGitHubValidator(nil))
			o.AccessTokenAudience = "https://aud.example"
			lookup := func(k string) (string, bool) {
				if k != "OAUTH_SUPPORT_RESOURCE" || tc.env == nil {
					return "", false
				}
				return *tc.env, true
			}
			err := configureSupportResource(o, lookup)
			if tc.refused {
				if err == nil {
					t.Fatalf("accepted %q", o.SupportResource)
				}
				return
			}
			if err != nil || o.SupportResource != tc.want {
				t.Fatalf("got %q, %v; want %q", o.SupportResource, err, tc.want)
			}
		})
	}
}

func ptr(s string) *string { return &s }

func TestConfigureGlovoResource(t *testing.T) {
	o := &auth.OAuthServer{BaseURL: "https://api.example", SupportResource: auth.DefaultSupportResource}
	look := func(v string, ok bool) func(string) (string, bool) {
		return func(string) (string, bool) { return v, ok }
	}
	if err := configureGlovoResource(o, look("", false)); err != nil || o.GlovoResource != "" {
		t.Fatalf("unset: %v %q", err, o.GlovoResource)
	}
	if err := configureGlovoResource(o, look(" "+auth.GlovoResourceIntended+" ", true)); err != nil || o.GlovoResource != auth.GlovoResourceIntended {
		t.Fatalf("valid: %v %q", err, o.GlovoResource)
	}
	for _, bad := range []string{"http://glovo.mctl.ai", auth.DefaultSupportResource, "https://api.example/mcp"} {
		if err := configureGlovoResource(o, look(bad, true)); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestConfigureGlovoLinkResource(t *testing.T) {
	o := &auth.OAuthServer{BaseURL: "https://api.example", SupportResource: auth.DefaultSupportResource, GlovoResource: auth.GlovoResourceIntended}
	look := func(v string, ok bool) func(string) (string, bool) {
		return func(string) (string, bool) { return v, ok }
	}
	if err := configureGlovoLinkResource(o, look("", false)); err != nil || o.GlovoLinkResource != "" {
		t.Fatalf("unset: %v %q", err, o.GlovoLinkResource)
	}
	if err := configureGlovoLinkResource(o, look(" https://glovo.mctl.ai/link ", true)); err != nil || o.GlovoLinkResource != "https://glovo.mctl.ai/link" {
		t.Fatalf("valid: %v %q", err, o.GlovoLinkResource)
	}
	for _, bad := range []string{"http://glovo.mctl.ai/link", auth.DefaultSupportResource, auth.GlovoResourceIntended, "https://api.example/mcp"} {
		if err := configureGlovoLinkResource(o, look(bad, true)); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

// mctl-api#1062: OAUTH_MCP_RESOURCES is parsed, validated and wired with
// the admin predicate; unset changes nothing.
func TestConfigureDownstreamResources(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := json.Marshal(map[string]any{"active": "k1", "keys": []map[string]string{{
		"kid": "k1", "alg": auth.JWTAlgEdDSA, "private_key_pem": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
	}}})
	newServer := func(t *testing.T, alg string) *auth.OAuthServer {
		t.Helper()
		o := auth.NewOAuthServer("https://api.example", "", "", []byte("secret"), nil, nil)
		c := auth.JWTSigningConfig{Alg: alg, AcceptHS256: true}
		if alg == auth.JWTAlgEdDSA {
			c.KeysJSON = string(keys)
		}
		if err := o.ConfigureSigning(c); err != nil {
			t.Fatal(err)
		}
		return o
	}
	const admin = "prn_01JZZZZZZZZZZZZZZZZZZZZZZZ"
	admins := map[string]bool{admin: true}

	o := newServer(t, auth.JWTAlgHS256)
	if err := configureDownstreamResources(o, "", nil); err != nil || len(o.DownstreamResources) != 0 {
		t.Fatalf("unset: %v %v", err, o.DownstreamResources)
	}
	if err := configureDownstreamResources(o, `[{"resource":"https://tg.mctl.ai/mcp"}]`, admins); err == nil {
		t.Fatal("registry accepted with HS256 signing")
	}

	o = newServer(t, auth.JWTAlgEdDSA)
	raw := `[{"resource":"https://tg.mctl.ai/mcp"},{"resource":"https://alice.mctl.ai/mcp","admin_only":true}]`
	if err := configureDownstreamResources(o, raw, admins); err != nil {
		t.Fatal(err)
	}
	if len(o.DownstreamResources) != 2 || o.IsAdminPrincipal == nil || !o.IsAdminPrincipal(admin) || o.IsAdminPrincipal("prn_01JBBBBBBBBBBBBBBBBBBBBBBB") {
		t.Fatalf("wiring: %v, admin predicate set=%v", o.DownstreamResources, o.IsAdminPrincipal != nil)
	}
	for _, bad := range []string{`not json`, `[{"resource":"https://api.example/mcp"}]`, `[{"resource":"https://alice.mctl.ai/mcp","adminOnly":true}]`} {
		if err := configureDownstreamResources(o, bad, admins); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	if err := configureDownstreamResources(o, `[{"resource":"https://alice.mctl.ai/mcp","admin_only":true}]`, nil); err == nil {
		t.Fatal("admin_only accepted with no admins")
	}
}
