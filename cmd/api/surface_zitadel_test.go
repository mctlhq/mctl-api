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
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/principals"
)

const testCustomersProviders = `[{"name":"zitadel","issuer":"https://auth.example","audiences":["api"],"customers_org_id":"395272528420931285"}]`

// customers_org_id reaches both the OAuth sign-in and the portal's
// resolution route, from the same entry.
func TestCustomersOrgWiring(t *testing.T) {
	cfg := zitadelUpstreamConfig("zitadel")
	cfg.OIDCProvidersRaw = testCustomersProviders
	cfg.MctlWebClientID, cfg.ZitadelPortalClientID = "web", "portal"
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate() = %v", err)
	}
	oauth := auth.NewOAuthServer("https://api.example", "", "", []byte("k"), nil, nil)
	if o := oauthZitadelOptions(cfg, &principals.Store{}, oauth); o == nil || o.CustomersOrgID != "395272528420931285" {
		t.Fatalf("OAuth upstream options = %+v, want the customers organization", o)
	}
	s := surfaceZitadelOptions(cfg)
	if s == nil || s.ProviderName != "zitadel" || s.Issuer != "https://auth.example" || s.CustomersOrgID != "395272528420931285" ||
		s.CreateClientID != "web" || s.SigninClientID != "portal" {
		t.Fatalf("surface options = %+v", s)
	}

	// Without customers_org_id nothing changes: no customers on the OAuth
	// path, and the route stays off.
	plain := zitadelUpstreamConfig("zitadel")
	if o := oauthZitadelOptions(plain, &principals.Store{}, oauth); o == nil || o.CustomersOrgID != "" {
		t.Fatalf("OAuth upstream options = %+v, want no customers organization", o)
	}
	if s := surfaceZitadelOptions(plain); s != nil {
		t.Fatalf("surface options without customers_org_id = %+v, want nil", s)
	}
}

// A customer must resolve the same way on every path: two entries naming a
// customers organization, one that disagrees with the identity hook, or one
// keyed on another claim refuse the boot.
func TestCustomersOrgConfigRefusals(t *testing.T) {
	cases := map[string]func(*config){
		"two entries": func(c *config) {
			c.OIDCProvidersRaw = `[{"name":"zitadel","issuer":"https://auth.example","audiences":["api"],"customers_org_id":"1"},` +
				`{"name":"zitadel2","issuer":"https://auth2.example","audiences":["api"],"customers_org_id":"2"}]`
		},
		"disagrees with the hook": func(c *config) {
			c.OIDCProvidersRaw = testCustomersProviders
			c.ZitadelHook.CustomersOrgID = "1"
		},
		"not keyed on sub": func(c *config) {
			c.OIDCProvidersRaw = `[{"name":"zitadel","issuer":"https://auth.example","audiences":["api"],"subject_claim":"email","customers_org_id":"1"}]`
		},
	}
	for name, mutate := range cases {
		cfg := zitadelUpstreamConfig("")
		cfg.OAuthZitadelProvider = ""
		mutate(&cfg)
		if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "customers_org_id") {
			t.Errorf("%s: validate() = %v, want a refusal naming customers_org_id", name, err)
		}
		if s := surfaceZitadelOptions(cfg); s != nil {
			t.Errorf("%s: surface options = %+v, want nil", name, s)
		}
	}
	agree := zitadelUpstreamConfig("")
	agree.OIDCProvidersRaw = testCustomersProviders
	agree.ZitadelHook.CustomersOrgID = "395272528420931285"
	if err := agree.validate(); err != nil {
		t.Fatalf("matching hook organization: validate() = %v", err)
	}
}
