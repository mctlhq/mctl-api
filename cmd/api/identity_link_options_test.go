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
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/principals"
)

// The browser flow turns on only with every input present; anything missing
// leaves the API endpoints (Store) and turns the flow off, never half on.
func TestIdentityLinkOptionsGating(t *testing.T) {
	const providers = `[{"name":"zitadel","issuer":"https://auth.example","audiences":["api"]}]`
	full := func() config {
		return config{
			SelfURL: "https://api.example", OIDCProvidersRaw: providers, ZitadelLinkProvider: "zitadel",
			ZitadelLinkClientID: "id", ZitadelLinkClientSecret: "secret",
		}
	}
	store := &principals.Store{}
	oauth := auth.NewOAuthServer("https://api.example", "gh", "gh-secret", []byte("k"), nil, nil)
	gh := auth.NewGitHubValidator(nil)

	if o := identityLinkOptions(full(), nil, nil, oauth, gh); o != nil {
		t.Fatalf("no store: %+v, want nil", o)
	}
	o := identityLinkOptions(full(), store, nil, oauth, gh)
	if o == nil || o.ProviderName != "zitadel" || o.Issuer != "https://auth.example" || o.ProveGitHub == nil || o.GitHubClientID != "gh" {
		t.Fatalf("full config: %+v, want the browser flow on", o)
	}
	if o.ForgetPrincipals != nil {
		t.Error("ForgetPrincipals set without a resolver")
	}
	if o := identityLinkOptions(full(), store, principals.NewResolver(store, nil, false), oauth, gh); o.ForgetPrincipals == nil {
		t.Error("ForgetPrincipals not wired to the resolver")
	}

	off := map[string]func(*config, **auth.OAuthServer, **auth.GitHubValidator){
		"no client at all": func(c *config, _ **auth.OAuthServer, _ **auth.GitHubValidator) {
			c.ZitadelLinkClientID, c.ZitadelLinkClientSecret = "", ""
		},
		"secret without id":   func(c *config, _ **auth.OAuthServer, _ **auth.GitHubValidator) { c.ZitadelLinkClientID = "" },
		"no OAuth server":     func(_ *config, o **auth.OAuthServer, _ **auth.GitHubValidator) { *o = nil },
		"no GitHub validator": func(_ *config, _ **auth.OAuthServer, g **auth.GitHubValidator) { *g = nil },
		"federation disabled": func(c *config, _ **auth.OAuthServer, _ **auth.GitHubValidator) { c.FederationDisabled = true },
		"no provider entry":   func(c *config, _ **auth.OAuthServer, _ **auth.GitHubValidator) { c.ZitadelLinkProvider = "other" },
		"malformed providers": func(c *config, _ **auth.OAuthServer, _ **auth.GitHubValidator) { c.OIDCProvidersRaw = "{" },
	}
	for name, mutate := range off {
		t.Run(name, func(t *testing.T) {
			c, oa, g := full(), oauth, gh
			mutate(&c, &oa, &g)
			o := identityLinkOptions(c, store, nil, oa, g)
			if o == nil || o.Store == nil {
				t.Fatalf("API endpoints lost: %+v", o)
			}
			if o.ClientID != "" || o.ClientSecret != "" || o.ProveGitHub != nil {
				t.Fatalf("browser flow half on: %+v", o)
			}
		})
	}
}
