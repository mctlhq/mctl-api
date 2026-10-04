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
	"time"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/principals"
)

const testZitadelProviders = `[{"name":"zitadel","issuer":"https://auth.example","audiences":["api"]}]`

func zitadelUpstreamConfig(mode string) config {
	return config{
		OAuthUpstreamRaw: mode, OAuthJWTSecret: "k", OAuthTokenTTL: time.Hour,
		OAuthZitadelClientID: "zid", OAuthZitadelClientSecret: "zsecret", OAuthZitadelProvider: "zitadel",
		OIDCProvidersRaw:    testZitadelProviders,
		OAuthGitHubClientID: "gh", OAuthGitHubClientSecret: "gh-secret",
	}
}

// The default changes nothing: the OAuth server is on exactly when the
// GitHub client and the JWT secret are set, as before mctl-api#467.
func TestOAuthGitHubModeGatingIsUnchanged(t *testing.T) {
	for _, mode := range []string{"", "github"} {
		on := config{OAuthUpstreamRaw: mode, OAuthGitHubClientID: "gh", OAuthJWTSecret: "k"}
		if err := on.validate(); err != nil || !on.oauthEnabled() {
			t.Fatalf("mode %q with GitHub client: validate=%v enabled=%v", mode, err, on.oauthEnabled())
		}
		for _, off := range []config{
			{OAuthUpstreamRaw: mode, OAuthJWTSecret: "k"},
			{OAuthUpstreamRaw: mode, OAuthGitHubClientID: "gh"},
			// ZITADEL settings alone never switch the server on under github.
			{OAuthUpstreamRaw: mode, OAuthJWTSecret: "k", OAuthZitadelClientID: "z", OAuthZitadelClientSecret: "s", OIDCProvidersRaw: testZitadelProviders, OAuthZitadelProvider: "zitadel"},
		} {
			if err := off.validate(); err != nil || off.oauthEnabled() {
				t.Fatalf("mode %q %+v: validate=%v enabled=%v, want off without an error", mode, off, err, off.oauthEnabled())
			}
		}
		if o := oauthZitadelOptions(zitadelUpstreamConfig(mode), &principals.Store{}, auth.NewOAuthServer("https://api.example", "gh", "s", []byte("k"), nil, nil)); o != nil {
			t.Fatalf("mode %q wired the ZITADEL upstream: %+v", mode, o)
		}
	}
}

// zitadel and both are explicit choices: incomplete configuration refuses
// the boot and names what is missing.
func TestOAuthUpstreamRefusesIncompleteConfig(t *testing.T) {
	for _, mode := range []string{"zitadel", "both"} {
		full := zitadelUpstreamConfig(mode)
		if err := full.validate(); err != nil || !full.oauthEnabled() {
			t.Fatalf("mode %s full config: validate=%v enabled=%v", mode, err, full.oauthEnabled())
		}
		cases := map[string]struct {
			mutate func(*config)
			names  string
		}{
			"no JWT secret":    {func(c *config) { c.OAuthJWTSecret = "" }, "OAUTH_JWT_SECRET"},
			"no client id":     {func(c *config) { c.OAuthZitadelClientID = "" }, "OAUTH_ZITADEL_CLIENT_ID"},
			"no client secret": {func(c *config) { c.OAuthZitadelClientSecret = "" }, "OAUTH_ZITADEL_CLIENT_SECRET"},
			"no providers":     {func(c *config) { c.OIDCProvidersRaw = "" }, "OAUTH_ZITADEL_PROVIDER"},
			"other entry name": {func(c *config) { c.OAuthZitadelProvider = "other" }, `"other"`},
			"non-sub subject": {func(c *config) {
				c.OIDCProvidersRaw = strings.Replace(testZitadelProviders, `"audiences"`, `"subject_claim":"email","audiences"`, 1)
			}, "sub"},
			"malformed entries": {func(c *config) { c.OIDCProvidersRaw = "{"; c.FederationDisabled = true }, "MCTL_OIDC_PROVIDERS"},
		}
		if mode == "both" {
			cases["no GitHub client"] = struct {
				mutate func(*config)
				names  string
			}{func(c *config) { c.OAuthGitHubClientID = "" }, "OAUTH_GITHUB_CLIENT_ID"}
			cases["no GitHub secret"] = struct {
				mutate func(*config)
				names  string
			}{func(c *config) { c.OAuthGitHubClientSecret = "" }, "OAUTH_GITHUB_CLIENT_SECRET"}
		}
		for name, tc := range cases {
			c := zitadelUpstreamConfig(mode)
			tc.mutate(&c)
			err := c.validate()
			if err == nil || !strings.Contains(err.Error(), tc.names) {
				t.Errorf("mode %s, %s: validate() = %v, want a refusal naming %s", mode, name, err, tc.names)
			}
		}
	}
	// Under zitadel the GitHub app stays optional (the link flow uses it).
	c := zitadelUpstreamConfig("zitadel")
	c.OAuthGitHubClientID, c.OAuthGitHubClientSecret = "", ""
	if err := c.validate(); err != nil || !c.oauthEnabled() {
		t.Fatalf("zitadel without GitHub: validate=%v enabled=%v", err, c.oauthEnabled())
	}
}

func TestOAuthUpstreamRefusesAnUnknownMode(t *testing.T) {
	c := zitadelUpstreamConfig("zitadel,github")
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "OAUTH_UPSTREAM") {
		t.Fatalf("validate() = %v, want a refusal naming OAUTH_UPSTREAM", err)
	}
}

func TestOAuthZitadelOptionsWiring(t *testing.T) {
	oauth := auth.NewOAuthServer("https://api.example", "", "", []byte("k"), nil, nil)
	cfg := zitadelUpstreamConfig("zitadel")
	o := oauthZitadelOptions(cfg, &principals.Store{}, oauth)
	if o == nil || o.ProviderName != "zitadel" || o.Issuer != "https://auth.example" || o.ClientID != "zid" || o.ClientSecret != "zsecret" || o.Store == nil {
		t.Fatalf("options = %+v", o)
	}
	if cfg.oauthUpstreamMode() != mctlapi.OAuthUpstreamZitadel {
		t.Fatalf("mode = %q", cfg.oauthUpstreamMode())
	}
	// No store: the interface must be nil, not a nil *Store the handler
	// would call.
	if o := oauthZitadelOptions(cfg, nil, oauth); o == nil || o.Store != nil {
		t.Fatalf("no store: %+v, want options with a nil Store", o)
	}
	if o := oauthZitadelOptions(cfg, &principals.Store{}, nil); o != nil {
		t.Fatalf("no OAuth server: %+v, want nil", o)
	}
}

// Under zitadel the OAuth server may have no GitHub app; linking needs one,
// so its browser flow stays off instead of redirecting to GitHub with an
// empty client id.
func TestIdentityLinkNeedsTheGitHubAppUnderZitadel(t *testing.T) {
	cfg := config{SelfURL: "https://api.example", OIDCProvidersRaw: testZitadelProviders, ZitadelLinkProvider: "zitadel",
		ZitadelLinkClientID: "id", ZitadelLinkClientSecret: "secret"}
	oauth := auth.NewOAuthServer("https://api.example", "", "", []byte("k"), nil, nil)
	if o := identityLinkOptions(cfg, &principals.Store{}, nil, oauth, auth.NewGitHubValidator(nil)); o == nil || o.ProveGitHub != nil || o.GitHubClientID != "" {
		t.Fatalf("link options without a GitHub app = %+v, want the browser flow off", o)
	}
}
