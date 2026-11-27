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

package main

import (
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/auth/flowstore"
	"github.com/mctlhq/mctl-api/internal/principals"
)

// The Glovo access page for the person asking is on only with the switch and
// every part it needs; one missing part leaves it unmounted.
func TestGlovoAccessSelfOptionsGating(t *testing.T) {
	const (
		org       = "300000000000000001"
		googleIdP = "300000000000000002"
		providers = `[{"name":"zitadel","issuer":"https://auth.example","audiences":["api"],"customers_org_id":"` + org + `"}]`
	)
	full := func() (config, glovoAccessSelfUIEnv) {
		return config{
				SelfURL: "https://api.example", OIDCProvidersRaw: providers, OAuthZitadelProvider: "zitadel",
				TenantAuthzModeRaw: "principal",
				ZitadelHook:        zitadelHookConfig{CustomersOrgID: org, GoogleIdPID: googleIdP},
			},
			glovoAccessSelfUIEnv{Enabled: true, ClientID: "id", ClientSecret: "secret"}
	}
	var pr auth.PrincipalResolver = principals.NewResolver(&principals.Store{}, nil, false)
	var flow flowstore.Store = &flowstore.PostgresStore{}

	c, env := full()
	o := glovoAccessSelfOptions(c, env, pr, flow, true)
	if o == nil || o.ProviderName != "zitadel" || o.Issuer != "https://auth.example" || o.ClientID != "id" ||
		o.ClientSecret != "secret" || o.BaseURL != "https://api.example" || o.Principals != pr || o.Flow != flow ||
		o.CustomersOrgID != org || o.CustomersGoogleIdPID != googleIdP {
		t.Fatalf("full config: %+v, want the page on", o)
	}
	type parts struct {
		c      *config
		env    *glovoAccessSelfUIEnv
		pr     *auth.PrincipalResolver
		flow   *flowstore.Store
		access *bool
	}
	off := map[string]func(p parts){
		"switch off":          func(p parts) { p.env.Enabled = false },
		"id without secret":   func(p parts) { p.env.ClientSecret = "" },
		"secret without id":   func(p parts) { p.env.ClientID = "" },
		"no self URL":         func(p parts) { p.c.SelfURL = "" },
		"no principal store":  func(p parts) { *p.pr = nil },
		"legacy authz mode":   func(p parts) { p.c.TenantAuthzModeRaw = "legacy" },
		"shadow authz mode":   func(p parts) { p.c.TenantAuthzModeRaw = "shadow" },
		"unknown authz mode":  func(p parts) { p.c.TenantAuthzModeRaw = "nonsense" },
		"no flow store":       func(p parts) { *p.flow = nil },
		"no access store":     func(p parts) { *p.access = false },
		"federation disabled": func(p parts) { p.c.FederationDisabled = true },
		"no provider entry":   func(p parts) { p.c.OAuthZitadelProvider = "other" },
		"malformed providers": func(p parts) { p.c.OIDCProvidersRaw = "{" },
		"no customers org": func(p parts) {
			p.c.OIDCProvidersRaw = `[{"name":"zitadel","issuer":"https://auth.example","audiences":["api"]}]`
		},
		"no google idp":        func(p parts) { p.c.ZitadelHook.GoogleIdPID = "" },
		"google idp other org": func(p parts) { p.c.ZitadelHook.CustomersOrgID = "300000000000000009" },
		"google idp malformed": func(p parts) { p.c.ZitadelHook.GoogleIdPID = "not-an-id" },
		"google idp == github": func(p parts) { p.c.ZitadelHook.GitHubIdPID = googleIdP },
	}
	for name, mutate := range off {
		c, env := full()
		p, f, access := pr, flow, true
		mutate(parts{&c, &env, &p, &f, &access})
		if o := glovoAccessSelfOptions(c, env, p, f, access); o != nil {
			t.Errorf("%s: %+v, want nil", name, o)
		}
	}
}

// The switch is on for the exact value "true" and nothing else.
func TestGlovoAccessSelfUIEnvSwitch(t *testing.T) {
	for v, want := range map[string]bool{"true": true, "": false, "TRUE": false, "1": false, "yes": false, "true" + " ": false} {
		t.Setenv("GLOVO_ACCESS_SELF_UI_ENABLED", v)
		t.Setenv("GLOVO_ACCESS_SELF_UI_CLIENT_ID", "id")
		t.Setenv("GLOVO_ACCESS_SELF_UI_CLIENT_SECRET", "secret")
		env := glovoAccessSelfUIEnvFromOS()
		if env.Enabled != want || env.ClientID != "id" || env.ClientSecret != "secret" {
			t.Errorf("GLOVO_ACCESS_SELF_UI_ENABLED=%q: %+v, want enabled=%v", v, env, want)
		}
	}
}
