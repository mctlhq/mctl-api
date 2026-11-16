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
	"context"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/gitops"
)

type hookTenants struct{}

func (hookTenants) ListTenantsStrict() ([]gitops.Tenant, error) { return nil, nil }

func TestZitadelHookOptionsInertUntilConfigured(t *testing.T) {
	if zitadelHookOptions(config{}, hookTenants{}) != nil {
		t.Fatal("unset ZITADEL_HOOK_CUSTOMERS_ORG_ID must leave the hook off")
	}
	partial := config{ZitadelHook: zitadelHookConfig{CustomersOrgID: "org", GitHubIdPID: "idp"}}
	if zitadelHookOptions(partial, hookTenants{}) != nil {
		t.Fatal("an incomplete configuration must leave the hook off")
	}
	full := config{AdminUsers: []string{"root"}, ZitadelHook: zitadelHookConfig{
		CustomersOrgID: "org", GitHubIdPID: "idp", LoginClientUserID: "login",
		ClaimClientIDs: []string{"web"}, UsernameDomain: "mctl.ai",
	}}
	opts := zitadelHookOptions(full, hookTenants{})
	if opts == nil || opts.Hook == nil {
		t.Fatal("a complete configuration must build the hook")
	}
	if len(opts.IntentKeys)+len(opts.CreateKeys)+len(opts.TokenKeys) != 0 {
		t.Fatal("no keys configured: every call must be refused by signature check")
	}
}

// A malformed creation allowlist refuses the boot: left to the hook it
// would switch the hook off, and existing customers with it. Unset is valid
// and creates nobody.
func TestZitadelHookCreateAllowlistValidatedAtBoot(t *testing.T) {
	for _, ok := range [][]string{nil, {"268260640", "47027422"}, {"*"}} {
		c := config{ZitadelHook: zitadelHookConfig{CustomerCreateGitHubIDs: ok}}
		if err := c.validate(); err != nil {
			t.Errorf("%q: validate() = %v", ok, err)
		}
	}
	for _, bad := range [][]string{{"octocat"}, {"1", "*"}} {
		c := config{ZitadelHook: zitadelHookConfig{CustomerCreateGitHubIDs: bad}}
		if err := c.validate(); err == nil || !strings.Contains(err.Error(), "ZITADEL_HOOK_CUSTOMER_CREATE_GITHUB_IDS") {
			t.Errorf("%q: validate() = %v, want a refusal naming ZITADEL_HOOK_CUSTOMER_CREATE_GITHUB_IDS", bad, err)
		}
	}
	t.Setenv("ZITADEL_HOOK_CUSTOMER_CREATE_GITHUB_IDS", " 268260640, 334465501 ,47027422")
	if got := loadZitadelHookConfig().CustomerCreateGitHubIDs; strings.Join(got, ",") != "268260640,334465501,47027422" {
		t.Fatalf("loaded allowlist %q", got)
	}
}

// The allowlist reaches the hook: a hook-shaped creation passes the gate
// only for a listed id.
func TestZitadelHookCreateAllowlistWired(t *testing.T) {
	create := []byte(`{"fullMethod":"/zitadel.user.v2.UserService/CreateUser","userID":"login","request":{` +
		`"organizationId":"org","username":"bob@mctl.ai","human":{"profile":{"givenName":"Bob"},` +
		`"email":{"email":"bob@example.com","isVerified":true},"idpLinks":[{"idpId":"idp","userId":"4242","userName":"bob"}]},` +
		`"metadata":[{"key":"github_id","value":"NDI0Mg=="},{"key":"github_login","value":"Ym9i"}]}}`)
	for ids, want := range map[string]string{"4242": "gate_customer_create", "": "gate_customer_create_not_allowed:4242"} {
		cfg := config{ZitadelHook: zitadelHookConfig{
			CustomersOrgID: "org", GitHubIdPID: "idp", LoginClientUserID: "login",
			ClaimClientIDs: []string{"web"}, UsernameDomain: "mctl.ai", CustomerCreateGitHubIDs: splitCSV(ids),
		}}
		opts := zitadelHookOptions(cfg, hookTenants{})
		if opts == nil {
			t.Fatalf("allowlist %q: hook not built", ids)
		}
		if r := opts.Hook.CreateGate(context.Background(), create); r.Reason != want {
			t.Errorf("allowlist %q: gate %s %s, want %s", ids, r.Reason, r.Body, want)
		}
	}
}

// The Google allowlist and IdP id refuse the boot when malformed, like the
// GitHub allowlist: left to the hook they would switch it off, and every
// existing GitHub customer with it.
func TestZitadelHookGoogleValidatedAtBoot(t *testing.T) {
	for name, zc := range map[string]zitadelHookConfig{
		"unset":       {},
		"subs":        {CustomerCreateGoogleSubs: []string{"109876543210987654321", "1"}},
		"anyone":      {CustomerCreateGoogleSubs: []string{"*"}},
		"google idp":  {GitHubIdPID: "300000000000000003", GoogleIdPID: "300000000000000006"},
		"only google": {GoogleIdPID: "300000000000000006"},
	} {
		if err := (config{ZitadelHook: zc}).validate(); err != nil {
			t.Errorf("%s: validate() = %v", name, err)
		}
	}
	for name, tc := range map[string]struct {
		zc   zitadelHookConfig
		want string
	}{
		"email in subs":     {zitadelHookConfig{CustomerCreateGoogleSubs: []string{"carol@gmail.com"}}, "ZITADEL_HOOK_CUSTOMER_CREATE_GOOGLE_SUBS"},
		"anyone mixed":      {zitadelHookConfig{CustomerCreateGoogleSubs: []string{"1", "*"}}, "ZITADEL_HOOK_CUSTOMER_CREATE_GOOGLE_SUBS"},
		"malformed idp":     {zitadelHookConfig{GoogleIdPID: "google"}, "ZITADEL_HOOK_GOOGLE_IDP_ID"},
		"idp equals github": {zitadelHookConfig{GitHubIdPID: "300000000000000003", GoogleIdPID: "300000000000000003"}, "ZITADEL_HOOK_GOOGLE_IDP_ID"},
	} {
		if err := (config{ZitadelHook: tc.zc}).validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: validate() = %v, want a refusal naming %s", name, err, tc.want)
		}
	}
	t.Setenv("ZITADEL_HOOK_GOOGLE_IDP_ID", "300000000000000006")
	t.Setenv("ZITADEL_HOOK_CUSTOMER_CREATE_GOOGLE_SUBS", " 1, 2 ")
	zc := loadZitadelHookConfig()
	if zc.GoogleIdPID != "300000000000000006" || strings.Join(zc.CustomerCreateGoogleSubs, ",") != "1,2" {
		t.Fatalf("loaded %q %q", zc.GoogleIdPID, zc.CustomerCreateGoogleSubs)
	}
}

// The Google settings reach the hook: a hook-shaped Google creation passes
// the gate only for a listed subject, and only with the IdP configured.
func TestZitadelHookGoogleWired(t *testing.T) {
	create := []byte(`{"fullMethod":"/zitadel.user.v2.UserService/CreateUser","userID":"login","request":{` +
		`"organizationId":"org","username":"google.4242@mctl.ai","human":{"profile":{"givenName":"Carol"},` +
		`"email":{"email":"carol@gmail.com","isVerified":true},"idpLinks":[{"idpId":"77","userId":"4242","userName":"carol@gmail.com"}]},` +
		`"metadata":[{"key":"google_sub","value":"NDI0Mg=="}]}}`)
	for name, tc := range map[string]struct {
		idp, subs, want string
	}{
		"listed":        {"77", "4242", "gate_customer_create"},
		"not listed":    {"77", "", "gate_customer_create_not_allowed:google:4242"},
		"idp not wired": {"", "4242", "gate_idp_links"},
	} {
		cfg := config{ZitadelHook: zitadelHookConfig{
			CustomersOrgID: "org", GitHubIdPID: "idp", GoogleIdPID: tc.idp, LoginClientUserID: "login",
			ClaimClientIDs: []string{"web"}, UsernameDomain: "mctl.ai", CustomerCreateGoogleSubs: splitCSV(tc.subs),
		}}
		opts := zitadelHookOptions(cfg, hookTenants{})
		if opts == nil {
			t.Fatalf("%s: hook not built", name)
		}
		if r := opts.Hook.CreateGate(context.Background(), create); r.Reason != tc.want {
			t.Errorf("%s: gate %s %s, want %s", name, r.Reason, r.Body, tc.want)
		}
	}
}
