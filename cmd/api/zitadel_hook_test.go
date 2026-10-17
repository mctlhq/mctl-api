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
