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
