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
	"fmt"
	"log/slog"
	"os"

	"github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/zitadelhook"
)

// zitadelHookConfig is the ZITADEL identity hook's environment
// (docs/zitadel-identity-hook.md). With ZITADEL_HOOK_CUSTOMERS_ORG_ID unset
// the hook is off and its routes answer 503.
type zitadelHookConfig struct {
	CustomersOrgID    string
	GitHubIdPID       string
	LoginClientUserID string
	UsernameDomain    string
	ClaimClientIDs    []string
	ReservedLogins    []string
	IntentKeys        []string
	CreateKeys        []string
	TokenKeys         []string
	// CustomerCreateGitHubIDs is ZITADEL_HOOK_CUSTOMER_CREATE_GITHUB_IDS:
	// the GitHub numeric ids that may create a new customers account, or
	// "*" for anyone. Unset creates nobody.
	CustomerCreateGitHubIDs []string
}

func loadZitadelHookConfig() zitadelHookConfig {
	return zitadelHookConfig{
		CustomersOrgID:    os.Getenv("ZITADEL_HOOK_CUSTOMERS_ORG_ID"),
		GitHubIdPID:       os.Getenv("ZITADEL_HOOK_GITHUB_IDP_ID"),
		LoginClientUserID: os.Getenv("ZITADEL_HOOK_LOGIN_CLIENT_USER_ID"),
		UsernameDomain:    envOr("ZITADEL_HOOK_USERNAME_DOMAIN", "mctl.ai"),
		ClaimClientIDs:    splitCSV(os.Getenv("ZITADEL_HOOK_CLAIM_CLIENT_IDS")),
		ReservedLogins:    splitCSV(os.Getenv("ZITADEL_HOOK_RESERVED_LOGINS")),
		IntentKeys:        splitCSV(os.Getenv("ZITADEL_HOOK_INTENT_SIGNING_KEYS")),
		CreateKeys:        splitCSV(os.Getenv("ZITADEL_HOOK_CREATE_SIGNING_KEYS")),
		TokenKeys:         splitCSV(os.Getenv("ZITADEL_HOOK_TOKEN_SIGNING_KEYS")),

		CustomerCreateGitHubIDs: splitCSV(os.Getenv("ZITADEL_HOOK_CUSTOMER_CREATE_GITHUB_IDS")),
	}
}

// validate refuses a malformed creation allowlist at boot. Left to New, it
// would only switch the hook off, which also stops existing customers from
// signing in; checked whether or not the hook is configured, so the value
// is right before the hook is switched on.
func (zc zitadelHookConfig) validate() error {
	if _, err := zitadelhook.ParseCustomerCreateAllowlist(zc.CustomerCreateGitHubIDs); err != nil {
		return fmt.Errorf("ZITADEL_HOOK_CUSTOMER_CREATE_GITHUB_IDS: %w", err)
	}
	return nil
}

// zitadelHookOptions builds the hook, or returns nil (routes answer 503)
// when it is not configured or the configuration is incomplete. ADMIN_USERS
// are always reserved logins.
func zitadelHookOptions(cfg config, tenants zitadelhook.TenantLister, pending ...func(context.Context, string) (bool, error)) *api.ZitadelHookOptions {
	zc := cfg.ZitadelHook
	if zc.CustomersOrgID == "" {
		return nil
	}
	var creationPending func(context.Context, string) (bool, error)
	if len(pending) > 0 {
		creationPending = pending[0]
	}
	hook, err := zitadelhook.New(zitadelhook.Config{
		CreationPending:   creationPending,
		CustomersOrgID:    zc.CustomersOrgID,
		GitHubIdPID:       zc.GitHubIdPID,
		LoginClientUserID: zc.LoginClientUserID,
		UsernameDomain:    zc.UsernameDomain,
		ClaimClientIDs:    zc.ClaimClientIDs,
		ReservedLogins:    append(append([]string{}, cfg.AdminUsers...), zc.ReservedLogins...),

		CustomerCreateGitHubIDs: zc.CustomerCreateGitHubIDs,
	}, tenants, nil)
	if err != nil {
		slog.Error("zitadel identity hook disabled: incomplete configuration", "error", err)
		return nil
	}
	return &api.ZitadelHookOptions{
		Hook:       hook,
		IntentKeys: zc.IntentKeys,
		CreateKeys: zc.CreateKeys,
		TokenKeys:  zc.TokenKeys,
	}
}
