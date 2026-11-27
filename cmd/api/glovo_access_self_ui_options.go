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
	"log/slog"
	"os"
	"strings"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/auth/flowstore"
)

// glovoAccessSelfUIEnv is the page's own configuration: the switch and the
// ZITADEL web client used by this page only.
type glovoAccessSelfUIEnv struct {
	Enabled      bool
	ClientID     string
	ClientSecret string
}

func glovoAccessSelfUIEnvFromOS() glovoAccessSelfUIEnv {
	return glovoAccessSelfUIEnv{
		Enabled:      os.Getenv("GLOVO_ACCESS_SELF_UI_ENABLED") == "true",
		ClientID:     os.Getenv("GLOVO_ACCESS_SELF_UI_CLIENT_ID"),
		ClientSecret: os.Getenv("GLOVO_ACCESS_SELF_UI_CLIENT_SECRET"),
	}
}

// glovoAccessSelfOptions configures the Glovo access page for the person
// asking, or returns nil (routes unmounted, every path a 404) with one log
// line naming what is missing. Off, silently, unless
// GLOVO_ACCESS_SELF_UI_ENABLED is exactly "true"; fails closed on anything
// else missing.
//
// The provider is the one the OAuth upstream signs customers in through
// (OAUTH_ZITADEL_PROVIDER), with its customers organization and that
// organization's Google IdP: the page accepts nothing but a Google customer.
func glovoAccessSelfOptions(cfg config, env glovoAccessSelfUIEnv, pr auth.PrincipalResolver, flow flowstore.Store, haveAccessStore bool) *mctlapi.GlovoAccessSelfPageOptions {
	if !env.Enabled {
		return nil
	}
	opts := &mctlapi.GlovoAccessSelfPageOptions{
		ClientID: env.ClientID, ClientSecret: env.ClientSecret, BaseURL: cfg.SelfURL,
		Principals: pr, Flow: flow,
	}
	var missing []string
	if env.ClientID == "" || env.ClientSecret == "" {
		missing = append(missing, "GLOVO_ACCESS_SELF_UI_CLIENT_ID and GLOVO_ACCESS_SELF_UI_CLIENT_SECRET (both)")
	}
	if cfg.SelfURL == "" {
		missing = append(missing, "SELF_URL")
	}
	if pr == nil {
		missing = append(missing, "the principal store")
	}
	if cfg.tenantAuthzMode() != mctlapi.TenantAuthzPrincipal {
		missing = append(missing, "TENANT_AUTHZ_MODE=principal")
	}
	if flow == nil {
		missing = append(missing, "the shared OAuth flow store (OAUTH_DB_URL)")
	}
	if !haveAccessStore {
		missing = append(missing, "the Glovo consent routes with the access store (GLOVO_CONSENT_ENABLED)")
	}
	if cfg.FederationDisabled {
		missing = append(missing, "the federation registry (MCTL_FEDERATION_DISABLED is on)")
	}
	entry, err := cfg.oauthZitadelProvider()
	switch {
	case err != nil:
		missing = append(missing, err.Error())
	case entry.Issuer == "":
		missing = append(missing, "an issuer on the MCTL_OIDC_PROVIDERS entry named "+entry.Name)
	default:
		opts.ProviderName, opts.Issuer = entry.Name, entry.Issuer
		opts.CustomersOrgID = entry.CustomersOrgID
		opts.CustomersGoogleIdPID = cfg.customersGoogleIdPID(entry)
		if opts.CustomersOrgID == "" {
			missing = append(missing, "customers_org_id on the MCTL_OIDC_PROVIDERS entry named "+entry.Name)
		}
		if opts.CustomersGoogleIdPID == "" {
			missing = append(missing, "the customers organization's Google IdP (ZITADEL_HOOK_GOOGLE_IDP_ID)")
		}
	}
	if len(missing) > 0 {
		slog.Error("glovo access self page disabled", "missing", strings.Join(missing, "; "))
		return nil
	}
	slog.Info("glovo access self page enabled", "provider", opts.ProviderName, "issuer", opts.Issuer)
	return opts
}
