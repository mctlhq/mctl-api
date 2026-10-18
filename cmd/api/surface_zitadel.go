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
	"fmt"
	"log/slog"

	"github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/auth"
)

// customersProvider is the MCTL_OIDC_PROVIDERS entry with customers_org_id
// set, if any. Two such entries are refused: a customer must resolve the
// same way on every path.
func (c config) customersProvider() (*auth.OIDCProviderConfigEntry, error) {
	if c.OIDCProvidersRaw == "" {
		return nil, nil
	}
	entries, err := auth.ParseOIDCProviders(c.OIDCProvidersRaw)
	if err != nil {
		return nil, err
	}
	var found *auth.OIDCProviderConfigEntry
	for i := range entries {
		e := &entries[i]
		if e.CustomersOrgID == "" {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("MCTL_OIDC_PROVIDERS: entries %q and %q both set customers_org_id", found.Name, e.Name)
		}
		if e.SubjectClaim != "" && e.SubjectClaim != "sub" {
			return nil, fmt.Errorf("MCTL_OIDC_PROVIDERS: entry %q sets customers_org_id and must key identities on sub, not %q", e.Name, e.SubjectClaim)
		}
		found = e
	}
	if found != nil && c.ZitadelHook.CustomersOrgID != "" && c.ZitadelHook.CustomersOrgID != found.CustomersOrgID {
		return nil, fmt.Errorf("MCTL_OIDC_PROVIDERS entry %q has customers_org_id %q, but ZITADEL_HOOK_CUSTOMERS_ORG_ID is %q",
			found.Name, found.CustomersOrgID, c.ZitadelHook.CustomersOrgID)
	}
	return found, nil
}

// customersGitHubIdPID is the GitHub IdP the OAuth customer sign-in entry
// sends ZITADEL to (mctl-web#158), or "" so that no customer entry is
// offered. The id is the identity hook's ZITADEL_HOOK_GITHUB_IDP_ID: the
// same zitadel-iac Secret writes it next to ZITADEL_HOOK_CUSTOMERS_ORG_ID,
// so it is taken only when that org is entry's customers_org_id. An IdP
// paired with an organization that could not be confirmed is not offered.
func (c config) customersGitHubIdPID(entry auth.OIDCProviderConfigEntry) string {
	zc := c.ZitadelHook
	if entry.CustomersOrgID == "" || zc.GitHubIdPID == "" {
		return ""
	}
	if zc.CustomersOrgID != entry.CustomersOrgID || !auth.ValidZitadelID(zc.GitHubIdPID) {
		slog.Warn("OAuth customer GitHub sign-in not offered: ZITADEL_HOOK_GITHUB_IDP_ID does not belong to the customers organization of this provider",
			"provider", entry.Name)
		return ""
	}
	return zc.GitHubIdPID
}

// surfaceZitadelOptions wires POST /api/v1/surface-principals/zitadel, or
// returns nil (the route answers 503) without a customers organization.
// MCTL_WEB_CLIENT_ID is the client of purpose "create" and
// ZITADEL_PORTAL_CLIENT_ID that of "signin"; an empty one leaves its
// purpose answering 503.
func surfaceZitadelOptions(cfg config) *api.SurfaceZitadelOptions {
	entry, err := cfg.customersProvider()
	if err != nil {
		// Unreachable after validate; keep the route off rather than half on.
		slog.Error("surface-principals/zitadel disabled", "error", err)
		return nil
	}
	if entry == nil {
		return nil
	}
	return &api.SurfaceZitadelOptions{
		ProviderName: entry.Name, Issuer: entry.Issuer, CustomersOrgID: entry.CustomersOrgID,
		CreateClientID: cfg.MctlWebClientID, SigninClientID: cfg.ZitadelPortalClientID,
	}
}
