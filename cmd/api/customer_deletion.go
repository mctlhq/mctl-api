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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/customerdelete"
	"github.com/mctlhq/mctl-api/internal/principals"
)

func customerDeletionPending(store *principals.Store, required bool) func(context.Context, string) (bool, error) {
	// A deployment with principals deliberately disabled/unconfigured has no
	// lifecycle feature. An attempted but failed store read remains unknown.
	if store == nil && !required {
		return nil
	}
	return func(ctx context.Context, id string) (bool, error) {
		if store == nil {
			return false, errors.New("customer deletion store unavailable")
		}
		return store.CustomerDeletionPending(ctx, id)
	}
}

func customerTenantDeletionPending(store *principals.Store, required bool) func(context.Context, string) (bool, error) {
	if store == nil && !required {
		return nil
	}
	return func(ctx context.Context, tenant string) (bool, error) {
		if store == nil {
			return false, errors.New("customer deletion store unavailable")
		}
		return store.CustomerTenantDeletionPending(ctx, tenant)
	}
}

func customerDeletionOptions(cfg config, store *principals.Store, cache *principals.Resolver, oauth *auth.OAuthServer, quota api.QuotaReader, argo api.ArgoStatusClient) *api.CustomerDeletionOptions {
	if os.Getenv("CUSTOMER_DELETION_ENABLED") != "true" {
		return nil
	}
	provider, err := cfg.oauthZitadelProvider()
	if err != nil {
		slog.Error("complete customer deletion unavailable: ZITADEL provider configuration invalid")
		return nil
	}
	p := &customerdelete.Providers{
		Issuer: provider.Issuer, CustomerOrg: provider.CustomersOrgID, GitHubIDP: cfg.customersGitHubIdPID(provider),
		ClientID: os.Getenv("ZITADEL_CUSTOMER_LIFECYCLE_CLIENT_ID"), ClientSecret: os.Getenv("ZITADEL_CUSTOMER_LIFECYCLE_CLIENT_SECRET"),
		SiteBase: envOr("CUSTOMER_DELETION_SITE_URL", "https://mctl.ai"), SessionAudience: os.Getenv("ZITADEL_CUSTOMER_LIFECYCLE_PROJECT_ID"),
		PortalBase: cfg.BackstageInternalURL, PortalToken: os.Getenv("BACKSTAGE_TOKEN"),
	}
	namespaces, ok := quota.(interface {
		NamespaceAbsent(context.Context, string) (bool, error)
	})
	if !p.Configured() || store == nil || cache == nil || oauth == nil || argo == nil || !ok {
		slog.Error("complete customer deletion unavailable: configuration or required store missing")
		return nil
	}
	return &api.CustomerDeletionOptions{
		Store: store, Issuer: p.Issuer, VerifyCustomer: p.VerifyCustomer, DeleteCustomer: p.DeleteCustomer,
		FreezePortal: p.FreezePortal, ReleasePortal: p.ReleasePortal,
		RevokeSiteSessions: p.RevokeSiteSessions, CleanPortal: p.CleanPortal, RevokeSessions: oauth.RevokePrincipalSessions, ForgetPrincipals: cache.Forget,
		CheckPlatformGone: func(ctx context.Context, tenant string) error {
			for _, ns := range []string{tenant, tenant + "-preview"} {
				absent, err := namespaces.NamespaceAbsent(ctx, ns)
				if err != nil {
					return err
				}
				if !absent {
					return fmt.Errorf("tenant namespace remains")
				}
			}
			apps, err := argo.ListWorkloads()
			if err != nil {
				return err
			}
			for i := range apps {
				app := &apps[i]
				if customerDeletionAppRemains(tenant, app.Name, app.DestNamespace) {
					return fmt.Errorf("tenant Argo application remains")
				}
			}
			return nil
		},
	}
}

// Service ownership follows the destination namespace, never a name prefix.
// A sibling name can be created after the removed tenant leaves GitOps.
func customerDeletionAppRemains(tenant, name, namespace string) bool {
	return name == "tenant-"+tenant || namespace == tenant || namespace == tenant+"-preview"
}
