package main

import (
	"context"
	"errors"
	"os"

	"github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/customerdelete"
	"github.com/mctlhq/mctl-api/internal/principals"
)

func signupOptions(cfg config, store *principals.Store) *api.SignupOptions {
	// Legacy deployments without customer signup keep their existing operation
	// path. A configured signup deployment never fails open on a database error.
	if cfg.ZitadelHook.CustomersOrgID == "" {
		return nil
	}
	public := len(cfg.ZitadelHook.CustomerCreateGitHubIDs) == 1 && cfg.ZitadelHook.CustomerCreateGitHubIDs[0] == "*"
	cohort := map[string]bool{}
	for _, id := range cfg.ZitadelHook.CustomerCreateGitHubIDs {
		if id != "*" {
			cohort[id] = true
		}
	}
	p := &customerdelete.Providers{Issuer: cfg.ZitadelHookIssuer(), ClientID: os.Getenv("ZITADEL_CUSTOMER_LIFECYCLE_CLIENT_ID"), ClientSecret: os.Getenv("ZITADEL_CUSTOMER_LIFECYCLE_CLIENT_SECRET"), SiteBase: envOr("CUSTOMER_DELETION_SITE_URL", "https://mctl.ai"), SessionAudience: os.Getenv("ZITADEL_CUSTOMER_LIFECYCLE_PROJECT_ID")}
	return &api.SignupOptions{Store: store, SiteCall: p.SignupSite, Cohort: cohort, PublicFlow: public}
}
func (cfg config) ZitadelHookIssuer() string {
	p, err := cfg.oauthZitadelProvider()
	if err != nil {
		return ""
	}
	return p.Issuer
}
func signupInvitationAllowed(store *principals.Store) func(context.Context, string) (bool, error) {
	return func(ctx context.Context, id string) (bool, error) {
		if store == nil {
			return false, errors.New("signup store unavailable")
		}
		return store.SignupAllowed(ctx, id)
	}
}
