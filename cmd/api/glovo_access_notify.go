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
	"os"
	"strings"

	"github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/customerdelete"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovoconsent"
	"github.com/mctlhq/mctl-api/internal/principals"
	"github.com/mctlhq/mctl-api/internal/zitadelhook"
)

// glovoAccessNotifyOutbox is what the store must offer for notifications:
// the outbox itself and its switch.
type glovoAccessNotifyOutbox interface {
	api.GlovoAccessNotifyStore
	SetAccessNotify(bool)
}

// glovoAccessNotifyDeps is everything configureGlovoAccessNotify reads
// besides the switch.
type glovoAccessNotifyDeps struct {
	Routes *api.GlovoConsentRoutes
	// Identities lists a principal's external identities; Identity builds
	// the masked label. Both are the principal store.
	Identities func(ctx context.Context, principalID string) ([]principals.ExternalIdentity, error)
	Identity   glovoconsent.IdentitySource
	// Providers is the customer-lifecycle machine: the Worker bridge and the
	// IdP email lookup.
	Providers *customerdelete.Providers
	// UsernameDomain is the identity hook's username domain.
	UsernameDomain string
	// PageBaseURL is the decision page's origin, "" when the page is off.
	PageBaseURL string
}

// configureGlovoAccessNotify builds the Glovo access notifier (mctl-glovo#82
// stage C): the owner's Telegram card with the decide link, and the
// requester's approved, rejected and lapsed emails.
//
// GLOVO_ACCESS_NOTIFY_ENABLED is the one switch. Unset or false: nil, and
// nothing is written or sent, exactly as before. True needs the consent
// routes with the access store, the decision page, the principal store and
// the customer-lifecycle machine; anything missing is an error for the boot
// log and leaves notifications off. Only on success is the store's outbox
// switched on, so a half-configured server never queues what it cannot send.
func configureGlovoAccessNotify(lookup func(string) (string, bool), deps glovoAccessNotifyDeps) (*api.GlovoAccessNotifier, error) {
	v, _ := lookup("GLOVO_ACCESS_NOTIFY_ENABLED")
	switch strings.TrimSpace(v) {
	case "", "false":
		return nil, nil
	case "true":
	default:
		return nil, fmt.Errorf("GLOVO_ACCESS_NOTIFY_ENABLED %q must be true or false; glovo access notifications stay off", v)
	}
	var missing []string
	var outbox glovoAccessNotifyOutbox
	if deps.Routes == nil || !deps.Routes.Enabled || glovo.IsNil(deps.Routes.Access) {
		missing = append(missing, "the glovo consent routes with the access store (GLOVO_CONSENT_ENABLED)")
	} else {
		ob, ok := deps.Routes.Access.(glovoAccessNotifyOutbox)
		if !ok || deps.Routes.AccessLinks == nil {
			missing = append(missing, "an access store with the notification outbox")
		}
		outbox = ob
	}
	if deps.PageBaseURL == "" {
		missing = append(missing, "the access decision page (RELEASE_APPROVAL_UI_ENABLED and its settings)")
	}
	if deps.Identities == nil || deps.Identity == nil {
		missing = append(missing, "the principal store")
	}
	if !deps.Providers.GlovoAccessConfigured() {
		missing = append(missing, "the customer-lifecycle machine (ZITADEL_CUSTOMER_LIFECYCLE_CLIENT_ID, _CLIENT_SECRET, _PROJECT_ID, the customers organization)")
	}
	if strings.TrimSpace(deps.UsernameDomain) == "" {
		missing = append(missing, "ZITADEL_HOOK_USERNAME_DOMAIN")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("GLOVO_ACCESS_NOTIFY_ENABLED=true is missing: %s; glovo access notifications stay off", strings.Join(missing, "; "))
	}
	n := &api.GlovoAccessNotifier{
		Store:       outbox,
		Identity:    deps.Identity,
		Recipient:   glovoAccessRecipient(deps.Identities, deps.Providers.CustomerEmail, deps.UsernameDomain),
		Bridge:      deps.Providers.GlovoAccessSite,
		PageBaseURL: deps.PageBaseURL,
	}
	if !n.Ready() {
		return nil, errors.New("GLOVO_ACCESS_NOTIFY_ENABLED=true but the decision page origin is not a bare https origin; glovo access notifications stay off")
	}
	outbox.SetAccessNotify(true)
	return n, nil
}

// glovoAccessRecipient resolves a principal's email for one delivery. The
// principal must be a customer: it holds exactly one live Google or GitHub
// customer identity, and the IdP holds a verified address for that customer.
// Any other principal (staff, an agent, one with both) has no recipient,
// which is api.ErrGlovoNoRecipient; a failed read is another error.
func glovoAccessRecipient(identities func(context.Context, string) ([]principals.ExternalIdentity, error),
	email func(ctx context.Context, provider, subject, username string) (string, error), domain string,
) func(context.Context, string) (string, error) {
	return func(ctx context.Context, principalID string) (string, error) {
		ids, err := identities(ctx, principalID)
		if err != nil {
			return "", fmt.Errorf("glovo access recipient: identities unreadable: %w", err)
		}
		var provider, subject, username string
		found := 0
		for i := range ids {
			x := &ids[i]
			if x.RevokedAt != nil || x.Issuer != "" {
				continue
			}
			switch {
			case x.Provider == auth.ProviderGoogle && auth.ValidGoogleSubject(x.Subject):
				provider, subject, username = x.Provider, x.Subject, zitadelhook.GoogleUsername(x.Subject, domain)
				found++
			case x.Provider == auth.ProviderGitHub && auth.ValidGitHubLogin(x.Display):
				provider, subject, username = x.Provider, x.Subject, zitadelhook.GitHubUsername(x.Display, domain)
				found++
			}
		}
		if found != 1 {
			return "", api.ErrGlovoNoRecipient
		}
		addr, err := email(ctx, provider, subject, username)
		if errors.Is(err, customerdelete.ErrNoCustomerEmail) {
			return "", api.ErrGlovoNoRecipient
		}
		if err != nil {
			return "", err
		}
		return addr, nil
	}
}

// glovoAccessNotifyDepsFor gathers the notifier's dependencies from the
// process configuration. A piece that is not there is left zero and named by
// configureGlovoAccessNotify.
func glovoAccessNotifyDepsFor(cfg config, routes *api.GlovoConsentRoutes, store *principals.Store, page *api.ReleaseApprovalPageOptions) glovoAccessNotifyDeps {
	deps := glovoAccessNotifyDeps{Routes: routes, UsernameDomain: cfg.ZitadelHook.UsernameDomain}
	if store != nil {
		deps.Identities, deps.Identity = store.Identities, store
	}
	if page != nil {
		deps.PageBaseURL = page.BaseURL
	}
	if provider, err := cfg.oauthZitadelProvider(); err == nil {
		deps.Providers = &customerdelete.Providers{
			Issuer: provider.Issuer, CustomerOrg: provider.CustomersOrgID,
			GitHubIDP: cfg.customersGitHubIdPID(provider), GoogleIDP: cfg.customersGoogleIdPID(provider),
			ClientID: os.Getenv("ZITADEL_CUSTOMER_LIFECYCLE_CLIENT_ID"), ClientSecret: os.Getenv("ZITADEL_CUSTOMER_LIFECYCLE_CLIENT_SECRET"),
			SiteBase: envOr("CUSTOMER_DELETION_SITE_URL", "https://mctl.ai"), SessionAudience: os.Getenv("ZITADEL_CUSTOMER_LIFECYCLE_PROJECT_ID"),
		}
	}
	return deps
}
