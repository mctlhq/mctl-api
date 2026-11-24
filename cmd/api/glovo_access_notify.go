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
	SetAccessEmail(bool)
}

// The two switches. The card is the base; the emails are added to it.
const (
	glovoAccessNotifyEnv = "GLOVO_ACCESS_NOTIFY_ENABLED"
	glovoAccessEmailEnv  = "GLOVO_ACCESS_EMAIL_ENABLED"
)

// glovoAccessSwitch reads one true/false switch. Unset, empty and false are
// off; anything but true or false is an error and off.
func glovoAccessSwitch(lookup func(string) (string, bool), name string) (bool, error) {
	v, _ := lookup(name)
	switch strings.TrimSpace(v) {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	}
	return false, fmt.Errorf("%s %q must be true or false", name, v)
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
// requester's approved, rejected and lapsed emails. Each has a switch, both
// off by default.
//
// GLOVO_ACCESS_NOTIFY_ENABLED switches the card. Unset or false: nil, and
// nothing is written or sent, exactly as before. True needs the consent
// routes with the access store, the decision page, the principal store and
// the customer-lifecycle machine's Worker bridge; anything missing is an
// error for the boot log and leaves everything off. Only on success is the
// store's outbox switched on, so a half-configured server never queues what
// it cannot send.
//
// GLOVO_ACCESS_EMAIL_ENABLED adds the emails. They read the requester's
// address from the IdP at send time, which the card never does, so they stay
// off until asked for: with this switch off no email is queued, the notifier
// has no recipient lookup and the IdP is never asked. True needs the card
// switch, the customers organization and the identity hook's username
// domain. A bad or incomplete email switch is an error and leaves the emails
// off; the card, if it is on and complete, is still returned.
func configureGlovoAccessNotify(lookup func(string) (string, bool), deps glovoAccessNotifyDeps) (*api.GlovoAccessNotifier, error) {
	card, err := glovoAccessSwitch(lookup, glovoAccessNotifyEnv)
	if err != nil {
		return nil, fmt.Errorf("%w; glovo access notifications stay off", err)
	}
	email, emailErr := glovoAccessSwitch(lookup, glovoAccessEmailEnv)
	if emailErr != nil {
		emailErr = fmt.Errorf("%w; glovo access emails stay off", emailErr)
	}
	if !card {
		if email {
			emailErr = fmt.Errorf("%s=true needs %s=true; glovo access emails stay off", glovoAccessEmailEnv, glovoAccessNotifyEnv)
		}
		return nil, emailErr
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
	if !deps.Providers.GlovoAccessBridgeConfigured() {
		missing = append(missing, "the customer-lifecycle machine (ZITADEL_CUSTOMER_LIFECYCLE_CLIENT_ID, _CLIENT_SECRET, _PROJECT_ID)")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%s=true is missing: %s; glovo access notifications stay off", glovoAccessNotifyEnv, strings.Join(missing, "; "))
	}
	n := &api.GlovoAccessNotifier{
		Store:       outbox,
		Identity:    deps.Identity,
		Bridge:      deps.Providers.GlovoAccessSite,
		PageBaseURL: deps.PageBaseURL,
	}
	if !n.Ready() {
		return nil, fmt.Errorf("%s=true but the decision page origin is not a bare https origin; glovo access notifications stay off", glovoAccessNotifyEnv)
	}
	if email {
		missing = nil
		if !deps.Providers.GlovoAccessConfigured() {
			missing = append(missing, "the customers organization with its GitHub and Google IdP ids")
		}
		if strings.TrimSpace(deps.UsernameDomain) == "" {
			missing = append(missing, "ZITADEL_HOOK_USERNAME_DOMAIN")
		}
		if len(missing) > 0 {
			email = false
			emailErr = fmt.Errorf("%s=true is missing: %s; glovo access emails stay off", glovoAccessEmailEnv, strings.Join(missing, "; "))
		}
	}
	if email {
		n.Recipient = glovoAccessRecipient(deps.Identities, deps.Providers.CustomerEmail, deps.UsernameDomain)
	}
	outbox.SetAccessNotify(true)
	outbox.SetAccessEmail(email)
	return n, emailErr
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
