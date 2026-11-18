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

// check_config.go: `mctl-api --check-config`, the startup validation of the
// configuration that the zitadel-iac Job writes into Secrets, runnable
// without a database, a cluster or any network access.
//
// Why it exists (2026-11-17): mctlhq/mctl-gitops#2737 added service_subjects
// to the MCTL_OIDC_PROVIDERS entry that also carries customers_org_id. The
// rule that refuses that combination lives here (ParseOIDCProviders), so no
// reviewer or CI step in the gitops repository saw it, and the rollout pod
// crash-looped. A gitops CI step now runs the image it deploys with this flag
// against the rendered Secret values; it must call this code and not a
// re-implementation, which would drift from it.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/auth"
)

// checkConfigFlag is the sole argument that selects the check. It is matched
// before anything else in main, so it never reaches telemetry, the signal
// handler or a store.
const checkConfigFlag = "--check-config"

// checkConfigOK is the exact line printed on success. A caller that runs an
// image which may predate this flag must require it: such an image ignores
// the argument and boots the server instead.
const checkConfigOK = "mctl-api check-config: ok"

// validateZitadelSecretConfig is every startup validation that reads a key
// the zitadel-iac Job writes (platform-gitops/helm-charts/zitadel-iac/iac
// mctl-api.tf and customers.tf), plus the values that cross-check them:
//
//   - ZITADEL_HOOK_CUSTOMER_CREATE_*, ZITADEL_HOOK_GOOGLE_IDP_ID and
//     ZITADEL_HOOK_GITHUB_IDP_ID (zitadelHookConfig.validate);
//   - OAUTH_UPSTREAM and what a zitadel or both upstream needs: OAUTH_JWT_SECRET,
//     OAUTH_ZITADEL_CLIENT_ID/SECRET, an MCTL_OIDC_PROVIDERS entry named
//     OAUTH_ZITADEL_PROVIDER keyed on sub, and OAUTH_ZITADEL_PROVIDER equal to
//     ZITADEL_LINK_PROVIDER (validateOAuthUpstream);
//   - MCTL_OIDC_PROVIDERS itself (auth.ParseOIDCProviders: shape, service_subjects
//     rules, reserved and duplicate names and issuers), at most
//     one entry with customers_org_id, and that entry's customers_org_id equal to
//     ZITADEL_HOOK_CUSTOMERS_ORG_ID (customersProvider);
//   - ZITADEL_HOOK_GITHUB_IDP_ID being a ZITADEL id where the customer sign-in
//     entry would be wired, and MCTL_GITHUB_ACTIONS_OIDC.
//
// skipFederation is MCTL_FEDERATION_DISABLED: the kill switch leaves the
// federation checks out of boot so that it can roll back a bad value. The
// gitops guard passes false regardless, since a value that only boots because
// the kill switch is on is not one to merge.
//
// validate() calls this, so a rule added here is a rule at boot and in the
// guard at once. NOT covered: auth.NewRegistry's composition invariants
// against the built-in providers, which need each entry's issuer discovered
// over the network (see BuildFederationRegistry), and every key from other
// Secrets (OAUTH_JWT_SIGNING_KEYS, database URLs).
func (c config) validateZitadelSecretConfig(skipFederation bool) error {
	if err := c.ZitadelHook.validate(); err != nil {
		return err
	}
	if err := c.validateOAuthUpstream(); err != nil {
		return err
	}
	if skipFederation {
		return nil
	}
	// MCTL_OIDC_PROVIDERS (mctl-api#374): shape-validated here, in the same
	// style as OAUTH_PREREGISTERED_CLIENTS, so a malformed value or an entry
	// missing audiences/naming a reserved provider refuses this boot rather
	// than the one after a second variable is also set. The full registry
	// (this plus the legacy Dex shim and the built-in providers) is built for
	// real in main(), which is where a duplicate against the local-OAuth or
	// Dex provider would also be caught. Skipped while
	// MCTL_FEDERATION_DISABLED is on, so the kill switch can roll back a
	// value that would otherwise refuse boot.
	entries, err := auth.ParseOIDCProviders(c.OIDCProvidersRaw)
	if err != nil {
		return err
	}
	// The Glovo consent reader must resolve to kind service on the provider
	// it names, or the consent gate admits nobody.
	if err := validateGlovoConsentReader(entries, os.LookupEnv); err != nil {
		return err
	}
	// customers_org_id on two entries, or one that disagrees with the
	// identity hook, would resolve a customer differently per path.
	customers, err := c.customersProvider()
	if err != nil {
		return err
	}
	// The customer sign-in entry puts the GitHub IdP id into a ZITADEL
	// scope (mctl-web#158); a malformed one refuses boot like a malformed
	// customers_org_id does. Only where that entry could be wired: elsewhere
	// the id feeds the identity hook alone, which takes it as it is, and
	// customersGitHubIdPID still refuses to offer a malformed one.
	if id := c.ZitadelHook.GitHubIdPID; id != "" && customers != nil &&
		c.oauthUpstreamMode() != mctlapi.OAuthUpstreamGitHub && !auth.ValidZitadelID(id) {
		return fmt.Errorf("ZITADEL_HOOK_GITHUB_IDP_ID %q is not a ZITADEL resource id", id)
	}
	if _, err := auth.ParseGitHubActionsOIDC(c.GitHubActionsOIDCRaw); err != nil {
		return err
	}
	return nil
}

// runCheckConfig reads the environment exactly as boot does, runs
// validateZitadelSecretConfig with the kill switch ignored, and reports. It
// returns the process exit code: 0 and checkConfigOK on stdout, or 1 and the
// refusal on stderr. It opens nothing and dials nothing.
func runCheckConfig(stdout, stderr io.Writer) int {
	cfg := loadConfig()
	if err := cfg.validateZitadelSecretConfig(false); err != nil {
		_, _ = fmt.Fprintf(stderr, "mctl-api check-config: invalid configuration: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, checkConfigOK)
	return 0
}

// validateGlovoConsentReader cross-checks GLOVO_CONSENT_SERVICE_PROVIDER and
// GLOVO_CONSENT_SERVICE_SUBJECT against MCTL_OIDC_PROVIDERS when
// GLOVO_CONSENT_ENABLED is true. The gate admits only a verified identity of
// kind service with exactly that provider and subject, so a reader that can
// never resolve to one is a misconfiguration to refuse now rather than a
// consent read that answers 401 forever:
//
//   - the provider must be an entry of MCTL_OIDC_PROVIDERS (the whole list is
//     read, so absent really is absent; the "dex" shim cannot be a service);
//   - on a kind service entry any subject resolves to service;
//   - on a human or agent entry the subject must be one of its
//     service_subjects (the only way such an entry yields kind service).
//
// Enabled with no provider or subject, or with a value that is neither true
// nor false, is refused too: configureGlovoConsent alone would log it and keep
// the routes off while the flag says on (a boot-time refusal where routes used
// to stay silently off; GLOVO_CONSENT_ENABLED is not set in any deployment
// today). Not enabled (unset or false) is left to configureGlovoConsent. The
// database URL is not checked: it comes from a Secret this check cannot see.
func validateGlovoConsentReader(entries []auth.OIDCProviderConfigEntry, lookup func(string) (string, bool)) error {
	v, _ := lookup("GLOVO_CONSENT_ENABLED")
	switch strings.TrimSpace(v) {
	case "", "false":
		return nil
	case "true":
	default:
		// configureGlovoConsent logs this and leaves the routes off; an
		// operator who typed it meant "on", so unknown is not ok.
		return fmt.Errorf("GLOVO_CONSENT_ENABLED %q must be true or false", v)
	}
	provider, _ := lookup("GLOVO_CONSENT_SERVICE_PROVIDER")
	subject, _ := lookup("GLOVO_CONSENT_SERVICE_SUBJECT")
	provider, subject = strings.TrimSpace(provider), strings.TrimSpace(subject)
	if provider == "" || subject == "" {
		// Enabled but no reader named: configureGlovoConsent would only log
		// and keep the routes off while the flag says on. Refuse instead.
		return errors.New("GLOVO_CONSENT_ENABLED=true requires GLOVO_CONSENT_SERVICE_PROVIDER and GLOVO_CONSENT_SERVICE_SUBJECT: the consent routes would silently stay off")
	}
	for i := range entries {
		e := &entries[i]
		if e.Name != provider {
			continue
		}
		if e.Kind == auth.KindService {
			return nil
		}
		if _, ok := e.ServiceSubjects[subject]; ok {
			return nil
		}
		return fmt.Errorf("GLOVO_CONSENT_SERVICE_SUBJECT %q is not a service identity of MCTL_OIDC_PROVIDERS entry %q (kind %q): list it in that entry's service_subjects, or the consent gate admits nobody", subject, provider, entryKind(e))
	}
	return fmt.Errorf("GLOVO_CONSENT_SERVICE_PROVIDER %q is not an MCTL_OIDC_PROVIDERS entry: the consent gate admits nobody", provider)
}

func entryKind(e *auth.OIDCProviderConfigEntry) string {
	if e.Kind == "" {
		return auth.KindHuman
	}
	return e.Kind
}
