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
	"log/slog"
	"os"
	"strings"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/auth/flowstore"
)

// glovoBasketUIEnv is what turns the Glovo basket approval page on
// (mctl-api#1006). It is read here rather than through config so the page
// stays one self-contained, dark-by-default switch.
type glovoBasketUIEnv struct {
	Enabled      bool
	ClientID     string
	ClientSecret string
}

func glovoBasketUIEnvFromOS() glovoBasketUIEnv {
	return glovoBasketUIEnv{
		Enabled:      os.Getenv("GLOVO_BASKET_UI_ENABLED") == "true",
		ClientID:     os.Getenv("GLOVO_BASKET_UI_CLIENT_ID"),
		ClientSecret: os.Getenv("GLOVO_BASKET_UI_CLIENT_SECRET"),
	}
}

// glovoBasketApprovalOptions configures the basket approval page, or returns
// nil (routes unmounted) with one log line saying what is missing. The page
// is off, silently, unless GLOVO_BASKET_UI_ENABLED is exactly "true"; it
// fails closed on anything else missing, the basket view included.
// configureGlovoBasket calls it with the basket store's view, and only when
// the basket MCP is on. flow is the OAuth server's shared flow
// store: without it the page would keep challenges in one replica's memory,
// so it stays off.
func glovoBasketApprovalOptions(cfg config, env glovoBasketUIEnv, pr auth.PrincipalResolver, authz *auth.PrincipalAuthz, view mctlapi.GlovoBasketApprovalView, flow flowstore.Store) *mctlapi.GlovoBasketApprovalPageOptions {
	if !env.Enabled {
		return nil
	}
	opts := &mctlapi.GlovoBasketApprovalPageOptions{
		ClientID: env.ClientID, ClientSecret: env.ClientSecret,
		BaseURL: cfg.SelfURL, Principals: pr, Authz: authz, View: view, Flow: flow,
	}
	var missing []string
	if env.ClientID == "" || env.ClientSecret == "" {
		missing = append(missing, "GLOVO_BASKET_UI_CLIENT_ID and GLOVO_BASKET_UI_CLIENT_SECRET (both)")
	}
	if cfg.SelfURL == "" {
		missing = append(missing, "SELF_URL")
	}
	if pr == nil {
		missing = append(missing, "the principal store")
	}
	if authz == nil {
		// Outside principal mode the owner's live membership is not read
		// by principal, and the decision handler refuses every owner.
		missing = append(missing, "TENANT_AUTHZ_MODE=principal")
	}
	if view == nil {
		missing = append(missing, "the Glovo basket store")
	}
	if flow == nil {
		missing = append(missing, "the shared OAuth flow store (OAUTH_DB_URL)")
	}
	if cfg.FederationDisabled {
		missing = append(missing, "the federation registry (MCTL_FEDERATION_DISABLED is on)")
	} else if entries, err := auth.ParseOIDCProviders(cfg.OIDCProvidersRaw); err == nil {
		for i := range entries {
			if entries[i].Name == cfg.ZitadelLinkProvider {
				opts.ProviderName, opts.Issuer = entries[i].Name, entries[i].Issuer
			}
		}
	}
	if opts.Issuer == "" && !cfg.FederationDisabled {
		missing = append(missing, "an MCTL_OIDC_PROVIDERS entry named "+cfg.ZitadelLinkProvider)
	}
	if len(missing) > 0 {
		slog.Error("glovo basket approval page disabled", "missing", strings.Join(missing, "; "))
		return nil
	}
	slog.Info("glovo basket approval page enabled", "provider", opts.ProviderName, "issuer", opts.Issuer)
	return opts
}

// oauthFlowStore is the OAuth server's shared flow store, or nil when there
// is no OAuth server or its store did not start.
func oauthFlowStore(s *auth.OAuthServer) flowstore.Store {
	if s == nil {
		return nil
	}
	return s.FlowStore
}
