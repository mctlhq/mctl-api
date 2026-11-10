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
// fails closed on anything else missing, the basket view included. main
// passes a nil view until the basket store (mctl-api#1006 slice 1) is wired,
// so the flag alone mounts nothing.
func glovoBasketApprovalOptions(cfg config, env glovoBasketUIEnv, pr auth.PrincipalResolver, authz *auth.PrincipalAuthz, view mctlapi.GlovoBasketApprovalView) *mctlapi.GlovoBasketApprovalPageOptions {
	if !env.Enabled {
		return nil
	}
	opts := &mctlapi.GlovoBasketApprovalPageOptions{
		ClientID: env.ClientID, ClientSecret: env.ClientSecret,
		BaseURL: cfg.SelfURL, Principals: pr, Authz: authz, View: view,
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
