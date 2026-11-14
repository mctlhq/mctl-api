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

// deployApprovalUIEnv is what turns the deploy approval page on
// (mctl-api#1026), the only place a deploy.apply grant is decided. Like the
// Glovo basket page it is one self-contained, dark-by-default switch.
type deployApprovalUIEnv struct {
	Enabled      bool
	ClientID     string
	ClientSecret string
}

func deployApprovalUIEnvFromOS() deployApprovalUIEnv {
	return deployApprovalUIEnv{
		Enabled:      os.Getenv("DEPLOY_APPROVAL_UI_ENABLED") == "true",
		ClientID:     os.Getenv("DEPLOY_APPROVAL_UI_CLIENT_ID"),
		ClientSecret: os.Getenv("DEPLOY_APPROVAL_UI_CLIENT_SECRET"),
	}
}

// deployApprovalOptions configures the deploy approval page, or returns nil
// (routes unmounted) with one log line saying what is missing. It is off,
// silently, unless DEPLOY_APPROVAL_UI_ENABLED is exactly "true", and fails
// closed on anything else missing. haveLedger and havePlans say whether the
// work-items and deploy-plan stores started: the page reads both.
func deployApprovalOptions(cfg config, env deployApprovalUIEnv, pr auth.PrincipalResolver, authz *auth.PrincipalAuthz, flow flowstore.Store, haveLedger, havePlans bool) *mctlapi.DeployApprovalPageOptions {
	if !env.Enabled {
		return nil
	}
	opts := &mctlapi.DeployApprovalPageOptions{
		ClientID: env.ClientID, ClientSecret: env.ClientSecret,
		BaseURL: cfg.SelfURL, Principals: pr, Authz: authz, Flow: flow,
	}
	var missing []string
	if env.ClientID == "" || env.ClientSecret == "" {
		missing = append(missing, "DEPLOY_APPROVAL_UI_CLIENT_ID and DEPLOY_APPROVAL_UI_CLIENT_SECRET (both)")
	}
	if cfg.SelfURL == "" {
		missing = append(missing, "SELF_URL")
	}
	if pr == nil {
		missing = append(missing, "the principal store")
	}
	if authz == nil {
		// Ownership is read by principal; outside principal mode every
		// owner check is unavailable and nothing could be decided.
		missing = append(missing, "TENANT_AUTHZ_MODE=principal")
	}
	if flow == nil {
		missing = append(missing, "the shared OAuth flow store (OAUTH_DB_URL)")
	}
	if !haveLedger {
		missing = append(missing, "the work-items store")
	}
	if !havePlans {
		missing = append(missing, "the deploy-plan store")
	}
	var why string
	opts.ProviderName, opts.Issuer, why = signInProvider(cfg)
	if why != "" {
		missing = append(missing, why)
	}
	if len(missing) > 0 {
		slog.Error("deploy approval page disabled", "missing", strings.Join(missing, "; "))
		return nil
	}
	slog.Info("deploy approval page enabled", "provider", opts.ProviderName, "issuer", opts.Issuer)
	return opts
}
