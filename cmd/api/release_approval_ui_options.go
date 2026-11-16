package main

import (
	"log/slog"
	"os"
	"strings"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/auth/flowstore"
)

// releaseApprovalUIEnv turns on the release approval page (mctl-api#1022
// S2), the only place a release.grant request is decided. Dark by default.
type releaseApprovalUIEnv struct {
	Enabled      bool
	ClientID     string
	ClientSecret string
	// Deciders: RELEASE_APPROVAL_DECIDERS, comma-separated principal ids
	// (from Vault). Owner decision 2026-11-16: the owner only.
	Deciders []string
	// RequiredAMR: RELEASE_APPROVAL_REQUIRED_AMR, comma-separated; "mfa"
	// when unset.
	RequiredAMR []string
}

func releaseApprovalUIEnvFromOS() releaseApprovalUIEnv {
	amr := splitCSV(os.Getenv("RELEASE_APPROVAL_REQUIRED_AMR"))
	if len(amr) == 0 {
		amr = []string{"mfa"}
	}
	return releaseApprovalUIEnv{
		Enabled:      os.Getenv("RELEASE_APPROVAL_UI_ENABLED") == "true",
		ClientID:     os.Getenv("RELEASE_APPROVAL_UI_CLIENT_ID"),
		ClientSecret: os.Getenv("RELEASE_APPROVAL_UI_CLIENT_SECRET"),
		Deciders:     splitCSV(os.Getenv("RELEASE_APPROVAL_DECIDERS")),
		RequiredAMR:  amr,
	}
}

// releaseApprovalOptions configures the release approval page, or returns
// nil (routes unmounted) with one log line naming what is missing. Off,
// silently, unless RELEASE_APPROVAL_UI_ENABLED is exactly "true"; fails
// closed on anything else missing, a malformed decider id included.
func releaseApprovalOptions(cfg config, env releaseApprovalUIEnv, pr auth.PrincipalResolver, authz *auth.PrincipalAuthz, flow flowstore.Store, haveLedger, haveGrants bool) *mctlapi.ReleaseApprovalPageOptions {
	if !env.Enabled {
		return nil
	}
	opts := &mctlapi.ReleaseApprovalPageOptions{
		ClientID: env.ClientID, ClientSecret: env.ClientSecret, BaseURL: cfg.SelfURL,
		Principals: pr, Authz: authz, Flow: flow, Deciders: env.Deciders, RequiredAMR: env.RequiredAMR,
	}
	var missing []string
	if env.ClientID == "" || env.ClientSecret == "" {
		missing = append(missing, "RELEASE_APPROVAL_UI_CLIENT_ID and RELEASE_APPROVAL_UI_CLIENT_SECRET (both)")
	}
	if len(env.Deciders) == 0 {
		missing = append(missing, "RELEASE_APPROVAL_DECIDERS")
	}
	for _, d := range env.Deciders {
		if !auth.ValidPrincipalID(d) {
			missing = append(missing, "RELEASE_APPROVAL_DECIDERS holds a value that is not a principal id")
			break
		}
	}
	if cfg.SelfURL == "" {
		missing = append(missing, "SELF_URL")
	}
	if pr == nil {
		missing = append(missing, "the principal store")
	}
	if authz == nil {
		missing = append(missing, "TENANT_AUTHZ_MODE=principal")
	}
	if flow == nil {
		missing = append(missing, "the shared OAuth flow store (OAUTH_DB_URL)")
	}
	if !haveLedger {
		missing = append(missing, "the work-items store")
	}
	if !haveGrants {
		missing = append(missing, "the release grant routes (RELEASE_GRANTS_ENABLED)")
	}
	var why string
	opts.ProviderName, opts.Issuer, why = signInProvider(cfg)
	if why != "" {
		missing = append(missing, why)
	}
	if len(missing) > 0 {
		slog.Error("release approval page disabled", "missing", strings.Join(missing, "; "))
		return nil
	}
	slog.Info("release approval page enabled", "provider", opts.ProviderName, "issuer", opts.Issuer,
		"deciders", len(opts.Deciders), "required_amr", strings.Join(opts.RequiredAMR, ","))
	return opts
}
