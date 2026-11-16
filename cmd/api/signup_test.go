package main

import (
	"context"
	"testing"
)

func TestSignupDisabledLegacyDeploymentHasNoAdmissionGate(t *testing.T) {
	if signupOptions(config{}, nil) != nil {
		t.Fatal("signup-disabled legacy deployment acquired an admission gate")
	}
}
func TestConfiguredSignupCannotFailOpenWithoutDatabase(t *testing.T) {
	cfg := config{PrincipalDBConfigured: true, ZitadelHook: zitadelHookConfig{CustomersOrgID: "customers", CustomerCreateGitHubIDs: []string{"123"}}}
	options := signupOptions(cfg, nil)
	if options == nil || options.Store != nil || !options.Cohort["123"] {
		t.Fatal("configured signup must retain its fail-closed gate")
	}
}
func TestPublicSignupUsesBudgetedModeInsteadOfExemptingEveryone(t *testing.T) {
	cfg := config{PrincipalDBConfigured: true, ZitadelHook: zitadelHookConfig{CustomersOrgID: "customers", CustomerCreateGitHubIDs: []string{"*"}}}
	options := signupOptions(cfg, nil)
	if options == nil || !options.PublicFlow || len(options.Cohort) != 0 {
		t.Fatal("public signup must use bounded public claims")
	}
}

func TestSignupAbsentByConfigurationKeepsStaticInvitationPolicy(t *testing.T) {
	for _, cfg := range []config{
		{ZitadelHook: zitadelHookConfig{CustomersOrgID: "customers"}},
		{PrincipalDBConfigured: true, PrincipalsDisabled: true, ZitadelHook: zitadelHookConfig{CustomersOrgID: "customers"}},
	} {
		if signupOptions(cfg, nil) != nil || signupInvitationAllowed(cfg, nil) != nil {
			t.Fatal("explicitly absent approval store must keep static policy")
		}
	}
}
func TestSignupFailedConfiguredStoreRemainsUnknown(t *testing.T) {
	cfg := config{PrincipalDBConfigured: true, ZitadelHook: zitadelHookConfig{CustomersOrgID: "customers"}}
	callback := signupInvitationAllowed(cfg, nil)
	if callback == nil {
		t.Fatal("configured store failure was treated as absence")
	}
	if allowed, err := callback(context.Background(), "123"); err == nil || allowed {
		t.Fatalf("unknown treated as %v %v", allowed, err)
	}
}

// mctl-api#1079: Google customers are admitted by the public flow only when
// Google customers are accepted at all and their creation is open to anyone.
func TestGooglePublicSignupNeedsTheGateAndAnOpenAllowlist(t *testing.T) {
	const org, gh, goog = "395272528420931285", "395272528420931999", "395272528420932777"
	cfg := zitadelUpstreamConfig("zitadel")
	cfg.OIDCProvidersRaw = testCustomersProviders
	cfg.PrincipalDBConfigured = true
	cfg.ZitadelHook.CustomersOrgID, cfg.ZitadelHook.GitHubIdPID, cfg.ZitadelHook.GoogleIdPID = org, gh, goog
	cfg.ZitadelHook.CustomerCreateGoogleSubs = []string{"*"}
	if o := signupOptions(cfg, nil); o == nil || !o.GooglePublicFlow || o.PublicFlow {
		t.Fatalf("options = %+v, want the Google public flow alone", o)
	}
	for name, mutate := range map[string]func(*config){
		"no Google IdP":       func(c *config) { c.ZitadelHook.GoogleIdPID = "" },
		"Google allowlist":    func(c *config) { c.ZitadelHook.CustomerCreateGoogleSubs = []string{"109876543210987654321"} },
		"no Google allowlist": func(c *config) { c.ZitadelHook.CustomerCreateGoogleSubs = nil },
		"GitHub open instead": func(c *config) {
			c.ZitadelHook.CustomerCreateGoogleSubs, c.ZitadelHook.CustomerCreateGitHubIDs = nil, []string{"*"}
		},
	} {
		c := cfg
		mutate(&c)
		if o := signupOptions(c, nil); o == nil || o.GooglePublicFlow {
			t.Errorf("%s: options = %+v, want no Google public flow", name, o)
		}
	}
}
