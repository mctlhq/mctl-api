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
