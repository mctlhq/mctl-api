package main

import "testing"

func TestSignupDisabledLegacyDeploymentHasNoAdmissionGate(t *testing.T) {
	if signupOptions(config{}, nil) != nil {
		t.Fatal("signup-disabled legacy deployment acquired an admission gate")
	}
}
func TestConfiguredSignupCannotFailOpenWithoutDatabase(t *testing.T) {
	cfg := config{ZitadelHook: zitadelHookConfig{CustomersOrgID: "customers", CustomerCreateGitHubIDs: []string{"123"}}}
	options := signupOptions(cfg, nil)
	if options == nil || options.Store != nil || !options.Cohort["123"] {
		t.Fatal("configured signup must retain its fail-closed gate")
	}
}
func TestPublicSignupUsesBudgetedModeInsteadOfExemptingEveryone(t *testing.T) {
	cfg := config{ZitadelHook: zitadelHookConfig{CustomersOrgID: "customers", CustomerCreateGitHubIDs: []string{"*"}}}
	options := signupOptions(cfg, nil)
	if options == nil || !options.PublicFlow || len(options.Cohort) != 0 {
		t.Fatal("public signup must use bounded public claims")
	}
}
