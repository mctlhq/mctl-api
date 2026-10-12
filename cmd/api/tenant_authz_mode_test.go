package main

import "testing"

func TestValidateTenantAuthzMode(t *testing.T) {
	for _, ok := range []string{"", "legacy", "shadow", " shadow "} {
		if err := validateTenantAuthzMode(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"principal", "Legacy", "off", "true"} {
		if err := validateTenantAuthzMode(bad); err == nil {
			t.Errorf("%q must refuse boot", bad)
		}
	}
}
