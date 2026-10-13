package main

import (
	"strings"
	"testing"
)

// MCTL_AGENTS_APPROVE_LEGACY_APPROVER (mctl-api#571) is on unless it says
// off, and an unrecognised value refuses the boot rather than picking a side.
func TestConfigValidate_LegacyApprover(t *testing.T) {
	for _, c := range []struct {
		raw          string
		wantDisabled bool
	}{
		{"", false}, {"true", false}, {"on", false}, {" 1 ", false},
		{"false", true}, {"OFF", true}, {"0", true}, {"no", true},
	} {
		raw, wantDisabled := c.raw, c.wantDisabled
		cfg := config{LegacyApproverRaw: raw, CommerceDisabled: true}
		if err := cfg.validate(); err != nil {
			t.Errorf("%q: validate() = %v", raw, err)
		}
		if got := cfg.legacyApproverDisabled(); got != wantDisabled {
			t.Errorf("%q: disabled = %v, want %v", raw, got, wantDisabled)
		}
	}
	for _, raw := range []string{"flase", "disabled", "2"} {
		cfg := config{LegacyApproverRaw: raw, CommerceDisabled: true}
		err := cfg.validate()
		if err == nil || !strings.Contains(err.Error(), "MCTL_AGENTS_APPROVE_LEGACY_APPROVER") {
			t.Errorf("%q: validate() = %v, want a refusal naming the variable", raw, err)
		}
		if cfg.legacyApproverDisabled() {
			t.Errorf("%q: an invalid value must not read as disabled", raw)
		}
	}
}
