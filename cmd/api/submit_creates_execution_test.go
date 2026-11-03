package main

import (
	"strings"
	"testing"
)

// MCTL_SUBMIT_CREATES_EXECUTION (mctlhq/mctl-agents#717 S3) is off unless it
// says on, and an unrecognised value refuses the boot.
func TestConfigValidate_SubmitCreatesExecution(t *testing.T) {
	for _, raw := range []string{"", "off", "on", " ON "} {
		cfg := config{SubmitCreatesExecutionRaw: raw, CommerceDisabled: true}
		if err := cfg.validate(); err != nil {
			t.Errorf("%q: validate() = %v", raw, err)
		}
	}
	for _, raw := range []string{"true", "1", "yes", "onn", "enabled"} {
		cfg := config{SubmitCreatesExecutionRaw: raw, CommerceDisabled: true}
		err := cfg.validate()
		if err == nil || !strings.Contains(err.Error(), "MCTL_SUBMIT_CREATES_EXECUTION") {
			t.Errorf("%q: validate() = %v, want a refusal naming the variable", raw, err)
		}
	}
}
