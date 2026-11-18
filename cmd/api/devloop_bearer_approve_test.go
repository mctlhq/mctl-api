package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestDevLoopBearerApproveIsOffUnlessExplicitlyTrue(t *testing.T) {
	for raw, want := range map[string]bool{"": false, "false": false, " FALSE ": false, "true": true, "True": true} {
		cfg := config{DevLoopBearerApproveRaw: raw, CommerceDisabled: true}
		if err := cfg.validate(); err != nil {
			t.Errorf("%q: validate() = %v", raw, err)
		}
		if got := cfg.devLoopBearerApproveEnabled(); got != want {
			t.Errorf("%q: enabled = %v, want %v", raw, got, want)
		}
	}
	for _, raw := range []string{"yes", "1", "on", "enabled", "ture"} {
		cfg := config{DevLoopBearerApproveRaw: raw, CommerceDisabled: true}
		err := cfg.validate()
		if err == nil || !strings.Contains(err.Error(), "DEVLOOP_BEARER_APPROVE_ENABLED") {
			t.Errorf("%q: validate() = %v, want a refusal naming the variable", raw, err)
		}
		if cfg.devLoopBearerApproveEnabled() {
			t.Errorf("%q: an invalid value must not read as enabled", raw)
		}
	}
}

func TestLoadConfigReadsDevLoopBearerApprove(t *testing.T) {
	t.Setenv("DEVLOOP_BEARER_APPROVE_ENABLED", "true")
	if got := loadConfig().DevLoopBearerApproveRaw; got != "true" {
		t.Errorf("DevLoopBearerApproveRaw = %q, want true", got)
	}
}

// main() is not unit-testable, so pin in the source that the break-glass
// reaches the router.
func TestMainPassesDevLoopBearerApproveToTheRouter(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`DevLoopBearerApproveEnabled:\s+cfg\.devLoopBearerApproveEnabled\(\),`).Match(src) {
		t.Error("main.go does not pass cfg.devLoopBearerApproveEnabled() into mctlapi.Options")
	}
}
