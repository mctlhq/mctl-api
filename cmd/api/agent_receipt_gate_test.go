package main

import (
	"strings"
	"testing"
	"time"

	mctlmcp "github.com/mctlhq/mctl-api/internal/mcp"
)

// MCTL_AGENT_RECEIPT_GATE refuses the boot on an unknown value instead of
// falling back to a mode the operator did not ask for.
func TestConfigValidate_AgentReceiptGate(t *testing.T) {
	for _, raw := range []string{"on", "Enforce", "enforced"} {
		cfg := config{AgentReceiptGateRaw: raw, CommerceDisabled: true}
		if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "MCTL_AGENT_RECEIPT_GATE") {
			t.Errorf("MCTL_AGENT_RECEIPT_GATE=%q: validate() = %v, want a refusal naming it", raw, err)
		}
	}
	for raw, want := range map[string]mctlmcp.AgentReceiptGateMode{
		"": mctlmcp.AgentReceiptGateOff, "off": mctlmcp.AgentReceiptGateOff,
		"observe": mctlmcp.AgentReceiptGateObserve, "enforce": mctlmcp.AgentReceiptGateEnforce,
	} {
		cfg := config{AgentReceiptGateRaw: raw, CommerceDisabled: true, WorkItemsConfigured: true}
		if err := cfg.validate(); err != nil {
			t.Errorf("MCTL_AGENT_RECEIPT_GATE=%q: validate() = %v", raw, err)
		}
		if got := cfg.agentReceiptGateMode(); got != want {
			t.Errorf("MCTL_AGENT_RECEIPT_GATE=%q: mode %q, want %q", raw, got, want)
		}
	}
}

// enforce without the approval store would refuse every governed agent call
// as unverifiable; it is a boot error instead. observe is allowed, since it
// refuses nothing.
func TestConfigValidate_AgentReceiptGateEnforceNeedsStore(t *testing.T) {
	cfg := config{AgentReceiptGateRaw: "enforce", CommerceDisabled: true}
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "work-items store") {
		t.Fatalf("enforce without a store: validate() = %v, want a refusal", err)
	}
	cfg.AgentReceiptGateRaw = "observe"
	if err := cfg.validate(); err != nil {
		t.Fatalf("observe without a store: validate() = %v", err)
	}
}

func TestLoadConfig_WorkItemsConfigured(t *testing.T) {
	for _, c := range []struct {
		disabled, workDB, auditDB string
		want                      bool
	}{
		{"", "", "", false},
		{"", "postgres://h/db", "", true},
		{"", "", "postgres://h/db", true},
		{"true", "postgres://h/db", "postgres://h/db", false},
		{"false", "", "postgres://h/db", true},
	} {
		t.Setenv("WORK_ITEMS_DISABLED", c.disabled)
		t.Setenv("WORK_ITEMS_DB_URL", c.workDB)
		t.Setenv("AUDIT_DB_URL", c.auditDB)
		if got := loadConfig().WorkItemsConfigured; got != c.want {
			t.Errorf("%+v: WorkItemsConfigured = %v", c, got)
		}
	}
}

// main opens the store from the same reading: WORK_ITEMS_DB_URL first, then
// AUDIT_DB_URL.
func TestWorkItemsStoreSource(t *testing.T) {
	t.Setenv("WORK_ITEMS_DISABLED", "")
	t.Setenv("WORK_ITEMS_DB_URL", "postgres://work/db")
	t.Setenv("AUDIT_DB_URL", "postgres://audit/db")
	if u, off := workItemsStoreSource(); u != postgresURL("postgres://work/db") || off {
		t.Fatalf("both set: %q %v", u, off)
	}
	t.Setenv("WORK_ITEMS_DB_URL", "")
	if u, _ := workItemsStoreSource(); u != postgresURL("postgres://audit/db") {
		t.Fatalf("audit fallback: %q", u)
	}
	t.Setenv("WORK_ITEMS_DISABLED", "true")
	if _, off := workItemsStoreSource(); !off {
		t.Fatal("kill switch not read")
	}
}

// MCTL_AGENT_RECEIPT_MAX_AGE (mctl-api#773) refuses the boot on a value that
// does not parse, is not positive or exceeds the cap, and defaults to 5m.
func TestConfigValidate_AgentReceiptMaxAge(t *testing.T) {
	for _, raw := range []string{"5", "five minutes", "0s", "-1m", "2h"} {
		cfg := config{AgentReceiptMaxAgeRaw: raw, CommerceDisabled: true}
		if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "MCTL_AGENT_RECEIPT_MAX_AGE") {
			t.Errorf("MCTL_AGENT_RECEIPT_MAX_AGE=%q: validate() = %v, want a refusal naming it", raw, err)
		}
	}
	for raw, want := range map[string]time.Duration{
		"": mctlmcp.DefaultAgentReceiptMaxAge, "90s": 90 * time.Second, "2m": 2 * time.Minute, "1h": time.Hour,
	} {
		cfg := config{AgentReceiptMaxAgeRaw: raw, CommerceDisabled: true}
		if err := cfg.validate(); err != nil {
			t.Errorf("MCTL_AGENT_RECEIPT_MAX_AGE=%q: validate() = %v", raw, err)
		}
		if got := cfg.agentReceiptMaxAge(); got != want {
			t.Errorf("MCTL_AGENT_RECEIPT_MAX_AGE=%q: %s, want %s", raw, got, want)
		}
	}	// Surrounding whitespace is trimmed.
	if got := (config{AgentReceiptMaxAgeRaw: "\t2m\n"}).agentReceiptMaxAge(); got != 2*time.Minute {
		t.Errorf("surrounding whitespace: %s", got)
	}
}
