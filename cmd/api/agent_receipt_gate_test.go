package main

import (
	"strings"
	"testing"

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
		cfg := config{AgentReceiptGateRaw: raw, CommerceDisabled: true}
		if err := cfg.validate(); err != nil {
			t.Errorf("MCTL_AGENT_RECEIPT_GATE=%q: validate() = %v", raw, err)
		}
		if got := cfg.agentReceiptGateMode(); got != want {
			t.Errorf("MCTL_AGENT_RECEIPT_GATE=%q: mode %q, want %q", raw, got, want)
		}
	}
}
