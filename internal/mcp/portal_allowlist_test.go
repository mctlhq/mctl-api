package mcp

import (
	"encoding/json"
	"os"
	"sort"
	"testing"
)

// portalAllowlist mirrors docs/portal-allowlist.json. The file is what the
// Cloudflare portal mapping for server `api` is applied from; this test is
// what keeps the file honest (counterpart of mctlhq/mctl-telegram#609).
type portalAllowlist struct {
	Portal          string `json:"portal"`
	Server          string `json:"server"`
	DefaultDisabled bool   `json:"default_disabled"`
	Tools           []struct {
		Name string `json:"name"`
		// Enabled is a pointer so that a missing or misspelled key is a
		// test failure, not a silent false. "Explicit decision for every
		// tool" has to be enforced here or it is enforced nowhere.
		Enabled *bool `json:"enabled"`
		// Reason is required on an enabled tool: readOnlyHint says a tool
		// has no side effects, not that its output belongs on a shared
		// surface. mctl_get_service_logs is read-only and returns log text.
		Reason string `json:"reason,omitempty"`
	} `json:"tools"`
}

// minReasonLen is a floor on the privacy decision, not a quality bar: it
// rejects a placeholder, not a short sentence.
const minReasonLen = 40

// TestPortalAllowlist_CoversEveryRegisteredTool is the drift guard for the
// portal's fail-closed exposure (mctlhq/.github#44, finding 6). The portal
// hides only what it has an explicit entry for, so a tool added to this
// server without a decision here would surface on the aggregate the moment
// the portal re-syncs. Failing the build is the decision being asked for.
//
// Three invariants:
//   - the set of names in the file equals the set of tools the server
//     registers -- no missing tool, no stale entry;
//   - a tool may be enabled only if it is recorded read-only in
//     recordedHints (the same record the runtime set is held to) AND the
//     entry says why its output is acceptable on a shared surface;
//   - default_disabled is true, the half of the mapping that hides a tool
//     the file does not know about.
func TestPortalAllowlist_CoversEveryRegisteredTool(t *testing.T) {
	raw, err := os.ReadFile("../../docs/portal-allowlist.json")
	if err != nil {
		t.Fatalf("read allowlist: %v", err)
	}
	var list portalAllowlist
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatalf("parse allowlist: %v", err)
	}
	if list.Portal != "mcp" || list.Server != "api" {
		t.Fatalf("allowlist targets portal=%q server=%q, want mcp/api", list.Portal, list.Server)
	}
	if !list.DefaultDisabled {
		t.Fatal("default_disabled must be true: it is the half of the configuration that hides a tool the list does not know about")
	}

	registered := NewServer("http://localhost:8080", "").NewMCPServer().ListTools()
	if len(registered) != len(recordedHints) {
		t.Fatalf("server registers %d tools, recordedHints has %d; fix annotations_test.go first", len(registered), len(recordedHints))
	}

	listed := make(map[string]bool, len(list.Tools))
	for _, tool := range list.Tools {
		if _, dup := listed[tool.Name]; dup {
			t.Errorf("%s: listed twice", tool.Name)
		}
		if tool.Enabled == nil {
			t.Errorf("%s: no \"enabled\" key; every entry must carry an explicit decision", tool.Name)
			listed[tool.Name] = false
			continue
		}
		listed[tool.Name] = *tool.Enabled
		if *tool.Enabled && len(tool.Reason) < minReasonLen {
			t.Errorf("%s: enabled but reason is %d chars (minimum %d): say what the tool exposes and why that is acceptable on a shared surface", tool.Name, len(tool.Reason), minReasonLen)
		}
	}

	var missing, stale, unsafe []string
	for name := range registered {
		enabled, ok := listed[name]
		if !ok {
			missing = append(missing, name)
			continue
		}
		if enabled && !recordedHints[name].readOnly {
			unsafe = append(unsafe, name)
		}
	}
	for name := range listed {
		if _, ok := registered[name]; !ok {
			stale = append(stale, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	sort.Strings(unsafe)
	if len(missing) > 0 {
		t.Errorf("tools registered by the server but absent from docs/portal-allowlist.json (add each with an explicit enabled decision): %v", missing)
	}
	if len(stale) > 0 {
		t.Errorf("entries in docs/portal-allowlist.json for tools the server no longer registers: %v", stale)
	}
	if len(unsafe) > 0 {
		t.Errorf("enabled on the portal but not recorded read-only: %v", unsafe)
	}
}
