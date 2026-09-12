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

// mutatingOnPortal names the tools that change platform state and are
// nevertheless exposed on the shared portal, by owner decision 2026-09-12
// (mctlhq/.github#35). Until then the rule here was "read-only only", which
// made the decision unmakeable rather than unmade; it is now makeable and
// written down, one line per tool, in reviewed Go.
//
// What this list is NOT: permission. The portal switch is per-server and
// user-blind, so it decides visibility only -- the mctl API's own
// authentication, team scope and role checks are what decide whether the
// call succeeds. A name here means "a client on the portal may see and
// attempt this", never "a client on the portal may do this".
//
// Adding a name is the decision being asked for. The value says what the
// tool changes, in the words of someone who would have to undo it.
var mutatingOnPortal = map[string]string{
	"mctl_acknowledge_incident":            "incident state other operators read",
	"mctl_add_custom_domain":               "tenant routing intent, plus a DNS ownership challenge",
	"mctl_apply_openclaw_resource_profile": "a tenant agent's CPU/memory profile in gitops",
	"mctl_approve_dev_loop":                "releases a running DevLoop to act on a repository",
	"mctl_create_agent":                    "adds an agent record that can later run",
	"mctl_create_preview":                  "provisions a preview environment and consumes quota",
	"mctl_create_tenant":                   "namespace, quota and gitops scaffolding",
	"mctl_delete_openclaw_identity":        "removes a tenant identity override from gitops",
	"mctl_delete_openclaw_skill":           "removes a capability from a running tenant agent",
	"mctl_delete_preview":                  "destroys a preview environment",
	"mctl_delete_tenant":                   "namespace, database and gitops entries -- the most destructive call here",
	"mctl_deploy_openclaw":                 "what runs for a tenant",
	"mctl_deploy_service":                  "what runs in production for a team and service",
	"mctl_deprecate_platform_skill":        "what tenants are offered going forward",
	"mctl_disable_tenant_skill":            "removes a capability from a tenant agent",
	"mctl_enable_tenant_skill":             "grants a capability to a tenant agent",
	"mctl_grant_repo_access":               "repository authorization for a tenant",
	"mctl_promote_agent":                   "which agent version tenants resolve to",
	"mctl_provision_database":              "creates persistent state and wires credentials",
	"mctl_publish_agent_version":           "makes an agent version runnable",
	"mctl_publish_platform_skill":          "offers a skill to every tenant",
	"mctl_remove_custom_domain":            "withdraws routing for a hostname",
	"mctl_resolve_incident":                "closes an incident other operators and alerts read",
	"mctl_resume_openclaw_deploy":          "lets a held rollout proceed",
	"mctl_retire_service":                  "removes a service's workloads and gitops entry",
	"mctl_rollback_agent":                  "what tenants run",
	"mctl_rollback_service":                "production image tag",
	"mctl_save_openclaw_identity":          "writes a tenant identity override the live agent picks up",
	"mctl_save_openclaw_skill":             "adds a capability to a running tenant agent",
	"mctl_scale_service":                   "replica count, and therefore cluster capacity",
	"mctl_sync_repos":                      "what the platform believes it owns",
	"mctl_trigger_agents_run":              "starts model spend and repository writes",
	"mctl_trigger_approve":                 "flips a proposal to accepted, which is what unblocks the implementer",
	"mctl_trigger_implementer":             "writes code and opens a pull request",
	"mctl_trigger_incident_responder":      "acts on live platform state",
	"mctl_trigger_issue":                   "starts the DevLoop: investigation, proposal, then code",
	"mctl_trigger_mentor_only":             "comments on work in the repository",
	"mctl_trigger_reconcile":               "may move workflow and proposal state",
	"mctl_trigger_shepherd":                "pushes fixes and can merge pull requests",
	"mctl_trigger_single_service":          "same spend and writes, scoped to one service",
	"mctl_verify_domain":                   "on success triggers the ingress and certificate workflow",
}

// TestPortalAllowlist_CoversEveryRegisteredTool is the drift guard for the
// portal's fail-closed exposure (mctlhq/.github#44, finding 6). The portal
// hides only what it has an explicit entry for, so a tool added to this
// server without a decision here would surface on the aggregate the moment
// the portal re-syncs. Failing the build is the decision being asked for.
//
// Three invariants:
//   - the set of names in the file equals the set of tools the server
//     registers -- no missing tool, no stale entry;
//   - a tool may be enabled only if it says why its output is acceptable on
//     a shared surface, and a tool that is NOT recorded read-only may be
//     enabled only if mutatingOnPortal names it: a reviewed Go change, not a
//     JSON edit;
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
			if _, vouched := mutatingOnPortal[name]; !vouched {
				unsafe = append(unsafe, name)
			}
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
		t.Errorf("enabled on the portal, not recorded read-only, and not named in mutatingOnPortal (add it there with what it changes, or disable it): %v", unsafe)
	}

	// A vouch is a claim about a tool, so it must still describe one, and it
	// must still be needed: a name that no longer registers, that the file
	// disables, or that turns out to be read-only leaves a live exemption
	// behind something nobody is looking at any more.
	var staleVouch []string
	for name := range mutatingOnPortal {
		if _, ok := registered[name]; !ok {
			staleVouch = append(staleVouch, name+" (no longer registered)")
			continue
		}
		if !listed[name] {
			staleVouch = append(staleVouch, name+" (disabled in the file)")
			continue
		}
		if recordedHints[name].readOnly {
			staleVouch = append(staleVouch, name+" (recorded read-only; no vouch needed)")
		}
	}
	sort.Strings(staleVouch)
	if len(staleVouch) > 0 {
		t.Errorf("mutatingOnPortal entries that no longer describe an enabled mutating tool: %v", staleVouch)
	}
}
