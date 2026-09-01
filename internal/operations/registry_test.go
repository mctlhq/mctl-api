// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package operations

import "testing"

// TestImplementAndShepherdServiceEnumCoversMctlAgentsServices guards against
// the enum silently drifting out of sync with mctl-agents' own
// config/settings.py SERVICES list. Caught live 2026-08-05: mctl-design was
// a fully valid implementer target (accepted by run_issue_investigator.py's
// SERVICES check, produced a real proposal) but rejected by this operation's
// service enum with a 400 — the enum here had never been updated when
// mctl-telegram/mctl-design/mctl-pairdesk were added on the mctl-agents side.
func TestImplementAndShepherdServiceEnumCoversMctlAgentsServices(t *testing.T) {
	// Mirrors config/settings.py's SERVICES list in mctlhq/mctl-agents.
	// Update both places together when a service is added/removed there.
	wantServices := []string{
		"mctl-web", "mctl-openclaw", "mctl-docs", "mctl-api", "mctl-portal",
		"mctl-agent", "mctl-gitops", "mctl-agents", "mctl-telegram", "mctl-design", "mctl-pairdesk", "mctl-academy",
	}

	registry := NewRegistry()
	// mctl-agents-approve and mctl-agents-reconcile duplicate the same enum
	// (mctl-agents-investigate takes an issue_url instead of a service param,
	// so it has no enum to drift).
	for _, opName := range []string{"mctl-agents-implement", "mctl-agents-shepherd", "mctl-agents-approve", "mctl-agents-reconcile"} {
		op, ok := registry.Get(opName)
		if !ok {
			t.Fatalf("operation %q not found in registry", opName)
		}
		var serviceParam *ParameterDef
		for i := range op.Parameters {
			if op.Parameters[i].Name == "service" {
				serviceParam = &op.Parameters[i]
				break
			}
		}
		if serviceParam == nil {
			t.Fatalf("operation %q has no 'service' parameter", opName)
		}
		enumSet := make(map[string]bool, len(serviceParam.Enum))
		for _, v := range serviceParam.Enum {
			enumSet[v] = true
		}
		for _, svc := range wantServices {
			if !enumSet[svc] {
				t.Errorf("operation %q's service enum is missing %q (mctl-agents SERVICES entry)", opName, svc)
			}
		}
	}
}

// TestCreateTenantDefaultsToClosedEgress pins the security-relevant default.
// ApplyDefaults fills in anything the caller omits, and MCP callers omitted
// this parameter entirely until it was added to the tool schema, so this
// single value decided the network posture of every workspace created through
// the agent path. It must stay "false" to match helm-charts/tenant/values.yaml
// (allowInternetEgress: false), wft-create-tenant.yaml and the Backstage
// scaffolder template.
func TestCreateTenantDefaultsToClosedEgress(t *testing.T) {
	reg := NewRegistry()
	op, ok := reg.Get("create-tenant")
	if !ok {
		t.Fatal("create-tenant operation not found in registry")
	}

	input := map[string]string{"tenant_name": "example"}
	filled := reg.ApplyDefaults(op, input)

	if got := filled["allow_internet_egress"]; got != "false" {
		t.Errorf("allow_internet_egress default = %q, want \"false\" (open egress must be opt-in)", got)
	}

	// An explicit opt-in must still survive ApplyDefaults.
	optIn := reg.ApplyDefaults(op, map[string]string{
		"tenant_name":           "example",
		"allow_internet_egress": "true",
	})
	if got := optIn["allow_internet_egress"]; got != "true" {
		t.Errorf("explicit allow_internet_egress overridden: got %q, want \"true\"", got)
	}
}

// TestReconcileDefaultsToWriting pins the reconcile sweep's dry_run default.
//
// The direction that matters is the quiet one. With dry_run defaulting to
// "true", every caller that omits the parameter — including Temporal's
// ReconcileWorkflow — would get a sweep that reads everything, decides
// everything, reports success, and writes nothing. That is exactly the
// failure mctlhq/mctl-agents#270 was: a reconcile pass indistinguishable
// from a working one, silently projecting nothing for four weeks. A wrong
// default here would reintroduce it from the API side.
func TestReconcileDefaultsToWriting(t *testing.T) {
	registry := NewRegistry()
	op, ok := registry.Get("mctl-agents-reconcile")
	if !ok {
		t.Fatal("operation \"mctl-agents-reconcile\" not found in registry")
	}
	if op.WorkflowTemplate != "mctl-agents-reconcile" {
		t.Errorf("WorkflowTemplate = %q, want %q — the CWFT that owns the "+
			"gitops commit", op.WorkflowTemplate, "mctl-agents-reconcile")
	}
	if !op.AdminOnly {
		t.Error("reconcile must stay AdminOnly: it commits to gitops main")
	}
	var dryRun *ParameterDef
	for i := range op.Parameters {
		if op.Parameters[i].Name == "dry_run" {
			dryRun = &op.Parameters[i]
			break
		}
	}
	if dryRun == nil {
		t.Fatal("operation has no 'dry_run' parameter")
	}
	if dryRun.Default != "false" {
		t.Errorf("dry_run default = %q, want \"false\": a sweep that writes "+
			"nothing by default is the #270 failure mode again", dryRun.Default)
	}
	if dryRun.Required {
		t.Error("dry_run must stay optional so callers can omit it")
	}
}
