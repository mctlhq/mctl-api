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
	for _, opName := range []string{"mctl-agents-implement", "mctl-agents-shepherd"} {
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
