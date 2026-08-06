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
