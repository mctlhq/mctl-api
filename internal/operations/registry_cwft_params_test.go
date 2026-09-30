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

// cwftDeclaredParams is a transcription of spec.arguments.parameters from the
// three mctl-agents ClusterWorkflowTemplates in mctlhq/mctl-gitops, as of
// mctl-gitops#1345 (investigate) and #1418 (implement, shepherd):
// platform-gitops/argo-workflows/cluster-templates/cwft-mctl-agents-investigate.yaml,
// cwft-mctl-agents-implement.yaml and cwft-mctl-agents-shepherd.yaml.
// Transcribe, do not guess: declaring a name the CWFT does not declare makes
// Argo reject the submit. All three templates declare the same five
// correlation identifiers (temporal_workflow_id, temporal_run_id,
// execution_request_id, work_item_id, execution_id) — resolving the
// requirements.md open question about whether implement/shepherd's set
// matches investigate's: it does, in full.
var cwftDeclaredParams = map[string][]string{
	"mctl-agents-investigate": {
		"issue_url", "agent_image", "agent_version",
		"work_item_id", "execution_id",
		"temporal_workflow_id", "temporal_run_id", "execution_request_id",
	},
	"mctl-agents-implement": {
		"service", "slug", "force", "max_proposals", "agent_image", "agent_version",
		"work_item_id", "execution_id",
		"temporal_workflow_id", "temporal_run_id", "execution_request_id",
	},
	"mctl-agents-shepherd": {
		"service", "slug", "dry_run", "agent_image", "agent_version",
		"work_item_id", "execution_id",
		"temporal_workflow_id", "temporal_run_id", "execution_request_id",
	},
}

// cwftParamsNotSettableViaAPI names CWFT parameters that mctl-api
// deliberately does not declare, each with the reason. A parameter is
// exempted here only because mctl-api itself, or the template, owns its
// value — never because declaring it was forgotten.
var cwftParamsNotSettableViaAPI = map[string]map[string]string{
	"mctl-agents-implement": {
		"force": "Deprecated compatibility parameter (cwft-mctl-agents-implement.yaml): " +
			"run_implementer.py rejects true, since retries now require an " +
			"operator-reviewed needs-triage -> accepted transition rather than a " +
			"caller-supplied force flag. Not exposed via the API on purpose.",
	},
}

// TestCWFTParamsAreDeclaredOrExplicitlyInternal guards against a CWFT
// parameter silently going undeclared in the registry the way the DevLoop
// correlation identifiers did before mctlhq/mctl-api#426: every name in
// cwftDeclaredParams must be either declared by the corresponding operation
// or carry a non-empty reason in cwftParamsNotSettableViaAPI, and every
// exemption must name a parameter the CWFT actually declares, so the
// exclusion list cannot accumulate dead entries that quietly excuse a future
// omission.
//
// What this catches: a CWFT parameter transcribed into cwftDeclaredParams but
// never declared in the registry and never exempted.
// What this cannot catch: a CWFT parameter added in mctl-gitops that nobody
// transcribed into cwftDeclaredParams here — closing that gap needs the real
// manifests at test time, which a unit test in this repository cannot reach
// (see TestImplementAndShepherdServiceEnumCoversMctlAgentsServices,
// registry_test.go, for the same limitation applied to the service enum).
// Recorded as a follow-up: a CI step that clones mctl-gitops and regenerates
// this inventory.
func TestCWFTParamsAreDeclaredOrExplicitlyInternal(t *testing.T) {
	registry := NewRegistry()

	for opName, cwftNames := range cwftDeclaredParams {
		op, ok := registry.Get(opName)
		if !ok {
			t.Fatalf("operation %q not found in registry", opName)
		}
		declared := make(map[string]struct{}, len(op.Parameters))
		for _, p := range op.Parameters {
			declared[p.Name] = struct{}{}
		}
		exempt := cwftParamsNotSettableViaAPI[opName]

		for _, name := range cwftNames {
			_, isDeclared := declared[name]
			reason, isExempt := exempt[name]
			if !isDeclared && !isExempt {
				t.Errorf("%s: CWFT parameter %q is neither declared by the operation "+
					"nor exempted in cwftParamsNotSettableViaAPI", opName, name)
			}
			if isExempt && reason == "" {
				t.Errorf("%s: exemption for %q has an empty reason", opName, name)
			}
		}

		// Converse: every exemption must name a parameter the CWFT inventory
		// actually lists, so a stale exemption cannot hide a real omission.
		cwftSet := make(map[string]struct{}, len(cwftNames))
		for _, name := range cwftNames {
			cwftSet[name] = struct{}{}
		}
		for name := range exempt {
			if _, ok := cwftSet[name]; !ok {
				t.Errorf("%s: cwftParamsNotSettableViaAPI exempts %q, which is not in "+
					"cwftDeclaredParams for this operation", opName, name)
			}
		}
	}
}

// TestCWFTCorrelationParamsAreOmitWhenEmptyWithPattern asserts the property
// that makes "declared" safe rather than merely present for the DevLoop
// correlation identifiers: each is OmitWhenEmpty (so an uncorrelated caller
// never overrides the CWFT's default with "") and carries a non-empty
// Pattern (so a malformed value is rejected with 400 before it reaches Argo,
// rather than forwarded raw).
func TestCWFTCorrelationParamsAreOmitWhenEmptyWithPattern(t *testing.T) {
	registry := NewRegistry()
	correlationNames := map[string]struct{}{
		"temporal_workflow_id": {},
		"temporal_run_id":      {},
		"execution_request_id": {},
	}
	for opName := range cwftDeclaredParams {
		op, ok := registry.Get(opName)
		if !ok {
			t.Fatalf("operation %q not found in registry", opName)
		}
		for _, p := range op.Parameters {
			if _, ok := correlationNames[p.Name]; !ok {
				continue
			}
			if !p.OmitWhenEmpty {
				t.Errorf("%s: %s must be OmitWhenEmpty", opName, p.Name)
			}
			if p.Pattern == "" {
				t.Errorf("%s: %s must have a non-empty Pattern", opName, p.Name)
			}
		}
	}
}
