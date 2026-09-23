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

// wantServices mirrors config/settings.py's SERVICES list in mctlhq/mctl-agents;
// update both places together when a service is added or removed there.
// Package-level so the enum-membership test and the ValidateInput test below
// read the same copy: a service added to one but not the other would otherwise
// be enumerated as present while never being exercised through validation.
var wantServices = []string{
	"mctl-web", "mctl-openclaw", "mctl-docs", "mctl-api", "mctl-portal",
	"mctl-agent", "mctl-gitops", "mctl-agents", "mctl-telegram", "mctl-design", "mctl-pairdesk", "mctl-academy", "seerrsense", "portfolio", ".github",
}

// TestImplementAndShepherdServiceEnumCoversMctlAgentsServices guards against
// the enum silently drifting out of sync with mctl-agents' own
// config/settings.py SERVICES list. Caught live 2026-08-05: mctl-design was
// a fully valid implementer target (accepted by run_issue_investigator.py's
// SERVICES check, produced a real proposal) but rejected by this operation's
// service enum with a 400 — the enum here had never been updated when
// mctl-telegram/mctl-design/mctl-pairdesk were added on the mctl-agents side.
// The same failure recurred for "portfolio" (mctl-api#281).
func TestImplementAndShepherdServiceEnumCoversMctlAgentsServices(t *testing.T) {
	// Note what this can and cannot catch. It is a hand-kept copy, so it fires
	// only when one enum in THIS repository falls behind the others -- it
	// cannot notice that mctl-agents has registered a service nobody mirrored
	// here, because the omission lands in this list too. That is how
	// "seerrsense" stayed missing from all four enums and this test stayed
	// green: the investigator ran against seerrsense, the proposal landed, and
	// mctl-agents-approve rejected service=seerrsense server-side with no
	// standalone path left to approve it. Catching that class needs the real
	// SERVICES list, which is in another repository and not reachable from a
	// unit test. Until something fetches it, adding a service means editing
	// nine places here: the four ParameterDef enums in registry.go, their four
	// mcplib.Enum mirrors in internal/mcp/server.go, and this list. The four
	// mirrors are backstopped by TestServiceEnumsMatchRegistry, which compares
	// the two sides value-for-value and in order, so forgetting one of those
	// still gets you a red build. This list is the one nothing backstops: it is
	// a fifth edit alongside the four registry enums, not a check on them.
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

		// And the converse. Membership alone is subset-only: it catches a
		// service added upstream and not mirrored here, and says nothing about
		// one removed upstream and left behind here. That direction fails
		// worse, not better -- the enum keeps accepting a service mctl-agents
		// will refuse, so instead of a 400 at the edge the caller gets a
		// dispatched workflow that dies in Argo. The empty string is not a
		// service: it is the "all services" default on the three optional
		// params, and absent on approve, where service is required.
		wantSet := make(map[string]bool, len(wantServices))
		for _, svc := range wantServices {
			wantSet[svc] = true
		}
		for _, v := range serviceParam.Enum {
			if v == "" || wantSet[v] {
				continue
			}
			t.Errorf("operation %q's service enum carries %q, which is not in mctl-agents SERVICES; a stale entry accepts a service the agent side will reject", opName, v)
		}
	}
}

// TestApproveAcceptsEveryMctlAgentsService exercises the exact code path that
// produced the 400 for portfolio (mctl-api#281) and again for seerrsense: not
// enum membership, but ValidateInput on mctl-agents-approve, which is what a
// caller actually hits. Driven off wantServices rather than one literal, so a
// service added there gets this end-to-end assertion without anyone
// remembering to write a second test for it -- the earlier single-service
// version passed throughout the seerrsense outage because "portfolio" was
// still fine.
func TestApproveAcceptsEveryMctlAgentsService(t *testing.T) {
	registry := NewRegistry()
	op, ok := registry.Get("mctl-agents-approve")
	if !ok {
		t.Fatal("mctl-agents-approve operation not found in registry")
	}

	for _, svc := range wantServices {
		t.Run(svc, func(t *testing.T) {
			errs := registry.ValidateInput(op, map[string]string{
				"service": svc,
				"slug":    "issue-1-example-slug",
			})
			if len(errs) != 0 {
				t.Errorf("ValidateInput(mctl-agents-approve, service=%s) returned unexpected errors: %v", svc, errs)
			}
		})
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

	// The declared default is only half the claim. What actually reaches the
	// workflow is whatever ApplyDefaults produces for a caller that omitted
	// the parameter — ReconcileWorkflow being exactly such a caller. A
	// regression in how omitted parameters are merged would leave the struct
	// field above untouched and still hand Argo a no-op sweep, so assert the
	// applied value the way TestCreateTenantDefaultsToClosedEgress does for
	// the egress default (agy P2 on mctl-api#234).
	filled := registry.ApplyDefaults(op, map[string]string{})
	if got := filled["dry_run"]; got != "false" {
		t.Errorf("ApplyDefaults gave dry_run = %q for a caller that omitted "+
			"it, want \"false\" — the sweep would read everything, report "+
			"success and write nothing", got)
	}

	// An explicit dry run must survive: the operator asking to see decisions
	// without writing is the whole reason the parameter exists.
	explicit := registry.ApplyDefaults(op, map[string]string{"dry_run": "true"})
	if got := explicit["dry_run"]; got != "true" {
		t.Errorf("explicit dry_run overridden: got %q, want \"true\"", got)
	}
}

// validInvestigateIssueURL is a sample GitHub issue URL matching
// mctl-agents-investigate's issue_url pattern.
const validInvestigateIssueURL = "https://github.com/mctlhq/mctl-api/issues/335"

// TestInvestigateAcceptsResumeIdentifiers pins the acceptance criterion "the
// two parameters are accepted" through the exact function the handler calls
// (mctlhq/mctl-agents#267).
func TestInvestigateAcceptsResumeIdentifiers(t *testing.T) {
	registry := NewRegistry()
	op, ok := registry.Get("mctl-agents-investigate")
	if !ok {
		t.Fatal("operation \"mctl-agents-investigate\" not found in registry")
	}

	input := map[string]string{
		"issue_url":    validInvestigateIssueURL,
		"work_item_id": "wi_5c8e1f2b-0000-0000-0000-000000000000",
		"execution_id": "we_9a010000-0000-0000-0000-000000000000",
	}
	if errs := registry.ValidateInput(op, input); len(errs) != 0 {
		t.Errorf("ValidateInput with issue_url + work_item_id + execution_id "+
			"returned errors, want none: %v", errs)
	}
}

// TestInvestigateResumeIdentifiersStayOptional pins "no invented default":
// a cold, issue-driven caller that never heard of #267 must keep working
// unchanged, and ApplyDefaults must not manufacture ids for it.
func TestInvestigateResumeIdentifiersStayOptional(t *testing.T) {
	registry := NewRegistry()
	op, ok := registry.Get("mctl-agents-investigate")
	if !ok {
		t.Fatal("operation \"mctl-agents-investigate\" not found in registry")
	}

	input := map[string]string{"issue_url": validInvestigateIssueURL}
	if errs := registry.ValidateInput(op, input); len(errs) != 0 {
		t.Errorf("ValidateInput with only issue_url returned errors, want none: %v", errs)
	}

	filled := registry.ApplyDefaults(op, input)
	if got := filled["work_item_id"]; got != "" {
		t.Errorf("ApplyDefaults gave work_item_id = %q for a caller that omitted "+
			"it, want \"\" — a cold issue-driven run must not get an invented id", got)
	}
	if got := filled["execution_id"]; got != "" {
		t.Errorf("ApplyDefaults gave execution_id = %q for a caller that omitted "+
			"it, want \"\" — a cold issue-driven run must not get an invented id", got)
	}

	var workItemID, executionID *ParameterDef
	for i := range op.Parameters {
		switch op.Parameters[i].Name {
		case "work_item_id":
			workItemID = &op.Parameters[i]
		case "execution_id":
			executionID = &op.Parameters[i]
		}
	}
	if workItemID == nil {
		t.Fatal("operation has no 'work_item_id' parameter")
	}
	if executionID == nil {
		t.Fatal("operation has no 'execution_id' parameter")
	}
	if workItemID.Required {
		t.Error("work_item_id must stay optional so callers can omit it")
	}
	if workItemID.Default != "" {
		t.Errorf("work_item_id Default = %q, want \"\"", workItemID.Default)
	}
	if executionID.Required {
		t.Error("execution_id must stay optional so callers can omit it")
	}
	if executionID.Default != "" {
		t.Errorf("execution_id Default = %q, want \"\"", executionID.Default)
	}
}

// TestInvestigateForwardsResumeIdentifiers pins "forwards them" and "a
// parameter outside the declared set is still rejected" at the exact
// function handlers_write.go calls before submitting to Argo.
func TestInvestigateForwardsResumeIdentifiers(t *testing.T) {
	registry := NewRegistry()
	op, ok := registry.Get("mctl-agents-investigate")
	if !ok {
		t.Fatal("operation \"mctl-agents-investigate\" not found in registry")
	}

	input := map[string]string{
		"issue_url":    validInvestigateIssueURL,
		"work_item_id": "wi_5c8e1f2b-0000-0000-0000-000000000000",
		"execution_id": "we_9a010000-0000-0000-0000-000000000000",
		"config_patch": ".image.tag = \"pwned\"",
	}
	result, dropped := registry.StripUndeclared(op, input)

	if got := result["issue_url"]; got != validInvestigateIssueURL {
		t.Errorf("StripUndeclared dropped or mutated issue_url: got %q, want %q", got, validInvestigateIssueURL)
	}
	if got := result["work_item_id"]; got != input["work_item_id"] {
		t.Errorf("StripUndeclared dropped or mutated work_item_id: got %q, want %q", got, input["work_item_id"])
	}
	if got := result["execution_id"]; got != input["execution_id"] {
		t.Errorf("StripUndeclared dropped or mutated execution_id: got %q, want %q", got, input["execution_id"])
	}
	if _, exists := result["config_patch"]; exists {
		t.Error("StripUndeclared kept config_patch, want it dropped — it is not a declared parameter")
	}
	if len(dropped) != 1 || dropped[0] != "config_patch" {
		t.Errorf("StripUndeclared dropped = %v, want [\"config_patch\"]", dropped)
	}
}

// TestInvestigateRejectsMalformedResumeIdentifiers pins the pattern that
// keeps work_item_id/execution_id from becoming a shell-injection or
// argument-smuggling vector on their way into the Argo workflow arguments.
func TestInvestigateRejectsMalformedResumeIdentifiers(t *testing.T) {
	registry := NewRegistry()
	op, ok := registry.Get("mctl-agents-investigate")
	if !ok {
		t.Fatal("operation \"mctl-agents-investigate\" not found in registry")
	}

	longID := ""
	for i := 0; i < 100; i++ {
		longID += "a"
	}

	malformed := []struct {
		param string
		value string
	}{
		{"work_item_id", "wi_x; rm -rf /"},
		{"execution_id", "we_a b"},
		{"work_item_id", longID},
		{"execution_id", "we_abc\ndef"},
	}
	for _, tc := range malformed {
		input := map[string]string{
			"issue_url": validInvestigateIssueURL,
			tc.param:    tc.value,
		}
		errs := registry.ValidateInput(op, input)
		found := false
		for _, e := range errs {
			if len(e) >= len(tc.param) && e[:len(tc.param)] == tc.param {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ValidateInput(%s=%q) errors = %v, want an error naming %q",
				tc.param, tc.value, errs, tc.param)
		}
	}

	wellFormed := map[string]string{
		"issue_url":    validInvestigateIssueURL,
		"work_item_id": "wi_5c8e1f2b-0000-0000-0000-000000000000",
		"execution_id": "we_9a010000-0000-0000-0000-000000000000",
	}
	if errs := registry.ValidateInput(op, wellFormed); len(errs) != 0 {
		t.Errorf("ValidateInput with well-formed resume identifiers returned errors, want none: %v", errs)
	}
}

// TestInvestigateStillRequiresIssueURL pins that adding resume identifiers
// did not turn issue_url optional by accident.
func TestInvestigateStillRequiresIssueURL(t *testing.T) {
	registry := NewRegistry()
	op, ok := registry.Get("mctl-agents-investigate")
	if !ok {
		t.Fatal("operation \"mctl-agents-investigate\" not found in registry")
	}

	input := map[string]string{
		"work_item_id": "wi_5c8e1f2b-0000-0000-0000-000000000000",
		"execution_id": "we_9a010000-0000-0000-0000-000000000000",
	}
	errs := registry.ValidateInput(op, input)
	found := false
	for _, e := range errs {
		if e == "missing required parameter: issue_url" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ValidateInput without issue_url errors = %v, want \"missing required parameter: issue_url\"", errs)
	}
}

// TestInvestigateForwardsReleasePin is the focused half of mctlhq/mctl-api#372:
// the DevLoop's agent_image/agent_version pass StripUndeclared untouched while
// an undeclared key in the same request is still dropped.
func TestInvestigateForwardsReleasePin(t *testing.T) {
	registry := NewRegistry()
	op, ok := registry.Get("mctl-agents-investigate")
	if !ok {
		t.Fatal("operation \"mctl-agents-investigate\" not found in registry")
	}

	input := map[string]string{
		"issue_url":     validInvestigateIssueURL,
		"agent_image":   "ghcr.io/mctlhq/mctl-agents:1.54.0",
		"agent_version": "issue-investigator@1.54.0",
		"config_patch":  ".image.tag = \"pwned\"",
	}
	result, dropped := registry.StripUndeclared(op, input)
	for _, k := range []string{"issue_url", "agent_image", "agent_version"} {
		if result[k] != input[k] {
			t.Errorf("StripUndeclared dropped or mutated %s: got %q, want %q", k, result[k], input[k])
		}
	}
	if len(dropped) != 1 || dropped[0] != "config_patch" {
		t.Errorf("StripUndeclared dropped = %v, want [\"config_patch\"]", dropped)
	}
	if errs := registry.ValidateInput(op, registry.ApplyDefaults(op, result)); len(errs) != 0 {
		t.Errorf("ValidateInput rejected the DevLoop's release pin: %v", errs)
	}
}

// TestReleasePinPatterns pins what the four pinned operations accept: the
// two image shapes mctl-agents builds, and only its own agent's version.
func TestReleasePinPatterns(t *testing.T) {
	registry := NewRegistry()
	agents := map[string]string{
		"mctl-agents-investigate": "issue-investigator",
		"mctl-agents-implement":   "implementer",
		"mctl-agents-shepherd":    "shepherd",
		"mctl-agents-incidents":   "incident-responder",
	}
	const digest = "sha256:6ef615deee2a2864195014760bf6c3989b26059b47435933f04c6d8f5060e9f6"
	for opName, agent := range agents {
		op, ok := registry.Get(opName)
		if !ok {
			t.Fatalf("operation %q not found in registry", opName)
		}
		base := map[string]string{}
		if opName == "mctl-agents-investigate" {
			base["issue_url"] = validInvestigateIssueURL
		}
		check := func(param, value string, wantOK bool) {
			t.Helper()
			input := map[string]string{param: value}
			for k, v := range base {
				input[k] = v
			}
			errs := registry.ValidateInput(op, input)
			if wantOK && len(errs) != 0 {
				t.Errorf("%s: %s=%q rejected, want accepted: %v", opName, param, value, errs)
			}
			if !wantOK && len(errs) == 0 {
				t.Errorf("%s: %s=%q accepted, want rejected", opName, param, value)
			}
		}

		check("agent_image", "ghcr.io/mctlhq/mctl-agents:1.54.0", true)
		check("agent_image", "ghcr.io/mctlhq/mctl-agents:1.22.0-2", true)
		check("agent_image", "ghcr.io/mctlhq/mctl-agents@"+digest, true)
		check("agent_image", "ghcr.io/mctlhq/mctl-agents:latest", false)
		check("agent_image", "ghcr.io/mctlhq/mctl-agents:1.54.0:1.54.0", false)
		check("agent_image", "ghcr.io/mctlhq/mctl-agents@"+digest+"@"+digest, false)
		check("agent_image", "ghcr.io/evil/mctl-agents:1.54.0", false)
		check("agent_image", "docker.io/mctlhq/mctl-agents:1.54.0", false)
		check("agent_image", "ghcr.io/mctlhq/mctl-agents-evil:1.54.0", false)
		check("agent_image", "ghcr.io/mctlhq/mctl-agents:1.54.0\n", false)
		check("agent_image", "ghcr.io/mctlhq/mctl-agents@sha256:abc", false)

		check("agent_version", agent+"@1.54.0", true)
		check("agent_version", agent+"@1.22.0-2", true)
		check("agent_version", "someone-else@1.54.0", false)
		check("agent_version", agent+"@latest", false)
		check("agent_version", agent+"@1.54.0; rm -rf /", false)
	}
}

// TestReleasePinIsOmittedWhenEmpty pins OmitWhenEmpty: ApplyDefaults must not
// turn an absent or empty pin into agent_image="", which Argo would use over
// the CWFT's default image.
func TestReleasePinIsOmittedWhenEmpty(t *testing.T) {
	registry := NewRegistry()
	for _, opName := range []string{"mctl-agents-investigate", "mctl-agents-implement", "mctl-agents-shepherd", "mctl-agents-incidents"} {
		op, _ := registry.Get(opName)
		for _, input := range []map[string]string{
			{},
			{"agent_image": "", "agent_version": ""},
		} {
			filled := registry.ApplyDefaults(op, input)
			for _, k := range []string{"agent_image", "agent_version"} {
				if v, ok := filled[k]; ok {
					t.Errorf("%s: ApplyDefaults(%v) set %s = %q, want it absent", opName, input, k, v)
				}
			}
		}
	}
}
