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

package securityfindings

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestTransitionsOnlyListedMovesAreAllowed(t *testing.T) {
	// Every state exists, every target is a known state, and no action
	// sets an arbitrary state.
	known := map[string]bool{}
	for _, s := range States {
		known[s] = true
	}
	if len(States) != 8 {
		t.Fatalf("want exactly 8 states, got %d", len(States))
	}
	for from, moves := range Transitions {
		if !known[from] {
			t.Errorf("unknown source state %q", from)
		}
		for action, to := range moves {
			if !known[to] {
				t.Errorf("%s --%s--> unknown state %q", from, action, to)
			}
		}
	}
	for _, s := range States {
		if _, ok := Transitions[s]; !ok {
			t.Errorf("state %q has no Transitions entry", s)
		}
	}
	if _, err := Next(StateResolved, ActionStartRemediation); !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("resolved must not start remediation: %v", err)
	}
	if _, err := Next(StateFixing, ActionVerifyPassed); !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("fixing must not accept a verification: %v", err)
	}
	if to, err := Next(StateFixing, ActionRecordFix); err != nil || to != StateAwaitingVerification {
		t.Errorf("a landed fix goes to awaiting_verification, got %q %v", to, err)
	}
	if len(Transitions[StateDismissed]) != 0 {
		t.Errorf("dismissed accepts no move")
	}
	if _, err := Next(StateResolved, ActionDismiss); !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("a resolved occurrence cannot be dismissed")
	}
	// Only a verification action ever reaches resolved.
	for from, moves := range Transitions {
		for action, to := range moves {
			if to == StateResolved && action != ActionVerifyPassed {
				t.Errorf("%s --%s--> resolved is not a verification", from, action)
			}
		}
	}
}

func TestStrengthOrdering(t *testing.T) {
	order := []Strength{StrengthDeterministicRegressionTest, StrengthAssuranceReplay,
		StrengthScannerRerunExactRevision, StrengthProviderClaim, StrengthManual}
	for i := range order {
		for j := range order {
			if got := order[i].AtLeast(order[j]); got != (i <= j) {
				t.Errorf("%s AtLeast %s = %v", order[i], order[j], got)
			}
		}
	}
	if MinStrength(StrengthAssuranceReplay, StrengthProviderClaim) != StrengthProviderClaim {
		t.Errorf("MinStrength must return the weaker")
	}
	if _, err := ParseStrength("strong"); !errors.Is(err, ErrInvalid) {
		t.Errorf("unknown strength must be refused: %v", err)
	}
	if s, err := ParseStrength(" manual "); err != nil || s != StrengthManual {
		t.Errorf("ParseStrength: %v %v", s, err)
	}
}

func TestObservationValidation(t *testing.T) {
	ok := func() ObservationInput {
		return ObservationInput{Tenant: "t", Identity: "CVE-2024-1234"}
	}
	in := ok()
	if err := in.validate(); err != nil || in.ClaimedAction != ClaimPresent {
		t.Fatalf("defaults: %v %q", err, in.ClaimedAction)
	}
	cases := map[string]func(*ObservationInput){
		"no tenant":      func(o *ObservationInput) { o.Tenant = "" },
		"no identity":    func(o *ObservationInput) { o.Identity = "" },
		"bad action":     func(o *ObservationInput) { o.ClaimedAction = "set_state" },
		"long title":     func(o *ObservationInput) { o.Untrusted.Title = strings.Repeat("a", MaxUntrustedTitle+1) },
		"long severity":  func(o *ObservationInput) { o.Untrusted.Severity = strings.Repeat("a", MaxUntrustedSeverity+1) },
		"long desc":      func(o *ObservationInput) { o.Untrusted.Description = strings.Repeat("a", MaxUntrustedDescripton+1) },
		"too many alias": func(o *ObservationInput) { o.Aliases = make([]string, MaxAliases+1) },
		"bad ref":        func(o *ObservationInput) { o.EvidenceRefs = []EvidenceRef{{Kind: "x"}} },
	}
	for name, mutate := range cases {
		o := ok()
		mutate(&o)
		if err := o.validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
	// The untrusted bounds are inclusive.
	edge := ok()
	edge.Untrusted = Untrusted{Title: strings.Repeat("a", MaxUntrustedTitle), Severity: strings.Repeat("a", MaxUntrustedSeverity),
		Description: strings.Repeat("a", MaxUntrustedDescripton)}
	if err := edge.validate(); err != nil {
		t.Errorf("limits are inclusive: %v", err)
	}
}

// No transition input type may carry provider text: untrusted data must be
// unable to reach any transition code (the typed inputs exclude it).
func TestTransitionInputsCarryNoUntrustedText(t *testing.T) {
	untrusted := reflect.TypeOf(Untrusted{})
	for _, v := range []any{TriageInput{}, StartRemediationInput{}, RecordFixInput{}, RecordVerificationInput{}, DismissInput{}} {
		typ := reflect.TypeOf(v)
		for i := 0; i < typ.NumField(); i++ {
			if typ.Field(i).Type == untrusted {
				t.Errorf("%s has an Untrusted field", typ.Name())
			}
		}
	}
}

func TestMutationInputValidation(t *testing.T) {
	actor := Actor{Principal: "github:alice"}
	if err := (&DismissInput{Reason: "because", AuthorityRef: "x", Actor: actor}).validate(); !errors.Is(err, ErrInvalid) {
		t.Errorf("unsupported dismissal reason: %v", err)
	}
	if err := (&DismissInput{Reason: DismissAcceptedRisk, Actor: actor}).validate(); !errors.Is(err, ErrInvalid) {
		t.Errorf("missing authority_ref: %v", err)
	}
	for _, r := range []string{DismissFalsePositive, DismissAcceptedRisk, DismissDuplicate, DismissNotApplicable, DismissProviderWithdrawn} {
		if err := (&DismissInput{Reason: r, AuthorityRef: "JIRA-1", Actor: actor}).validate(); err != nil {
			t.Errorf("reason %s: %v", r, err)
		}
	}
	if err := (&RecordFixInput{Landed: true, Actor: actor}).validate(); !errors.Is(err, ErrInvalid) {
		t.Errorf("landed needs a revision or digest: %v", err)
	}
	if err := (&RecordFixInput{LandedRevision: "abc", Actor: actor}).validate(); !errors.Is(err, ErrInvalid) {
		t.Errorf("landed_* needs landed=true: %v", err)
	}
	if err := (&StartRemediationInput{WorkItemID: "x", Actor: actor}).validate(); !errors.Is(err, ErrInvalid) {
		t.Errorf("work item id shape: %v", err)
	}
	if err := (&RecordVerificationInput{Mechanism: StrengthManual, Result: "ok", Ceiling: StrengthManual, Actor: actor}).validate(); !errors.Is(err, ErrInvalid) {
		t.Errorf("unsupported result: %v", err)
	}
}

func TestAttemptBinding(t *testing.T) {
	a := &attemptRow{LandedRevision: "r1"}
	if !a.bound("r1", "") || a.bound("r2", "") || a.bound("", "") {
		t.Errorf("revision binding")
	}
	b := &attemptRow{LandedRevision: "r1", LandedArtifact: "sha256:aa"}
	if !b.bound("r1", "sha256:aa") || b.bound("r1", "sha256:bb") || b.bound("r1", "") {
		t.Errorf("both set must both match")
	}
	if (&attemptRow{}).bound("", "") {
		t.Errorf("an attempt with no landed fix binds nothing")
	}
}
