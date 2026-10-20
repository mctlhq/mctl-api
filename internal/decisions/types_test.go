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

package decisions

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/workitems"
)

func TestDecisionInputValidate(t *testing.T) {
	base := newAction().decision(CodeAllowed, VerdictAllow, "")
	if err := base.validate(); err != nil {
		t.Fatalf("valid input refused: %v", err)
	}
	for name, mutate := range map[string]func(*DecisionInput){
		"approved without approval": func(in *DecisionInput) { in.Code, in.Verdict = CodeApproved, VerdictRequireApproval },
		"allowed under deny":        func(in *DecisionInput) { in.Verdict = VerdictDeny },
		"approved under allow":      func(in *DecisionInput) { in.Code, in.ApprovalID = CodeApproved, "aar_x" },
		"approval on a rule denial": func(in *DecisionInput) { in.Code, in.Verdict, in.ApprovalID = CodeDenied, VerdictDeny, "aar_x" },
		"unknown code":              func(in *DecisionInput) { in.Code = "maybe" },
		"unknown verdict":           func(in *DecisionInput) { in.Verdict = "perhaps" },
		"target in clear":           func(in *DecisionInput) { in.TargetDigest = "mctlhq/mctl-api#1" },
		"args in clear":             func(in *DecisionInput) { in.ArgsDigest = `{"body":"x"}` },
		"missing action digest":     func(in *DecisionInput) { in.ActionDigest = "" },
		"free-text reason":          func(in *DecisionInput) { in.PolicyReasons = []string{"Because I said so"} },
		"too many reasons":          func(in *DecisionInput) { in.PolicyReasons = make([]string, MaxPolicyReasons+1) },
		"secret in actor":           func(in *DecisionInput) { in.Actor = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789" },
		"whitespace in execution":   func(in *DecisionInput) { in.ExecutionID = "we_ a" },
		"wrong principal prefix":    func(in *DecisionInput) { in.PrincipalID = "usr_1" },
		"wrong work item prefix":    func(in *DecisionInput) { in.WorkItemID = "we_1" },
		"missing decided_at":        func(in *DecisionInput) { in.DecidedAt = time.Time{} },
		"missing idempotency key":   func(in *DecisionInput) { in.IdempotencyKey = "" },
		"missing recorded_by":       func(in *DecisionInput) { in.RecordedBy = "" },
		"missing policy version":    func(in *DecisionInput) { in.PolicyVersion = "" },
		"approval with wrong prefix": func(in *DecisionInput) {
			in.Code, in.Verdict, in.ApprovalID = CodeApprovalDenied, VerdictRequireApproval, "we_1"
		},
		"over-long idempotency key":   func(in *DecisionInput) { in.IdempotencyKey = strings.Repeat("k", MaxKeyBytes+1) },
		"approved missing approval 2": func(in *DecisionInput) { in.Code = CodeApproved },
	} {
		in := base
		in.PolicyReasons = append([]string(nil), base.PolicyReasons...)
		mutate(&in)
		if err := in.validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}

func TestAttemptInputValidate(t *testing.T) {
	ok := []AttemptInput{
		event("dec_1", 0, PhaseStarted),
		event("dec_1", 1, PhaseSucceeded),
	}
	for _, in := range ok {
		if err := in.validate(); err != nil {
			t.Fatalf("%s refused: %v", in.Phase, err)
		}
	}
	for name, in := range map[string]AttemptInput{
		"start names attempt": event("dec_1", 1, PhaseStarted),
		"start with outcome":  func() AttemptInput { e := event("dec_1", 0, PhaseStarted); e.ErrorCode = "x"; return e }(),
		"start with evidence": func() AttemptInput {
			e := event("dec_1", 0, PhaseStarted)
			e.EvidenceID = "ev-0000000000000001"
			return e
		}(),
		"terminal without no":  event("dec_1", 0, PhaseSucceeded),
		"failed without code":  event("dec_1", 1, PhaseFailed),
		"partial without code": event("dec_1", 1, PhasePartial),
		"success with code":    func() AttemptInput { e := event("dec_1", 1, PhaseSucceeded); e.ErrorCode = "x"; return e }(),
		"error message": func() AttemptInput {
			e := event("dec_1", 1, PhaseFailed)
			e.ErrorCode = "Connection refused at 10.0.0.1"
			return e
		}(),
		"bad evidence id":       func() AttemptInput { e := event("dec_1", 1, PhaseSucceeded); e.EvidenceID = "ev-xyz"; return e }(),
		"bad runtime id":        func() AttemptInput { e := event("dec_1", 0, PhaseStarted); e.RuntimeExecutionID = "we_1"; return e }(),
		"bad invocation prefix": func() AttemptInput { e := event("dec_1", 1, PhaseSucceeded); e.CommerceInvocationID = "cq_1"; return e }(),
		"result in clear":       func() AttemptInput { e := event("dec_1", 1, PhaseSucceeded); e.ResultDigest = "merged"; return e }(),
		"unknown phase":         event("dec_1", 1, "retrying"),
		"wrong decision prefix": event("aar_1", 0, PhaseStarted),
		"missing occurred_at":   func() AttemptInput { e := event("dec_1", 0, PhaseStarted); e.OccurredAt = time.Time{}; return e }(),
		"missing key":           func() AttemptInput { e := event("dec_1", 0, PhaseStarted); e.IdempotencyKey = ""; return e }(),
		"over-long key": func() AttemptInput {
			e := event("dec_1", 0, PhaseStarted)
			e.IdempotencyKey = strings.Repeat("k", MaxKeyBytes+1)
			return e
		}(),
	} {
		if err := in.validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}

func TestContentDigestCoversEveryField(t *testing.T) {
	base := newAction().decision(CodeApprovalDenied, VerdictRequireApproval, "aar_1")
	base.WorkItemID, base.TraceID, base.AuthorityBasis = "wi_1", "t1", "owner"
	want := base.contentDigest()
	for name, mutate := range map[string]func(*DecisionInput){
		"execution_id":    func(in *DecisionInput) { in.ExecutionID += "x" },
		"work_item_id":    func(in *DecisionInput) { in.WorkItemID += "x" },
		"intent_source":   func(in *DecisionInput) { in.IntentSource += "x" },
		"trace_id":        func(in *DecisionInput) { in.TraceID += "x" },
		"policy_version":  func(in *DecisionInput) { in.PolicyVersion += "x" },
		"rule_id":         func(in *DecisionInput) { in.RuleID += "x" },
		"verdict":         func(in *DecisionInput) { in.Verdict = VerdictDeny },
		"code":            func(in *DecisionInput) { in.Code = CodeApprovalExpired },
		"policy_reasons":  func(in *DecisionInput) { in.PolicyReasons = []string{"other"} },
		"actor":           func(in *DecisionInput) { in.Actor += "x" },
		"principal_id":    func(in *DecisionInput) { in.PrincipalID += "x" },
		"tenant":          func(in *DecisionInput) { in.Tenant += "x" },
		"approval_id":     func(in *DecisionInput) { in.ApprovalID += "x" },
		"authority_basis": func(in *DecisionInput) { in.AuthorityBasis += "x" },
		"action_kind":     func(in *DecisionInput) { in.ActionKind += "x" },
		"operation":       func(in *DecisionInput) { in.Operation += "x" },
		"target_digest":   func(in *DecisionInput) { in.TargetDigest = digestOf("t") },
		"args_digest":     func(in *DecisionInput) { in.ArgsDigest = digestOf("a") },
		"action_digest":   func(in *DecisionInput) { in.ActionDigest = digestOf("d") },
		"decided_at":      func(in *DecisionInput) { in.DecidedAt = in.DecidedAt.Add(time.Microsecond) },
	} {
		in := base
		mutate(&in)
		if in.contentDigest() == want {
			t.Errorf("content digest ignores %s", name)
		}
	}
}

func TestGroupAttemptsAndResult(t *testing.T) {
	permitted := &Decision{Permitted: true}
	ev := func(no int, phase string) AttemptEvent { return AttemptEvent{AttemptNo: no, Phase: phase} }
	for name, tc := range map[string]struct {
		events   []AttemptEvent
		statuses []string
		result   string
	}{
		"none":        {nil, []string{}, ResultPending},
		"open":        {[]AttemptEvent{ev(1, PhaseStarted)}, []string{AttemptInProgress}, ResultInProgress},
		"failed":      {[]AttemptEvent{ev(1, PhaseStarted), ev(1, PhaseFailed)}, []string{PhaseFailed}, ResultFailed},
		"partial":     {[]AttemptEvent{ev(1, PhaseStarted), ev(1, PhasePartial)}, []string{PhasePartial}, ResultPartial},
		"abandoned":   {[]AttemptEvent{ev(1, PhaseStarted), ev(2, PhaseStarted)}, []string{AttemptUnknown, AttemptInProgress}, ResultInProgress},
		"recovered":   {[]AttemptEvent{ev(1, PhaseStarted), ev(1, PhasePartial), ev(2, PhaseStarted), ev(2, PhaseSucceeded)}, []string{PhasePartial, PhaseSucceeded}, ResultSucceeded},
		"late result": {[]AttemptEvent{ev(1, PhaseStarted), ev(2, PhaseStarted), ev(2, PhaseFailed), ev(1, PhaseSucceeded)}, []string{PhaseSucceeded, PhaseFailed}, ResultSucceeded},
	} {
		attempts := groupAttempts(tc.events)
		got := make([]string, 0, len(attempts))
		for _, a := range attempts {
			got = append(got, a.Status)
		}
		if !equalStrings(got, tc.statuses) {
			t.Errorf("%s: statuses %v, want %v", name, got, tc.statuses)
		}
		if r := deriveResult(permitted, attempts); r != tc.result {
			t.Errorf("%s: result %q, want %q", name, r, tc.result)
		}
	}
	if r := deriveResult(&Decision{}, nil); r != ResultRefused {
		t.Errorf("refusal: %q", r)
	}
}

// checkApprovalBinding binds only code approved, whatever validate() admits:
// an approval that matches the action in every field is accepted for
// approved and still refused for any other code.
func TestCheckApprovalBindingRefusesOtherCodes(t *testing.T) {
	a := newAction()
	aar := &workitems.ActionApprovalRequest{
		ExecutionID: a.executionID, ActionKind: a.kind, Target: a.target, ArgsDigest: a.args,
		PolicyRuleID: a.rule, PolicyVersion: a.version, State: workitems.ApprovalApproved,
	}
	approved := a.decision(CodeApproved, VerdictRequireApproval, "aar_1")
	if err := checkApprovalBinding(&approved, aar); err != nil {
		t.Fatalf("matching approval refused for approved: %v", err)
	}
	allowed := a.decision(CodeAllowed, VerdictAllow, "aar_1")
	if err := checkApprovalBinding(&allowed, aar); !errors.Is(err, ErrApprovalBinding) {
		t.Fatalf("allowed bound to an approval: %v, want ErrApprovalBinding", err)
	}
}
