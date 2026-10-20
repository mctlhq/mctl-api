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
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/mctlhq/mctl-api/internal/evidence"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Postgres-backed tests skip without TEST_DATABASE_URL (a developer laptop),
// and run in CI, where the test job exports it.
func newTestStores(t *testing.T) (*Store, *workitems.Store, *fakeEvidence) {
	t.Helper()
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed decision store test")
	}
	ctx := context.Background()
	wi, err := workitems.NewStore(ctx, connStr)
	if err != nil {
		t.Fatalf("workitems.NewStore: %v", err)
	}
	t.Cleanup(wi.Close)
	s, err := NewStore(ctx, connStr)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(s.Close)
	ev := &fakeEvidence{records: map[string]*evidence.Evidence{}}
	s.SetLookups(wi, ev)
	return s, wi, ev
}

type fakeEvidence struct {
	records map[string]*evidence.Evidence
	err     error
}

func (f *fakeEvidence) Get(_ context.Context, id string) (*evidence.Evidence, error) {
	if f.err != nil {
		return nil, f.err
	}
	if e, ok := f.records[id]; ok {
		return e, nil
	}
	return nil, fmt.Errorf("evidence: %s: %w", id, evidence.ErrEvidenceNotFound)
}

type failingApprovals struct{ err error }

// fixedApproval serves one stored approval as given.
type fixedApproval struct {
	a *workitems.ActionApprovalRequest
}

func (f fixedApproval) ActionApproval(context.Context, string) (*workitems.ActionApprovalRequest, error) {
	return f.a, nil
}

func (f failingApprovals) ActionApproval(context.Context, string) (*workitems.ActionApprovalRequest, error) {
	return nil, f.err
}

func digestOf(s string) string { return TargetDigest(s) }

func uid() string { return uuid.NewString() }

// action is one concrete side effect, as both an aar_ and a decision see it.
type action struct {
	executionID, workItemID, kind, target, args, rule, version string
}

func newAction() action {
	return action{
		executionID: "we_" + uid(),
		kind:        "github.pr.merge",
		target:      "mctlhq/mctl-api#" + uid()[:6],
		args:        digestOf("args-" + uid()),
		rule:        "github-pr-merge",
		version:     "mctl-agents/policy/v1",
	}
}

func (a action) decision(code, verdict, approvalID string) DecisionInput {
	return DecisionInput{
		ExecutionID:    a.executionID,
		WorkItemID:     a.workItemID,
		IntentSource:   "execution:" + a.executionID,
		PolicyVersion:  a.version,
		RuleID:         a.rule,
		Verdict:        verdict,
		Code:           code,
		PolicyReasons:  []string{"rule.github-pr-merge"},
		Actor:          "agent:implementer",
		PrincipalID:    "prn_01JTESTPRINCIPAL",
		Tenant:         "mctl",
		ApprovalID:     approvalID,
		ActionKind:     a.kind,
		Operation:      "merge",
		TargetDigest:   TargetDigest(a.target),
		ArgsDigest:     a.args,
		ActionDigest:   digestOf("action-" + a.executionID),
		DecidedAt:      time.Now().UTC().Truncate(time.Microsecond),
		IdempotencyKey: "idem-" + uid(),
		RecordedBy:     "svc-agents",
	}
}

// approval creates an aar_ for a through the canonical store and moves it
// to state ("pending", "approved", "consumed" or "denied").
func approval(t *testing.T, wi *workitems.Store, a action, state string) *workitems.ActionApprovalRequest {
	t.Helper()
	ctx := context.Background()
	req, _, err := wi.CreateActionApproval(ctx, workitems.ActionApprovalInput{
		ActionIntent: workitems.ActionIntent{
			ExecutionID: a.executionID, ActionKind: a.kind, Target: a.target, ArgsDigest: a.args,
			PolicyRuleID: a.rule, PolicyVersion: a.version, WorkItemID: a.workItemID,
		},
		RequestedBy:    "svc-agents",
		IdempotencyKey: "aar-" + uid(),
		ExpiresAt:      time.Now().Add(time.Hour),
		IntentSource:   "execution:" + a.executionID,
		SideEffect:     "write",
		PolicyDecision: "require_approval",
		PolicyReasons:  []string{"rule.github-pr-merge"},
	})
	if err != nil {
		t.Fatalf("CreateActionApproval: %v", err)
	}
	if state == workitems.ApprovalPending {
		return req
	}
	decision := workitems.DecisionApprove
	if state == workitems.ApprovalDenied {
		decision = workitems.DecisionDeny
	}
	req, err = wi.DecideActionApproval(ctx, workitems.ActionDecisionInput{ID: req.ID, DecidedBy: "human:owner", Decision: decision})
	if err != nil {
		t.Fatalf("DecideActionApproval: %v", err)
	}
	if state == workitems.ApprovalConsumed {
		if req, err = wi.ConsumeActionApproval(ctx, req.ID, req.IntentHash); err != nil {
			t.Fatalf("ConsumeActionApproval: %v", err)
		}
	}
	return req
}

func mustRecord(t *testing.T, s *Store, in DecisionInput) *Decision {
	t.Helper()
	d, created, err := s.Record(context.Background(), in)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if !created {
		t.Fatalf("Record: created=false for a new key")
	}
	return d
}

func event(decisionID string, attemptNo int, phase string) AttemptInput {
	return AttemptInput{
		DecisionID:     decisionID,
		AttemptNo:      attemptNo,
		Phase:          phase,
		OccurredAt:     time.Now().UTC().Truncate(time.Microsecond),
		IdempotencyKey: "ev-" + uid(),
		RecordedBy:     "svc-agents",
	}
}

func mustAppend(t *testing.T, s *Store, in AttemptInput) *AttemptEvent {
	t.Helper()
	e, created, err := s.AppendAttempt(context.Background(), in)
	if err != nil {
		t.Fatalf("AppendAttempt(%s #%d): %v", in.Phase, in.AttemptNo, err)
	}
	if !created {
		t.Fatalf("AppendAttempt: created=false for a new key")
	}
	return e
}

func mustChain(t *testing.T, s *Store, id string) *Chain {
	t.Helper()
	c, err := s.Chain(context.Background(), id)
	if err != nil {
		t.Fatalf("Chain: %v", err)
	}
	return c
}

func statuses(c *Chain) []string {
	out := make([]string, 0, len(c.Attempts))
	for _, a := range c.Attempts {
		out = append(out, a.Status)
	}
	return out
}

func equalStrings(a, b []string) bool { return slices.Equal(a, b) }

// TestChainSuccess: an approved, consumed aar_ authorizes one decision whose
// single attempt succeeds; the chain carries every link back to the intent.
func TestChainSuccess(t *testing.T) {
	s, wi, ev := newTestStores(t)
	ctx := context.Background()
	a := newAction()
	aar := approval(t, wi, a, workitems.ApprovalConsumed)

	d := mustRecord(t, s, a.decision(CodeApproved, VerdictRequireApproval, aar.ID))
	if !d.Permitted || d.IntentHash != aar.IntentHash {
		t.Fatalf("decision: permitted=%v intent_hash=%q, want true and %q", d.Permitted, d.IntentHash, aar.IntentHash)
	}

	start := event(d.ID, 0, PhaseStarted)
	start.RuntimeExecutionID = "ex-0123456789abcdef"
	if e := mustAppend(t, s, start); e.AttemptNo != 1 || e.Seq != 1 {
		t.Fatalf("started: attempt %d seq %d, want 1/1", e.AttemptNo, e.Seq)
	}
	done := event(d.ID, 1, PhaseSucceeded)
	done.EvidenceID = "ev-00000000000000a1"
	done.ResultDigest = digestOf("merged")
	mustAppend(t, s, done)
	ev.records[done.EvidenceID] = &evidence.Evidence{ID: done.EvidenceID, ExecutionID: a.executionID}

	c := mustChain(t, s, d.ID)
	if c.Result != ResultSucceeded {
		t.Fatalf("result %q, want succeeded", c.Result)
	}
	if c.Decision.Code != CodeApproved || c.Decision.RuleID != a.rule || c.Decision.PolicyVersion != a.version ||
		c.Decision.IntentSource != "execution:"+a.executionID || c.Decision.ActionDigest == "" {
		t.Fatalf("decision links missing: %+v", c.Decision)
	}
	if c.Approval == nil || c.Approval.Status != RefFound || c.Approval.Approval.State != workitems.ApprovalConsumed {
		t.Fatalf("approval ref %+v, want found and consumed", c.Approval)
	}
	if len(c.Evidence) != 1 || c.Evidence[0].Status != RefFound || c.Evidence[0].AttemptNo != 1 {
		t.Fatalf("evidence refs %+v, want one found ref on attempt 1", c.Evidence)
	}
	if !equalStrings(statuses(c), []string{PhaseSucceeded}) {
		t.Fatalf("attempts %v", statuses(c))
	}
	// Nothing runs a second time once a decision has succeeded.
	if _, _, err := s.AppendAttempt(ctx, event(d.ID, 0, PhaseStarted)); !errors.Is(err, ErrAlreadySucceeded) {
		t.Fatalf("start after success: %v, want ErrAlreadySucceeded", err)
	}
}

// TestChainRefusal: a refusing decision is durable, has zero attempts by
// construction, and reads as refused.
func TestChainRefusal(t *testing.T) {
	s, wi, _ := newTestStores(t)
	ctx := context.Background()

	a := newAction()
	d := mustRecord(t, s, a.decision(CodeDenied, VerdictDeny, ""))
	if d.Permitted {
		t.Fatal("denied_by_rule must not be permitted")
	}
	if _, _, err := s.AppendAttempt(ctx, event(d.ID, 0, PhaseStarted)); !errors.Is(err, ErrNotPermitted) {
		t.Fatalf("start on a refusal: %v, want ErrNotPermitted", err)
	}
	c := mustChain(t, s, d.ID)
	if c.Result != ResultRefused || len(c.Attempts) != 0 {
		t.Fatalf("refusal chain: result %q attempts %d", c.Result, len(c.Attempts))
	}

	// A refusal that waits on a human names its pending aar_, which the
	// chain resolves.
	b := newAction()
	pending := approval(t, wi, b, workitems.ApprovalPending)
	pd := mustRecord(t, s, b.decision(CodeApprovalPending, VerdictRequireApproval, pending.ID))
	if _, _, err := s.AppendAttempt(ctx, event(pd.ID, 0, PhaseStarted)); !errors.Is(err, ErrNotPermitted) {
		t.Fatalf("start on approval_pending: %v, want ErrNotPermitted", err)
	}
	pc := mustChain(t, s, pd.ID)
	if pc.Result != ResultRefused || pc.Approval == nil || pc.Approval.Approval.State != workitems.ApprovalPending {
		t.Fatalf("pending chain: %+v / %+v", pc.Result, pc.Approval)
	}
}

// TestChainRetry: a failed attempt and its retry are two attempts; an HTTP
// retry of the same event is the same event, never a third attempt.
func TestChainRetry(t *testing.T) {
	s, _, _ := newTestStores(t)
	ctx := context.Background()
	d := mustRecord(t, s, newAction().decision(CodeAllowed, VerdictAllow, ""))

	start1 := event(d.ID, 0, PhaseStarted)
	mustAppend(t, s, start1)
	// The same start replayed: the stored event, no new attempt.
	again, created, err := s.AppendAttempt(ctx, start1)
	if err != nil || created || again.AttemptNo != 1 {
		t.Fatalf("replay: %+v created=%v err=%v, want attempt 1 not created", again, created, err)
	}
	// The same key with different content is a conflict, not an overwrite.
	changed := start1
	changed.RuntimeExecutionID = "ex-fedcba9876543210"
	if _, _, err := s.AppendAttempt(ctx, changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed replay: %v, want ErrIdempotencyConflict", err)
	}

	fail := event(d.ID, 1, PhaseFailed)
	fail.ErrorCode = "github.timeout"
	mustAppend(t, s, fail)
	if c := mustChain(t, s, d.ID); c.Result != ResultFailed {
		t.Fatalf("after failure: %q, want failed", c.Result)
	}

	if e := mustAppend(t, s, event(d.ID, 0, PhaseStarted)); e.AttemptNo != 2 {
		t.Fatalf("retry opened attempt %d, want 2", e.AttemptNo)
	}
	if c := mustChain(t, s, d.ID); c.Result != ResultInProgress {
		t.Fatalf("during retry: %q, want in_progress", c.Result)
	}
	mustAppend(t, s, event(d.ID, 2, PhaseSucceeded))

	c := mustChain(t, s, d.ID)
	if c.Result != ResultSucceeded || !equalStrings(statuses(c), []string{PhaseFailed, PhaseSucceeded}) {
		t.Fatalf("result %q attempts %v, want succeeded [failed succeeded]", c.Result, statuses(c))
	}
	// The failure is still there, with its code, after the success.
	if got := c.Attempts[0].Events[1].ErrorCode; got != "github.timeout" {
		t.Fatalf("attempt 1 error_code %q, want github.timeout", got)
	}
}

// TestChainPartialFailureRecovery: a partial attempt, an abandoned one and
// a recovering one stay three distinguishable attempts, and terminal events
// are checked against the attempt they close.
func TestChainPartialFailureRecovery(t *testing.T) {
	s, _, ev := newTestStores(t)
	ctx := context.Background()
	a := newAction()
	d := mustRecord(t, s, a.decision(CodeAllowed, VerdictAllow, ""))

	if _, _, err := s.AppendAttempt(ctx, event(d.ID, 1, PhaseSucceeded)); !errors.Is(err, ErrAttemptNotFound) {
		t.Fatalf("terminal before start: %v, want ErrAttemptNotFound", err)
	}

	mustAppend(t, s, event(d.ID, 0, PhaseStarted))
	partial := event(d.ID, 1, PhasePartial)
	partial.ErrorCode = "gitops.partial_apply"
	partial.EvidenceID = "ev-00000000000000b1"
	mustAppend(t, s, partial)
	ev.records[partial.EvidenceID] = &evidence.Evidence{ID: partial.EvidenceID, ExecutionID: a.executionID}
	if c := mustChain(t, s, d.ID); c.Result != ResultPartial {
		t.Fatalf("after partial: %q, want partial", c.Result)
	}
	closeAgain := event(d.ID, 1, PhaseSucceeded)
	if _, _, err := s.AppendAttempt(ctx, closeAgain); !errors.Is(err, ErrAttemptClosed) {
		t.Fatalf("second terminal on attempt 1: %v, want ErrAttemptClosed", err)
	}

	mustAppend(t, s, event(d.ID, 0, PhaseStarted)) // attempt 2: never reports back
	start3 := event(d.ID, 0, PhaseStarted)
	start3.RuntimeExecutionID = "ex-00000000000000c3"
	mustAppend(t, s, start3)
	done := event(d.ID, 3, PhaseSucceeded)
	done.EvidenceID = "ev-00000000000000c3"
	mustAppend(t, s, done)
	// Evidence keyed by the attempt's runtime execution, not the work one.
	ev.records[done.EvidenceID] = &evidence.Evidence{ID: done.EvidenceID, RuntimeExecutionID: start3.RuntimeExecutionID}

	c := mustChain(t, s, d.ID)
	if want := []string{PhasePartial, AttemptUnknown, PhaseSucceeded}; !equalStrings(statuses(c), want) {
		t.Fatalf("attempts %v, want %v", statuses(c), want)
	}
	if c.Result != ResultSucceeded {
		t.Fatalf("result %q, want succeeded", c.Result)
	}
	if len(c.Evidence) != 2 || c.Evidence[0].Status != RefFound || c.Evidence[1].Status != RefFound {
		t.Fatalf("evidence %+v, want two found refs", c.Evidence)
	}

	// The abandoned attempt reporting late is recorded, not refused: an
	// observed outcome is never dropped, even after recovery.
	late := event(d.ID, 2, PhaseFailed)
	late.ErrorCode = "worker.lost"
	mustAppend(t, s, late)
	c = mustChain(t, s, d.ID)
	if want := []string{PhasePartial, PhaseFailed, PhaseSucceeded}; !equalStrings(statuses(c), want) {
		t.Fatalf("after late report %v, want %v", statuses(c), want)
	}
	var seqs []int
	for _, at := range c.Attempts {
		for _, e := range at.Events {
			seqs = append(seqs, e.Seq)
		}
	}
	// Grouped by attempt, the late event (seq 6) sits under attempt 2: six
	// events, none lost or renumbered.
	if want := []int{1, 2, 3, 6, 4, 5}; len(seqs) != len(want) || fmt.Sprint(seqs) != fmt.Sprint(want) {
		t.Fatalf("event seqs %v, want %v", seqs, want)
	}
}

// TestChainReadsDecisionByID covers reconstruction from nothing but the id:
// unknown ids are not found, and every reference is resolved.
func TestChainReadsDecisionByID(t *testing.T) {
	s, _, _ := newTestStores(t)
	if _, err := s.Chain(context.Background(), "dec_doesnotexist"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id: %v, want ErrNotFound", err)
	}
	a := newAction()
	a.workItemID = "wi_" + uid()
	d := mustRecord(t, s, a.decision(CodeAllowed, VerdictAllow, ""))
	got, err := s.List(context.Background(), Filter{WorkItemID: a.workItemID})
	if err != nil || len(got.Decisions) != 1 || got.Decisions[0].ID != d.ID || got.Truncated {
		t.Fatalf("List by work item: %+v %v", got, err)
	}
	if _, err := s.List(context.Background(), Filter{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unfiltered List: %v, want ErrInvalid", err)
	}
}

// TestRecordApprovalBinding: a decision cannot claim an approval that binds
// a different action or never approved anything, and an approval that
// cannot be read refuses the write rather than passing.
func TestRecordApprovalBinding(t *testing.T) {
	s, wi, _ := newTestStores(t)
	ctx := context.Background()

	a := newAction()
	aar := approval(t, wi, a, workitems.ApprovalApproved)
	other := a
	other.args = digestOf("other-args")
	if _, _, err := s.Record(ctx, other.decision(CodeApproved, VerdictRequireApproval, aar.ID)); !errors.Is(err, ErrApprovalBinding) {
		t.Fatalf("different args: %v, want ErrApprovalBinding", err)
	}
	otherRule := a
	otherRule.version = "mctl-agents/policy/v1-merge-approval"
	if _, _, err := s.Record(ctx, otherRule.decision(CodeApproved, VerdictRequireApproval, aar.ID)); !errors.Is(err, ErrApprovalBinding) {
		t.Fatalf("different policy version: %v, want ErrApprovalBinding", err)
	}

	b := newAction()
	pending := approval(t, wi, b, workitems.ApprovalPending)
	if _, _, err := s.Record(ctx, b.decision(CodeApproved, VerdictRequireApproval, pending.ID)); !errors.Is(err, ErrApprovalBinding) {
		t.Fatalf("approved on a pending aar_: %v, want ErrApprovalBinding", err)
	}
	c := newAction()
	denied := approval(t, wi, c, workitems.ApprovalDenied)
	if _, _, err := s.Record(ctx, c.decision(CodeApproved, VerdictRequireApproval, denied.ID)); !errors.Is(err, ErrApprovalBinding) {
		t.Fatalf("approved on a denied aar_: %v, want ErrApprovalBinding", err)
	}
	// The denial itself records fine against the same aar_.
	deniedDec := mustRecord(t, s, c.decision(CodeApprovalDenied, VerdictRequireApproval, denied.ID))

	// A refusal keeps its reference even when the approval binds another
	// intent: that is exactly what approval_intent_mismatch reports. It
	// binds nothing, and the chain names the diverging field.
	mismatch := mustRecord(t, s, other.decision(CodeApprovalIntentMismatch, VerdictRequireApproval, aar.ID))
	if mismatch.IntentHash != "" {
		t.Fatalf("refusal bound intent_hash %q", mismatch.IntentHash)
	}
	if mc := mustChain(t, s, mismatch.ID); mc.Result != ResultRefused || mc.Approval.Status != RefMismatch ||
		mc.Approval.Detail != "args_digest differ from the approval" {
		t.Fatalf("intent-mismatch chain: %q / %+v", mc.Result, mc.Approval)
	}
	// A refusal about the very action its approval binds reads found.
	if dc := mustChain(t, s, deniedDec.ID); dc.Approval.Status != RefFound {
		t.Fatalf("denial chain: %+v, want found", dc.Approval)
	}

	if _, _, err := s.Record(ctx, a.decision(CodeApproved, VerdictRequireApproval, "aar_missing")); !errors.Is(err, ErrApprovalNotFound) {
		t.Fatalf("missing aar_: %v, want ErrApprovalNotFound", err)
	}

	s.SetLookups(failingApprovals{err: errors.New("connection reset")}, nil)
	if _, _, err := s.Record(ctx, a.decision(CodeApproved, VerdictRequireApproval, aar.ID)); !errors.Is(err, ErrUnobservable) {
		t.Fatalf("failing lookup: %v, want ErrUnobservable", err)
	}
	// A refusal that could not read its approval still records it.
	mustRecord(t, s, a.decision(CodeApprovalLookupError, VerdictRequireApproval, aar.ID))
	s.SetLookups(nil, nil)
	if _, _, err := s.Record(ctx, a.decision(CodeApproved, VerdictRequireApproval, aar.ID)); !errors.Is(err, ErrUnobservable) {
		t.Fatalf("no lookup: %v, want ErrUnobservable", err)
	}
}

// TestChainNeverPartial: a reference that cannot be read fails the chain; a
// reference the store reports absent, or about another execution, is
// reported as such.
func TestChainNeverPartial(t *testing.T) {
	s, wi, ev := newTestStores(t)
	ctx := context.Background()
	a := newAction()
	aar := approval(t, wi, a, workitems.ApprovalConsumed)
	d := mustRecord(t, s, a.decision(CodeApproved, VerdictRequireApproval, aar.ID))
	mustAppend(t, s, event(d.ID, 0, PhaseStarted))
	done := event(d.ID, 1, PhaseSucceeded)
	done.EvidenceID = "ev-00000000000000d1"
	mustAppend(t, s, done)

	if c := mustChain(t, s, d.ID); len(c.Evidence) != 1 || c.Evidence[0].Status != RefNotFound {
		t.Fatalf("missing evidence: %+v, want not_found", c.Evidence)
	}
	ev.records[done.EvidenceID] = &evidence.Evidence{ID: done.EvidenceID, ExecutionID: "we_someone-else"}
	if c := mustChain(t, s, d.ID); c.Evidence[0].Status != RefMismatch {
		t.Fatalf("foreign evidence: %+v, want mismatch", c.Evidence)
	}

	ev.err = errors.New("connection reset")
	if _, err := s.Chain(ctx, d.ID); !errors.Is(err, ErrUnobservable) {
		t.Fatalf("failing evidence read: %v, want ErrUnobservable", err)
	}
	ev.err = nil
	s.SetLookups(wi, nil)
	if _, err := s.Chain(ctx, d.ID); !errors.Is(err, ErrUnobservable) {
		t.Fatalf("no evidence store: %v, want ErrUnobservable", err)
	}
	s.SetLookups(failingApprovals{err: errors.New("connection reset")}, ev)
	if _, err := s.Chain(ctx, d.ID); !errors.Is(err, ErrUnobservable) {
		t.Fatalf("failing approval read: %v, want ErrUnobservable", err)
	}
	s.SetLookups(failingApprovals{err: fmt.Errorf("gone: %w", workitems.ErrApprovalNotFound)}, ev)
	if c := mustChain(t, s, d.ID); c.Approval.Status != RefNotFound {
		t.Fatalf("purged approval: %+v, want not_found", c.Approval)
	}
	// An approval whose binding no longer matches the one recorded is
	// shown as a mismatch, never as the authority for this decision.
	tampered := *aar
	tampered.IntentHash = digestOf("other-intent")
	s.SetLookups(fixedApproval{a: &tampered}, ev)
	if c := mustChain(t, s, d.ID); c.Approval.Status != RefMismatch {
		t.Fatalf("rebound approval: %+v, want mismatch", c.Approval)
	}
}

// TestRecordIsIdempotent: a replayed decision is the stored one; the same
// key with different content is refused, never overwritten.
func TestRecordIsIdempotent(t *testing.T) {
	s, _, _ := newTestStores(t)
	ctx := context.Background()
	in := newAction().decision(CodeAllowed, VerdictAllow, "")
	d := mustRecord(t, s, in)
	again, created, err := s.Record(ctx, in)
	if err != nil || created || again.ID != d.ID {
		t.Fatalf("replay: %v created=%v err=%v, want %s", again, created, err, d.ID)
	}
	in.Code, in.Verdict = CodeDenied, VerdictDeny
	if _, _, err := s.Record(ctx, in); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed replay: %v, want ErrIdempotencyConflict", err)
	}
	if got, _ := s.Get(ctx, d.ID); got.Code != CodeAllowed {
		t.Fatalf("stored code %q changed", got.Code)
	}
}

// TestRowsAreImmutable: the database itself refuses an UPDATE on either
// table, whatever the store does.
func TestRowsAreImmutable(t *testing.T) {
	s, _, _ := newTestStores(t)
	ctx := context.Background()
	d := mustRecord(t, s, newAction().decision(CodeAllowed, VerdictAllow, ""))
	mustAppend(t, s, event(d.ID, 0, PhaseStarted))
	if _, err := s.pool.Exec(ctx, `UPDATE decision_records SET code='denied_by_rule' WHERE id=$1`, d.ID); err == nil {
		t.Fatal("UPDATE decision_records succeeded")
	}
	if _, err := s.pool.Exec(ctx, `UPDATE decision_attempt_events SET phase='succeeded' WHERE decision_id=$1`, d.ID); err == nil {
		t.Fatal("UPDATE decision_attempt_events succeeded")
	}
}

// TestPurgeDeletesWholeDecisions: retention removes a decision with its
// attempts, and refuses a non-positive age.
func TestPurgeDeletesWholeDecisions(t *testing.T) {
	s, _, _ := newTestStores(t)
	ctx := context.Background()
	d := mustRecord(t, s, newAction().decision(CodeAllowed, VerdictAllow, ""))
	mustAppend(t, s, event(d.ID, 0, PhaseStarted))
	if _, err := s.PurgeOlderThan(ctx, 0); err == nil {
		t.Fatal("PurgeOlderThan(0) succeeded")
	}
	s.now = func() time.Time { return time.Now().UTC().Add(48 * time.Hour) }
	if _, err := s.PurgeOlderThan(ctx, time.Hour); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if _, err := s.Chain(ctx, d.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after purge: %v, want ErrNotFound", err)
	}
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM decision_attempt_events WHERE decision_id=$1`, d.ID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("orphan events: %d %v", n, err)
	}
}
