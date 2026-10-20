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
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/evidence"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Reference statuses in a Chain.
const (
	// RefFound: the referenced record was read and agrees with the chain.
	RefFound = "found"
	// RefNotFound: the store answered that the record does not exist (for
	// example, it aged out under its own retention). An observed absence,
	// reported, never silently dropped.
	RefNotFound = "not_found"
	// RefMismatch: the record exists but is about a different execution or
	// action than the chain that references it.
	RefMismatch = "mismatch"
)

// Attempt is one attempt with its events, in order.
type Attempt struct {
	AttemptNo int `json:"attempt_no"`
	// Status is the terminal phase, AttemptInProgress for the open latest
	// attempt, or AttemptUnknown for an open attempt a later one followed.
	Status string         `json:"status"`
	Events []AttemptEvent `json:"events"`
}

// ApprovalRef is the decision's aar_ as read now.
type ApprovalRef struct {
	ID       string                           `json:"id"`
	Status   string                           `json:"status"`
	Approval *workitems.ActionApprovalRequest `json:"approval,omitempty"`
	// Detail names what disagrees, for RefMismatch.
	Detail string `json:"detail,omitempty"`
}

// EvidenceRef is one ev- an attempt event references, as read now.
type EvidenceRef struct {
	ID        string             `json:"id"`
	AttemptNo int                `json:"attempt_no"`
	Seq       int                `json:"seq"`
	Status    string             `json:"status"`
	Evidence  *evidence.Evidence `json:"evidence,omitempty"`
	Detail    string             `json:"detail,omitempty"`
}

// Chain is everything a decision id reconstructs: intent, policy and
// authority (Decision), the approval it names, every attempt with its
// events, the evidence they reference, and the derived result.
type Chain struct {
	Decision *Decision     `json:"decision"`
	Approval *ApprovalRef  `json:"approval,omitempty"`
	Attempts []Attempt     `json:"attempts"`
	Evidence []EvidenceRef `json:"evidence"`
	Result   string        `json:"result"`
}

// groupAttempts folds events (seq order) into attempts (attempt order) and
// derives each attempt's status.
func groupAttempts(evs []AttemptEvent) []Attempt {
	byNo := map[int]*Attempt{}
	var order []int
	for i := range evs {
		e := evs[i]
		a, ok := byNo[e.AttemptNo]
		if !ok {
			a = &Attempt{AttemptNo: e.AttemptNo, Status: AttemptInProgress}
			byNo[e.AttemptNo] = a
			order = append(order, e.AttemptNo)
		}
		a.Events = append(a.Events, e)
		if IsTerminalPhase(e.Phase) {
			a.Status = e.Phase
		}
	}
	slices.Sort(order)
	out := make([]Attempt, 0, len(order))
	for i, n := range order {
		a := byNo[n]
		if a.Status == AttemptInProgress && i < len(order)-1 {
			a.Status = AttemptUnknown
		}
		out = append(out, *a)
	}
	return out
}

// deriveResult is the decision's terminal result: refused when it did not
// permit execution; otherwise succeeded once any attempt succeeded (a later
// duplicate success is still visible in Attempts); otherwise the latest
// attempt's status, or pending before the first attempt.
func deriveResult(d *Decision, attempts []Attempt) string {
	if !d.Permitted {
		return ResultRefused
	}
	if len(attempts) == 0 {
		return ResultPending
	}
	for i := range attempts {
		if attempts[i].Status == PhaseSucceeded {
			return ResultSucceeded
		}
	}
	switch last := attempts[len(attempts)-1].Status; last {
	case PhaseFailed:
		return ResultFailed
	case PhasePartial:
		return ResultPartial
	default:
		return ResultInProgress
	}
}

// Chain reconstructs a decision from its id. Every reference is resolved
// live; a reference the store reports absent is listed with RefNotFound,
// but a reference that could not be read at all (no store wired, or a read
// error) fails the whole call with ErrUnobservable. A partial chain is
// never returned as if it were complete.
func (s *Store) Chain(ctx context.Context, id string) (*Chain, error) {
	d, evs, err := s.snapshot(ctx, id)
	if err != nil {
		return nil, err
	}
	attempts := groupAttempts(evs)
	c := &Chain{Decision: d, Attempts: attempts, Evidence: []EvidenceRef{}, Result: deriveResult(d, attempts)}

	if d.ApprovalID != "" {
		ref, err := s.resolveApproval(ctx, d)
		if err != nil {
			return nil, err
		}
		c.Approval = ref
	}
	for i := range evs {
		e := &evs[i]
		if e.EvidenceID == "" {
			continue
		}
		ref, err := s.resolveEvidence(ctx, d, attempts, e)
		if err != nil {
			return nil, err
		}
		c.Evidence = append(c.Evidence, *ref)
	}
	return c, nil
}

// snapshot reads the decision and its events in one REPEATABLE READ
// transaction, so a concurrent purge cannot leave a decision that reads as
// having no attempts.
func (s *Store) snapshot(ctx context.Context, id string) (*Decision, []AttemptEvent, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, nil, fmt.Errorf("decisions: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	d, err := scanDecision(tx.QueryRow(ctx, `SELECT `+decisionColumns+` FROM decision_records WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, fmt.Errorf("decisions: %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("decisions: get %s: %w", id, err)
	}
	evs, err := events(ctx, tx, id)
	if err != nil {
		return nil, nil, err
	}
	return d, evs, nil
}

func (s *Store) resolveApproval(ctx context.Context, d *Decision) (*ApprovalRef, error) {
	if s.approvals == nil {
		return nil, fmt.Errorf("%w: approval %s: no action approval store", ErrUnobservable, d.ApprovalID)
	}
	a, err := s.approvals.ActionApproval(ctx, d.ApprovalID)
	if errors.Is(err, workitems.ErrApprovalNotFound) {
		return &ApprovalRef{ID: d.ApprovalID, Status: RefNotFound}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: approval %s: %w", ErrUnobservable, d.ApprovalID, err)
	}
	ref := &ApprovalRef{ID: d.ApprovalID, Status: RefFound, Approval: a}
	// Every decision's digests are compared with the approval's, so a
	// refusal naming an approval about another action (as
	// approval_intent_mismatch does) reads mismatch, with the fields named.
	// A permitting decision is also held to the intent_hash it bound at
	// write, so a chain never presents an approval that does not authorize
	// its action.
	mismatched := bindingMismatches(actionBinding{
		executionID: d.ExecutionID, workItemID: d.WorkItemID, actionKind: d.ActionKind,
		targetDigest: d.TargetDigest, argsDigest: d.ArgsDigest, ruleID: d.RuleID, policyVersion: d.PolicyVersion,
	}, a)
	if d.IntentHash != "" && a.IntentHash != d.IntentHash {
		mismatched = append(mismatched, "intent_hash")
	}
	if len(mismatched) > 0 {
		ref.Status, ref.Detail = RefMismatch, strings.Join(mismatched, ", ")+" differ from the approval"
	}
	return ref, nil
}

func (s *Store) resolveEvidence(ctx context.Context, d *Decision, attempts []Attempt, e *AttemptEvent) (*EvidenceRef, error) {
	if s.evidence == nil {
		return nil, fmt.Errorf("%w: evidence %s: no evidence store", ErrUnobservable, e.EvidenceID)
	}
	ref := &EvidenceRef{ID: e.EvidenceID, AttemptNo: e.AttemptNo, Seq: e.Seq}
	ev, err := s.evidence.Get(ctx, e.EvidenceID)
	if errors.Is(err, evidence.ErrEvidenceNotFound) {
		ref.Status = RefNotFound
		return ref, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: evidence %s: %w", ErrUnobservable, e.EvidenceID, err)
	}
	ref.Evidence = ev
	ref.Status = RefFound
	// Evidence must be about this decision's execution: its work execution
	// id is the decision's, or its runtime execution id is the attempt's.
	runtimeID := attemptRuntimeID(attempts, e.AttemptNo)
	switch {
	case ev.ExecutionID != "" && ev.ExecutionID == d.ExecutionID:
	case ev.RuntimeExecutionID != "" && (ev.RuntimeExecutionID == d.ExecutionID || ev.RuntimeExecutionID == runtimeID):
	default:
		ref.Status, ref.Detail = RefMismatch, "evidence is about a different execution"
	}
	return ref, nil
}

// attemptRuntimeID is the runtime execution id any event of the attempt
// carries.
func attemptRuntimeID(attempts []Attempt, no int) string {
	for i := range attempts {
		if attempts[i].AttemptNo != no {
			continue
		}
		for j := range attempts[i].Events {
			if id := attempts[i].Events[j].RuntimeExecutionID; id != "" {
				return id
			}
		}
	}
	return ""
}
