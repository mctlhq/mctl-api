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
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/evidence"
	"github.com/mctlhq/mctl-api/internal/pgshared"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// schema is two immutable tables. A BEFORE UPDATE trigger refuses every
// UPDATE on both, the execution_evidence_no_update shape: a retry or a late
// outcome is a new row, never an overwrite. DELETE stays permitted: it is
// the retention mechanism, and attempts cascade with their decision.
//
// There is no foreign key to work_items, action_approval_requests or
// execution_evidence: those have their own retention, and a decision must
// not die with a work-item purge. References are resolved, and reported
// missing explicitly, at read time (chain.go).
const schema = `
CREATE TABLE IF NOT EXISTS decision_records (
    id                       TEXT PRIMARY KEY,
    execution_id             TEXT NOT NULL,
    work_item_id             TEXT NOT NULL DEFAULT '',
    intent_source            TEXT NOT NULL DEFAULT '',
    trace_id                 TEXT NOT NULL DEFAULT '',
    policy_version           TEXT NOT NULL,
    rule_id                  TEXT NOT NULL DEFAULT '',
    verdict                  TEXT NOT NULL CHECK (verdict IN ('allow', 'deny', 'require_approval')),
    code                     TEXT NOT NULL,
    policy_reasons           TEXT[] NOT NULL DEFAULT '{}',
    actor                    TEXT NOT NULL,
    principal_id             TEXT NOT NULL DEFAULT '',
    tenant                   TEXT NOT NULL DEFAULT '',
    approval_id              TEXT NOT NULL DEFAULT '',
    authority_basis          TEXT NOT NULL DEFAULT '',
    action_kind              TEXT NOT NULL,
    operation                TEXT NOT NULL,
    target_digest            TEXT NOT NULL,
    args_digest              TEXT NOT NULL,
    action_digest            TEXT NOT NULL,
    intent_hash              TEXT NOT NULL DEFAULT '',
    decided_at               TIMESTAMPTZ NOT NULL,
    content_digest           TEXT NOT NULL,
    idempotency_key          TEXT NOT NULL,
    recorded_by              TEXT NOT NULL,
    recorded_by_principal_id TEXT NOT NULL DEFAULT '',
    recorded_at              TIMESTAMPTZ NOT NULL,
    schema_version           TEXT NOT NULL,
    UNIQUE (recorded_by, idempotency_key),
    CONSTRAINT decision_records_approved_has_approval CHECK (code <> 'approved' OR approval_id <> '')
);
CREATE INDEX IF NOT EXISTS decision_records_execution
    ON decision_records (execution_id, recorded_at DESC);
CREATE INDEX IF NOT EXISTS decision_records_work_item
    ON decision_records (work_item_id, recorded_at DESC) WHERE work_item_id <> '';
CREATE INDEX IF NOT EXISTS decision_records_approval
    ON decision_records (approval_id) WHERE approval_id <> '';
CREATE INDEX IF NOT EXISTS decision_records_recorded
    ON decision_records (recorded_at DESC);

CREATE TABLE IF NOT EXISTS decision_attempt_events (
    decision_id              TEXT NOT NULL REFERENCES decision_records (id) ON DELETE CASCADE,
    seq                      INTEGER NOT NULL CHECK (seq >= 1),
    attempt_no               INTEGER NOT NULL CHECK (attempt_no >= 1),
    phase                    TEXT NOT NULL CHECK (phase IN ('started', 'succeeded', 'failed', 'partial')),
    evidence_id              TEXT NOT NULL DEFAULT '',
    runtime_execution_id     TEXT NOT NULL DEFAULT '',
    commerce_invocation_id   TEXT NOT NULL DEFAULT '',
    error_code               TEXT NOT NULL DEFAULT '',
    result_digest            TEXT NOT NULL DEFAULT '',
    occurred_at              TIMESTAMPTZ NOT NULL,
    idempotency_key          TEXT NOT NULL,
    recorded_by              TEXT NOT NULL,
    recorded_by_principal_id TEXT NOT NULL DEFAULT '',
    recorded_at              TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (decision_id, seq),
    UNIQUE (decision_id, idempotency_key)
);
-- Backstops for the store's own checks: one start and at most one terminal
-- event per attempt, however callers race.
CREATE UNIQUE INDEX IF NOT EXISTS decision_attempt_events_one_start
    ON decision_attempt_events (decision_id, attempt_no) WHERE phase = 'started';
CREATE UNIQUE INDEX IF NOT EXISTS decision_attempt_events_one_end
    ON decision_attempt_events (decision_id, attempt_no) WHERE phase <> 'started';
CREATE INDEX IF NOT EXISTS decision_attempt_events_evidence
    ON decision_attempt_events (evidence_id) WHERE evidence_id <> '';

CREATE OR REPLACE FUNCTION decision_records_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION '% rows are immutable', TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'decision_records_no_update') THEN
        CREATE TRIGGER decision_records_no_update
            BEFORE UPDATE ON decision_records
            FOR EACH ROW EXECUTE FUNCTION decision_records_immutable();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'decision_attempt_events_no_update') THEN
        CREATE TRIGGER decision_attempt_events_no_update
            BEFORE UPDATE ON decision_attempt_events
            FOR EACH ROW EXECUTE FUNCTION decision_records_immutable();
    END IF;
END;
$$;
`

// ApprovalLookup reads one action approval request (workitems.Store).
type ApprovalLookup interface {
	ActionApproval(ctx context.Context, id string) (*workitems.ActionApprovalRequest, error)
}

// EvidenceLookup reads one sealed evidence record (evidence.Store).
type EvidenceLookup interface {
	Get(ctx context.Context, id string) (*evidence.Evidence, error)
}

// Store persists decisions and their attempt events.
type Store struct {
	pool        *pgxpool.Pool
	releaseOnce sync.Once
	now         func() time.Time

	// approvals and evidence resolve references. Nil means the reference
	// cannot be observed: a write naming an approval is refused, and a
	// chain naming one fails, rather than reading the reference as absent.
	approvals ApprovalLookup
	evidence  EvidenceLookup
}

// NewStore connects, applies the schema and returns a ready store.
func NewStore(ctx context.Context, connStr string) (*Store, error) {
	pool, err := pgshared.Open(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("decisions: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pgshared.Release(pool)
		return nil, fmt.Errorf("decisions: ping: %w", err)
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pgshared.Release(pool)
		return nil, fmt.Errorf("decisions: schema: %w", err)
	}
	slog.Info("decision record store initialized")
	return &Store{pool: pool, now: func() time.Time { return time.Now().UTC() }}, nil
}

// SetLookups wires the reference resolvers. Call once, before serving.
func (s *Store) SetLookups(approvals ApprovalLookup, ev EvidenceLookup) {
	s.approvals = approvals
	s.evidence = ev
}

// Close releases the pool.
func (s *Store) Close() {
	if s != nil && s.pool != nil {
		s.releaseOnce.Do(func() { pgshared.Release(s.pool) })
	}
}

const decisionColumns = `id, execution_id, work_item_id, intent_source, trace_id, policy_version,
	rule_id, verdict, code, policy_reasons, actor, principal_id, tenant, approval_id, authority_basis,
	action_kind, operation, target_digest, args_digest, action_digest, intent_hash, decided_at,
	content_digest, idempotency_key, recorded_by, recorded_by_principal_id, recorded_at, schema_version`

func scanDecision(row pgx.Row) (*Decision, error) {
	var d Decision
	if err := row.Scan(&d.ID, &d.ExecutionID, &d.WorkItemID, &d.IntentSource, &d.TraceID, &d.PolicyVersion,
		&d.RuleID, &d.Verdict, &d.Code, &d.PolicyReasons, &d.Actor, &d.PrincipalID, &d.Tenant, &d.ApprovalID,
		&d.AuthorityBasis, &d.ActionKind, &d.Operation, &d.TargetDigest, &d.ArgsDigest, &d.ActionDigest,
		&d.IntentHash, &d.DecidedAt, &d.ContentDigest, &d.IdempotencyKey, &d.RecordedBy,
		&d.RecordedByPrincipalID, &d.RecordedAt, &d.SchemaVersion); err != nil {
		return nil, err
	}
	d.DecidedAt = d.DecidedAt.UTC()
	d.RecordedAt = d.RecordedAt.UTC()
	d.Permitted = Permitted(d.Code)
	return &d, nil
}

const eventColumns = `decision_id, seq, attempt_no, phase, evidence_id, runtime_execution_id,
	commerce_invocation_id, error_code, result_digest, occurred_at, idempotency_key, recorded_by,
	recorded_by_principal_id, recorded_at`

func scanEvent(row pgx.Row) (*AttemptEvent, error) {
	var e AttemptEvent
	if err := row.Scan(&e.DecisionID, &e.Seq, &e.AttemptNo, &e.Phase, &e.EvidenceID, &e.RuntimeExecutionID,
		&e.CommerceInvocationID, &e.ErrorCode, &e.ResultDigest, &e.OccurredAt, &e.IdempotencyKey,
		&e.RecordedBy, &e.RecordedByPrincipalID, &e.RecordedAt); err != nil {
		return nil, err
	}
	e.OccurredAt = e.OccurredAt.UTC()
	e.RecordedAt = e.RecordedAt.UTC()
	return &e, nil
}

// actionBinding is what a decision and an approval must agree on for the
// approval to be about this action.
type actionBinding struct {
	executionID, workItemID, actionKind, targetDigest, argsDigest, ruleID, policyVersion string
}

// bindingMismatches names every binding field on which b and the approval
// disagree; nil when the approval is about exactly this action.
func bindingMismatches(b actionBinding, a *workitems.ActionApprovalRequest) []string {
	var mismatched []string
	for _, f := range []struct {
		name      string
		got, want string
	}{
		{"execution_id", b.executionID, a.ExecutionID},
		{"action_kind", b.actionKind, a.ActionKind},
		{"target_digest", b.targetDigest, TargetDigest(a.Target)},
		{"args_digest", b.argsDigest, a.ArgsDigest},
		{"rule_id", b.ruleID, a.PolicyRuleID},
		{"policy_version", b.policyVersion, a.PolicyVersion},
	} {
		if f.got != f.want {
			mismatched = append(mismatched, f.name)
		}
	}
	if b.workItemID != "" && a.WorkItemID != "" && b.workItemID != a.WorkItemID {
		mismatched = append(mismatched, "work_item_id")
	}
	return mismatched
}

// checkApprovalBinding refuses an approval that is not bound to exactly
// this action under exactly this rule, or that never reached a human
// approval. It runs for permitting decisions only, against the stored aar_,
// so a decision cannot claim an approval it does not have.
func checkApprovalBinding(in *DecisionInput, a *workitems.ActionApprovalRequest) error {
	// validate() admits an approval on a permitting decision only with
	// code approved; refuse anything else here too rather than rely on it.
	if in.Code != CodeApproved {
		return fmt.Errorf("%w: only code approved is bound to an approval, got %s", ErrApprovalBinding, in.Code)
	}
	mismatched := bindingMismatches(actionBinding{
		executionID: in.ExecutionID, workItemID: in.WorkItemID, actionKind: in.ActionKind,
		targetDigest: in.TargetDigest, argsDigest: in.ArgsDigest, ruleID: in.RuleID, policyVersion: in.PolicyVersion,
	}, a)
	if len(mismatched) > 0 {
		return fmt.Errorf("%w: %s differs from %s (%s)", ErrApprovalBinding,
			strings.Join(mismatched, ", "), a.ID, "the approval binds a different action")
	}
	switch a.State {
	case workitems.ApprovalApproved, workitems.ApprovalConsumed, workitems.ApprovalExecuted:
		return nil
	case workitems.ApprovalExpired:
		// Lazy expiry hides whether the request was ever decided; a
		// decided one that expired after this decision was approved.
		// Denied requests keep their stored state and never read expired.
		if a.DecidedAt != nil {
			return nil
		}
	}
	return fmt.Errorf("%w: %s is %s, which never authorized execution", ErrApprovalBinding, a.ID, a.State)
}

// Record stores one decision. The same (recorded_by, idempotency_key) with
// the same content returns the stored record (created=false); with
// different content it is ErrIdempotencyConflict.
func (s *Store) Record(ctx context.Context, in DecisionInput) (*Decision, bool, error) {
	if err := in.validate(); err != nil {
		return nil, false, err
	}
	// TIMESTAMPTZ keeps microseconds: digest the instant as it is stored.
	in.DecidedAt = in.DecidedAt.UTC().Truncate(time.Microsecond)
	if in.PolicyReasons == nil {
		in.PolicyReasons = []string{}
	}
	digest := in.contentDigest()

	// A replay must not depend on the approval still being readable or in
	// the same state: the binding was checked when the record was first
	// written.
	if existing, err := s.byIdempotencyKey(ctx, in.RecordedBy, in.IdempotencyKey); err == nil {
		if existing.ContentDigest != digest {
			return nil, false, fmt.Errorf("%w: %s", ErrIdempotencyConflict, existing.ID)
		}
		return existing, false, nil
	} else if !errors.Is(err, ErrNotFound) {
		return nil, false, err
	}

	// Only a permitting decision claims its approval as authority, so only
	// it is resolved and bound at write. A refusal names the approval it is
	// about, which may by definition bind something else
	// (approval_intent_mismatch) or be unreadable (approval_lookup_error):
	// it is kept as a reference and resolved, never bound, at read.
	var intentHash string
	if in.ApprovalID != "" && Permitted(in.Code) {
		if s.approvals == nil {
			return nil, false, fmt.Errorf("%w: approval %s: no action approval store", ErrUnobservable, in.ApprovalID)
		}
		a, err := s.approvals.ActionApproval(ctx, in.ApprovalID)
		switch {
		case errors.Is(err, workitems.ErrApprovalNotFound):
			return nil, false, fmt.Errorf("%w: %s", ErrApprovalNotFound, in.ApprovalID)
		case err != nil:
			return nil, false, fmt.Errorf("%w: approval %s: %w", ErrUnobservable, in.ApprovalID, err)
		}
		if err := checkApprovalBinding(&in, a); err != nil {
			return nil, false, err
		}
		intentHash = a.IntentHash
	}

	id := DecisionIDPrefix + strings.ReplaceAll(uuid.NewString(), "-", "")
	d, err := scanDecision(s.pool.QueryRow(ctx, `
INSERT INTO decision_records (`+decisionColumns+`)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28)
ON CONFLICT (recorded_by, idempotency_key) DO NOTHING
RETURNING `+decisionColumns,
		id, in.ExecutionID, in.WorkItemID, in.IntentSource, in.TraceID, in.PolicyVersion,
		in.RuleID, in.Verdict, in.Code, in.PolicyReasons, in.Actor, in.PrincipalID, in.Tenant, in.ApprovalID,
		in.AuthorityBasis, in.ActionKind, in.Operation, in.TargetDigest, in.ArgsDigest, in.ActionDigest,
		intentHash, in.DecidedAt, digest, in.IdempotencyKey, in.RecordedBy, in.RecordedByPrincipalID,
		s.now(), SchemaVersion))
	if errors.Is(err, pgx.ErrNoRows) {
		// Lost a race with a concurrent write of the same key.
		existing, gerr := s.byIdempotencyKey(ctx, in.RecordedBy, in.IdempotencyKey)
		if gerr != nil {
			return nil, false, gerr
		}
		if existing.ContentDigest != digest {
			return nil, false, fmt.Errorf("%w: %s", ErrIdempotencyConflict, existing.ID)
		}
		return existing, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("decisions: insert: %w", err)
	}
	return d, true, nil
}

func (s *Store) byIdempotencyKey(ctx context.Context, recordedBy, key string) (*Decision, error) {
	d, err := scanDecision(s.pool.QueryRow(ctx,
		`SELECT `+decisionColumns+` FROM decision_records WHERE recorded_by=$1 AND idempotency_key=$2`,
		recordedBy, key))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("decisions: lookup idempotency key: %w", err)
	}
	return d, nil
}

// Get returns one decision.
func (s *Store) Get(ctx context.Context, id string) (*Decision, error) {
	d, err := scanDecision(s.pool.QueryRow(ctx, `SELECT `+decisionColumns+` FROM decision_records WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("decisions: %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("decisions: get %s: %w", id, err)
	}
	return d, nil
}

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// events returns every event of a decision in seq order. A scan or
// iteration error is returned, never a shorter list.
func events(ctx context.Context, q querier, decisionID string) ([]AttemptEvent, error) {
	rows, err := q.Query(ctx, `SELECT `+eventColumns+` FROM decision_attempt_events
WHERE decision_id=$1 ORDER BY seq`, decisionID)
	if err != nil {
		return nil, fmt.Errorf("decisions: events %s: %w", decisionID, err)
	}
	defer rows.Close()
	out := []AttemptEvent{}
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("decisions: scan event: %w", err)
		}
		out = append(out, *e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("decisions: events %s: %w", decisionID, err)
	}
	return out, nil
}

// Events returns every attempt event of a decision in order.
// ErrNotFound when the decision does not exist.
func (s *Store) Events(ctx context.Context, decisionID string) ([]AttemptEvent, error) {
	_, evs, err := s.snapshot(ctx, decisionID)
	return evs, err
}

func sameEvent(e *AttemptEvent, in *AttemptInput) bool {
	return e.Phase == in.Phase &&
		(in.Phase == PhaseStarted || e.AttemptNo == in.AttemptNo) &&
		e.EvidenceID == in.EvidenceID &&
		e.RuntimeExecutionID == in.RuntimeExecutionID &&
		e.CommerceInvocationID == in.CommerceInvocationID &&
		e.ErrorCode == in.ErrorCode &&
		e.ResultDigest == in.ResultDigest &&
		e.OccurredAt.Equal(in.OccurredAt) &&
		e.RecordedBy == in.RecordedBy
}

// AppendAttempt appends one event under the decision's row lock:
//
//   - a started event opens attempt max+1, only on a permitting decision
//     and only while no attempt has succeeded;
//   - a terminal event closes one started, still-open attempt;
//   - nothing is ever rewritten: a retry is a new attempt, and an attempt
//     abandoned without a terminal event stays open (read as unknown).
//
// The same idempotency key with the same content returns the stored event
// (created=false); with different content it is ErrIdempotencyConflict.
func (s *Store) AppendAttempt(ctx context.Context, in AttemptInput) (*AttemptEvent, bool, error) {
	if err := in.validate(); err != nil {
		return nil, false, err
	}
	// TIMESTAMPTZ keeps microseconds: normalize before comparing with a
	// stored event, or a replay carrying nanoseconds reads as a conflict.
	in.OccurredAt = in.OccurredAt.UTC().Truncate(time.Microsecond)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("decisions: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once Commit has succeeded

	var code string
	err = tx.QueryRow(ctx, `SELECT code FROM decision_records WHERE id=$1 FOR UPDATE`, in.DecisionID).Scan(&code)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, fmt.Errorf("decisions: %s: %w", in.DecisionID, ErrNotFound)
	}
	if err != nil {
		return nil, false, fmt.Errorf("decisions: lock %s: %w", in.DecisionID, err)
	}

	evs, err := events(ctx, tx, in.DecisionID)
	if err != nil {
		return nil, false, err
	}
	if i := slices.IndexFunc(evs, func(e AttemptEvent) bool { return e.IdempotencyKey == in.IdempotencyKey }); i >= 0 {
		if !sameEvent(&evs[i], &in) {
			return nil, false, fmt.Errorf("%w: event %d of %s", ErrIdempotencyConflict, evs[i].Seq, in.DecisionID)
		}
		return &evs[i], false, nil
	}

	attemptNo, err := nextAttempt(code, evs, &in)
	if err != nil {
		return nil, false, err
	}

	e, err := scanEvent(tx.QueryRow(ctx, `
INSERT INTO decision_attempt_events (`+eventColumns+`)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
RETURNING `+eventColumns,
		in.DecisionID, len(evs)+1, attemptNo, in.Phase, in.EvidenceID, in.RuntimeExecutionID,
		in.CommerceInvocationID, in.ErrorCode, in.ResultDigest, in.OccurredAt, in.IdempotencyKey,
		in.RecordedBy, in.RecordedByPrincipalID, s.now()))
	if err != nil {
		return nil, false, fmt.Errorf("decisions: insert event: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, fmt.Errorf("decisions: commit: %w", err)
	}
	return e, true, nil
}

// nextAttempt applies the attempt rules to the decision's existing events
// and returns the attempt number the new event belongs to.
func nextAttempt(code string, evs []AttemptEvent, in *AttemptInput) (int, error) {
	maxAttempt := 0
	started := map[int]bool{}
	closed := map[int]bool{}
	succeeded := false
	for i := range evs {
		e := &evs[i]
		maxAttempt = max(maxAttempt, e.AttemptNo)
		if e.Phase == PhaseStarted {
			started[e.AttemptNo] = true
			continue
		}
		closed[e.AttemptNo] = true
		if e.Phase == PhaseSucceeded {
			succeeded = true
		}
	}

	if in.Phase == PhaseStarted {
		if !Permitted(code) {
			return 0, fmt.Errorf("%w: %s refused it (%s)", ErrNotPermitted, in.DecisionID, code)
		}
		if succeeded {
			return 0, fmt.Errorf("%w: %s", ErrAlreadySucceeded, in.DecisionID)
		}
		if maxAttempt >= maxAttemptsPerDec {
			return 0, fmt.Errorf("%w: %d", ErrTooManyAttempts, maxAttemptsPerDec)
		}
		return maxAttempt + 1, nil
	}

	if !started[in.AttemptNo] {
		return 0, fmt.Errorf("%w: attempt %d of %s was never started", ErrAttemptNotFound, in.AttemptNo, in.DecisionID)
	}
	if closed[in.AttemptNo] {
		return 0, fmt.Errorf("%w: attempt %d of %s", ErrAttemptClosed, in.AttemptNo, in.DecisionID)
	}
	return in.AttemptNo, nil
}

// Filter narrows List. At least one field must be set.
type Filter struct {
	ExecutionID string
	WorkItemID  string
	ApprovalID  string
	Limit       int
}

// ListResult is a bounded page, newest first. Truncated is part of the
// answer: a clipped page never reads as a complete one.
type ListResult struct {
	Decisions []*Decision `json:"decisions"`
	Truncated bool        `json:"truncated"`
	Limit     int         `json:"limit"`
}

// List finds decisions by one of their correlation ids.
func (s *Store) List(ctx context.Context, f Filter) (*ListResult, error) {
	var where []string
	var args []any
	for _, c := range [][2]string{
		{"execution_id", f.ExecutionID}, {"work_item_id", f.WorkItemID}, {"approval_id", f.ApprovalID},
	} {
		if c[1] == "" {
			continue
		}
		args = append(args, c[1])
		where = append(where, fmt.Sprintf("%s=$%d", c[0], len(args)))
	}
	if len(where) == 0 {
		return nil, invalid("one of execution_id, work_item_id or approval_id is required")
	}
	limit := f.Limit
	if limit <= 0 {
		limit = defaultList
	}
	limit = min(limit, MaxList)
	args = append(args, limit+1)
	rows, err := s.pool.Query(ctx, `SELECT `+decisionColumns+` FROM decision_records WHERE `+
		strings.Join(where, " AND ")+fmt.Sprintf(" ORDER BY recorded_at DESC, id LIMIT $%d", len(args)), args...)
	if err != nil {
		return nil, fmt.Errorf("decisions: list: %w", err)
	}
	defer rows.Close()
	out := &ListResult{Decisions: []*Decision{}, Limit: limit}
	for rows.Next() {
		d, err := scanDecision(rows)
		if err != nil {
			return nil, fmt.Errorf("decisions: scan: %w", err)
		}
		out.Decisions = append(out.Decisions, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("decisions: list: %w", err)
	}
	if len(out.Decisions) > limit {
		out.Decisions = out.Decisions[:limit]
		out.Truncated = true
	}
	return out, nil
}

// PurgeOlderThan deletes whole decisions recorded more than maxAge ago,
// with their attempt events (ON DELETE CASCADE). Retention never redacts a
// record partially.
func (s *Store) PurgeOlderThan(ctx context.Context, maxAge time.Duration) (int64, error) {
	// A non-positive age would put the cutoff at or after now and delete
	// every row.
	if maxAge <= 0 {
		return 0, fmt.Errorf("decisions: purge: maxAge must be positive, got %s", maxAge)
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM decision_records WHERE recorded_at < $1`, s.now().Add(-maxAge))
	if err != nil {
		return 0, fmt.Errorf("decisions: purge: %w", err)
	}
	return tag.RowsAffected(), nil
}
