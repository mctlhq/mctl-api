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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/pgshared"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// schema is applied idempotently at NewStore, the repo convention
// (internal/evidence, internal/workitems). Lifecycle state lives only on
// security_occurrences. Observations, verifications and occurrence events are
// immutable (BEFORE UPDATE triggers). work_item_id is a correlation, not a
// foreign key (docs/work-context-contract.md): history survives a WorkItem
// retention purge.
const schema = `
CREATE TABLE IF NOT EXISTS security_findings (
    id               TEXT PRIMARY KEY,
    tenant           TEXT NOT NULL,
    identity_kind    TEXT NOT NULL,
    identity_key     TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL,
    last_observed_at TIMESTAMPTZ NOT NULL,
    schema_version   TEXT NOT NULL,
    CONSTRAINT security_findings_id_shape CHECK (id LIKE 'sf\_%'),
    CONSTRAINT security_findings_kind CHECK (identity_kind IN ('cve', 'ghsa', 'rule')),
    UNIQUE (tenant, identity_key)
);

CREATE TABLE IF NOT EXISTS security_finding_aliases (
    tenant     TEXT NOT NULL,
    alias_key  TEXT NOT NULL,
    finding_id TEXT NOT NULL REFERENCES security_findings (id),
    PRIMARY KEY (tenant, alias_key)
);
CREATE INDEX IF NOT EXISTS security_finding_aliases_finding
    ON security_finding_aliases (finding_id);

CREATE TABLE IF NOT EXISTS security_occurrences (
    id                        TEXT PRIMARY KEY,
    finding_id                TEXT NOT NULL REFERENCES security_findings (id),
    tenant                    TEXT NOT NULL,
    subject_fingerprint       TEXT NOT NULL,
    subject                   JSONB NOT NULL,
    state                     TEXT NOT NULL,
    state_version             BIGINT NOT NULL DEFAULT 1,
    active_attempt_id         TEXT NULL,
    current_affected_revision TEXT NOT NULL DEFAULT '',
    current_affected_artifact TEXT NOT NULL DEFAULT '',
    dismissal_reason          TEXT NOT NULL DEFAULT '',
    dismissal_authority_ref   TEXT NOT NULL DEFAULT '',
    dismissed_by              TEXT NOT NULL DEFAULT '',
    created_at                TIMESTAMPTZ NOT NULL,
    updated_at                TIMESTAMPTZ NOT NULL,
    last_observed_at          TIMESTAMPTZ NOT NULL,
    CONSTRAINT security_occurrences_id_shape CHECK (id LIKE 'soc\_%'),
    CONSTRAINT security_occurrences_state CHECK (state IN
        ('open', 'triaged', 'fixing', 'awaiting_verification', 'resolved', 'reopened', 'unverifiable', 'dismissed')),
    UNIQUE (finding_id, subject_fingerprint)
);
CREATE INDEX IF NOT EXISTS security_occurrences_tenant_state
    ON security_occurrences (tenant, state);
CREATE INDEX IF NOT EXISTS security_occurrences_repository
    ON security_occurrences ((subject->>'repository'));

CREATE TABLE IF NOT EXISTS security_observations (
    id                         TEXT PRIMARY KEY,
    occurrence_id              TEXT NOT NULL REFERENCES security_occurrences (id),
    tenant                     TEXT NOT NULL,
    provider_ref               TEXT NOT NULL,
    observation_hash           TEXT NOT NULL,
    delivery_id                TEXT NOT NULL DEFAULT '',
    source_finding_id          TEXT NOT NULL DEFAULT '',
    claimed_action             TEXT NOT NULL,
    observed_revision          TEXT NOT NULL DEFAULT '',
    observed_artifact_digest   TEXT NOT NULL DEFAULT '',
    evidence_refs              JSONB NOT NULL DEFAULT '[]',
    evidence_digest            TEXT NOT NULL DEFAULT '',
    untrusted                  JSONB NOT NULL DEFAULT '{}',
    observed_at                TIMESTAMPTZ NOT NULL,
    ingested_at                TIMESTAMPTZ NOT NULL,
    ingested_by_principal_id   TEXT NOT NULL DEFAULT '',
    CONSTRAINT security_observations_id_shape CHECK (id LIKE 'sob\_%'),
    CONSTRAINT security_observations_action CHECK (claimed_action IN ('present', 'fixed', 'absent', 'withdrawn')),
    UNIQUE (provider_ref, observation_hash)
);
CREATE INDEX IF NOT EXISTS security_observations_occurrence
    ON security_observations (occurrence_id, observed_at);

CREATE TABLE IF NOT EXISTS security_remediation_attempts (
    id                      TEXT PRIMARY KEY,
    occurrence_id           TEXT NOT NULL REFERENCES security_occurrences (id),
    tenant                  TEXT NOT NULL,
    seq                     INT NOT NULL,
    work_item_id            TEXT NOT NULL,
    execution_id            TEXT NOT NULL DEFAULT '',
    devloop_workflow_id     TEXT NOT NULL DEFAULT '',
    started_by              TEXT NOT NULL,
    started_by_principal_id TEXT NOT NULL DEFAULT '',
    start_source            TEXT NOT NULL DEFAULT '',
    affected_revisions      JSONB NOT NULL DEFAULT '[]',
    candidate_revision      TEXT NOT NULL DEFAULT '',
    landed_revision         TEXT NOT NULL DEFAULT '',
    landed_artifact_digest  TEXT NOT NULL DEFAULT '',
    landed_ref              TEXT NOT NULL DEFAULT '',
    outcome                 TEXT NULL,
    started_at              TIMESTAMPTZ NOT NULL,
    landed_at               TIMESTAMPTZ NULL,
    ended_at                TIMESTAMPTZ NULL,
    CONSTRAINT security_attempts_id_shape CHECK (id LIKE 'sra\_%'),
    CONSTRAINT security_attempts_work_item_shape CHECK (work_item_id LIKE 'wi\_%'),
    CONSTRAINT security_attempts_outcome CHECK (outcome IS NULL OR outcome IN ('resolved', 'superseded', 'cancelled_dismissed')),
    UNIQUE (occurrence_id, seq)
);
CREATE UNIQUE INDEX IF NOT EXISTS security_attempts_one_active
    ON security_remediation_attempts (occurrence_id) WHERE outcome IS NULL;

CREATE TABLE IF NOT EXISTS security_verifications (
    id                        TEXT PRIMARY KEY,
    attempt_id                TEXT NOT NULL REFERENCES security_remediation_attempts (id),
    occurrence_id             TEXT NOT NULL REFERENCES security_occurrences (id),
    mechanism                 TEXT NOT NULL,
    declared_strength         TEXT NOT NULL,
    derived_strength          TEXT NOT NULL,
    result                    TEXT NOT NULL,
    revision                  TEXT NOT NULL DEFAULT '',
    artifact_digest           TEXT NOT NULL DEFAULT '',
    evidence_refs             JSONB NOT NULL DEFAULT '[]',
    recorded_by               TEXT NOT NULL,
    recorded_by_principal_id  TEXT NOT NULL DEFAULT '',
    source_observation_id     TEXT NOT NULL DEFAULT '',
    recorded_at               TIMESTAMPTZ NOT NULL,
    CONSTRAINT security_verifications_id_shape CHECK (id LIKE 'svr\_%'),
    CONSTRAINT security_verifications_result CHECK (result IN
        ('passed', 'failed', 'unavailable', 'error', 'timeout', 'unverifiable'))
);
CREATE INDEX IF NOT EXISTS security_verifications_attempt
    ON security_verifications (attempt_id, recorded_at);

CREATE TABLE IF NOT EXISTS security_occurrence_events (
    occurrence_id      TEXT NOT NULL REFERENCES security_occurrences (id),
    seq                INT NOT NULL,
    kind               TEXT NOT NULL,
    from_state         TEXT NOT NULL DEFAULT '',
    to_state           TEXT NOT NULL DEFAULT '',
    actor_principal    TEXT NOT NULL,
    actor_principal_id TEXT NOT NULL DEFAULT '',
    via_principal_id   TEXT NOT NULL DEFAULT '',
    source             TEXT NOT NULL,
    reason             TEXT NOT NULL DEFAULT '',
    refs               JSONB NOT NULL DEFAULT '{}',
    created_at         TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (occurrence_id, seq)
);

CREATE TABLE IF NOT EXISTS security_requests (
    scope           TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    operation       TEXT NOT NULL,
    request_hash    TEXT NOT NULL,
    actor           TEXT NOT NULL,
    result          JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (scope, idempotency_key)
);

CREATE OR REPLACE FUNCTION security_rows_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION '% rows are immutable', TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;
DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['security_observations', 'security_verifications', 'security_occurrence_events']
    LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = t || '_no_update') THEN
            EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION security_rows_immutable()', t || '_no_update', t);
        END IF;
    END LOOP;
END;
$$;
`

// WorkItemLookup is the slice of the work-items store a remediation attempt
// needs: the WorkItem must exist, in the occurrence's tenant.
type WorkItemLookup interface {
	Get(ctx context.Context, id string) (*workitems.WorkItem, error)
}

// Store is the Postgres-backed SecurityFinding store. Every mutation runs in
// one transaction under advisory locks keyed on the finding identity or the
// occurrence, so racing producers resolve to one effect.
type Store struct {
	pool *pgxpool.Pool
	// The pool is shared (pgshared): a second Close must not drop another
	// holder's reference.
	releaseOnce sync.Once
	now         func() time.Time
	workItems   WorkItemLookup
	minStrength Strength
}

// StoreOption configures a Store.
type StoreOption func(*Store)

// WithClock sets the store's clock.
func WithClock(now func() time.Time) StoreOption {
	return func(s *Store) {
		if now != nil {
			s.now = now
		}
	}
}

// WithWorkItems supplies the WorkItem lookup used when an attempt starts.
func WithWorkItems(l WorkItemLookup) StoreOption {
	return func(s *Store) { s.workItems = l }
}

// WithMinStrength sets the weakest verification that may resolve an
// occurrence (default DefaultMinStrength).
func WithMinStrength(m Strength) StoreOption {
	return func(s *Store) {
		if m != "" {
			s.minStrength = m
		}
	}
}

// NewStore connects and applies the schema.
func NewStore(ctx context.Context, connStr string, opts ...StoreOption) (*Store, error) {
	st := &Store{now: func() time.Time { return time.Now().UTC() }, minStrength: DefaultMinStrength}
	for _, o := range opts {
		o(st)
	}
	if _, err := ParseStrength(string(st.minStrength)); err != nil {
		return nil, fmt.Errorf("securityfindings: minimum verification strength: %w", err)
	}
	pool, err := pgshared.Open(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("securityfindings: connect: %w", err)
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pgshared.Release(pool)
		return nil, fmt.Errorf("securityfindings: create schema: %w", err)
	}
	st.pool = pool
	slog.Info("security findings store initialized", "min_verification_strength", st.minStrength)
	return st, nil
}

// Close releases the pool.
func (s *Store) Close() { s.releaseOnce.Do(func() { pgshared.Release(s.pool) }) }

// MinStrength is the configured minimum strength for resolution.
func (s *Store) MinStrength() Strength { return s.minStrength }

// withTx runs fn in a transaction holding an advisory lock per key, taken in
// sorted order so two transactions needing overlapping key sets cannot
// deadlock.
func (s *Store) withTx(ctx context.Context, lockKeys []string, fn func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("securityfindings: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once Commit has succeeded
	keys := append([]string(nil), lockKeys...)
	sort.Strings(keys)
	for _, k := range keys {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, k); err != nil {
			return fmt.Errorf("securityfindings: acquire lock: %w", err)
		}
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("securityfindings: commit: %w", err)
	}
	return nil
}

func occurrenceLock(id string) string { return "security-occurrence:" + id }

func isUniqueViolation(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}

func newID(prefix string) string { return prefix + uuid.NewString() }

func marshal(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(b)
}

func hashJSON(v any) string {
	sum := sha256.Sum256([]byte(marshal(v)))
	return hex.EncodeToString(sum[:])
}

// occRow is the locked occurrence a mutation works on.
type occRow struct {
	ID, FindingID, Tenant, Fingerprint, State string
	Version                                   int64
	ActiveAttempt                             string
}

func lockOccurrence(ctx context.Context, tx pgx.Tx, id string) (*occRow, error) {
	var o occRow
	err := tx.QueryRow(ctx, `SELECT id, finding_id, tenant, subject_fingerprint, state, state_version, COALESCE(active_attempt_id, '')
		FROM security_occurrences WHERE id = $1 FOR UPDATE`, id).
		Scan(&o.ID, &o.FindingID, &o.Tenant, &o.Fingerprint, &o.State, &o.Version, &o.ActiveAttempt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("securityfindings: load occurrence: %w", err)
	}
	return &o, nil
}

func checkVersion(o *occRow, expected *int64) error {
	if expected != nil && *expected != o.Version {
		return fmt.Errorf("%w: expected %d, current %d", ErrVersionConflict, *expected, o.Version)
	}
	return nil
}

// appendEvent writes the next event of an occurrence. The caller holds the
// occurrence lock, so MAX(seq)+1 cannot race.
func (s *Store) appendEvent(ctx context.Context, tx pgx.Tx, occurrenceID, kind, from, to string, actor Actor, reason string, refs map[string]string) error {
	if refs == nil {
		refs = map[string]string{}
	}
	_, err := tx.Exec(ctx, `INSERT INTO security_occurrence_events
		(occurrence_id, seq, kind, from_state, to_state, actor_principal, actor_principal_id, via_principal_id, source, reason, refs, created_at)
		SELECT $1::text, COALESCE(MAX(seq), 0) + 1, $2::text, $3::text, $4::text, $5::text, $6::text, $7::text, $8::text, $9::text, $10::jsonb, $11::timestamptz
		FROM security_occurrence_events WHERE occurrence_id = $1`,
		occurrenceID, kind, from, to, actor.Principal, actor.PrincipalID, actor.ViaID, sourceOf(actor), reason, marshal(refs), s.now())
	if err != nil {
		return fmt.Errorf("securityfindings: append event: %w", err)
	}
	return nil
}

func sourceOf(a Actor) string {
	if a.Source == "" {
		return "api"
	}
	return a.Source
}

// move applies one lifecycle action to a locked occurrence: it validates the
// move against Transitions, updates the occurrence (bumping state_version and
// the active-attempt projection) and appends the event. It is the only code
// that changes occurrence state.
func (s *Store) move(ctx context.Context, tx pgx.Tx, o *occRow, action string, actor Actor, reason string, refs map[string]string, activeAttempt string) (string, error) {
	to, err := Next(o.State, action)
	if err != nil {
		return "", err
	}
	from := o.State
	if _, err := tx.Exec(ctx, `UPDATE security_occurrences
		SET state = $2, state_version = state_version + 1, updated_at = $3, active_attempt_id = NULLIF($4, '')
		WHERE id = $1`, o.ID, to, s.now(), activeAttempt); err != nil {
		return "", fmt.Errorf("securityfindings: update occurrence: %w", err)
	}
	if err := s.appendEvent(ctx, tx, o.ID, action, from, to, actor, reason, refs); err != nil {
		return "", err
	}
	o.State, o.Version, o.ActiveAttempt = to, o.Version+1, activeAttempt
	return to, nil
}

// replayed returns the original result of a repeated Idempotency-Key, nil
// when the key is new, and ErrIdempotencyKeyReuse when the same key arrives
// with a different request or actor.
func (s *Store) replayed(ctx context.Context, tx pgx.Tx, scope, key, op, hash, actor string) (*MutationResult, error) {
	if key == "" {
		return nil, nil
	}
	var storedOp, storedHash, storedActor string
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT operation, request_hash, actor, result FROM security_requests
		WHERE scope = $1 AND idempotency_key = $2`, scope, key).Scan(&storedOp, &storedHash, &storedActor, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("securityfindings: idempotency lookup: %w", err)
	}
	if storedOp != op || storedHash != hash || storedActor != actor {
		return nil, ErrIdempotencyKeyReuse
	}
	var res MutationResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("securityfindings: idempotency result: %w", err)
	}
	res.Replayed = true
	return &res, nil
}

func (s *Store) remember(ctx context.Context, tx pgx.Tx, scope, key, op, hash, actor string, res MutationResult) error {
	if key == "" {
		return nil
	}
	if _, err := tx.Exec(ctx, `INSERT INTO security_requests (scope, idempotency_key, operation, request_hash, actor, result, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`, scope, key, op, hash, actor, marshal(res), s.now()); err != nil {
		return fmt.Errorf("securityfindings: remember request: %w", err)
	}
	return nil
}

func (o *occRow) result() MutationResult {
	return MutationResult{OccurrenceID: o.ID, State: o.State, StateVersion: o.Version, AttemptID: o.ActiveAttempt}
}

// OccurrenceTenant returns the tenant of an occurrence, for the caller's
// visibility decision before it mutates.
func (s *Store) OccurrenceTenant(ctx context.Context, id string) (string, error) {
	var t string
	err := s.pool.QueryRow(ctx, `SELECT tenant FROM security_occurrences WHERE id = $1`, id).Scan(&t)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("securityfindings: occurrence tenant: %w", err)
	}
	return t, nil
}

// AttemptRef returns the occurrence and tenant of a remediation attempt.
func (s *Store) AttemptRef(ctx context.Context, id string) (occurrenceID, tenant string, err error) {
	err = s.pool.QueryRow(ctx, `SELECT occurrence_id, tenant FROM security_remediation_attempts WHERE id = $1`, id).Scan(&occurrenceID, &tenant)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrNotFound
	}
	if err != nil {
		return "", "", fmt.Errorf("securityfindings: attempt ref: %w", err)
	}
	return occurrenceID, tenant, nil
}
