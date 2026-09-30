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

package evidence

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// schema is the two-table design from design.md: an immutable sealed record
// (execution_evidence) and a rebuildable, non-authoritative retrieval
// projection (execution_evidence_refs). Applied idempotently at NewStore,
// the repo convention (internal/workitems, internal/usage).
//
// Two structural guarantees carry contract meaning:
//
//   - execution_evidence_immutable(): a BEFORE UPDATE trigger that refuses
//     every UPDATE outright, in the same shape as
//     work_item_context_snapshots_no_update. DELETE stays permitted: it is
//     the retention mechanism.
//   - No foreign key from execution_evidence to work_items or
//     work_item_executions: docs/work-context-contract.md mandates
//     correlation over foreign keys, and evidence must not die with a
//     WORKITEM_RETENTION_DAYS purge.
const schema = `
CREATE TABLE IF NOT EXISTS execution_evidence (
    id                       TEXT PRIMARY KEY,
    content_hash             TEXT NOT NULL UNIQUE,
    api_version              TEXT NOT NULL,
    envelope                 BYTEA NOT NULL,
    execution_id             TEXT NOT NULL DEFAULT '',
    runtime_execution_id     TEXT NOT NULL DEFAULT '',
    work_item_id             TEXT NOT NULL DEFAULT '',
    trace_id                 TEXT NOT NULL DEFAULT '',
    created_at               TIMESTAMPTZ NOT NULL,
    ingested_by              TEXT NOT NULL,
    ingested_by_principal_id TEXT NOT NULL DEFAULT '',
    ingested_at              TIMESTAMPTZ NOT NULL,
    CONSTRAINT execution_evidence_join_present CHECK (execution_id <> '' OR runtime_execution_id <> ''),
    CONSTRAINT execution_evidence_work_shape    CHECK (execution_id = '' OR execution_id LIKE 'we\_%'),
    CONSTRAINT execution_evidence_runtime_shape CHECK (runtime_execution_id = '' OR runtime_execution_id ~ '^ex-[0-9a-f]{16}$')
);

CREATE INDEX IF NOT EXISTS execution_evidence_work_exec
    ON execution_evidence (execution_id, ingested_at DESC) WHERE execution_id <> '';
CREATE INDEX IF NOT EXISTS execution_evidence_runtime_exec
    ON execution_evidence (runtime_execution_id, ingested_at DESC) WHERE runtime_execution_id <> '';
CREATE INDEX IF NOT EXISTS execution_evidence_trace
    ON execution_evidence (trace_id, ingested_at DESC) WHERE trace_id <> '';
CREATE INDEX IF NOT EXISTS execution_evidence_ingested
    ON execution_evidence (ingested_at DESC);
CREATE INDEX IF NOT EXISTS execution_evidence_work_item
    ON execution_evidence (work_item_id, ingested_at DESC) WHERE work_item_id <> '';

CREATE OR REPLACE FUNCTION execution_evidence_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'execution_evidence rows are immutable';
END;
$$ LANGUAGE plpgsql;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'execution_evidence_no_update') THEN
        CREATE TRIGGER execution_evidence_no_update
            BEFORE UPDATE ON execution_evidence
            FOR EACH ROW EXECUTE FUNCTION execution_evidence_immutable();
    END IF;
END;
$$;

-- Rebuildable index projection (design.md section 1). It has no authority:
-- if a column here disagrees with canonical state, canonical state wins and
-- the entry is a stale index, never an answer. Deleting and recomputing
-- every row loses nothing.
CREATE TABLE IF NOT EXISTS execution_evidence_refs (
    evidence_id       TEXT PRIMARY KEY
                      REFERENCES execution_evidence (id) ON DELETE CASCADE,
    work_execution_id TEXT NOT NULL DEFAULT '',
    work_item_id      TEXT NOT NULL DEFAULT '',
    tenant            TEXT NOT NULL DEFAULT '',
    engine            TEXT NOT NULL DEFAULT '',
    engine_ref        TEXT NOT NULL DEFAULT '',
    repository        TEXT NOT NULL DEFAULT '',
    issue_number      BIGINT,
    pr_number         BIGINT,
    derived_at        TIMESTAMPTZ NOT NULL,
    CONSTRAINT execution_evidence_refs_work_prefix CHECK (
        work_execution_id = '' OR work_execution_id LIKE 'we\_%'
    )
);

CREATE INDEX IF NOT EXISTS execution_evidence_refs_work_exec
    ON execution_evidence_refs (work_execution_id) WHERE work_execution_id <> '';
CREATE INDEX IF NOT EXISTS execution_evidence_refs_item
    ON execution_evidence_refs (work_item_id) WHERE work_item_id <> '';
CREATE INDEX IF NOT EXISTS execution_evidence_refs_engine
    ON execution_evidence_refs (engine, engine_ref) WHERE engine_ref <> '';
CREATE INDEX IF NOT EXISTS execution_evidence_refs_repo_issue
    ON execution_evidence_refs (repository, issue_number)
    WHERE repository <> '' AND issue_number IS NOT NULL;
CREATE INDEX IF NOT EXISTS execution_evidence_refs_repo_pr
    ON execution_evidence_refs (repository, pr_number)
    WHERE repository <> '' AND pr_number IS NOT NULL;
`

const evidenceColumns = `id, content_hash, api_version, envelope, execution_id, runtime_execution_id,
	work_item_id, trace_id, created_at, ingested_by, ingested_by_principal_id, ingested_at`

const refColumns = `evidence_id, work_execution_id, work_item_id, tenant, engine, engine_ref,
	repository, issue_number, pr_number, derived_at`

// Store is the durable evidence store.
type Store struct {
	pool *pgxpool.Pool
	now  func() time.Time
	// resolver is the best-effort work-execution correlation lookup used
	// to populate the derived projection (derive.go). Nil until SetResolver
	// is called; a nil resolver simply leaves every projection empty.
	resolver ExecutionResolver
}

// NewStore connects, applies the schema and returns a ready store.
func NewStore(ctx context.Context, connStr string) (*Store, error) {
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("evidence: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("evidence: ping: %w", err)
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("evidence: schema: %w", err)
	}
	slog.Info("evidence store initialized")
	return &Store{pool: pool, now: func() time.Time { return time.Now().UTC() }}, nil
}

// Close releases the pool.
func (s *Store) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}

type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// scanEvidenceRow scans one execution_evidence row and re-verifies its
// content hash: bytes that no longer hash to the stored content_hash are
// refused rather than served, mirroring workitems.scanSnapshot.
func scanEvidenceRow(row pgx.Row) (*Evidence, error) {
	var e Evidence
	var envelope []byte
	if err := row.Scan(&e.ID, &e.ContentHash, &e.APIVersion, &envelope, &e.ExecutionID, &e.RuntimeExecutionID,
		&e.WorkItemID, &e.TraceID, &e.CreatedAt, &e.IngestedBy, &e.IngestedByPrincipalID, &e.IngestedAt); err != nil {
		return nil, err
	}
	p, err := parseEnvelope(envelope)
	if err != nil {
		return nil, fmt.Errorf("evidence: stored envelope %s no longer parses: %w", e.ID, err)
	}
	canonical, err := CanonicalContentJSON(p)
	if err != nil {
		return nil, fmt.Errorf("evidence: stored envelope %s no longer canonicalizes: %w", e.ID, err)
	}
	if got := ContentHash(canonical); got != e.ContentHash {
		return nil, fmt.Errorf("evidence: %s: stored bytes hash to %s, not %s", e.ID, got, e.ContentHash)
	}
	e.Envelope = envelope
	e.CreatedAt = e.CreatedAt.UTC()
	e.IngestedAt = e.IngestedAt.UTC()
	e.PrimaryRefKind, e.PrimaryRefID = e.PrimaryExecutionRef()
	return &e, nil
}

func scanRef(row pgx.Row) (*EvidenceRef, error) {
	var ref EvidenceRef
	var evidenceID string
	if err := row.Scan(&evidenceID, &ref.WorkExecutionID, &ref.WorkItemID, &ref.Tenant, &ref.Engine,
		&ref.EngineRef, &ref.Repository, &ref.IssueNumber, &ref.PRNumber, &ref.DerivedAt); err != nil {
		return nil, err
	}
	ref.EvidenceID = evidenceID
	ref.DerivedAt = ref.DerivedAt.UTC()
	return &ref, nil
}

func getRef(ctx context.Context, q querier, evidenceID string) (*EvidenceRef, error) {
	ref, err := scanRef(q.QueryRow(ctx, `SELECT `+refColumns+` FROM execution_evidence_refs WHERE evidence_id=$1`, evidenceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("evidence: get ref: %w", err)
	}
	return ref, nil
}

// attachRef loads and attaches the derived projection, when one exists. A
// missing projection is not an error: an unresolvable valid join stores
// evidence with an empty projection by design (design.md section 5).
func (s *Store) attachRef(ctx context.Context, e *Evidence) error {
	ref, err := getRef(ctx, s.pool, e.ID)
	if err != nil {
		return err
	}
	e.Ref = ref
	return nil
}

func withTx(ctx context.Context, pool *pgxpool.Pool, lockKey string, fn func(pgx.Tx) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("evidence: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once Commit has succeeded
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, lockKey); err != nil {
		return fmt.Errorf("evidence: acquire lock: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("evidence: commit: %w", err)
	}
	return nil
}
