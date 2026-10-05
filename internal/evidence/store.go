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

// schemaAmendment2 is the ADR 018 Amendment 2 migration (Tier B follow-up,
// checklist items 4-5). It is DDL only — ALTER TABLE ... ADD COLUMN, never
// an UPDATE — so the execution_evidence_no_update trigger stays untouched
// and existing rows need no backfill: no pre-amendment envelope can carry a
// subject or provenance, and the column defaults (” / NULL) are exactly
// what such a row would have been written with. Every column is written
// once, at ingest, from the envelope itself; versions and tool_calls stay
// in the verbatim envelope only (no columns, no second copy).
//
// Constraints are added under their own names inside DO blocks that
// tolerate duplicate_object, so concurrent replicas applying the schema at
// startup cannot fail each other. They are added NOT VALID: every new row
// is still checked, but startup skips a full-table validation scan under
// ACCESS EXCLUSIVE — no existing row can violate them (every pre-amendment
// row holds the column defaults).
const schemaAmendment2 = `
ALTER TABLE execution_evidence
    ADD COLUMN IF NOT EXISTS subject_kind       TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS subject_repository TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS subject_ref        TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS subject_revision   TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS authority          TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS observed_at        TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS supersedes         TEXT NOT NULL DEFAULT '';

DO $$
DECLARE
    c RECORD;
BEGIN
    FOR c IN SELECT * FROM (VALUES
        ('execution_evidence_authority_vocab',
         $c$authority IN ('', 'observed', 'derived', 'asserted')$c$),
        ('execution_evidence_supersedes_shape',
         $c$supersedes = '' OR supersedes ~ '^ev-[0-9a-f]{16}$'$c$),
        ('execution_evidence_supersedes_not_self',
         $c$supersedes <> id$c$),
        ('execution_evidence_subject_needs_provenance',
         $c$subject_kind = '' OR (authority <> '' AND observed_at IS NOT NULL)$c$),
        ('execution_evidence_sha_bound_revision',
         $c$subject_kind NOT IN ('pull_request', 'branch', 'release') OR subject_revision ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'$c$),
        -- Beyond the ADR's list, the same rules Tier A states: a closed
        -- subject vocabulary, a numbered ref for pull_request/issue (never
        -- excused by redaction), no subject columns without a subject, and
        -- provenance written as a whole (authority and observed_at
        -- together).
        ('execution_evidence_subject_kind_vocab',
         $c$subject_kind IN ('', 'pull_request', 'issue', 'branch', 'release', 'work_item')$c$),
        ('execution_evidence_numbered_ref',
         $c$subject_kind NOT IN ('pull_request', 'issue') OR subject_ref ~ '^[1-9][0-9]{0,9}$'$c$),
        ('execution_evidence_subject_columns_need_kind',
         $c$subject_kind <> '' OR (subject_repository = '' AND subject_ref = '' AND subject_revision = '')$c$),
        ('execution_evidence_provenance_whole',
         $c$(authority = '') = (observed_at IS NULL)$c$)
    ) AS t(name, expr)
    LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = c.name) THEN
            BEGIN
                EXECUTE format('ALTER TABLE execution_evidence ADD CONSTRAINT %I CHECK (%s) NOT VALID', c.name, c.expr);
            EXCEPTION WHEN duplicate_object THEN
                NULL;
            END;
        END IF;
    END LOOP;
END;
$$;

CREATE INDEX IF NOT EXISTS execution_evidence_subject
    ON execution_evidence (subject_kind, subject_repository, subject_ref, subject_revision, observed_at DESC)
    WHERE subject_kind <> '';
CREATE INDEX IF NOT EXISTS execution_evidence_supersedes
    ON execution_evidence (supersedes) WHERE supersedes <> '';
`

// evidenceColumns are the pre-amendment columns, in insert order.
const evidenceColumns = `id, content_hash, api_version, envelope, execution_id, runtime_execution_id,
	work_item_id, trace_id, created_at, ingested_by, ingested_by_principal_id, ingested_at`

// evidenceSubjectColumns are the ADR 018 Amendment 2 columns.
const evidenceSubjectColumns = `subject_kind, subject_repository, subject_ref, subject_revision,
	authority, observed_at, supersedes`

// evidenceRowColumns is every column scanEvidenceRow reads, in scan order.
const evidenceRowColumns = evidenceColumns + `, ` + evidenceSubjectColumns

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
	if _, err := pool.Exec(ctx, schemaAmendment2); err != nil {
		pool.Close()
		return nil, fmt.Errorf("evidence: schema (ADR 018 Amendment 2): %w", err)
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
// refused rather than served, mirroring workitems.scanSnapshot. The
// Amendment 2 columns are cross-checked against the envelope they were
// written from: a disagreement is a corrupt row (an error), never a
// silently preferred value.
func scanEvidenceRow(row pgx.Row) (*Evidence, error) {
	var e Evidence
	var envelope []byte
	var col subjectColumns
	if err := row.Scan(&e.ID, &e.ContentHash, &e.APIVersion, &envelope, &e.ExecutionID, &e.RuntimeExecutionID,
		&e.WorkItemID, &e.TraceID, &e.CreatedAt, &e.IngestedBy, &e.IngestedByPrincipalID, &e.IngestedAt,
		&col.kind, &col.repository, &col.ref, &col.revision, &col.authority, &col.observedAt, &col.supersedes); err != nil {
		return nil, err
	}
	p, err := parseEnvelope(envelope)
	if err != nil {
		return nil, fmt.Errorf("evidence: stored envelope %s no longer parses: %v", e.ID, err) //nolint:errorlint // a corrupt stored row is a server fault: never carry ErrEvidenceInvalid (400) out of it
	}
	canonical, err := CanonicalContentJSON(p)
	if err != nil {
		return nil, fmt.Errorf("evidence: stored envelope %s no longer canonicalizes: %v", e.ID, err) //nolint:errorlint // see above
	}
	if got := ContentHash(canonical); got != e.ContentHash {
		return nil, fmt.Errorf("evidence: %s: stored bytes hash to %s, not %s", e.ID, got, e.ContentHash)
	}
	want, err := subjectColumnsOf(p)
	if err != nil {
		return nil, fmt.Errorf("evidence: stored envelope %s: %v", e.ID, err) //nolint:errorlint // see above
	}
	if !col.equal(want) {
		return nil, fmt.Errorf("evidence: %s: subject/provenance columns disagree with the stored envelope", e.ID)
	}
	e.Envelope = envelope
	e.CreatedAt = e.CreatedAt.UTC()
	e.IngestedAt = e.IngestedAt.UTC()
	e.PrimaryRefKind, e.PrimaryRefID = e.PrimaryExecutionRef()
	if p.a2.subject != nil {
		subject := *p.a2.subject
		e.Subject = &subject
	}
	if p.a2.provenance != nil {
		e.Authority = p.a2.provenance.Authority
		e.Supersedes = p.a2.provenance.Supersedes
		e.observedAtRaw = p.a2.provenance.ObservedAt
		if want.observedAt != nil {
			at := want.observedAt.UTC()
			e.ObservedAt = &at
		}
	}
	e.subjectRedacted = p.a2.subjectRedacted()
	return &e, nil
}

// subjectColumns is the ADR 018 Amendment 2 column set of one row.
type subjectColumns struct {
	kind, repository, ref, revision string
	authority                       string
	observedAt                      *time.Time
	supersedes                      string
}

func (c subjectColumns) equal(o subjectColumns) bool {
	if c.kind != o.kind || c.repository != o.repository || c.ref != o.ref || c.revision != o.revision ||
		c.authority != o.authority || c.supersedes != o.supersedes {
		return false
	}
	if (c.observedAt == nil) != (o.observedAt == nil) {
		return false
	}
	return c.observedAt == nil || c.observedAt.Equal(*o.observedAt)
}

// subjectColumnsOf derives the Amendment 2 columns from a parsed envelope:
// what Ingest writes, and what scanEvidenceRow cross-checks.
func subjectColumnsOf(p *parsedEnvelope) (subjectColumns, error) {
	var c subjectColumns
	if s := p.a2.subject; s != nil {
		c.kind, c.repository, c.ref, c.revision = s.Kind, s.Repository, s.Ref, s.Revision
	}
	if pr := p.a2.provenance; pr != nil {
		c.authority, c.supersedes = pr.Authority, pr.Supersedes
		if pr.ObservedAt != "" {
			at, err := time.Parse(time.RFC3339Nano, pr.ObservedAt)
			if err != nil {
				return c, fmt.Errorf("%w: provenance.observed_at %q is not a real UTC instant: %s",
					ErrEvidenceInvalid, truncate(pr.ObservedAt), err)
			}
			at = at.UTC()
			c.observedAt = &at
		}
	}
	return c, nil
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
