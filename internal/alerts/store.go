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

package alerts

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrIDConflict is returned by Create when the alert's id collides with an
// existing row owned by a different tenant. Callers must not surface which
// tenant actually owns the id — that would reopen the same leak.
var ErrIDConflict = errors.New("alerts store: id already exists")

// ErrNotFound is returned when no incident matches the requested id or prefix.
var ErrNotFound = errors.New("alerts store: incident not found")

// ErrPrefixTooShort is returned by GetByPrefix when there is no exact id match
// and the prefix is shorter than MinPrefixLen.
var ErrPrefixTooShort = errors.New("alerts store: id prefix too short")

// ErrAmbiguousPrefix is returned by GetByPrefix when a prefix matches more
// than one incident. It deliberately carries no ids or tenant names.
var ErrAmbiguousPrefix = errors.New("alerts store: id prefix matches more than one incident")

// MinPrefixLen is the minimum length of an id prefix accepted by GetByPrefix
// when there is no exact match.
const MinPrefixLen = 8

const alertSchema = `
CREATE TABLE IF NOT EXISTS alerts (
    id              TEXT PRIMARY KEY,
    source          TEXT NOT NULL,
    type            TEXT NOT NULL,
    tenant          TEXT NOT NULL,
    service         TEXT NOT NULL,
    summary         TEXT NOT NULL,
    severity        TEXT NOT NULL,
    status          TEXT NOT NULL,
    analysis        TEXT NOT NULL DEFAULT '',
    proposed_fix    TEXT NOT NULL DEFAULT '',
    pr_url          TEXT NOT NULL DEFAULT '',
    pr_number       INTEGER NOT NULL DEFAULT 0,
    confidence      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL,
    resolved_at     TIMESTAMPTZ,
    acknowledged_by TEXT NOT NULL DEFAULT '',
    acknowledged_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS alerts_status ON alerts (status);
CREATE INDEX IF NOT EXISTS alerts_tenant ON alerts (tenant);
CREATE INDEX IF NOT EXISTS alerts_created_at ON alerts (created_at DESC);

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS fingerprint      TEXT NOT NULL DEFAULT '';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS occurrence_count INTEGER NOT NULL DEFAULT 1;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS last_seen_at     TIMESTAMPTZ;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS trace_id         TEXT NOT NULL DEFAULT '';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS workflow_name    TEXT NOT NULL DEFAULT '';

DROP INDEX IF EXISTS alerts_fingerprint_open;
CREATE UNIQUE INDEX IF NOT EXISTS alerts_tenant_fingerprint_open
  ON alerts (tenant, fingerprint)
  WHERE fingerprint <> '' AND status NOT IN ('resolved', 'suppressed');

CREATE TABLE IF NOT EXISTS alert_evidence (
    id           SERIAL PRIMARY KEY,
    alert_id     TEXT NOT NULL REFERENCES alerts(id),
    type         TEXT NOT NULL,
    content      TEXT NOT NULL,
    collected_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS alert_evidence_alert_id ON alert_evidence (alert_id);
`

// alertColumns is the single SELECT/RETURNING column list; scanAlert is its
// matching Scan target list. Keep them in lockstep.
const alertColumns = `id, source, type, tenant, service, summary, severity, status,
		 analysis, proposed_fix, pr_url, pr_number, confidence,
		 created_at, updated_at, resolved_at, acknowledged_by, acknowledged_at,
		 fingerprint, occurrence_count, last_seen_at, trace_id, workflow_name`

func scanAlert(row pgx.Row, a *Alert) error {
	if err := row.Scan(
		&a.ID, &a.Source, &a.Type, &a.Tenant, &a.Service, &a.Summary, &a.Severity, &a.Status,
		&a.Analysis, &a.ProposedFix, &a.PRURL, &a.PRNumber, &a.Confidence,
		&a.CreatedAt, &a.UpdatedAt, &a.ResolvedAt, &a.AcknowledgedBy, &a.AcknowledgedAt,
		&a.Fingerprint, &a.OccurrenceCount, &a.LastSeenAt, &a.TraceID, &a.WorkflowName,
	); err != nil {
		return err
	}
	return nil
}

// Store is a PostgreSQL-backed alert store.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore creates an alert store and auto-creates the schema.
func NewStore(ctx context.Context, connStr string) (*Store, error) {
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("alerts store: connect: %w", err)
	}
	if _, err := pool.Exec(ctx, alertSchema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("alerts store: create schema: %w", err)
	}
	slog.Info("alert store initialized")
	return &Store{pool: pool}, nil
}

// Create inserts a new alert with its evidence, or — when a.Fingerprint is
// non-empty and matches an existing open alert — merges into that alert
// instead (bumping occurrence_count and last_seen_at). The returned Alert is
// the actual stored/matched row, so on a dedup hit its ID is the ORIGINAL
// incident's ID, not a.ID.
func (s *Store) Create(ctx context.Context, a *Alert) (*Alert, error) {
	now := time.Now().UTC()
	if a.CreatedAt.IsZero() {
		a.CreatedAt = now
	}
	a.UpdatedAt = now
	if a.OccurrenceCount == 0 {
		a.OccurrenceCount = 1
	}

	stored := &Alert{}
	row := s.pool.QueryRow(ctx,
		`INSERT INTO alerts (id, source, type, tenant, service, summary, severity, status,
		 analysis, proposed_fix, pr_url, pr_number, confidence, created_at, updated_at, resolved_at,
		 acknowledged_by, acknowledged_at, fingerprint, occurrence_count, last_seen_at,
		 trace_id, workflow_name)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)
		 ON CONFLICT (tenant, fingerprint) WHERE fingerprint <> '' AND status NOT IN ('resolved','suppressed')
		 DO UPDATE SET occurrence_count = alerts.occurrence_count + 1,
		               last_seen_at = EXCLUDED.updated_at,
		               updated_at = EXCLUDED.updated_at,
		               trace_id = CASE WHEN EXCLUDED.trace_id <> '' THEN EXCLUDED.trace_id ELSE alerts.trace_id END,
		               -- trace_id and workflow_name describe one run and move
		               -- together: a trace reported without a name clears the
		               -- stale name rather than pairing it with the new trace.
		               workflow_name = CASE
		                   WHEN EXCLUDED.trace_id <> '' THEN EXCLUDED.workflow_name
		                   WHEN alerts.trace_id = '' AND EXCLUDED.workflow_name <> '' THEN EXCLUDED.workflow_name
		                   ELSE alerts.workflow_name END
		 RETURNING `+alertColumns,
		a.ID, a.Source, a.Type, a.Tenant, a.Service, a.Summary, a.Severity, a.Status,
		a.Analysis, a.ProposedFix, a.PRURL, a.PRNumber, a.Confidence,
		a.CreatedAt, a.UpdatedAt, a.ResolvedAt, a.AcknowledgedBy, a.AcknowledgedAt,
		a.Fingerprint, a.OccurrenceCount, a.LastSeenAt, a.TraceID, a.WorkflowName,
	)
	err := scanAlert(row, stored)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "alerts_pkey" {
			// Same-id retry (e.g. a network retry of the same POST): treat as
			// an idempotent no-op and return the row already on disk, matching
			// the old ON CONFLICT (id) DO NOTHING behavior. But the id is
			// caller-supplied, so a cross-tenant caller could guess/enumerate
			// another tenant's id and use this path to read their alert. Only
			// treat it as an idempotent no-op when the existing row belongs to
			// the same tenant; otherwise report a conflict without revealing
			// the row.
			existing, getErr := s.Get(ctx, a.ID)
			if getErr != nil {
				return nil, fmt.Errorf("alerts store: create: id %q already exists: %w", a.ID, getErr)
			}
			if existing.Tenant != a.Tenant {
				return nil, ErrIDConflict
			}
			return existing, nil
		}
		return nil, fmt.Errorf("alerts store: create: %w", err)
	}

	for _, ev := range a.Evidence {
		_, err := s.pool.Exec(ctx,
			`INSERT INTO alert_evidence (alert_id, type, content, collected_at)
			 VALUES ($1, $2, $3, $4)`,
			stored.ID, ev.Type, ev.Content, ev.CollectedAt,
		)
		if err != nil {
			slog.Error("alerts store: insert evidence failed", "alert_id", stored.ID, "error", err)
		}
	}

	if stored.ID == a.ID {
		stored.Evidence = a.Evidence
	} else {
		// Dedup hit: stored.ID is the original alert's ID, so a.Evidence (just
		// the newly submitted evidence) would be an incomplete picture. Return
		// the full accumulated evidence list instead.
		stored.Evidence, _ = s.getEvidence(ctx, stored.ID)
	}
	return stored, nil
}

// Update patches an existing alert (status, analysis, pr_url, etc).
func (s *Store) Update(ctx context.Context, a *Alert) error {
	a.UpdatedAt = time.Now().UTC()

	_, err := s.pool.Exec(ctx,
		`UPDATE alerts SET status=$2, analysis=$3, proposed_fix=$4, pr_url=$5, pr_number=$6,
		 confidence=$7, updated_at=$8, resolved_at=$9, acknowledged_by=$10, acknowledged_at=$11,
		 trace_id=CASE WHEN $12::text <> '' THEN $12::text ELSE trace_id END
		 WHERE id=$1`,
		a.ID, a.Status, a.Analysis, a.ProposedFix, a.PRURL, a.PRNumber,
		a.Confidence, a.UpdatedAt, a.ResolvedAt, a.AcknowledgedBy, a.AcknowledgedAt,
		a.TraceID,
	)
	if err != nil {
		return fmt.Errorf("alerts store: update: %w", err)
	}

	for _, ev := range a.Evidence {
		_, err := s.pool.Exec(ctx,
			`INSERT INTO alert_evidence (alert_id, type, content, collected_at)
			 VALUES ($1, $2, $3, $4)`,
			a.ID, ev.Type, ev.Content, ev.CollectedAt,
		)
		if err != nil {
			slog.Error("alerts store: insert evidence failed", "alert_id", a.ID, "error", err)
		}
	}

	return nil
}

// Get returns a single alert with evidence.
func (s *Store) Get(ctx context.Context, id string) (*Alert, error) {
	a := &Alert{}
	err := scanAlert(s.pool.QueryRow(ctx,
		`SELECT `+alertColumns+` FROM alerts WHERE id=$1`, id), a)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("alerts store: get: %w", ErrNotFound)
		}
		return nil, fmt.Errorf("alerts store: get: %w", err)
	}

	a.Evidence, _ = s.getEvidence(ctx, a.ID)
	return a, nil
}

var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// escapeLike escapes LIKE metacharacters so the input is matched literally.
func escapeLike(s string) string { return likeEscaper.Replace(s) }

// GetByPrefix resolves an incident by id. An exact id match always wins, at
// any length. Otherwise the prefix must be at least MinPrefixLen characters,
// is matched literally (LIKE wildcards are escaped), and must match exactly
// one incident. It returns ErrPrefixTooShort, ErrNotFound or
// ErrAmbiguousPrefix accordingly; it never picks one of several matches.
func (s *Store) GetByPrefix(ctx context.Context, prefix string) (*Alert, error) {
	a, err := s.Get(ctx, prefix)
	if err == nil {
		return a, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	if len(prefix) < MinPrefixLen {
		return nil, ErrPrefixTooShort
	}

	rows, err := s.pool.Query(ctx,
		`SELECT `+alertColumns+` FROM alerts WHERE id LIKE $1 ESCAPE '\' ORDER BY id LIMIT 2`,
		escapeLike(prefix)+"%")
	if err != nil {
		return nil, fmt.Errorf("alerts store: get by prefix: %w", err)
	}
	defer rows.Close()

	var found []*Alert
	for rows.Next() {
		m := &Alert{}
		if err := scanAlert(rows, m); err != nil {
			return nil, fmt.Errorf("alerts store: get by prefix: %w", err)
		}
		found = append(found, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("alerts store: get by prefix: %w", err)
	}
	rows.Close()

	switch len(found) {
	case 0:
		return nil, ErrNotFound
	case 1:
		found[0].Evidence, _ = s.getEvidence(ctx, found[0].ID)
		return found[0], nil
	default:
		return nil, ErrAmbiguousPrefix
	}
}

// ResolveByFingerprint resolves the open alert matching tenant+fingerprint,
// if one exists. Zero rows affected (no matching open alert) is expected and
// not an error — it just means nothing needed resolving.
func (s *Store) ResolveByFingerprint(ctx context.Context, tenant, fingerprint string) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE alerts SET status='resolved', resolved_at=now(), updated_at=now()
		 WHERE tenant=$1 AND fingerprint=$2 AND status NOT IN ('resolved','suppressed')`,
		tenant, fingerprint,
	)
	if err != nil {
		return false, fmt.Errorf("alerts store: resolve by fingerprint: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

func (s *Store) getEvidence(ctx context.Context, alertID string) ([]Evidence, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, alert_id, type, content, collected_at FROM alert_evidence
		 WHERE alert_id=$1 ORDER BY collected_at`, alertID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var evidence []Evidence
	for rows.Next() {
		var ev Evidence
		if err := rows.Scan(&ev.ID, &ev.AlertID, &ev.Type, &ev.Content, &ev.CollectedAt); err != nil {
			continue
		}
		evidence = append(evidence, ev)
	}
	return evidence, nil
}

// List returns alerts matching the filter.
func (s *Store) List(ctx context.Context, f ListFilter) ([]Alert, error) {
	var conditions []string
	var args []interface{}
	argIdx := 1

	// "active" is a virtual status meaning "any non-terminal" — i.e. anything
	// the operator might still need to react to. Mirrors the implicit filter
	// used by Summary() so list and summary stay consistent.
	if f.Status == StatusActive {
		conditions = append(conditions,
			fmt.Sprintf("status NOT IN ('%s', '%s')", StatusResolved, StatusSuppressed))
	} else if f.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status=$%d", argIdx))
		args = append(args, f.Status)
		argIdx++
	}
	if f.Tenant != "" {
		conditions = append(conditions, fmt.Sprintf("tenant=$%d", argIdx))
		args = append(args, f.Tenant)
		argIdx++
	}
	if f.Service != "" {
		conditions = append(conditions, fmt.Sprintf("service=$%d", argIdx))
		args = append(args, f.Service)
		argIdx++
	}
	if f.Type != "" {
		conditions = append(conditions, fmt.Sprintf("type=$%d", argIdx))
		args = append(args, f.Type)
		argIdx++
	}
	if f.Severity != "" {
		conditions = append(conditions, fmt.Sprintf("severity=$%d", argIdx))
		args = append(args, f.Severity)
		argIdx++
	}
	if !f.Since.IsZero() {
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", argIdx))
		args = append(args, f.Since)
		argIdx++
	}

	query := `SELECT ` + alertColumns + ` FROM alerts`
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY created_at DESC"

	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	query += fmt.Sprintf(" LIMIT $%d", argIdx)
	args = append(args, limit)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("alerts store: list: %w", err)
	}
	defer rows.Close()

	var alerts []Alert
	for rows.Next() {
		var a Alert
		if err := scanAlert(rows, &a); err != nil {
			slog.Error("alerts store: scan failed", "error", err)
			continue
		}
		alerts = append(alerts, a)
	}
	return alerts, nil
}

// Summary returns aggregate counts by status, severity, and type.
func (s *Store) Summary(ctx context.Context) (*Summary, error) {
	sum := &Summary{
		ByStatus:   make(map[string]int),
		BySeverity: make(map[string]int),
		ByType:     make(map[string]int),
	}

	rows, err := s.pool.Query(ctx, `SELECT status, severity, type FROM alerts WHERE status NOT IN ('resolved', 'suppressed')`)
	if err != nil {
		return nil, fmt.Errorf("alerts store: summary: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var status, severity, alertType string
		if err := rows.Scan(&status, &severity, &alertType); err != nil {
			continue
		}
		sum.ByStatus[status]++
		sum.BySeverity[severity]++
		sum.ByType[alertType]++
		sum.Total++
	}
	return sum, nil
}
