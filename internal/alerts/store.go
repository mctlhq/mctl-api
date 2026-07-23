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
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

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

CREATE UNIQUE INDEX IF NOT EXISTS alerts_fingerprint_open
  ON alerts (fingerprint)
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
	err := s.pool.QueryRow(ctx,
		`INSERT INTO alerts (id, source, type, tenant, service, summary, severity, status,
		 analysis, proposed_fix, pr_url, pr_number, confidence, created_at, updated_at, resolved_at,
		 acknowledged_by, acknowledged_at, fingerprint, occurrence_count, last_seen_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
		 ON CONFLICT (fingerprint) WHERE fingerprint <> '' AND status NOT IN ('resolved','suppressed')
		 DO UPDATE SET occurrence_count = alerts.occurrence_count + 1,
		               last_seen_at = EXCLUDED.updated_at,
		               updated_at = EXCLUDED.updated_at
		 RETURNING id, source, type, tenant, service, summary, severity, status,
		           analysis, proposed_fix, pr_url, pr_number, confidence,
		           created_at, updated_at, resolved_at, acknowledged_by, acknowledged_at,
		           fingerprint, occurrence_count, last_seen_at`,
		a.ID, a.Source, a.Type, a.Tenant, a.Service, a.Summary, a.Severity, a.Status,
		a.Analysis, a.ProposedFix, a.PRURL, a.PRNumber, a.Confidence,
		a.CreatedAt, a.UpdatedAt, a.ResolvedAt, a.AcknowledgedBy, a.AcknowledgedAt,
		a.Fingerprint, a.OccurrenceCount, a.LastSeenAt,
	).Scan(
		&stored.ID, &stored.Source, &stored.Type, &stored.Tenant, &stored.Service, &stored.Summary,
		&stored.Severity, &stored.Status, &stored.Analysis, &stored.ProposedFix, &stored.PRURL,
		&stored.PRNumber, &stored.Confidence, &stored.CreatedAt, &stored.UpdatedAt, &stored.ResolvedAt,
		&stored.AcknowledgedBy, &stored.AcknowledgedAt, &stored.Fingerprint, &stored.OccurrenceCount,
		&stored.LastSeenAt,
	)
	if err != nil {
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

	stored.Evidence = a.Evidence
	return stored, nil
}

// Update patches an existing alert (status, analysis, pr_url, etc).
func (s *Store) Update(ctx context.Context, a *Alert) error {
	a.UpdatedAt = time.Now().UTC()

	_, err := s.pool.Exec(ctx,
		`UPDATE alerts SET status=$2, analysis=$3, proposed_fix=$4, pr_url=$5, pr_number=$6,
		 confidence=$7, updated_at=$8, resolved_at=$9, acknowledged_by=$10, acknowledged_at=$11
		 WHERE id=$1`,
		a.ID, a.Status, a.Analysis, a.ProposedFix, a.PRURL, a.PRNumber,
		a.Confidence, a.UpdatedAt, a.ResolvedAt, a.AcknowledgedBy, a.AcknowledgedAt,
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
	err := s.pool.QueryRow(ctx,
		`SELECT id, source, type, tenant, service, summary, severity, status,
		 analysis, proposed_fix, pr_url, pr_number, confidence,
		 created_at, updated_at, resolved_at, acknowledged_by, acknowledged_at,
		 fingerprint, occurrence_count, last_seen_at
		 FROM alerts WHERE id=$1`, id).Scan(
		&a.ID, &a.Source, &a.Type, &a.Tenant, &a.Service, &a.Summary, &a.Severity, &a.Status,
		&a.Analysis, &a.ProposedFix, &a.PRURL, &a.PRNumber, &a.Confidence,
		&a.CreatedAt, &a.UpdatedAt, &a.ResolvedAt, &a.AcknowledgedBy, &a.AcknowledgedAt,
		&a.Fingerprint, &a.OccurrenceCount, &a.LastSeenAt,
	)
	if err != nil {
		return nil, fmt.Errorf("alerts store: get: %w", err)
	}

	a.Evidence, _ = s.getEvidence(ctx, a.ID)
	return a, nil
}

// GetByPrefix finds an alert by ID prefix (minimum 8 chars).
func (s *Store) GetByPrefix(ctx context.Context, prefix string) (*Alert, error) {
	if len(prefix) >= 36 {
		return s.Get(ctx, prefix)
	}

	a := &Alert{}
	err := s.pool.QueryRow(ctx,
		`SELECT id, source, type, tenant, service, summary, severity, status,
		 analysis, proposed_fix, pr_url, pr_number, confidence,
		 created_at, updated_at, resolved_at, acknowledged_by, acknowledged_at,
		 fingerprint, occurrence_count, last_seen_at
		 FROM alerts WHERE id LIKE $1 ORDER BY created_at DESC LIMIT 1`, prefix+"%").Scan(
		&a.ID, &a.Source, &a.Type, &a.Tenant, &a.Service, &a.Summary, &a.Severity, &a.Status,
		&a.Analysis, &a.ProposedFix, &a.PRURL, &a.PRNumber, &a.Confidence,
		&a.CreatedAt, &a.UpdatedAt, &a.ResolvedAt, &a.AcknowledgedBy, &a.AcknowledgedAt,
		&a.Fingerprint, &a.OccurrenceCount, &a.LastSeenAt,
	)
	if err != nil {
		return nil, fmt.Errorf("alerts store: get by prefix: %w", err)
	}

	a.Evidence, _ = s.getEvidence(ctx, a.ID)
	return a, nil
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

	query := `SELECT id, source, type, tenant, service, summary, severity, status,
		analysis, proposed_fix, pr_url, pr_number, confidence,
		created_at, updated_at, resolved_at, acknowledged_by, acknowledged_at,
		fingerprint, occurrence_count, last_seen_at
		FROM alerts`
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
		if err := rows.Scan(
			&a.ID, &a.Source, &a.Type, &a.Tenant, &a.Service, &a.Summary, &a.Severity, &a.Status,
			&a.Analysis, &a.ProposedFix, &a.PRURL, &a.PRNumber, &a.Confidence,
			&a.CreatedAt, &a.UpdatedAt, &a.ResolvedAt, &a.AcknowledgedBy, &a.AcknowledgedAt,
			&a.Fingerprint, &a.OccurrenceCount, &a.LastSeenAt,
		); err != nil {
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
