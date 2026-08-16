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

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const schema = `
CREATE TABLE IF NOT EXISTS audit_events (
  id           TEXT PRIMARY KEY,
  timestamp    TIMESTAMPTZ NOT NULL,
  user_id      TEXT NOT NULL,
  operation    TEXT NOT NULL,
  params       JSONB,
  workflow     TEXT,
  status       TEXT NOT NULL,
  risk_level   TEXT,
  message      TEXT,
  client_ip    TEXT,
  user_agent   TEXT,
  request_id   TEXT
);
CREATE INDEX IF NOT EXISTS audit_events_timestamp ON audit_events (timestamp DESC);
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS client_ip TEXT;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS user_agent TEXT;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS request_id TEXT;
`

// PostgresLogger persists audit entries to PostgreSQL via pgx.
type PostgresLogger struct {
	pool *pgxpool.Pool
}

// NewPostgresLogger creates a PostgreSQL-backed audit logger.
// It auto-creates the schema on startup.
func NewPostgresLogger(ctx context.Context, connStr string) (*PostgresLogger, error) {
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("audit postgres: connect: %w", err)
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("audit postgres: create schema: %w", err)
	}
	// Separate Exec, and deliberately not part of `schema`: CONCURRENTLY cannot
	// run inside a transaction, and pgx wraps a multi-statement Exec in an
	// implicit one. Partial because most denied/failed rows have no workflow.
	// A failure here costs an index, not a startup — GetByWorkflow, UpdateStatus
	// and the reconciler all still work, just with a sequential scan.
	for _, idx := range []struct{ name, stmt string }{
		{"audit_events_workflow",
			`CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_events_workflow
			 ON audit_events (workflow) WHERE workflow <> ''`},
		// The reconciler's queue query: oldest rows in one status. Without the
		// composite index this walks the timestamp index discarding every
		// already-terminal row, which is nearly all of them as the table grows.
		{"audit_events_queue",
			`CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_events_queue
			 ON audit_events (status, timestamp ASC) WHERE workflow <> ''`},
	} {
		if _, err := pool.Exec(ctx, idx.stmt); err != nil {
			slog.Warn("audit postgres: could not create index", "index", idx.name, "error", err)
		}
	}
	slog.Info("audit postgres logger initialized")
	return &PostgresLogger{pool: pool}, nil
}

// Ping reports whether the audit database is reachable.
func (p *PostgresLogger) Ping(ctx context.Context) error {
	return p.pool.Ping(ctx)
}

// Log inserts an audit entry into PostgreSQL.
func (p *PostgresLogger) Log(entry Entry) {
	if entry.ID == "" {
		entry.ID = uuid.NewString()
	}
	entry.Timestamp = time.Now().UTC()

	params, _ := json.Marshal(entry.Parameters)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := p.pool.Exec(ctx,
		`INSERT INTO audit_events (id, timestamp, user_id, operation, params, workflow, status, risk_level, message, client_ip, user_agent, request_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		 ON CONFLICT (id) DO NOTHING`,
		entry.ID, entry.Timestamp, entry.UserID, entry.Operation,
		params, entry.WorkflowName, entry.Status, entry.RiskLevel, entry.Message,
		entry.ClientIP, entry.UserAgent, entry.RequestID,
	)
	if err != nil {
		slog.Error("audit postgres: insert failed", "error", err)
	}

	slog.Info("audit",
		"user", entry.UserID,
		"operation", entry.Operation,
		"workflow", entry.WorkflowName,
		"status", entry.Status,
		"riskLevel", entry.RiskLevel,
		"clientIp", entry.ClientIP,
		"requestId", entry.RequestID,
	)
}

// List returns the most recent audit entries from PostgreSQL.
func (p *PostgresLogger) List(limit int) []Entry {
	if limit <= 0 {
		limit = 50
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := p.pool.Query(ctx,
		`SELECT id, timestamp, user_id, operation, params, workflow, status, risk_level, message, client_ip, user_agent, request_id
		 FROM audit_events ORDER BY timestamp DESC LIMIT $1`, limit)
	if err != nil {
		slog.Error("audit postgres: list failed", "error", err)
		return nil
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		e, err := scanAuditEntry(rows.Scan)
		if err != nil {
			slog.Error("audit postgres: scan failed", "error", err)
			continue
		}
		entries = append(entries, e)
	}
	return entries
}

// GetByWorkflow returns the audit entry for a specific workflow.
func (p *PostgresLogger) GetByWorkflow(workflowName string) *Entry {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	row := p.pool.QueryRow(ctx,
		`SELECT id, timestamp, user_id, operation, params, workflow, status, risk_level, message, client_ip, user_agent, request_id
		 FROM audit_events WHERE workflow = $1 ORDER BY timestamp DESC LIMIT 1`, workflowName)

	e, err := scanAuditEntry(row.Scan)
	if err != nil {
		return nil
	}
	return &e
}

func scanAuditEntry(scan func(dest ...any) error) (Entry, error) {
	var e Entry
	var params []byte
	var workflow, riskLevel, message, clientIP, userAgent, requestID *string
	if err := scan(&e.ID, &e.Timestamp, &e.UserID, &e.Operation,
		&params, &workflow, &e.Status, &riskLevel, &message, &clientIP, &userAgent, &requestID); err != nil {
		return Entry{}, err
	}
	if workflow != nil {
		e.WorkflowName = *workflow
	}
	if riskLevel != nil {
		e.RiskLevel = *riskLevel
	}
	if message != nil {
		e.Message = *message
	}
	if clientIP != nil {
		e.ClientIP = *clientIP
	}
	if userAgent != nil {
		e.UserAgent = *userAgent
	}
	if requestID != nil {
		e.RequestID = *requestID
	}
	if len(params) > 0 {
		_ = json.Unmarshal(params, &e.Parameters)
	}
	return e, nil
}

// UpdateStatus closes out a non-terminal audit row for workflowName.
//
// This is an UPDATE in place rather than a second "completion" row on purpose:
// GetByWorkflow reads ORDER BY timestamp DESC LIMIT 1, so a completion row —
// which carries no params — would become the newest match and break the tenant
// lookup that authorizes GET /workflows/{name}/logs for non-admins. Updating
// in place also keeps the original submission timestamp, so ordering in
// ListWorkflows and ListAudit stays "by time submitted".
//
// The status guard makes redelivery a no-op: a webhook that arrives twice, or
// races the reconciler, updates zero rows the second time.
func (p *PostgresLogger) UpdateStatus(workflowName, status, message string) bool {
	if workflowName == "" || status == "" {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Scoped to the newest matching row via the subquery, so this matches the
	// in-memory implementation. Argo names carry a generated suffix so reuse is
	// unlikely, but "close every historical run that shares this name" is not a
	// behaviour worth leaving to chance in an audit table.
	//
	// The terminal set is built from TerminalStatuses rather than written out,
	// so the SQL guard cannot drift from what IsTerminal believes. A drift here
	// would let redelivery reopen a row the Go layer already considers closed.
	tag, err := p.pool.Exec(ctx,
		`UPDATE audit_events
		    SET status = $2,
		        message = CASE WHEN $3 = '' THEN message ELSE $3 END
		  WHERE id IN (
		        SELECT id FROM audit_events
		         WHERE workflow = $1 AND NOT (status = ANY($4))
		         ORDER BY timestamp DESC
		         LIMIT 1
		  )`,
		workflowName, status, message, TerminalStatuses)
	if err != nil {
		slog.Error("audit postgres: update status failed", "workflow", workflowName, "error", err)
		return false
	}
	return tag.RowsAffected() > 0
}

// ListByStatus returns audit entries in the given status, oldest first — see
// the interface doc for why the reconciler must drain from the old end.
func (p *PostgresLogger) ListByStatus(status string, maxAge time.Duration, limit int, after time.Time) []Entry {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows, err := p.pool.Query(ctx,
		`SELECT id, timestamp, user_id, operation, params, workflow, status, risk_level, message, client_ip, user_agent, request_id
		   FROM audit_events
		  WHERE status = $1 AND workflow <> '' AND timestamp > $2 AND timestamp > $4
		  ORDER BY timestamp ASC
		  LIMIT $3`,
		status, time.Now().UTC().Add(-maxAge), limit, after)
	if err != nil {
		slog.Error("audit postgres: list by status failed", "status", status, "error", err)
		return nil
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		e, err := scanAuditEntry(rows.Scan)
		if err != nil {
			slog.Error("audit postgres: scan failed", "error", err)
			continue
		}
		entries = append(entries, e)
	}
	return entries
}
