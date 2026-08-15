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
