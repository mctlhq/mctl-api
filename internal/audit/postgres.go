package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

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
  message      TEXT
);
CREATE INDEX IF NOT EXISTS audit_events_timestamp ON audit_events (timestamp DESC);
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

// Log inserts an audit entry into PostgreSQL.
func (p *PostgresLogger) Log(entry Entry) {
	entry.Timestamp = time.Now().UTC()

	params, _ := json.Marshal(entry.Parameters)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := p.pool.Exec(ctx,
		`INSERT INTO audit_events (id, timestamp, user_id, operation, params, workflow, status, risk_level, message)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 ON CONFLICT (id) DO NOTHING`,
		entry.ID, entry.Timestamp, entry.UserID, entry.Operation,
		params, entry.WorkflowName, entry.Status, entry.RiskLevel, entry.Message,
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
		`SELECT id, timestamp, user_id, operation, params, workflow, status, risk_level, message
		 FROM audit_events ORDER BY timestamp DESC LIMIT $1`, limit)
	if err != nil {
		slog.Error("audit postgres: list failed", "error", err)
		return nil
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var e Entry
		var params []byte
		var workflow, riskLevel, message *string
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.UserID, &e.Operation,
			&params, &workflow, &e.Status, &riskLevel, &message); err != nil {
			slog.Error("audit postgres: scan failed", "error", err)
			continue
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
		if len(params) > 0 {
			_ = json.Unmarshal(params, &e.Parameters)
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
		`SELECT id, timestamp, user_id, operation, params, workflow, status, risk_level, message
		 FROM audit_events WHERE workflow = $1 ORDER BY timestamp DESC LIMIT 1`, workflowName)

	var e Entry
	var params []byte
	var workflow, riskLevel, message *string
	if err := row.Scan(&e.ID, &e.Timestamp, &e.UserID, &e.Operation,
		&params, &workflow, &e.Status, &riskLevel, &message); err != nil {
		return nil
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
	if len(params) > 0 {
		_ = json.Unmarshal(params, &e.Parameters)
	}
	return &e
}
