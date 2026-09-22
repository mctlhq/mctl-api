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

package usage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// usageSchema follows the repo convention: CREATE ... IF NOT EXISTS executed at
// startup rather than a migration file (see internal/lifecycle, internal/alerts
// and internal/agentregistry).
//
// Two constraints carry contract meaning rather than hygiene:
//
//   - PRIMARY KEY (id). The id is the deterministic dedupe key, so the primary
//     key IS the idempotency guarantee. Re-delivering a paid invocation cannot
//     produce a second row no matter how many times a retry, a replay or a
//     reprocessing run repeats the write.
//   - calculated_cost_requires_version. ADR-012 invariant 6. A stored estimate
//     with no record of the rates that produced it cannot be reproduced after a
//     price change, so the database refuses to hold one.
//
// Every token column is NULLable on purpose: NULL means the provider did not
// report the figure, 0 means it reported zero, and SUM() over the column
// ignores the former while counting the latter. Making these NOT NULL DEFAULT 0
// would silently convert "not measured" into "nothing spent".
const usageSchema = `
CREATE TABLE IF NOT EXISTS model_usage_records (
    id                      TEXT PRIMARY KEY,
    schema_version          INTEGER NOT NULL,
    session_id              TEXT NOT NULL,
    result_uuid             TEXT NOT NULL DEFAULT '',
    model_key               TEXT NOT NULL,
    canonical_model         TEXT NOT NULL DEFAULT '',
    provider                TEXT NOT NULL DEFAULT '',

    temporal_workflow_id    TEXT NOT NULL DEFAULT '',
    argo_workflow_name      TEXT NOT NULL DEFAULT '',
    agent                   TEXT NOT NULL DEFAULT '',
    devloop_stage           TEXT NOT NULL DEFAULT '',
    target_repo             TEXT NOT NULL DEFAULT '',
    issue_number            BIGINT,
    pr_number               BIGINT,
    work_item_id            TEXT NOT NULL DEFAULT '',
    trace_id                TEXT NOT NULL DEFAULT '',
    span_id                 TEXT NOT NULL DEFAULT '',

    input_tokens            BIGINT,
    output_tokens           BIGINT,
    cache_read_tokens       BIGINT,
    cache_write_tokens      BIGINT,
    reasoning_tokens        BIGINT,
    web_search_requests     BIGINT,

    provider_reported_cost  DOUBLE PRECISION,
    calculated_cost         DOUBLE PRECISION,
    pricing_version         TEXT NOT NULL DEFAULT '',
    invoice_reconciled_cost DOUBLE PRECISION,

    outcome                 TEXT NOT NULL DEFAULT '',
    api_error_status        TEXT NOT NULL DEFAULT '',
    stop_reason             TEXT NOT NULL DEFAULT '',
    terminal_reason         TEXT NOT NULL DEFAULT '',
    num_turns               BIGINT,
    duration_api_ms         BIGINT,
    retry_attempt           BIGINT,

    recorded_at             TIMESTAMPTZ NOT NULL,
    ingested_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT calculated_cost_requires_version
        CHECK (calculated_cost IS NULL OR pricing_version <> '')
);

CREATE INDEX IF NOT EXISTS model_usage_recorded_at_idx ON model_usage_records (recorded_at);
CREATE INDEX IF NOT EXISTS model_usage_workflow_idx    ON model_usage_records (temporal_workflow_id);
CREATE INDEX IF NOT EXISTS model_usage_repo_issue_idx  ON model_usage_records (target_repo, issue_number);
CREATE INDEX IF NOT EXISTS model_usage_repo_pr_idx     ON model_usage_records (target_repo, pr_number);
CREATE INDEX IF NOT EXISTS model_usage_agent_idx       ON model_usage_records (agent, devloop_stage);
CREATE INDEX IF NOT EXISTS model_usage_model_idx       ON model_usage_records (canonical_model, provider);
CREATE INDEX IF NOT EXISTS model_usage_work_item_idx   ON model_usage_records (work_item_id);
`

// Store is the durable ledger.
type Store struct {
	pool    *pgxpool.Pool
	catalog *Catalog
}

// NewStore connects, applies the schema and returns a ready store.
func NewStore(ctx context.Context, connStr string, catalog *Catalog) (*Store, error) {
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("usage: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("usage: ping: %w", err)
	}
	if _, err := pool.Exec(ctx, usageSchema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("usage: schema: %w", err)
	}
	return &Store{pool: pool, catalog: catalog}, nil
}

// Close releases the pool.
func (s *Store) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}

// Catalog exposes the pricing catalog this store prices with.
func (s *Store) Catalog() *Catalog { return s.catalog }

const insertRecordSQL = `
INSERT INTO model_usage_records (
    id, schema_version, session_id, result_uuid, model_key, canonical_model, provider,
    temporal_workflow_id, argo_workflow_name, agent, devloop_stage, target_repo,
    issue_number, pr_number, work_item_id, trace_id, span_id,
    input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
    reasoning_tokens, web_search_requests,
    provider_reported_cost, calculated_cost, pricing_version, invoice_reconciled_cost,
    outcome, api_error_status, stop_reason, terminal_reason,
    num_turns, duration_api_ms, retry_attempt, recorded_at
) VALUES (
    $1,$2,$3,$4,$5,$6,$7,
    $8,$9,$10,$11,$12,
    $13,$14,$15,$16,$17,
    $18,$19,$20,$21,
    $22,$23,
    $24,$25,$26,$27,
    $28,$29,$30,$31,
    $32,$33,$34,$35
)
ON CONFLICT (id) DO NOTHING
`

// IngestResult reports what a batch did. Deduped counts records whose id was
// already present, which is a success, not an error: it is the guarantee doing
// its job.
type IngestResult struct {
	Accepted []string `json:"accepted"`
	Deduped  []string `json:"deduped"`
}

// Ingest persists records idempotently.
//
// The whole batch is one transaction, so a producer retrying after a partial
// failure re-sends a batch that either applied entirely or not at all — and in
// the "entirely" case every row collides on its id and the retry is a no-op.
//
// Pricing is applied here, at ingest, and the resulting number plus the rate
// card version are stored on the row. That is what makes invariant 7 hold: a
// later rate card cannot reach back into history.
func (s *Store) Ingest(ctx context.Context, records []*Record) (*IngestResult, error) {
	res := &IngestResult{Accepted: []string{}, Deduped: []string{}}
	if len(records) == 0 {
		return res, nil
	}
	for _, r := range records {
		if err := r.EnsureID(); err != nil {
			return nil, err
		}
		if r.CalculatedCost == nil && r.ProviderReportedCost == nil && s.catalog != nil {
			// A model with no rate card is not a reason to reject the record:
			// the token counts are still the truth, and a cost can be derived
			// later once a card exists. Dropping the record would lose the
			// measurement permanently.
			if err := s.catalog.Calculate(r); err != nil && !errors.Is(err, ErrNoPricing) {
				return nil, err
			}
		}
		if err := r.Validate(); err != nil {
			return nil, err
		}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("usage: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, r := range records {
		tag, err := tx.Exec(ctx, insertRecordSQL,
			r.ID, r.SchemaVersion, r.SessionID, r.ResultUUID, r.ModelKey, r.CanonicalModel, r.Provider,
			r.TemporalWorkflowID, r.ArgoWorkflowName, r.Agent, r.DevLoopStage, r.TargetRepo,
			r.IssueNumber, r.PRNumber, r.WorkItemID, r.TraceID, r.SpanID,
			r.InputTokens, r.OutputTokens, r.CacheReadTokens, r.CacheWriteTokens,
			r.ReasoningTokens, r.WebSearchRequests,
			r.ProviderReportedCost, r.CalculatedCost, r.PricingVersion, r.InvoiceReconciledCost,
			r.Outcome, r.APIErrorStatus, r.StopReason, r.TerminalReason,
			r.NumTurns, r.DurationAPIMs, r.RetryAttempt, r.RecordedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("usage: insert %s: %w", r.ID, err)
		}
		if tag.RowsAffected() == 0 {
			res.Deduped = append(res.Deduped, r.ID)
		} else {
			res.Accepted = append(res.Accepted, r.ID)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("usage: commit: %w", err)
	}
	return res, nil
}

// Filter narrows a query. A zero Filter matches everything.
type Filter struct {
	TemporalWorkflowID string
	WorkItemID         string
	TargetRepo         string
	IssueNumber        *int64
	PRNumber           *int64
	Agent              string
	DevLoopStage       string
	Provider           string
	CanonicalModel     string
	Outcome            string
	Since              *time.Time
	Until              *time.Time
	Limit              int
}

// where builds the shared predicate for both the record list and the
// aggregation, so a filter can never mean one thing in a total and another in
// the rows that total is supposed to explain.
func (f Filter) where() (string, []any) {
	var clauses []string
	var args []any
	add := func(expr string, v any) {
		args = append(args, v)
		clauses = append(clauses, fmt.Sprintf(expr, len(args)))
	}
	if f.TemporalWorkflowID != "" {
		add("temporal_workflow_id = $%d", f.TemporalWorkflowID)
	}
	if f.WorkItemID != "" {
		add("work_item_id = $%d", f.WorkItemID)
	}
	if f.TargetRepo != "" {
		add("target_repo = $%d", f.TargetRepo)
	}
	if f.IssueNumber != nil {
		add("issue_number = $%d", *f.IssueNumber)
	}
	if f.PRNumber != nil {
		add("pr_number = $%d", *f.PRNumber)
	}
	if f.Agent != "" {
		add("agent = $%d", f.Agent)
	}
	if f.DevLoopStage != "" {
		add("devloop_stage = $%d", f.DevLoopStage)
	}
	if f.Provider != "" {
		add("provider = $%d", f.Provider)
	}
	if f.CanonicalModel != "" {
		add("canonical_model = $%d", f.CanonicalModel)
	}
	if f.Outcome != "" {
		add("outcome = $%d", f.Outcome)
	}
	if f.Since != nil {
		add("recorded_at >= $%d", *f.Since)
	}
	if f.Until != nil {
		add("recorded_at < $%d", *f.Until)
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

const selectColumns = `
    id, schema_version, session_id, result_uuid, model_key, canonical_model, provider,
    temporal_workflow_id, argo_workflow_name, agent, devloop_stage, target_repo,
    issue_number, pr_number, work_item_id, trace_id, span_id,
    input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
    reasoning_tokens, web_search_requests,
    provider_reported_cost, calculated_cost, pricing_version, invoice_reconciled_cost,
    outcome, api_error_status, stop_reason, terminal_reason,
    num_turns, duration_api_ms, retry_attempt, recorded_at
`

// List returns matching records, newest first.
func (s *Store) List(ctx context.Context, f Filter) ([]*Record, error) {
	where, args := f.where()
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	args = append(args, limit)
	q := "SELECT" + selectColumns + "FROM model_usage_records" + where +
		fmt.Sprintf(" ORDER BY recorded_at DESC, id ASC LIMIT $%d", len(args))
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("usage: list: %w", err)
	}
	defer rows.Close()
	var out []*Record
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("usage: list rows: %w", err)
	}
	return out, nil
}

func scanRecord(rows pgx.Rows) (*Record, error) {
	var r Record
	if err := rows.Scan(
		&r.ID, &r.SchemaVersion, &r.SessionID, &r.ResultUUID, &r.ModelKey, &r.CanonicalModel, &r.Provider,
		&r.TemporalWorkflowID, &r.ArgoWorkflowName, &r.Agent, &r.DevLoopStage, &r.TargetRepo,
		&r.IssueNumber, &r.PRNumber, &r.WorkItemID, &r.TraceID, &r.SpanID,
		&r.InputTokens, &r.OutputTokens, &r.CacheReadTokens, &r.CacheWriteTokens,
		&r.ReasoningTokens, &r.WebSearchRequests,
		&r.ProviderReportedCost, &r.CalculatedCost, &r.PricingVersion, &r.InvoiceReconciledCost,
		&r.Outcome, &r.APIErrorStatus, &r.StopReason, &r.TerminalReason,
		&r.NumTurns, &r.DurationAPIMs, &r.RetryAttempt, &r.RecordedAt,
	); err != nil {
		return nil, fmt.Errorf("usage: scan: %w", err)
	}
	return &r, nil
}

// GroupBy names a dimension the summary can aggregate over. The set is closed
// and mapped to a fixed column here rather than interpolated from the request,
// so a query parameter can never become SQL.
type GroupBy string

const (
	GroupByAgent    GroupBy = "agent"
	GroupByStage    GroupBy = "devloop_stage"
	GroupByModel    GroupBy = "canonical_model"
	GroupByProvider GroupBy = "provider"
	GroupByRepo     GroupBy = "target_repo"
	GroupByWorkflow GroupBy = "temporal_workflow_id"
	GroupByWorkItem GroupBy = "work_item_id"
	GroupByOutcome  GroupBy = "outcome"
)

var groupColumns = map[GroupBy]string{
	GroupByAgent:    "agent",
	GroupByStage:    "devloop_stage",
	GroupByModel:    "canonical_model",
	GroupByProvider: "provider",
	GroupByRepo:     "target_repo",
	GroupByWorkflow: "temporal_workflow_id",
	GroupByWorkItem: "work_item_id",
	GroupByOutcome:  "outcome",
}

// ParseGroupBy resolves a request value to a known dimension.
func ParseGroupBy(s string) (GroupBy, bool) {
	g := GroupBy(strings.TrimSpace(strings.ToLower(s)))
	_, ok := groupColumns[g]
	return g, ok
}

// Bucket is one row of a summary.
//
// The token totals are nullable for the same reason the columns are: SUM()
// over a column where every matching row is NULL yields NULL, and that answer
// ("no row reported this") is different from 0 ("rows reported zero"). Flattening
// it here would undo the distinction the schema went to trouble to keep.
type Bucket struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`

	InputTokens       *int64 `json:"input_tokens,omitempty"`
	OutputTokens      *int64 `json:"output_tokens,omitempty"`
	CacheReadTokens   *int64 `json:"cache_read_tokens,omitempty"`
	CacheWriteTokens  *int64 `json:"cache_write_tokens,omitempty"`
	ReasoningTokens   *int64 `json:"reasoning_tokens,omitempty"`
	WebSearchRequests *int64 `json:"web_search_requests,omitempty"`

	// Kept apart on purpose: an estimate must never be readable as invoice
	// truth, so they are never summed into one number.
	ProviderReportedCost  *float64 `json:"provider_reported_cost,omitempty"`
	CalculatedCost        *float64 `json:"calculated_cost,omitempty"`
	InvoiceReconciledCost *float64 `json:"invoice_reconciled_cost,omitempty"`
}

// Summary aggregates matching records over one dimension.
func (s *Store) Summary(ctx context.Context, f Filter, by GroupBy) ([]*Bucket, error) {
	col, ok := groupColumns[by]
	if !ok {
		return nil, fmt.Errorf("%w: unknown group_by %q", ErrInvalidRecord, string(by))
	}
	where, args := f.where()
	q := fmt.Sprintf(`
SELECT %s AS key,
       COUNT(*),
       SUM(input_tokens), SUM(output_tokens), SUM(cache_read_tokens), SUM(cache_write_tokens),
       SUM(reasoning_tokens), SUM(web_search_requests),
       SUM(provider_reported_cost), SUM(calculated_cost), SUM(invoice_reconciled_cost)
FROM model_usage_records%s
GROUP BY %s
ORDER BY COUNT(*) DESC, key ASC`, col, where, col)
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("usage: summary: %w", err)
	}
	defer rows.Close()
	var out []*Bucket
	for rows.Next() {
		var b Bucket
		if err := rows.Scan(&b.Key, &b.Count,
			&b.InputTokens, &b.OutputTokens, &b.CacheReadTokens, &b.CacheWriteTokens,
			&b.ReasoningTokens, &b.WebSearchRequests,
			&b.ProviderReportedCost, &b.CalculatedCost, &b.InvoiceReconciledCost,
		); err != nil {
			return nil, fmt.Errorf("usage: summary scan: %w", err)
		}
		out = append(out, &b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("usage: summary rows: %w", err)
	}
	return out, nil
}
