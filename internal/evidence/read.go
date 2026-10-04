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
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// qualifiedEvidenceColumns is evidenceColumns with every column qualified
// to the "e" alias List uses, so an unqualified column that also exists on
// execution_evidence_refs (work_item_id) is never ambiguous once the
// filter joins that table in.
var qualifiedEvidenceColumns = qualifyColumns("e", evidenceRowColumns)

func qualifyColumns(alias, columns string) string {
	parts := strings.Split(columns, ",")
	for i, p := range parts {
		parts[i] = alias + "." + strings.TrimSpace(p)
	}
	return strings.Join(parts, ", ")
}

// Query page bounds. Exported for the same reason usage.DefaultQueryLimit
// is: the HTTP layer rejects an over-large limit before it reaches the
// store, and the two must not drift.
const (
	DefaultQueryLimit = 200
	MaxQueryLimit     = 1000
)

func clampLimit(limit int) int {
	switch {
	case limit <= 0:
		return DefaultQueryLimit
	case limit > MaxQueryLimit:
		return MaxQueryLimit
	default:
		return limit
	}
}

// Get returns one evidence record by its ev- id, with its derived
// projection attached. ErrEvidenceNotFound when no such row exists. A row
// whose stored bytes no longer hash to their content_hash is refused with an
// error that is deliberately NOT ErrEvidenceNotFound: the row exists but is
// corrupt, which is a server-side fault (500), not an absence (404).
func (s *Store) Get(ctx context.Context, id string) (*Evidence, error) {
	e, err := scanEvidenceRow(s.pool.QueryRow(ctx, `SELECT `+evidenceRowColumns+` FROM execution_evidence WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("evidence: %s: %w", id, ErrEvidenceNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("evidence: get %s: %w", id, err)
	}
	if err := s.attachRef(ctx, e); err != nil {
		return nil, err
	}
	if err := s.attachSupersededBy(ctx, []*Evidence{e}); err != nil {
		return nil, err
	}
	return e, nil
}

// Filter narrows a List query. A zero Filter matches every row (bounded by
// Limit). Every documented filter (execution_id, runtime_execution_id,
// trace_id, work_item_id, engine+engine_ref, repository+issue,
// repository+pr) returns an identically-shaped ListResult, so a caller
// cannot tell which filter it used from the response shape alone
// (requirements.md "Retrieval and authorization").
type Filter struct {
	ExecutionID        string
	RuntimeExecutionID string
	TraceID            string
	WorkItemID         string
	Engine             string
	EngineRef          string
	Repository         string
	IssueNumber        *int64
	PRNumber           *int64
	// ADR 018 Amendment 2 subject filters, matched on the immutable
	// subject_* columns.
	SubjectKind       string
	SubjectRepository string
	SubjectRef        string
	SubjectRevision   string
	Limit             int
}

// ListResult is a bounded page of evidence, newest first. Truncated is part
// of the answer: a clipped page must never read as a complete one.
type ListResult struct {
	Evidence  []*Evidence `json:"evidence"`
	Truncated bool        `json:"truncated"`
	Limit     int         `json:"limit"`
}

// List returns matching evidence, newest first. Every filter that names a
// column on execution_evidence_refs (engine, engine_ref, repository, issue,
// pr) joins through that table; work_item_id is matched on either table so
// a row is found whether or not its projection is resolved.
func (s *Store) List(ctx context.Context, f Filter) (*ListResult, error) {
	var clauses []string
	var args []any
	add := func(expr string, v any) {
		args = append(args, v)
		clauses = append(clauses, fmt.Sprintf(expr, len(args)))
	}
	needsRefJoin := false
	if f.ExecutionID != "" {
		add("e.execution_id = $%d", f.ExecutionID)
	}
	if f.RuntimeExecutionID != "" {
		add("e.runtime_execution_id = $%d", f.RuntimeExecutionID)
	}
	if f.TraceID != "" {
		add("e.trace_id = $%d", f.TraceID)
	}
	if f.WorkItemID != "" {
		// A runtime-only envelope may carry no work_item_id of its own while
		// the resolver has filled it in on the projection, so match either
		// column. One parameter, referenced twice.
		needsRefJoin = true
		args = append(args, f.WorkItemID)
		clauses = append(clauses, fmt.Sprintf("(e.work_item_id = $%d OR r.work_item_id = $%d)", len(args), len(args)))
	}
	if f.Engine != "" {
		needsRefJoin = true
		add("r.engine = $%d", f.Engine)
	}
	if f.EngineRef != "" {
		needsRefJoin = true
		add("r.engine_ref = $%d", f.EngineRef)
	}
	if f.Repository != "" {
		needsRefJoin = true
		add("r.repository = $%d", f.Repository)
	}
	if f.IssueNumber != nil {
		needsRefJoin = true
		add("r.issue_number = $%d", *f.IssueNumber)
	}
	if f.PRNumber != nil {
		needsRefJoin = true
		add("r.pr_number = $%d", *f.PRNumber)
	}
	if f.SubjectKind != "" {
		add("e.subject_kind = $%d", f.SubjectKind)
	}
	if f.SubjectRepository != "" {
		add("e.subject_repository = $%d", f.SubjectRepository)
	}
	if f.SubjectRef != "" {
		add("e.subject_ref = $%d", f.SubjectRef)
	}
	if f.SubjectRevision != "" {
		add("e.subject_revision = $%d", f.SubjectRevision)
	}

	limit := clampLimit(f.Limit)
	args = append(args, limit+1)

	from := "execution_evidence e"
	if needsRefJoin {
		// LEFT, so a row with no projection row still matches on its own
		// e.work_item_id. The other r.* predicates are equalities that a
		// missing ref row (all NULL) never satisfies, so they keep INNER
		// semantics. evidence_id is the refs primary key: at most one ref
		// row per evidence row, so the join never duplicates results.
		from = "execution_evidence e LEFT JOIN execution_evidence_refs r ON r.evidence_id = e.id"
	}
	query := "SELECT " + qualifiedEvidenceColumns + " FROM " + from
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += fmt.Sprintf(" ORDER BY e.ingested_at DESC, e.id ASC LIMIT $%d", len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("evidence: list: %w", err)
	}
	defer rows.Close()
	out := []*Evidence{}
	for rows.Next() {
		e, err := scanEvidenceRow(rows)
		if err != nil {
			return nil, fmt.Errorf("evidence: list scan: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("evidence: list rows: %w", err)
	}
	res := &ListResult{Limit: limit}
	if len(out) > limit {
		res.Truncated = true
		out = out[:limit]
	}
	for _, e := range out {
		if err := s.attachRef(ctx, e); err != nil {
			return nil, err
		}
	}
	if err := s.attachSupersededBy(ctx, out); err != nil {
		return nil, err
	}
	res.Evidence = out
	return res, nil
}

// ByWorkItem lists the evidence attached to one work item, newest first.
// Used by GET /api/v1/work-items/{id}/evidence, after the caller has
// already checked visibility on the work item itself.
//
// f narrows the result further (its subject filters, ADR 018 Amendment 2);
// f.WorkItemID is always overridden by workItemID.
func (s *Store) ByWorkItem(ctx context.Context, workItemID string, f Filter) (*ListResult, error) {
	f.WorkItemID = workItemID
	return s.List(ctx, f)
}

// attachSupersededBy fills the read-time SupersededBy of every record in
// recs: the stored envelopes whose provenance.supersedes names it through
// a valid link (validLink — the same predicate resolve_current applies).
// A row that fails to read is an error, never a shorter list.
func (s *Store) attachSupersededBy(ctx context.Context, recs []*Evidence) error {
	if len(recs) == 0 {
		return nil
	}
	ids := make([]string, 0, len(recs))
	byID := make(map[string][]*Evidence, len(recs))
	for _, e := range recs {
		e.SupersededBy = nil
		if _, seen := byID[e.ID]; !seen {
			ids = append(ids, e.ID)
		}
		byID[e.ID] = append(byID[e.ID], e)
	}
	rows, err := s.pool.Query(ctx, `SELECT `+evidenceRowColumns+` FROM execution_evidence
		WHERE supersedes = ANY($1) ORDER BY id`, ids)
	if err != nil {
		return fmt.Errorf("evidence: superseded_by: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		sup, err := scanEvidenceRow(rows)
		if err != nil {
			return fmt.Errorf("evidence: superseded_by scan: %w", err)
		}
		for _, target := range byID[sup.Supersedes] {
			if validLink(sup.candidate(), target.candidate()) {
				target.SupersededBy = append(target.SupersededBy, sup.ID)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("evidence: superseded_by rows: %w", err)
	}
	return nil
}

// PurgeOlderThan deletes whole evidence rows ingested more than maxAge ago
// and returns how many were removed. Retention deletes entire rows, never
// partially redacts one: a redacted envelope would no longer hash to its
// content_hash and would be refused on read anyway (requirements.md
// "Availability, gaps and retention"). DELETE cascades to
// execution_evidence_refs.
func (s *Store) PurgeOlderThan(ctx context.Context, maxAge time.Duration) (int64, error) {
	// A non-positive age puts the cutoff at or after now and would delete
	// every row. Refuse it here too, so no caller (an overflowed duration,
	// a zero read as "no retention") can empty the store by mistake.
	if maxAge <= 0 {
		return 0, fmt.Errorf("evidence: purge: maxAge must be positive, got %s", maxAge)
	}
	cutoff := s.now().Add(-maxAge)
	tag, err := s.pool.Exec(ctx, `DELETE FROM execution_evidence WHERE ingested_at < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("evidence: purge: %w", err)
	}
	return tag.RowsAffected(), nil
}
