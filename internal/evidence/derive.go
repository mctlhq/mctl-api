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
	"log/slog"
	"regexp"
	"strconv"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/workitems"
)

// ExecutionResolver looks up correlation facts about a canonical work
// execution, for the best-effort derived projection only
// (execution_evidence_refs). Satisfied by *workitems.Store. Never a
// foreign key: the evidence store may be pointed at a different database
// than the work-item store, and a resolver that cannot find anything is not
// an error — the projection simply stays empty for that row.
type ExecutionResolver interface {
	ResolveExecution(ctx context.Context, executionID string) (*workitems.ExecutionCorrelation, error)
}

// SetResolver wires the best-effort work-execution resolver. A nil resolver
// (the default) leaves every derived projection empty, which is still a
// correct, honest answer — never an error.
func (s *Store) SetResolver(r ExecutionResolver) { s.resolver = r }

// externalKeyPattern parses a work item's external_key when it is a GitHub
// issue or pull request URL — the shape internal/workitems documents
// (inputs.go: "ExternalKey (for example a GitHub issue URL)") and the shape
// issue-investigator and the implementer actually set it to. An
// external_key in any other shape (or absent) leaves repository/issue/pr
// unset: this is a best-effort projection, never a second parser Tier A or
// workitems must agree with.
var externalKeyPattern = regexp.MustCompile(`^https://github\.com/([^/\s]+/[^/\s]+)/(issues|pull)/(\d+)/?$`)

// parseExternalKey best-effort extracts (repository, issueNumber, prNumber)
// from a work item's external_key. At most one of issueNumber/prNumber is
// non-nil. An unparseable external_key returns all three empty/nil.
func parseExternalKey(externalKey string) (repository string, issueNumber, prNumber *int64) {
	m := externalKeyPattern.FindStringSubmatch(externalKey)
	if m == nil {
		return "", nil, nil
	}
	n, err := strconv.ParseInt(m[3], 10, 64)
	if err != nil {
		return "", nil, nil
	}
	if m[2] == "pull" {
		return m[1], nil, &n
	}
	return m[1], &n, nil
}

// deriveAndStoreRef computes the best-effort projection for e from corr
// (resolveExecution's answer, looked up before tx was opened) and stores it
// in the same transaction as the evidence insert (tasks.md task 5). It
// never returns an error that would roll back a valid ingest; a resolver
// miss, a nil resolver, or an unparseable external_key all simply leave the
// corresponding fields empty.
func (s *Store) deriveAndStoreRef(ctx context.Context, tx pgx.Tx, e *Evidence, corr *workitems.ExecutionCorrelation) error {
	ref := EvidenceRef{EvidenceID: e.ID, DerivedAt: s.now()}
	populateRef(&ref, e, corr)
	_, err := tx.Exec(ctx, `INSERT INTO execution_evidence_refs (`+refColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (evidence_id) DO UPDATE SET
			work_execution_id=EXCLUDED.work_execution_id, work_item_id=EXCLUDED.work_item_id,
			tenant=EXCLUDED.tenant, engine=EXCLUDED.engine, engine_ref=EXCLUDED.engine_ref,
			repository=EXCLUDED.repository, issue_number=EXCLUDED.issue_number,
			pr_number=EXCLUDED.pr_number, derived_at=EXCLUDED.derived_at`,
		ref.EvidenceID, ref.WorkExecutionID, ref.WorkItemID, ref.Tenant, ref.Engine, ref.EngineRef,
		ref.Repository, ref.IssueNumber, ref.PRNumber, ref.DerivedAt)
	return err
}

// populateRef fills in every field it can resolve, best-effort. A `we_`
// join value that resolves populates engine/engine_ref/work_item_id/tenant
// and, when the work item's external_key parses, repository plus exactly
// one of issue_number/pr_number. A join with no we_ (runtime-only,
// implementer and shepherd runs today) resolves nothing in mctl-api yet, so
// the projection stays empty — an honest absence, not an error (design.md
// section 5, the "we_/ex- split" open question in requirements.md).
func populateRef(ref *EvidenceRef, e *Evidence, c *workitems.ExecutionCorrelation) {
	if c == nil || e.ExecutionID == "" {
		return
	}
	ref.WorkExecutionID = e.ExecutionID
	ref.WorkItemID = c.WorkItemID
	ref.Engine = c.Engine
	ref.EngineRef = c.EngineRef
	ref.Tenant = c.Tenant
	ref.Repository, ref.IssueNumber, ref.PRNumber = parseExternalKey(c.ExternalKey)
}

// resolveExecution asks the resolver about executionID, best-effort: a nil
// resolver, an empty id, a miss or an error all answer nil. Callers must
// run it outside any transaction of this store (see Ingest).
func (s *Store) resolveExecution(ctx context.Context, executionID string) *workitems.ExecutionCorrelation {
	if s.resolver == nil || executionID == "" {
		return nil
	}
	c, err := s.resolver.ResolveExecution(ctx, executionID)
	if err != nil {
		// Logged so a failed lookup, which RebuildRefs can repair, is told
		// apart from an execution that does not correlate at all.
		slog.Warn("evidence: execution lookup failed, projection left empty",
			"execution_id", executionID, "error", err)
		return nil
	}
	return c
}

// RebuildRefs recomputes the derived projection for the named evidence ids
// (or, with none given, does nothing — a full-table rebuild is an operator
// action, not a hot path). It is idempotent and never changes any
// execution_evidence row: only execution_evidence_refs is rewritten.
func (s *Store) RebuildRefs(ctx context.Context, ids []string) error {
	for _, id := range ids {
		e, err := scanEvidenceRow(s.pool.QueryRow(ctx, `SELECT `+evidenceRowColumns+` FROM execution_evidence WHERE id=$1`, id))
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			return err
		}
		corr := s.resolveExecution(ctx, e.ExecutionID)
		if err := withTx(ctx, s.pool, "evidence:"+id, func(tx pgx.Tx) error {
			return s.deriveAndStoreRef(ctx, tx, e, corr)
		}); err != nil {
			return err
		}
	}
	return nil
}
