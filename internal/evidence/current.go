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
)

// MaxCurrentPool bounds how many envelopes the current read loads for one
// (subject, revision). A larger pool is an error, never a truncated answer:
// resolve_current over a short list would turn an unknown into
// no_evidence.
const MaxCurrentPool = 1000

// maxCurrentPool is MaxCurrentPool, overridable by tests.
var maxCurrentPool = MaxCurrentPool

// MaxSupersedersPerRead bounds the superseding envelopes one read loads
// for superseded_by across all its records (each record is also capped at
// MaxCurrentPool on its own).
const MaxSupersedersPerRead = 10 * MaxCurrentPool

// maxSupersedersPerRead is MaxSupersedersPerRead, overridable by tests.
var maxSupersedersPerRead = MaxSupersedersPerRead

var (
	// ErrCurrentPoolTooLarge: more than MaxCurrentPool envelopes share the
	// subject and revision, so the complete pool cannot be loaded.
	ErrCurrentPoolTooLarge = errors.New("current-evidence pool exceeds the server cap")
	// ErrCurrentNotVisible: the work-item-scoped current read would have to
	// answer from evidence attached to other work items. The caller may not
	// see that evidence, and resolving over only the visible part would be
	// resolving over a partial pool, so the read refuses instead.
	ErrCurrentNotVisible = errors.New("the current evidence for this subject is not attached to this work item")
)

// CurrentResult is the current read's answer: a state and, only for
// current, the one envelope that is current.
type CurrentResult struct {
	State    string    `json:"state"`
	Evidence *Evidence `json:"evidence"`

	// considered are every stored record the answer depended on (the
	// whole pool, plus the other-revision witness when one was needed).
	considered []*Evidence
}

// Current implements GET /api/v1/evidence/current: ADR 018 Amendment 2's
// resolve_current over the complete pool for q. It loads every envelope at
// (subject key, revision) — failing rather than truncating past
// MaxCurrentPool — and, only when no usable pool member exists, one
// unredacted envelope for the same subject key at another revision as the
// stale_revision witness. That pair is exactly the information Tier A's
// resolve_current reads from a complete candidate list: other-revision
// envelopes affect nothing but the stale_revision/no_evidence choice.
// Any read or verification error is returned as an error, never as
// no_evidence.
func (s *Store) Current(ctx context.Context, q SubjectQuery) (*CurrentResult, error) {
	return s.current(ctx, q, "")
}

// current is Current with superseded_by scoped to scope (see
// attachSupersededBy).
func (s *Store) current(ctx context.Context, q SubjectQuery, scope string) (*CurrentResult, error) {
	if err := ValidateSubjectQuery(q); err != nil {
		return nil, err
	}
	if q.Revision == "" && shaBoundSubjectKinds[q.Kind] {
		return &CurrentResult{State: CurrentStateUnknownRevision}, nil
	}
	pool, err := s.loadPool(ctx, q)
	if err != nil {
		return nil, err
	}
	considered := pool
	usable := false
	for _, e := range pool {
		if !e.subjectRedacted {
			usable = true
			break
		}
	}
	if !usable {
		witness, err := s.loadStaleWitness(ctx, q)
		if err != nil {
			return nil, err
		}
		if witness != nil {
			considered = append(considered, witness)
		}
	}
	candidates := make([]*Candidate, len(considered))
	for i, e := range considered {
		candidates[i] = e.candidate()
	}
	state, winner, err := ResolveCurrent(candidates, q)
	if err != nil {
		return nil, err
	}
	res := &CurrentResult{State: state, considered: considered}
	if winner != nil {
		rec := winner.Record
		if err := s.attachRef(ctx, rec); err != nil {
			return nil, err
		}
		if err := s.attachSupersededBy(ctx, []*Evidence{rec}, scope); err != nil {
			return nil, err
		}
		res.Evidence = rec
	}
	return res, nil
}

// CurrentForWorkItem is the work-item-scoped variant of Current (GET
// /api/v1/work-items/{id}/evidence/current), for a caller the HTTP layer
// has already confirmed can see the work item. The answer is computed over
// the same complete pool as Current — never over the work item's slice of
// it, which could call a superseded envelope current — and is served only
// when every record it depended on is attached to the work item.
// Otherwise ErrCurrentNotVisible: an explicit refusal, never a fabricated
// no_evidence and never another work item's evidence.
func (s *Store) CurrentForWorkItem(ctx context.Context, q SubjectQuery, workItemID string) (*CurrentResult, error) {
	res, err := s.current(ctx, q, workItemID)
	if err != nil {
		return nil, err
	}
	for _, e := range res.considered {
		if e.Ref == nil {
			if err := s.attachRef(ctx, e); err != nil {
				return nil, err
			}
		}
		if !attachedTo(e, workItemID) {
			return nil, fmt.Errorf("evidence: work item %s: %w", workItemID, ErrCurrentNotVisible)
		}
	}
	return res, nil
}

// loadPool reads every envelope at exactly (subject key, revision),
// verifying each one. More than maxCurrentPool rows is
// ErrCurrentPoolTooLarge.
func (s *Store) loadPool(ctx context.Context, q SubjectQuery) ([]*Evidence, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+evidenceRowColumns+` FROM execution_evidence
		WHERE subject_kind=$1 AND subject_repository=$2 AND subject_ref=$3 AND subject_revision=$4
		ORDER BY id LIMIT $5`, q.Kind, q.Repository, q.Ref, q.Revision, maxCurrentPool+1)
	if err != nil {
		return nil, fmt.Errorf("evidence: current pool: %w", err)
	}
	defer rows.Close()
	var out []*Evidence
	for rows.Next() {
		e, err := scanEvidenceRow(rows)
		if err != nil {
			return nil, fmt.Errorf("evidence: current pool scan: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("evidence: current pool rows: %w", err)
	}
	if len(out) > maxCurrentPool {
		return nil, fmt.Errorf("evidence: %d+ envelopes for one subject revision: %w", maxCurrentPool+1, ErrCurrentPoolTooLarge)
	}
	return out, nil
}

// loadStaleWitness returns one envelope for the same subject key at another
// revision whose subject is not redacted, or nil when there is none. Any
// such envelope gives the same answer (resolve_current only asks whether
// one exists), so the scan is unordered. It is bounded like the pool: past
// maxCurrentPool redacted rows without a witness it fails with
// ErrCurrentPoolTooLarge rather than guessing. Every row it reads is
// verified; a row that fails is an error, not a skip.
func (s *Store) loadStaleWitness(ctx context.Context, q SubjectQuery) (*Evidence, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+evidenceRowColumns+` FROM execution_evidence
		WHERE subject_kind=$1 AND subject_repository=$2 AND subject_ref=$3 AND subject_revision<>$4
		LIMIT $5`, q.Kind, q.Repository, q.Ref, q.Revision, maxCurrentPool+1)
	if err != nil {
		return nil, fmt.Errorf("evidence: stale witness: %w", err)
	}
	defer rows.Close()
	scanned := 0
	for rows.Next() {
		scanned++
		e, err := scanEvidenceRow(rows)
		if err != nil {
			return nil, fmt.Errorf("evidence: stale witness scan: %w", err)
		}
		if !e.subjectRedacted {
			return e, nil
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("evidence: stale witness rows: %w", err)
	}
	if scanned > maxCurrentPool {
		return nil, fmt.Errorf("evidence: %d+ redacted envelopes at other revisions: %w", maxCurrentPool+1, ErrCurrentPoolTooLarge)
	}
	return nil, nil
}
