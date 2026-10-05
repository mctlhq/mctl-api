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

	"github.com/jackc/pgx/v5"
)

// Ingest validates in, then stores it or returns the record it already
// matches — the SealSnapshot pattern (internal/workitems/snapshots.go),
// inside a transaction under an advisory lock keyed on the ev- id:
//
//   - no row with this id -> INSERT, created=true (201);
//   - a row with the same id AND the same content_hash -> this is the same
//     evidence (a byte-identical replay, or a re-seal that changed only
//     created_at, which Tier A excludes from the hash). Return the FIRST
//     stored row unchanged, created=false (200);
//   - a row with the same id but a DIFFERENT content_hash -> a 64-bit
//     id-prefix collision between different content. ErrEvidenceDivergence
//     (409), nothing written.
//
// Server-owned ingest provenance (ingested_by, ingested_by_principal_id) is
// never compared: a replay from a different authorised principal still
// returns the first record untouched.
func (s *Store) Ingest(ctx context.Context, in IngestInput) (*Evidence, bool, error) {
	p, contentHash, evidenceID, err := Validate(in)
	if err != nil {
		return nil, false, err
	}

	var out *Evidence
	created := false
	err = withTx(ctx, s.pool, "evidence:"+evidenceID, func(tx pgx.Tx) error {
		// Divergence is decided on the recorded content_hash alone, before
		// the stored bytes are re-verified: a different recorded hash under
		// this id is a collision whatever state the stored row is in, and
		// must answer 409 without touching it.
		var storedHash string
		switch getErr := tx.QueryRow(ctx, `SELECT content_hash FROM execution_evidence WHERE id=$1`,
			evidenceID).Scan(&storedHash); {
		case getErr == nil:
			if storedHash != contentHash {
				return fmt.Errorf("evidence: id %s: %w (stored %s, submitted %s)",
					evidenceID, ErrEvidenceDivergence, storedHash, contentHash)
			}
			existing, readErr := scanEvidenceRow(tx.QueryRow(ctx, `SELECT `+evidenceRowColumns+`
				FROM execution_evidence WHERE id=$1`, evidenceID))
			if readErr != nil {
				return fmt.Errorf("evidence: read existing %s: %w", evidenceID, readErr)
			}
			out = existing
			return nil
		case !errors.Is(getErr, pgx.ErrNoRows):
			return fmt.Errorf("evidence: find: %w", getErr)
		}

		cols, colErr := subjectColumnsOf(p)
		if colErr != nil {
			return colErr
		}
		if err := checkSupersedesTarget(ctx, tx, cols); err != nil {
			return err
		}

		now := s.now()
		inserted, insErr := scanEvidenceRow(tx.QueryRow(ctx, `INSERT INTO execution_evidence (`+evidenceRowColumns+`)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) RETURNING `+evidenceRowColumns,
			evidenceID, contentHash, p.APIVersion(), in.EnvelopeBytes, p.ExecutionID(), p.RuntimeExecutionID(),
			p.WorkItemID(), p.TraceID(), p.CreatedAt(), in.IngestedBy, in.IngestedByPrincipalID, now,
			cols.kind, cols.repository, cols.ref, cols.revision, cols.authority, cols.observedAt, cols.supersedes))
		if insErr != nil {
			return fmt.Errorf("evidence: insert: %w", insErr)
		}
		// Derivation is best-effort by design (design.md section 5,
		// tasks.md task 5 DoD): a valid join that mctl-api cannot resolve
		// stores the evidence anyway with an empty projection, and a
		// derivation error never fails or rolls back a valid ingest. A
		// failed statement aborts the whole Postgres transaction, so the
		// derivation runs under a savepoint (pgx nests Begin as SAVEPOINT)
		// and only the savepoint is rolled back on failure. The projection
		// is rebuildable (RebuildRefs), so a skipped row is recoverable.
		if err := s.deriveUnderSavepoint(ctx, tx, inserted); err != nil {
			slog.Warn("evidence: derived projection skipped", "evidence_id", inserted.ID, "error", err)
		}
		created = true
		out = inserted
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	if err := s.attachRef(ctx, out); err != nil {
		return nil, false, err
	}
	if err := s.attachSupersededBy(ctx, []*Evidence{out}, ""); err != nil {
		return nil, false, err
	}
	return out, created, nil
}

// checkSupersedesTarget enforces ADR 018 Amendment 2 Tier B checklist item
// 6. When the envelope names an earlier one in provenance.supersedes and
// that envelope is stored, it must be about the same (subject_kind,
// subject_repository, subject_ref, subject_revision) and carry an
// authority no stronger than the new one, else
// ErrEvidenceSupersedesInvalid (422). A target that does not exist (yet) is
// accepted: the producer never blocks on ordering, and the read rule only
// honours links inside a pool, so a dangling link retires nothing.
func checkSupersedesTarget(ctx context.Context, tx pgx.Tx, cols subjectColumns) error {
	if cols.supersedes == "" {
		return nil
	}
	var target subjectColumns
	err := tx.QueryRow(ctx, `SELECT subject_kind, subject_repository, subject_ref, subject_revision, authority
		FROM execution_evidence WHERE id=$1`, cols.supersedes).
		Scan(&target.kind, &target.repository, &target.ref, &target.revision, &target.authority)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil
	case err != nil:
		return fmt.Errorf("evidence: read supersedes target %s: %w", cols.supersedes, err)
	}
	if target.kind != cols.kind || target.repository != cols.repository || target.ref != cols.ref ||
		target.revision != cols.revision {
		return fmt.Errorf("%w: %s is about a different subject or revision", ErrEvidenceSupersedesInvalid, cols.supersedes)
	}
	if AuthorityRank(target.authority) > AuthorityRank(cols.authority) {
		return fmt.Errorf("%w: %s carries a stronger authority (%s) than the superseding envelope (%s)",
			ErrEvidenceSupersedesInvalid, cols.supersedes, target.authority, cols.authority)
	}
	return nil
}

// deriveUnderSavepoint runs deriveAndStoreRef inside a savepoint of tx and
// rolls back only that savepoint when it fails, leaving tx usable.
func (s *Store) deriveUnderSavepoint(ctx context.Context, tx pgx.Tx, e *Evidence) error {
	sp, err := tx.Begin(ctx)
	if err != nil {
		return fmt.Errorf("savepoint: %w", err)
	}
	if err := s.deriveAndStoreRef(ctx, sp, e); err != nil {
		if rbErr := sp.Rollback(ctx); rbErr != nil {
			return fmt.Errorf("%w (rollback to savepoint: %v)", err, rbErr)
		}
		return err
	}
	return sp.Commit(ctx)
}
