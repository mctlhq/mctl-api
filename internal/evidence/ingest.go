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
		existing, getErr := scanEvidenceRow(tx.QueryRow(ctx, `SELECT `+evidenceColumns+`
			FROM execution_evidence WHERE id=$1`, evidenceID))
		switch {
		case getErr == nil:
			if existing.ContentHash != contentHash {
				return fmt.Errorf("evidence: id %s: %w (stored %s, submitted %s)",
					evidenceID, ErrEvidenceDivergence, existing.ContentHash, contentHash)
			}
			out = existing
			return nil
		case !errors.Is(getErr, pgx.ErrNoRows):
			return fmt.Errorf("evidence: find: %w", getErr)
		}

		now := s.now()
		inserted, insErr := scanEvidenceRow(tx.QueryRow(ctx, `INSERT INTO execution_evidence (`+evidenceColumns+`)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING `+evidenceColumns,
			evidenceID, contentHash, p.APIVersion(), in.EnvelopeBytes, p.ExecutionID(), p.RuntimeExecutionID(),
			p.WorkItemID(), p.TraceID(), now, in.IngestedBy, in.IngestedByPrincipalID, now))
		if insErr != nil {
			return fmt.Errorf("evidence: insert: %w", insErr)
		}
		// Derivation is best-effort by design (design.md section 5,
		// tasks.md task 5 DoD): a valid join that mctl-api cannot resolve
		// stores the evidence anyway with an empty projection, and a
		// derivation error never fails or rolls back a valid ingest.
		_ = s.deriveAndStoreRef(ctx, tx, inserted)
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
	return out, created, nil
}
