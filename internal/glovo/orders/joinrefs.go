// Copyright 2026 MCTL Authors
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

package orders

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
)

var joinPrefix = map[JoinKind]string{JoinTenant: "tnr_", JoinPrincipal: "prr_", JoinInstallRevision: "irv_"}

// There is no ordr_ kind: that ref is the order's own order_ref column.

func validateJoin(kind JoinKind, tenant, principalID, subjectID string) error {
	if _, ok := joinPrefix[kind]; !ok || tenant == "" || len(tenant) > 253 || subjectID == "" || len(subjectID) > 253 {
		return glovo.Refuse(glovo.CodeInvalidRequest)
	}
	if kind == JoinPrincipal {
		if !strings.HasPrefix(principalID, glovo.PrincipalPrefix) || len(principalID) > 128 {
			return glovo.Refuse(glovo.CodeInvalidRequest)
		}
	} else if principalID != "" {
		return glovo.Refuse(glovo.CodeInvalidRequest)
	}
	return nil
}

// MintJoinRefTx returns the opaque ref of (kind, tenant, subject), minting it
// on first use (insert-or-read) on the caller's transaction.
func (s *Store) MintJoinRefTx(ctx context.Context, tx pgx.Tx, kind JoinKind, tenant, principalID, subjectID string) (string, error) {
	if err := s.ready(); err != nil {
		return "", err
	}
	if err := validateJoin(kind, tenant, principalID, subjectID); err != nil {
		return "", err
	}
	ref, err := newID(joinPrefix[kind])
	if err != nil {
		return "", glovo.Refuse(glovo.CodeUnavailable)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO glovo.join_refs (kind, ref, tenant, principal_id, subject_id, created_at)
 VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (kind, tenant, subject_id) DO NOTHING`,
		string(kind), ref, tenant, principalID, subjectID, s.now()); err != nil {
		return "", mapErr(err)
	}
	return s.LookupJoinRefTx(ctx, tx, kind, tenant, principalID, subjectID)
}

// LookupJoinRefTx is read-only; a ref that was never minted is not_found.
func (s *Store) LookupJoinRefTx(ctx context.Context, q dbq.Querier, kind JoinKind, tenant, principalID, subjectID string) (string, error) {
	if err := s.ready(); err != nil {
		return "", err
	}
	if err := validateJoin(kind, tenant, principalID, subjectID); err != nil {
		return "", err
	}
	var ref string
	err := q.QueryRow(ctx, `SELECT ref FROM glovo.join_refs WHERE kind = $1 AND tenant = $2 AND subject_id = $3 AND principal_id = $4`,
		string(kind), tenant, subjectID, principalID).Scan(&ref)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", glovo.ErrNotFound
	}
	if err != nil {
		return "", mapErr(err)
	}
	return ref, nil
}
