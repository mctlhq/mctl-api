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

package principals

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Surface identity links are MIRRORED, not replaced (mctl-api#373 D4).
// surface_identity_links stays the source of truth for the challenge →
// redeem flow and for a link's expiry; a live link is copied into
// external_identities as (provider=<surface>, issuer="", subject=<external
// id>) for the human the link names, and its revocation sets revoked_at.
// The surface store calls these inside its own transaction, which is why the
// two stores share one database.

// MirrorLink records a live surface link for the human principal it names
// (principal is the link's "github:<login>"). A link whose human has no
// GitHub identity yet is skipped, not failed: the startup backfill mirrors
// it once the human is known.
func (s *Store) MirrorLink(ctx context.Context, tx pgx.Tx, surface, externalID, principal string) error {
	_, err := s.mirrorLink(ctx, tx, surface, externalID, principal, false)
	return err
}

// mirrorLink writes the mirror row and reports whether it wrote one.
func (s *Store) mirrorLink(ctx context.Context, tx pgx.Tx, surface, externalID, principal string, onlyIfAbsent bool) (bool, error) {
	login, ok := strings.CutPrefix(principal, "github:")
	if !ok || login == "" || surface == "" || externalID == "" {
		return false, nil
	}
	var principalID string
	err := tx.QueryRow(ctx, `SELECT principal_id FROM external_identities
		WHERE provider='github' AND display <> '' AND lower(display)=lower($1) AND revoked_at IS NULL
		ORDER BY verified_at DESC LIMIT 1`, login).Scan(&principalID)
	if errors.Is(err, pgx.ErrNoRows) {
		slog.Info("surface link not mirrored yet: its human has no principal", "surface", surface, "principal", principal)
		return false, nil
	}
	if err != nil {
		return false, err
	}
	now := s.now()
	xid, err := newPrefixedID(externalIdentityIDPrefix, now)
	if err != nil {
		return false, err
	}
	conflict := `ON CONFLICT (provider, issuer, subject) DO UPDATE
		SET principal_id=EXCLUDED.principal_id, verified_at=EXCLUDED.verified_at, revoked_at=NULL`
	if onlyIfAbsent {
		conflict = `ON CONFLICT (provider, issuer, subject) DO NOTHING`
	}
	tag, err := tx.Exec(ctx, `INSERT INTO external_identities
		(id, principal_id, provider, issuer, subject, display, verified_at) VALUES ($1,$2,$3,'',$4,'',$5) `+conflict,
		xid, principalID, surface, externalID, now)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// MirrorRevoke marks a revoked surface link's mirrored identity revoked.
func (s *Store) MirrorRevoke(ctx context.Context, tx pgx.Tx, surface, externalID string, at time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE external_identities SET revoked_at=$3
		WHERE provider=$1 AND issuer='' AND subject=$2 AND revoked_at IS NULL`, surface, externalID, at)
	return err
}
