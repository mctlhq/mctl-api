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

package glovojoin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
)

// PreviewTTL is the life of a preview row (design 5: the 15 minute window; the
// table's CHECK is the hard ceiling). It does not depend on the #986 read
// result TTL: prepare never reads bridge_read_results.
const PreviewTTL = 15 * time.Minute

// ReadRefTTL is the life of an issued pho_ or cursor ref (design 5a): longer
// than the preview window and independent of the read-result TTL.
const ReadRefTTL = time.Hour

// Preview is a row of glovo.join_previews. Approval is nil and Fingerprint ""
// for a valid empty preview.
type Preview struct {
	ID              string
	Tenant          string
	PrincipalID     string
	ConnectionID    string
	InstallID       string
	InstallRevision int64
	Approval        []byte
	Fingerprint     string
	PayloadHash     string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	// ConsumedOrderRef is non-empty once a prepare claimed the preview.
	ConsumedOrderRef string
}

// NewPreviewID mints a gpv_ id from 128 bits of crypto/rand.
func NewPreviewID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("glovojoin: preview id entropy: %w: %w", glovo.Refuse(glovo.CodeUnavailable), err)
	}
	return "gpv_" + base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// PayloadHash is the stored transport digest of the read payload a preview was
// built from (an audit aid, never an approval fingerprint).
func PayloadHash(data []byte) string {
	s := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(s[:])
}

// InsertPreview stores a preview. The caller sets every field; the table's
// CHECKs make an inconsistent basket and fingerprint impossible.
func InsertPreview(ctx context.Context, q dbq.Querier, p Preview) error {
	var basketArg any
	if p.Approval != nil {
		basketArg = p.Approval
	}
	_, err := q.Exec(ctx, `INSERT INTO glovo.join_previews
 (id, tenant, principal_id, connection_id, install_id, install_revision, approval_basket, fingerprint, payload_hash, created_at, expires_at)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		p.ID, p.Tenant, p.PrincipalID, p.ConnectionID, p.InstallID, p.InstallRevision, basketArg, p.Fingerprint, p.PayloadHash,
		p.CreatedAt.UTC(), p.ExpiresAt.UTC())
	if err != nil {
		return fmt.Errorf("glovojoin: store preview: %w: %w", glovo.Refuse(glovo.CodeUnavailable), err)
	}
	return nil
}

// LoadPreview reads a preview by (id, tenant, principal). An absent, foreign or
// expired row is 404 not_found with no distinction on the wire; a failed read
// is unavailable.
func LoadPreview(ctx context.Context, q dbq.Querier, id, tenant, principal string, now time.Time) (*Preview, *Refusal) {
	var p Preview
	var consumed *string
	err := q.QueryRow(ctx, `SELECT id, tenant, principal_id, connection_id, install_id, install_revision, approval_basket, fingerprint,
 payload_hash, created_at, expires_at, consumed_order_ref FROM glovo.join_previews
 WHERE id = $1 AND tenant = $2 AND principal_id = $3`, id, tenant, principal).
		Scan(&p.ID, &p.Tenant, &p.PrincipalID, &p.ConnectionID, &p.InstallID, &p.InstallRevision, &p.Approval, &p.Fingerprint,
			&p.PayloadHash, &p.CreatedAt, &p.ExpiresAt, &consumed)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, refusal(glovo.CodeNotFound, "preview_not_found")
	case err != nil:
		return nil, &Refusal{Err: glovo.Refuse(glovo.CodeUnavailable), Reason: "dependency_unavailable:previews"}
	}
	if !p.ExpiresAt.After(now) {
		return nil, refusal(glovo.CodeNotFound, "preview_expired")
	}
	if consumed != nil {
		p.ConsumedOrderRef = *consumed
	}
	return &p, nil
}

// ClaimPreview is the single-use claim (design 6 step 4b): it sets
// consumed_order_ref only while it is NULL and only for the row's own tenant
// and principal. claimed is false when no row matched, so the caller re-reads:
// a lost race is a consumed preview, never a second order.
func ClaimPreview(ctx context.Context, q dbq.Querier, id, tenant, principal, orderRef string) (claimed bool, err error) {
	tag, err := q.Exec(ctx, `UPDATE glovo.join_previews SET consumed_order_ref = $4
 WHERE id = $1 AND tenant = $2 AND principal_id = $3 AND consumed_order_ref IS NULL`, id, tenant, principal, orderRef)
	if err != nil {
		return false, fmt.Errorf("glovojoin: claim preview: %w: %w", glovo.Refuse(glovo.CodeUnavailable), err)
	}
	return tag.RowsAffected() == 1, nil
}

// SweepPreviews deletes at most limit expired previews.
func SweepPreviews(ctx context.Context, q dbq.Querier, now time.Time, limit int) (int64, error) {
	tag, err := q.Exec(ctx, `DELETE FROM glovo.join_previews WHERE id IN
 (SELECT id FROM glovo.join_previews WHERE expires_at <= $1 LIMIT $2)`, now.UTC(), limit)
	if err != nil {
		return 0, fmt.Errorf("glovojoin: sweep previews: %w", err)
	}
	return tag.RowsAffected(), nil
}

// Read ref kinds (the table's CHECK).
const (
	RefKindPho    = "pho"
	RefKindCursor = "cursor"
)

// RecordIssuedRefs inserts the pho_ refs and the cursor a history read
// returned, for this (tenant, principal, connection), before the handler
// answers. A later preview or cursor read is accepted only for a ref recorded
// here (#1059 consumer duty 10).
func RecordIssuedRefs(ctx context.Context, q dbq.Querier, tenant, principal, connection string, pho []string, cursor string, now time.Time) error {
	insert := func(kind, ref string) error {
		_, err := q.Exec(ctx, `INSERT INTO glovo.join_read_refs (tenant, principal_id, connection_id, kind, ref, created_at, expires_at)
 VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, tenant, principal, connection, kind, ref, now.UTC(), now.Add(ReadRefTTL).UTC())
		if err != nil {
			return fmt.Errorf("glovojoin: record issued ref: %w: %w", glovo.Refuse(glovo.CodeUnavailable), err)
		}
		return nil
	}
	for _, r := range pho {
		if err := insert(RefKindPho, r); err != nil {
			return err
		}
	}
	if cursor != "" {
		return insert(RefKindCursor, cursor)
	}
	return nil
}

// RefIssued reports whether an earlier history read returned ref to this
// (tenant, principal, connection) and it has not expired. A failed read is an
// error, never "not issued".
func RefIssued(ctx context.Context, q dbq.Querier, tenant, principal, connection, kind, ref string, now time.Time) (bool, error) {
	var one int
	err := q.QueryRow(ctx, `SELECT 1 FROM glovo.join_read_refs
 WHERE tenant = $1 AND principal_id = $2 AND connection_id = $3 AND kind = $4 AND ref = $5 AND expires_at > $6`,
		tenant, principal, connection, kind, ref, now.UTC()).Scan(&one)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("glovojoin: read issued ref: %w: %w", glovo.Refuse(glovo.CodeUnavailable), err)
	}
	return true, nil
}

// SweepReadRefs deletes at most limit expired issued refs.
func SweepReadRefs(ctx context.Context, q dbq.Querier, now time.Time, limit int) (int64, error) {
	tag, err := q.Exec(ctx, `DELETE FROM glovo.join_read_refs WHERE ctid IN
 (SELECT ctid FROM glovo.join_read_refs WHERE expires_at <= $1 LIMIT $2)`, now.UTC(), limit)
	if err != nil {
		return 0, fmt.Errorf("glovojoin: sweep read refs: %w", err)
	}
	return tag.RowsAffected(), nil
}
