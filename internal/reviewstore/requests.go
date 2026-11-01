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

package reviewstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/mctlhq/mctl-api/internal/evidence"
	"github.com/mctlhq/mctl-api/internal/reviewreceipts"
)

// StoredRequest is a stored review request with its computed closure.
type StoredRequest struct {
	Request    reviewreceipts.ReviewRequest
	Document   []byte
	IngestSeq  int64
	Tenant     string
	IngestedBy string
	IngestedAt time.Time

	// Closure is computed on every read, never stored.
	Closed       bool
	ClosedReason string
	ClosedBy     string
}

func nonceDigest(nonce string) string {
	sum := sha256.Sum256([]byte(nonce))
	return hex.EncodeToString(sum[:])
}

// resolveTenant maps the authoring execution to its evidence tenant. An
// unreadable evidence store is never reported as an unresolved reference.
func (s *Store) resolveTenant(ctx context.Context, executionID string) (string, error) {
	if s.evidence == nil {
		return "", errEvidenceStoreMissing
	}
	f := evidence.Filter{Limit: 1}
	if strings.HasPrefix(executionID, "we_") {
		f.ExecutionID = executionID
	} else {
		f.RuntimeExecutionID = executionID
	}
	res, err := s.evidence.List(ctx, f)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrEvidenceUnavailable, err)
	}
	if res == nil || len(res.Evidence) == 0 || res.Evidence[0] == nil {
		return "", fmt.Errorf("%w: %s", ErrAuthoringUnresolved, executionID)
	}
	ref := res.Evidence[0].Ref
	if ref == nil || ref.Tenant == "" {
		return "", fmt.Errorf("%w: %s", ErrTenantUnresolved, executionID)
	}
	return ref.Tenant, nil
}

// IngestRequest stores one sealed review request verbatim. The same bytes
// again are a replay (replayed=true); different bytes under the same
// request_id are ErrIdempotencyConflict; another request's nonce is
// ErrNonceReused. The tenant is derived from the authoring evidence, never
// from the caller.
func (s *Store) IngestRequest(ctx context.Context, raw []byte, actor Actor) (*StoredRequest, bool, error) {
	req, err := reviewreceipts.ParseRequest(raw)
	if err != nil {
		return nil, false, err
	}
	if req.ContentHash == "" || req.RequestID == "" {
		return nil, false, ErrUnsealed
	}
	tenant, err := s.resolveTenant(ctx, req.AuthoringExecutionID)
	if err != nil {
		return nil, false, err
	}
	tag, err := s.pool.Exec(ctx, `
INSERT INTO review_requests (request_id, content_hash, document, subject_kind, identity_key, binding_key,
    mode, nonce_sha256, authoring_execution_id, tenant, ingested_by, ingested_by_principal_id, ingested_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
ON CONFLICT (request_id) DO NOTHING`,
		req.RequestID, req.ContentHash, raw, req.Subject.Kind, req.Subject.Identity().Key(),
		req.Subject.Binding().Key(), req.Mode, nonceDigest(req.Nonce), req.AuthoringExecutionID,
		tenant, actor.Name, actor.PrincipalID, s.now())
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "review_requests_nonce" {
			return nil, false, ErrNonceReused
		}
		return nil, false, fmt.Errorf("reviewstore: insert request: %w", err)
	}
	stored, err := s.Request(ctx, req.RequestID)
	if err != nil {
		return nil, false, err
	}
	if tag.RowsAffected() == 1 {
		return stored, false, nil
	}
	if !bytes.Equal(stored.Document, raw) {
		return nil, false, fmt.Errorf("%w: %s", ErrIdempotencyConflict, req.RequestID)
	}
	return stored, true, nil
}

const requestSelect = `
SELECT r.ingest_seq, r.request_id, r.document, r.tenant, r.ingested_by, r.ingested_at,
       COALESCE((SELECT r2.request_id FROM review_requests r2
                  WHERE r2.identity_key = r.identity_key AND r2.binding_key <> r.binding_key
                    AND r2.ingest_seq > r.ingest_seq
                  ORDER BY r2.ingest_seq LIMIT 1), '')
FROM review_requests r `

func (s *Store) scanRequest(row pgx.Row) (*StoredRequest, error) {
	var (
		sr       StoredRequest
		id       string
		closedBy string
	)
	if err := row.Scan(&sr.IngestSeq, &id, &sr.Document, &sr.Tenant, &sr.IngestedBy, &sr.IngestedAt, &closedBy); err != nil {
		return nil, err
	}
	sr.IngestedAt = sr.IngestedAt.UTC()
	req, err := reviewreceipts.ParseRequest(sr.Document)
	if err != nil || req.RequestID != id {
		return nil, fmt.Errorf("%w: request %s", ErrStoreCorrupt, id)
	}
	sr.Request = req
	switch {
	case !sr.IngestedAt.Add(s.ttl).After(s.now()):
		sr.Closed, sr.ClosedReason = true, ClosedTTL
	case closedBy != "":
		sr.Closed, sr.ClosedReason, sr.ClosedBy = true, ClosedSuperseded, closedBy
	}
	return &sr, nil
}

// Request returns one request with its closure, or ErrRequestNotFound.
func (s *Store) Request(ctx context.Context, id string) (*StoredRequest, error) {
	sr, err := s.scanRequest(s.pool.QueryRow(ctx, requestSelect+`WHERE r.request_id = $1`, id))
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, fmt.Errorf("%w: %s", ErrRequestNotFound, id)
	case err != nil:
		if errors.Is(err, ErrStoreCorrupt) {
			return nil, err
		}
		return nil, fmt.Errorf("reviewstore: read request: %w", err)
	}
	return sr, nil
}

// newestRequestForBinding is the newest request (max ingest_seq) whose
// binding equals live's, open or closed; nil when there is none.
func (s *Store) newestRequestForBinding(ctx context.Context, live reviewreceipts.ReviewSubject) (*StoredRequest, error) {
	sr, err := s.scanRequest(s.pool.QueryRow(ctx,
		requestSelect+`WHERE r.binding_key = $1 ORDER BY r.ingest_seq DESC LIMIT 1`, live.Binding().Key()))
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, nil
	case err != nil:
		if errors.Is(err, ErrStoreCorrupt) {
			return nil, err
		}
		return nil, fmt.Errorf("reviewstore: read request: %w", err)
	}
	return sr, nil
}
