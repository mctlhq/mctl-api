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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/reviewreceipts"
)

// StoredReceipt is a stored review receipt.
type StoredReceipt struct {
	Receipt     reviewreceipts.ReviewReceipt
	Document    []byte
	IngestSeq   int64
	Tenant      string
	SubmittedBy string
	SubmittedAt time.Time
}

// ManualInput is the caller-owned part of a manual receipt. Everything else
// (reviewer, assurance, mode, nonce, time, tenant) is server-owned.
type ManualInput struct {
	RequestID   string
	Subject     reviewreceipts.ReviewSubject
	Outcome     string
	Criteria    []reviewreceipts.Criterion
	FindingsRef reviewreceipts.ArtifactRef
}

// SubmitManual records one manual advisory receipt against an open manual
// request. It never consumes the request's nonce and can never produce an
// independent receipt.
func (s *Store) SubmitManual(ctx context.Context, in ManualInput, actor Actor, now time.Time) (*StoredReceipt, error) {
	req, err := s.Request(ctx, in.RequestID)
	if err != nil {
		return nil, err
	}
	if req.Closed {
		return nil, fmt.Errorf("%w: %s (%s)", ErrRequestClosed, req.Request.RequestID, req.ClosedReason)
	}
	if req.Request.Mode != reviewreceipts.ModeManual {
		return nil, fmt.Errorf("%w: %s", ErrRequestModeWorker, req.Request.RequestID)
	}
	if in.Subject.Binding() != req.Request.Subject.Binding() {
		return nil, fmt.Errorf("%w: %s", ErrBindingMismatch, req.Request.RequestID)
	}
	now = now.UTC()
	rc, err := reviewreceipts.SealReceipt(req.Request, reviewreceipts.SealReceiptInput{
		Outcome:       in.Outcome,
		Criteria:      in.Criteria,
		FindingsRef:   in.FindingsRef,
		ReviewerActor: actor.Name,
		CreatedAt:     now.Format("2006-01-02T15:04:05Z"),
	})
	if err != nil {
		return nil, err
	}
	// Defence in depth beside the table CHECK.
	if rc.Mode != reviewreceipts.ModeManual || rc.Assurance != reviewreceipts.AssuranceAdvisory {
		return nil, ErrManualNotAdvisory
	}
	doc, err := marshalDict(rc.Dict())
	if err != nil {
		return nil, err
	}
	if _, err := s.pool.Exec(ctx, `
INSERT INTO review_receipts (receipt_id, request_id, content_hash, document, mode, assurance, tenant,
    submitted_by, submitted_by_principal_id, submitted_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (receipt_id) DO NOTHING`,
		rc.ReceiptID, rc.RequestID, rc.ContentHash, doc, rc.Mode, rc.Assurance, req.Tenant,
		actor.Name, actor.PrincipalID, now); err != nil {
		return nil, fmt.Errorf("reviewstore: insert receipt: %w", err)
	}
	return s.receipt(ctx, rc.ReceiptID)
}

const receiptColumns = `ingest_seq, receipt_id, document, tenant, submitted_by, submitted_at`

func scanReceipt(row pgx.Row) (*StoredReceipt, error) {
	var (
		sr StoredReceipt
		id string
	)
	if err := row.Scan(&sr.IngestSeq, &id, &sr.Document, &sr.Tenant, &sr.SubmittedBy, &sr.SubmittedAt); err != nil {
		return nil, err
	}
	sr.SubmittedAt = sr.SubmittedAt.UTC()
	rc, err := reviewreceipts.ParseReceipt(sr.Document)
	if err != nil || rc.ReceiptID != id {
		return nil, fmt.Errorf("%w: receipt %s", ErrStoreCorrupt, id)
	}
	sr.Receipt = rc
	return &sr, nil
}

func (s *Store) receipt(ctx context.Context, id string) (*StoredReceipt, error) {
	sr, err := scanReceipt(s.pool.QueryRow(ctx, `SELECT `+receiptColumns+` FROM review_receipts WHERE receipt_id = $1`, id))
	if err != nil {
		if errors.Is(err, ErrStoreCorrupt) {
			return nil, err
		}
		return nil, fmt.Errorf("reviewstore: read receipt: %w", err)
	}
	return sr, nil
}

// Pool returns every stored receipt in ingest order, oldest first. It is
// complete or an error: more than PoolMax rows is ErrPoolTooLarge, and a row
// that no longer parses is ErrStoreCorrupt. No partial pool is returned.
func (s *Store) Pool(ctx context.Context) ([]reviewreceipts.ReviewReceipt, []StoredReceipt, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+receiptColumns+` FROM review_receipts ORDER BY ingest_seq ASC LIMIT $1`, s.poolMax+1)
	if err != nil {
		return nil, nil, fmt.Errorf("reviewstore: read pool: %w", err)
	}
	defer rows.Close()
	receipts := []reviewreceipts.ReviewReceipt{}
	stored := []StoredReceipt{}
	for rows.Next() {
		sr, err := scanReceipt(rows)
		if err != nil {
			if errors.Is(err, ErrStoreCorrupt) {
				return nil, nil, err
			}
			return nil, nil, fmt.Errorf("reviewstore: read pool: %w", err)
		}
		if len(stored) == s.poolMax {
			return nil, nil, ErrPoolTooLarge
		}
		stored = append(stored, *sr)
		receipts = append(receipts, sr.Receipt)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("reviewstore: read pool: %w", err)
	}
	return receipts, stored, nil
}

// GateInput returns the newest request for live's binding (nil when none)
// and the complete receipt pool: the Tier A gate input.
func (s *Store) GateInput(ctx context.Context, live reviewreceipts.ReviewSubject) (*StoredRequest, []reviewreceipts.ReviewReceipt, error) {
	pool, _, err := s.Pool(ctx)
	if err != nil {
		return nil, nil, err
	}
	req, err := s.newestRequestForBinding(ctx, live)
	if err != nil {
		return nil, nil, err
	}
	return req, pool, nil
}

func marshalDict(d map[string]any) ([]byte, error) {
	b, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("reviewstore: encode receipt: %w", err)
	}
	return b, nil
}
