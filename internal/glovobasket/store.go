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

package glovobasket

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// ApprovalRequest is what glovo_request_approval returns: an opaque ref to
// the pending aar_ of one exact revision.
type ApprovalRequest struct {
	ApprovalRef string    `json:"approval_ref"`
	BasketID    string    `json:"basket_id"`
	Revision    int64     `json:"revision"`
	Fingerprint string    `json:"basket_fingerprint"`
	State       string    `json:"state"`
	ExpiresAt   time.Time `json:"expires_at"`
	Created     bool      `json:"created"`
	// ApprovalURL is the owner approval page of this approval; empty when
	// no page is configured (Config.ApprovalPageBaseURL).
	ApprovalURL string `json:"approval_url,omitempty"`
}

// ApprovalStatus is the approval's state plus whether it authorizes the
// basket as it is now. An approval only ever authorizes the revision it was
// requested for: once the basket moves on, authorizes_current is false.
type ApprovalStatus struct {
	workitems.GlovoBasketApprovalStatus
	CurrentRevision   int64 `json:"current_revision"`
	AuthorizesCurrent bool  `json:"authorizes_current_revision"`
}

// DecisionPayload is what the human decision surface shows the owner: the
// exact revision behind the approval. The tenant and owner are for the
// route's own checks and are not rendered.
type DecisionPayload struct {
	ApprovalRef string `json:"approval_ref"`
	BasketID    string `json:"basket_id"`
	Revision    int64  `json:"revision"`
	StoreRef    string `json:"store_ref"`
	Lines       []Line `json:"lines"`
	Totals      Totals `json:"totals"`
	Fingerprint string `json:"basket_fingerprint"`
	Tenant      string `json:"-"`
	Owner       string `json:"-"`
}

// Store is the basket ledger. Every method is scoped to the owner: another
// tenant's or another principal's basket is glovo.ErrNotFound, exactly like a
// missing one. A failed read is an error, never not-found.
type Store interface {
	Create(ctx context.Context, o Owner, clientKey string, maxBaskets int) (*Basket, bool, error)
	Get(ctx context.Context, o Owner, id string) (*Basket, error)
	Update(ctx context.Context, o Owner, id string, expectedRevision int64, ops []Op) (*Basket, error)
	RequestApproval(ctx context.Context, o Owner, id string, expectedRevision int64, ttl time.Duration) (*ApprovalRequest, error)
	ApprovalStatus(ctx context.Context, o Owner, ref string) (*ApprovalStatus, error)
	DecisionPayload(ctx context.Context, approvalRef string) (*DecisionPayload, error)
}

// PGStore is the Postgres Store on the Glovo pool (glovo_runtime).
type PGStore struct {
	Pool *pgxpool.Pool
	// Now is the clock of the revision timestamps; nil is time.Now.
	Now func() time.Time
}

var _ Store = (*PGStore)(nil)

func (s *PGStore) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func unavailable(op string, err error) error {
	var ge *glovo.Error
	if errors.As(err, &ge) {
		return err
	}
	return fmt.Errorf("glovo basket: %s: %w", op, errors.Join(glovo.Refuse(glovo.CodeUnavailable), err))
}

const revisionColumns = `revision, store_ref, lines, currency, subtotal_minor, delivery_fee_minor, service_fee_minor,
	discount_minor, total_minor, canonical, basket_fingerprint, created_at`

func scanRevision(row pgx.Row) (Revision, error) {
	var (
		r   Revision
		raw []byte
	)
	if err := row.Scan(&r.Revision, &r.StoreRef, &raw, &r.Totals.Currency, &r.Totals.SubtotalMinor, &r.Totals.DeliveryFeeMinor,
		&r.Totals.ServiceFeeMinor, &r.Totals.DiscountMinor, &r.Totals.TotalMinor, &r.Canonical, &r.Fingerprint, &r.CreatedAt); err != nil {
		return Revision{}, err
	}
	if err := json.Unmarshal(raw, &r.Lines); err != nil {
		return Revision{}, fmt.Errorf("glovo basket: stored lines: %w", err)
	}
	r.CreatedAt = r.CreatedAt.UTC()
	return r, nil
}

func insertRevision(ctx context.Context, tx pgx.Tx, id string, o Owner, r Revision) error {
	lines, err := json.Marshal(r.Lines)
	if err != nil {
		return err
	}
	var canonical []byte
	if len(r.Canonical) > 0 {
		canonical = r.Canonical
	}
	_, err = tx.Exec(ctx, `INSERT INTO glovo.basket_revisions (basket_id, revision, tenant, owner_principal_id, lines, currency,
		store_ref, subtotal_minor, delivery_fee_minor, service_fee_minor, discount_minor, total_minor, canonical, basket_fingerprint, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		id, r.Revision, o.Tenant, o.PrincipalID, lines, r.Totals.Currency, r.StoreRef, r.Totals.SubtotalMinor,
		r.Totals.DeliveryFeeMinor, r.Totals.ServiceFeeMinor, r.Totals.DiscountMinor, r.Totals.TotalMinor, canonical, r.Fingerprint, r.CreatedAt)
	return err
}

// head reads the owner's basket head, locked when lock is set.
func head(ctx context.Context, q pgx.Tx, o Owner, id string, lock bool) (*Basket, error) {
	if !workitems.GlovoBasketIDRE.MatchString(id) {
		return nil, glovo.ErrNotFound
	}
	sql := `SELECT basket_id, client_key, current_revision, created_at, updated_at FROM glovo.baskets
		WHERE basket_id=$1 AND tenant=$2 AND owner_principal_id=$3`
	if lock {
		sql += ` FOR UPDATE`
	}
	b := &Basket{Tenant: o.Tenant, Owner: o.PrincipalID}
	err := q.QueryRow(ctx, sql, id, o.Tenant, o.PrincipalID).Scan(&b.ID, &b.ClientKey, &b.Current.Revision, &b.CreatedAt, &b.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, glovo.ErrNotFound
	}
	if err != nil {
		return nil, unavailable("read basket", err)
	}
	r, err := scanRevision(q.QueryRow(ctx, `SELECT `+revisionColumns+` FROM glovo.basket_revisions WHERE basket_id=$1 AND revision=$2`,
		id, b.Current.Revision))
	if err != nil {
		// The guard trigger only lets the head name a written revision: a
		// miss here is a broken ledger, not an absent basket.
		return nil, unavailable("read basket revision", err)
	}
	b.Current = r
	b.CreatedAt, b.UpdatedAt = b.CreatedAt.UTC(), b.UpdatedAt.UTC()
	return b, nil
}

func (s *PGStore) inTx(ctx context.Context, op string, fn func(tx pgx.Tx) error) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return unavailable(op, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '3s'`); err != nil {
		return unavailable(op, err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return unavailable(op, err)
	}
	return nil
}

// Create returns the owner's basket for clientKey, creating it (empty, at
// revision 1) when it does not exist. maxBaskets bounds how many baskets one
// owner holds in one team.
func (s *PGStore) Create(ctx context.Context, o Owner, clientKey string, maxBaskets int) (*Basket, bool, error) {
	var (
		out     *Basket
		created bool
	)
	err := s.inTx(ctx, "create basket", func(tx pgx.Tx) error {
		// One owner's creates are serialized, so the quota count is exact.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "glovo-basket:"+o.Tenant+"\n"+o.PrincipalID); err != nil {
			return unavailable("lock owner", err)
		}
		var existing string
		err := tx.QueryRow(ctx, `SELECT basket_id FROM glovo.baskets WHERE tenant=$1 AND owner_principal_id=$2 AND client_key=$3`,
			o.Tenant, o.PrincipalID, clientKey).Scan(&existing)
		switch {
		case err == nil:
			out, err = head(ctx, tx, o, existing, false)
			return err
		case !errors.Is(err, pgx.ErrNoRows):
			return unavailable("find basket", err)
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM glovo.baskets WHERE tenant=$1 AND owner_principal_id=$2`, o.Tenant, o.PrincipalID).Scan(&n); err != nil {
			return unavailable("count baskets", err)
		}
		if n >= maxBaskets {
			return glovo.Refuse(glovo.CodeRateLimited)
		}
		id, err := newBasketID()
		if err != nil {
			return unavailable("mint basket id", err)
		}
		now := s.now()
		r, err := price(1, nil, now)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO glovo.baskets (basket_id, tenant, owner_principal_id, client_key, current_revision, created_at, updated_at)
			VALUES ($1,$2,$3,$4,1,$5,$5)`, id, o.Tenant, o.PrincipalID, clientKey, now); err != nil {
			return unavailable("insert basket", err)
		}
		if err := insertRevision(ctx, tx, id, o, r); err != nil {
			return unavailable("insert revision", err)
		}
		out = &Basket{ID: id, Tenant: o.Tenant, Owner: o.PrincipalID, ClientKey: clientKey, CreatedAt: now, UpdatedAt: now, Current: r}
		created = true
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return out, created, nil
}

// Get reads the owner's basket at its current revision.
func (s *PGStore) Get(ctx context.Context, o Owner, id string) (*Basket, error) {
	var out *Basket
	err := s.inTx(ctx, "read basket", func(tx pgx.Tx) error {
		var err error
		out, err = head(ctx, tx, o, id, false)
		return err
	})
	return out, err
}

// Update appends the revision ops make of the current one. expectedRevision
// must be the current revision (optimistic concurrency): a stale caller is
// refused, never merged.
func (s *PGStore) Update(ctx context.Context, o Owner, id string, expectedRevision int64, ops []Op) (*Basket, error) {
	var out *Basket
	err := s.inTx(ctx, "update basket", func(tx pgx.Tx) error {
		b, err := head(ctx, tx, o, id, true)
		if err != nil {
			return err
		}
		if b.Current.Revision != expectedRevision {
			return glovo.Refuse(glovo.CodeStaleVersion)
		}
		if b.Current.Revision >= MaxRevisions {
			return glovo.Refuse(glovo.CodeRateLimited)
		}
		qty, err := applyOps(b.Current.Lines, ops)
		if err != nil {
			return err
		}
		now := s.now()
		r, err := price(b.Current.Revision+1, qty, now)
		if err != nil {
			return err
		}
		if err := insertRevision(ctx, tx, id, o, r); err != nil {
			return unavailable("insert revision", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE glovo.baskets SET current_revision=$2, updated_at=$3 WHERE basket_id=$1`, id, r.Revision, now); err != nil {
			return unavailable("advance basket", err)
		}
		b.Current, b.UpdatedAt = r, now
		out = b
		return nil
	})
	return out, err
}

// RequestApproval freezes the current revision for approval, in one
// transaction with the basket locked: the stored canonical form is re-parsed
// and its fingerprint re-checked, then the aar_ and its binding are written.
// One revision has one approval; asking again returns it.
func (s *PGStore) RequestApproval(ctx context.Context, o Owner, id string, expectedRevision int64, ttl time.Duration) (*ApprovalRequest, error) {
	var out *ApprovalRequest
	err := s.inTx(ctx, "request approval", func(tx pgx.Tx) error {
		b, err := head(ctx, tx, o, id, true)
		if err != nil {
			return err
		}
		if b.Current.Revision != expectedRevision {
			return glovo.Refuse(glovo.CodeStaleVersion)
		}
		if err := verifyFrozen(b.Current); err != nil {
			return err
		}
		a, created, err := workitems.CreateGlovoBasketApprovalTx(ctx, tx, workitems.GlovoBasketApprovalInput{
			Tenant: o.Tenant, OwnerPrincipalID: o.PrincipalID, BasketID: id, Revision: b.Current.Revision,
			BasketFingerprint: b.Current.Fingerprint, ExpiresIn: ttl})
		if err != nil {
			return mapApprovalErr(err)
		}
		var now time.Time
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return unavailable("read clock", err)
		}
		out = &ApprovalRequest{ApprovalRef: a.ID, BasketID: id, Revision: b.Current.Revision, Fingerprint: b.Current.Fingerprint,
			State: workitems.GlovoBasketReceiptState(a.State, a.ExpiresAt, a.FreshUntil, now), ExpiresAt: a.ExpiresAt.UTC(), Created: created}
		return nil
	})
	return out, err
}

func mapApprovalErr(err error) error {
	var ge *glovo.Error
	switch {
	case errors.As(err, &ge):
		return err
	case errors.Is(err, workitems.ErrInvalid):
		return glovo.Refuse(glovo.CodeInvalidRequest)
	}
	return unavailable("write approval", err)
}

// ApprovalStatus reads the owner's approval and compares it with the basket
// as it is now.
func (s *PGStore) ApprovalStatus(ctx context.Context, o Owner, ref string) (*ApprovalStatus, error) {
	var out *ApprovalStatus
	err := s.inTx(ctx, "approval status", func(tx pgx.Tx) error {
		st, err := workitems.ReadGlovoBasketApprovalStatus(ctx, tx, o.Tenant, o.PrincipalID, ref)
		if err != nil {
			return err
		}
		b, err := head(ctx, tx, o, st.BasketID, false)
		if err != nil {
			if errors.Is(err, glovo.ErrNotFound) {
				// The binding's FK names the owner's own basket: its absence
				// is a broken ledger.
				return unavailable("read approved basket", err)
			}
			return err
		}
		out = &ApprovalStatus{GlovoBasketApprovalStatus: *st, CurrentRevision: b.Current.Revision,
			AuthorizesCurrent: st.State == workitems.GlovoBasketStateApproved && st.Revision == b.Current.Revision &&
				st.BasketFingerprint == b.Current.Fingerprint}
		return nil
	})
	return out, err
}

// DecisionPayload reads the revision behind a basket approval, for the
// owner's decision surface. The caller checks that the reader is the owner.
// A missing or non-basket approval is workitems.ErrApprovalNotFound.
func (s *PGStore) DecisionPayload(ctx context.Context, approvalRef string) (*DecisionPayload, error) {
	var out *DecisionPayload
	err := s.inTx(ctx, "decision payload", func(tx pgx.Tx) error {
		_, b, err := workitems.GlovoBasketApprovalForDecision(ctx, tx, approvalRef, s.now())
		if err != nil {
			return err
		}
		r, err := scanRevision(tx.QueryRow(ctx, `SELECT `+revisionColumns+` FROM glovo.basket_revisions
			WHERE basket_id=$1 AND revision=$2 AND basket_fingerprint=$3`, b.BasketID, b.Revision, b.BasketFingerprint))
		if err != nil {
			return unavailable("read approved revision", err)
		}
		out = &DecisionPayload{ApprovalRef: b.ApprovalID, BasketID: b.BasketID, Revision: b.Revision, StoreRef: r.StoreRef,
			Lines: r.Lines, Totals: r.Totals, Fingerprint: r.Fingerprint, Tenant: b.Tenant, Owner: b.OwnerPrincipalID}
		return nil
	})
	return out, err
}
