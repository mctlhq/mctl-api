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

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/basket"
	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
)

// CreateInput is the input of Create.
type CreateInput struct {
	Scope                   Scope
	Actor                   Actor
	IdempotencyKey          string // client key, per (tenant, owner)
	RequestHash             string
	ConnectionID, InstallID string
	ExpectedInstallRevision int64
	ApprovalBasket          []byte // the JCS bytes stored with the #957 preview
	ExpectedFingerprint     string // the preview's fingerprint
	ExecutionID             string // we_ from #989 CreateGlovoExecutionTx
	OrderRef                string // ordr_, minted by #957 with NewOrderRef
}

func (in CreateInput) validate() error {
	if err := in.Scope.validate(); err != nil {
		return err
	}
	if err := in.Actor.validate(); err != nil {
		return err
	}
	if in.IdempotencyKey == "" || len(in.IdempotencyKey) > maxIdempotencyKey || in.RequestHash == "" || len(in.RequestHash) > 200 ||
		in.ConnectionID == "" || in.InstallID == "" || in.ExpectedInstallRevision < 1 ||
		len(in.ApprovalBasket) == 0 || !fingerprintRE.MatchString(in.ExpectedFingerprint) ||
		!orderRefRE.MatchString(in.OrderRef) {
		return glovo.Refuse(glovo.CodeInvalidRequest)
	}
	return nil
}

func requireReadCommitted(ctx context.Context, tx pgx.Tx) error {
	var iso string
	if err := tx.QueryRow(ctx, `SELECT current_setting('transaction_isolation')`).Scan(&iso); err != nil {
		return mapErr(err)
	}
	if iso != "read committed" {
		return glovo.Refuse(glovo.CodeUnavailable)
	}
	return nil
}

// checkConnection re-reads the owner's live connection on the caller's
// transaction and requires it to be the one the order was made on.
func (s *Store) checkConnection(ctx context.Context, tx pgx.Tx, sc Scope, connectionID, installID string, installRevision int64) error {
	c, err := s.conns.LiveConnectionTx(ctx, tx, glovo.Owner{TenantID: sc.Tenant, PrincipalID: sc.PrincipalID})
	if err != nil {
		return mapErr(err)
	}
	if c == nil {
		return glovo.Refuse(glovo.CodeNoConnection)
	}
	if c.ConnectionID != connectionID {
		return glovo.Refuse(glovo.CodeConnectionRevoked)
	}
	if c.InstallID != installID || c.InstallRevision != installRevision {
		return glovo.Refuse(glovo.CodeStaleInstall)
	}
	return nil
}

// Create makes one order from a preview basket on the caller's transaction,
// which must be READ COMMITTED. With an existing (tenant, owner, key) and the
// same request hash it writes nothing and returns the stored order with
// replayed=true, whatever OrderRef and ExecutionID the caller passed; a
// caller that sees replayed after it wrote other rows in its transaction must
// roll the whole transaction back. Another request hash is
// idempotency_key_reused.
func (s *Store) Create(ctx context.Context, tx pgx.Tx, in CreateInput) (*Order, bool, error) {
	if err := s.ready(); err != nil {
		return nil, false, err
	}
	if err := in.validate(); err != nil {
		return nil, false, err
	}
	if !executionIDRE.MatchString(in.ExecutionID) {
		return nil, false, glovo.ErrNotFound
	}
	if err := requireReadCommitted(ctx, tx); err != nil {
		return nil, false, err
	}
	if err := s.checkConnection(ctx, tx, in.Scope, in.ConnectionID, in.InstallID, in.ExpectedInstallRevision); err != nil {
		return nil, false, err
	}
	approval, canonical, err := basket.Parse(in.ApprovalBasket)
	if err != nil {
		return nil, false, glovo.Refuse(glovo.CodeInvalidRequest)
	}
	fp := basket.Fingerprint(canonical)
	if fp != in.ExpectedFingerprint {
		return nil, false, glovo.Refuse(glovo.CodeFingerprintChanged)
	}
	tenant, owner, _, _, err := s.execs.ExecutionBindingTx(ctx, tx, in.ExecutionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, glovo.ErrNotFound
	}
	if err != nil {
		return nil, false, mapErr(err)
	}
	if tenant != in.Scope.Tenant || owner != in.Scope.PrincipalID {
		return nil, false, glovo.ErrNotFound
	}
	orderID, err := newID("pord_")
	if err != nil {
		return nil, false, glovo.Refuse(glovo.CodeUnavailable)
	}
	now := s.now()
	tag, err := tx.Exec(ctx, `INSERT INTO glovo.orders
 (order_id, order_ref, tenant, owner_principal_id, connection_id, install_id, install_revision,
  execution_id, idempotency_key, request_hash, created_at, updated_at)
 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11)
 ON CONFLICT (tenant, owner_principal_id, idempotency_key) DO NOTHING`,
		orderID, in.OrderRef, in.Scope.Tenant, in.Scope.PrincipalID, in.ConnectionID, in.InstallID, in.ExpectedInstallRevision,
		in.ExecutionID, in.IdempotencyKey, in.RequestHash, now)
	if err != nil {
		return nil, false, mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		o, err := s.LookupByIdempotencyKey(ctx, tx, in.Scope, in.IdempotencyKey)
		if err != nil {
			return nil, false, err
		}
		if o.RequestHash != in.RequestHash {
			return nil, false, glovo.Refuse(glovo.CodeIdempotencyReused)
		}
		return o, true, nil
	}
	if _, err := tx.Exec(ctx, `INSERT INTO glovo.order_snapshots (order_id, seq, basket_fingerprint, basket_canonical, line_count, created_at)
 VALUES ($1, 1, $2, $3, $4, $5)`, orderID, fp, canonical, len(approval.Lines), now); err != nil {
		return nil, false, mapErr(err)
	}
	if err := s.appendEvent(ctx, tx, in.Scope.Tenant, in.OrderRef, in.Actor, "created", "", StateOpen, 1); err != nil {
		return nil, false, err
	}
	o, err := readOrder(ctx, tx, in.Scope, in.OrderRef, false)
	if err != nil {
		return nil, false, err
	}
	return o, false, nil
}

// LookupByIdempotencyKey is one read-only statement on (tenant, owner, key);
// a miss is not_found.
func (s *Store) LookupByIdempotencyKey(ctx context.Context, q dbq.Querier, sc Scope, key string) (*Order, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	if err := sc.validate(); err != nil {
		return nil, err
	}
	o, err := scanOrder(q.QueryRow(ctx, `SELECT `+orderColumns+` FROM glovo.orders o
 WHERE o.tenant = $1 AND o.owner_principal_id = $2 AND o.idempotency_key = $3`, sc.Tenant, sc.PrincipalID, key))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, glovo.ErrNotFound
	}
	if err != nil {
		return nil, mapErr(err)
	}
	return o, nil
}

// Get reads one order of the scope in one statement.
func (s *Store) Get(ctx context.Context, q dbq.Querier, sc Scope, orderRef string) (*Order, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	if err := sc.validate(); err != nil {
		return nil, err
	}
	return readOrder(ctx, q, sc, orderRef, false)
}

// LockOrder reads one order of the scope FOR UPDATE on the caller's
// transaction. It re-reads no connection: reads work after a revoke.
func (s *Store) LockOrder(ctx context.Context, tx pgx.Tx, sc Scope, orderRef string) (*Order, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	if err := sc.validate(); err != nil {
		return nil, err
	}
	return readOrder(ctx, tx, sc, orderRef, true)
}

// Snapshot reads snapshot seq of one order of the scope in one statement.
func (s *Store) Snapshot(ctx context.Context, q dbq.Querier, sc Scope, orderRef string, seq int) (*Snapshot, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	if err := sc.validate(); err != nil {
		return nil, err
	}
	var sn Snapshot
	err := q.QueryRow(ctx, `SELECT o.order_ref, s.seq, s.line_count, s.basket_fingerprint, s.basket_canonical, s.created_at
 FROM glovo.order_snapshots s JOIN glovo.orders o ON o.order_id = s.order_id
 WHERE o.order_ref = $1 AND o.tenant = $2 AND o.owner_principal_id = $3 AND s.seq = $4`,
		orderRef, sc.Tenant, sc.PrincipalID, seq).Scan(&sn.OrderRef, &sn.Seq, &sn.LineCount, &sn.Fingerprint, &sn.Canonical, &sn.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, glovo.ErrNotFound
	}
	if err != nil {
		return nil, mapErr(err)
	}
	return &sn, nil
}

// lockForWrite locks the order, requires state and version, and re-reads the
// live connection the order was made on.
func (s *Store) lockForWrite(ctx context.Context, tx pgx.Tx, sc Scope, a Actor, orderRef string, state string, expectedVersion int64) (*Order, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	if err := sc.validate(); err != nil {
		return nil, err
	}
	if err := a.validate(); err != nil {
		return nil, err
	}
	o, err := readOrder(ctx, tx, sc, orderRef, true)
	if err != nil {
		return nil, err
	}
	if o.State != state || o.Version != expectedVersion {
		return nil, glovo.Refuse(glovo.CodeInvalidTransition)
	}
	if err := s.checkConnection(ctx, tx, sc, o.ConnectionID, o.InstallID, o.InstallRevision); err != nil {
		return nil, err
	}
	return o, nil
}

// cas moves one order with a compare-and-set on state and version.
func cas(ctx context.Context, tx pgx.Tx, o *Order, set string, args ...any) error {
	base := []any{o.orderID, o.State, o.Version}
	tag, err := tx.Exec(ctx, `UPDATE glovo.orders SET `+set+`, version = version + 1, updated_at = clock_timestamp()
 WHERE order_id = $1 AND state = $2 AND version = $3`, append(base, args...)...)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() != 1 {
		return glovo.Refuse(glovo.CodeInvalidTransition)
	}
	return nil
}

// AppendSnapshot appends the next snapshot of an open order. It re-reads the
// live connection and refuses a wrong expected fingerprint.
func (s *Store) AppendSnapshot(ctx context.Context, tx pgx.Tx, sc Scope, a Actor, orderRef string, expectedVersion int64, b basket.Approval, expectedFP string) (*Snapshot, error) {
	o, err := s.lockForWrite(ctx, tx, sc, a, orderRef, StateOpen, expectedVersion)
	if err != nil {
		return nil, err
	}
	canonical, err := basket.Canonical(b)
	if err != nil {
		return nil, glovo.Refuse(glovo.CodeInvalidRequest)
	}
	fp := basket.Fingerprint(canonical)
	if !fingerprintRE.MatchString(expectedFP) || fp != expectedFP {
		return nil, glovo.Refuse(glovo.CodeFingerprintChanged)
	}
	sn := Snapshot{OrderRef: o.OrderRef, LineCount: len(b.Lines), Fingerprint: fp, Canonical: canonical, CreatedAt: s.now()}
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(seq), 0) + 1 FROM glovo.order_snapshots WHERE order_id = $1`, o.orderID).Scan(&sn.Seq); err != nil {
		return nil, mapErr(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO glovo.order_snapshots (order_id, seq, basket_fingerprint, basket_canonical, line_count, created_at)
 VALUES ($1, $2, $3, $4, $5, $6)`, o.orderID, sn.Seq, fp, canonical, sn.LineCount, sn.CreatedAt); err != nil {
		return nil, mapErr(err)
	}
	if err := cas(ctx, tx, o, `state = state`); err != nil {
		return nil, err
	}
	if err := s.appendEvent(ctx, tx, o.Tenant, o.OrderRef, a, "snapshot_appended", StateOpen, StateOpen, sn.Seq); err != nil {
		return nil, err
	}
	return &sn, nil
}

// Finalize freezes the fingerprint of the latest snapshot. After it a new
// basket needs a new order.
func (s *Store) Finalize(ctx context.Context, tx pgx.Tx, sc Scope, a Actor, orderRef string, expectedVersion int64, expectedFP string) (*Order, error) {
	o, err := s.lockForWrite(ctx, tx, sc, a, orderRef, StateOpen, expectedVersion)
	if err != nil {
		return nil, err
	}
	var seq int
	var fp string
	if err := tx.QueryRow(ctx, `SELECT seq, basket_fingerprint FROM glovo.order_snapshots WHERE order_id = $1 ORDER BY seq DESC LIMIT 1`,
		o.orderID).Scan(&seq, &fp); err != nil {
		return nil, mapErr(err)
	}
	if fp != expectedFP {
		return nil, glovo.Refuse(glovo.CodeFingerprintChanged)
	}
	if err := cas(ctx, tx, o, `state = 'finalized', final_basket_fingerprint = $4, final_snapshot_seq = $5`, fp, seq); err != nil {
		return nil, err
	}
	if err := s.appendEvent(ctx, tx, o.Tenant, o.OrderRef, a, "finalized", StateOpen, StateFinalized, seq); err != nil {
		return nil, err
	}
	return readOrder(ctx, tx, sc, orderRef, false)
}

// BindApproval writes the write-once aar_ reference of a finalized order. It
// holds no approval authority: the approval itself is owned by #989.
func (s *Store) BindApproval(ctx context.Context, tx pgx.Tx, sc Scope, a Actor, orderRef, approvalRef string) error {
	if !approvalRefRE.MatchString(approvalRef) {
		return glovo.Refuse(glovo.CodeInvalidRequest)
	}
	if err := s.ready(); err != nil {
		return err
	}
	if err := sc.validate(); err != nil {
		return err
	}
	if err := a.validate(); err != nil {
		return err
	}
	o, err := readOrder(ctx, tx, sc, orderRef, true)
	if err != nil {
		return err
	}
	if o.State != StateFinalized || o.ApprovalRef != "" {
		return glovo.Refuse(glovo.CodeInvalidTransition)
	}
	if err := s.checkConnection(ctx, tx, sc, o.ConnectionID, o.InstallID, o.InstallRevision); err != nil {
		return err
	}
	if err := cas(ctx, tx, o, `approval_ref = $4`, approvalRef); err != nil {
		return err
	}
	return s.appendEvent(ctx, tx, o.Tenant, o.OrderRef, a, "approval_bound", StateFinalized, StateFinalized, o.FinalSnapshotSeq)
}
