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
	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
)

// The control path serves the #985 control worker. The scope comes from the
// order row itself, restricted to the tenants the worker is bound to, never
// from a caller-supplied owner.

// PeekOrderScope reads tenant and owner of an order by order_ref with
// tenant = ANY(tenants), without a lock. A miss is not_found.
func (s *Store) PeekOrderScope(ctx context.Context, q dbq.Querier, orderRef string, tenants []string) (Scope, error) {
	if err := s.ready(); err != nil {
		return Scope{}, err
	}
	var sc Scope
	err := q.QueryRow(ctx, `SELECT tenant, owner_principal_id FROM glovo.orders WHERE order_ref = $1 AND tenant = ANY($2)`,
		orderRef, tenants).Scan(&sc.Tenant, &sc.PrincipalID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Scope{}, glovo.ErrNotFound
	}
	if err != nil {
		return Scope{}, mapErr(err)
	}
	return sc, nil
}

// LockOrderForControl re-reads the order FOR UPDATE under the same predicate
// as PeekOrderScope. It re-reads no connection.
func (s *Store) LockOrderForControl(ctx context.Context, tx pgx.Tx, orderRef string, tenants []string) (*Order, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	o, err := scanOrder(tx.QueryRow(ctx, `SELECT `+orderColumns+` FROM glovo.orders o
 WHERE o.order_ref = $1 AND o.tenant = ANY($2) FOR UPDATE OF o`, orderRef, tenants))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, glovo.ErrNotFound
	}
	if err != nil {
		return nil, mapErr(err)
	}
	return o, nil
}

// ScopeFromRefs resolves a tnr_/prr_ pair through glovo.join_refs and requires
// both to map to the same tenant. A miss is not_found.
func (s *Store) ScopeFromRefs(ctx context.Context, q dbq.Querier, tenantRef, principalRef string) (Scope, error) {
	if err := s.ready(); err != nil {
		return Scope{}, err
	}
	var sc Scope
	err := q.QueryRow(ctx, `SELECT t.tenant, p.principal_id FROM glovo.join_refs t
 JOIN glovo.join_refs p ON p.tenant = t.tenant AND p.kind = 'principal' AND p.ref = $2
 WHERE t.kind = 'tenant' AND t.ref = $1`, tenantRef, principalRef).Scan(&sc.Tenant, &sc.PrincipalID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Scope{}, glovo.ErrNotFound
	}
	if err != nil {
		return Scope{}, mapErr(err)
	}
	return sc, nil
}

// MarkDispatched records the command id of a finalized, approved order and
// writes the one place_order_fake effect row, effect first, in the caller's
// transaction. It does not re-read the connection: #985 does that itself
// before Enqueue.
func (s *Store) MarkDispatched(ctx context.Context, tx pgx.Tx, o *Order, commandID string, a Actor) error {
	if err := s.ready(); err != nil {
		return err
	}
	if o == nil || !commandIDRE.MatchString(commandID) {
		return glovo.Refuse(glovo.CodeInvalidRequest)
	}
	if err := a.validate(); err != nil {
		return err
	}
	if o.State != StateFinalized || o.ApprovalRef == "" {
		return glovo.Refuse(glovo.CodeInvalidTransition)
	}
	effectID, err := newID("peff_")
	if err != nil {
		return glovo.Refuse(glovo.CodeUnavailable)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO glovo.order_effects
 (effect_id, order_id, tenant, owner_principal_id, effect_kind, execution_id, basket_fingerprint, idempotency_key, request_hash, created_at)
 VALUES ($1, $2, $3, $4, 'place_order_fake', $5, $6, $7, $8, $9)`,
		effectID, o.orderID, o.Tenant, o.OwnerPrincipalID, o.ExecutionID, o.FinalBasketFingerprint,
		"glovo-dispatch:"+o.OrderRef, o.FinalBasketFingerprint, s.now()); err != nil {
		return mapErr(err)
	}
	return s.move(ctx, tx, o, StateDispatched, "dispatched", a, commandID)
}

// MarkCancelled moves an open, finalized or dispatched order to cancelled. It
// never re-reads the connection: a revoke is exactly when it runs.
func (s *Store) MarkCancelled(ctx context.Context, tx pgx.Tx, o *Order, a Actor) error {
	if err := s.guardMark(o, a); err != nil {
		return err
	}
	if o.State != StateOpen && o.State != StateFinalized && o.State != StateDispatched {
		return glovo.Refuse(glovo.CodeInvalidTransition)
	}
	return s.move(ctx, tx, o, StateCancelled, "cancelled", a, "")
}

// MarkUnknown moves a dispatched order to unknown.
func (s *Store) MarkUnknown(ctx context.Context, tx pgx.Tx, o *Order, a Actor) error {
	if err := s.guardMark(o, a); err != nil {
		return err
	}
	if o.State != StateDispatched {
		return glovo.Refuse(glovo.CodeInvalidTransition)
	}
	return s.move(ctx, tx, o, StateUnknown, "unknown", a, "")
}

// MarkClosed moves a dispatched order to closed. It is the only edge into
// closed this API offers.
func (s *Store) MarkClosed(ctx context.Context, tx pgx.Tx, o *Order, a Actor) error {
	if err := s.guardMark(o, a); err != nil {
		return err
	}
	if o.State != StateDispatched {
		return glovo.Refuse(glovo.CodeInvalidTransition)
	}
	return s.move(ctx, tx, o, StateClosed, "closed", a, "")
}

func (s *Store) guardMark(o *Order, a Actor) error {
	if err := s.ready(); err != nil {
		return err
	}
	if o == nil {
		return glovo.Refuse(glovo.CodeInvalidRequest)
	}
	return a.validate()
}

// move CASes the order to state `to` (and, for a dispatch, writes commandID)
// and appends the event, then updates o in place.
func (s *Store) move(ctx context.Context, tx pgx.Tx, o *Order, to, event string, a Actor, commandID string) error {
	from := o.State
	args := []any{o.orderID, from, o.Version, to}
	set := `state = $4`
	if commandID != "" {
		set += `, command_id = $5`
		args = append(args, commandID)
	}
	tag, err := tx.Exec(ctx, `UPDATE glovo.orders SET `+set+`, version = version + 1, updated_at = clock_timestamp()
 WHERE order_id = $1 AND state = $2 AND version = $3`, args...)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() != 1 {
		return glovo.Refuse(glovo.CodeInvalidTransition)
	}
	if err := s.appendEvent(ctx, tx, o.Tenant, o.OrderRef, a, event, from, to, o.FinalSnapshotSeq); err != nil {
		return err
	}
	o.State = to
	o.Version++
	if commandID != "" {
		o.CommandID = commandID
	}
	return nil
}
