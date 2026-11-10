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

package control

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/basket"
	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
	"github.com/mctlhq/mctl-api/internal/glovo/orders"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// ActorID is the identity every order event, bridge transition and receipt
// revocation written by the control worker carries (mctl-api#985 design 8). It
// equals auth.GlovoControlWorkerUserID; the api tests pin the two together.
const ActorID = "service:glovo-control-worker"

var actor = orders.Actor{Kind: orders.ActorControlWorker, ID: ActorID}

// lockTimeout is the SET LOCAL lock_timeout of every control transaction: a
// lock that cannot be had in this time is tenant_busy (SQLSTATE 55P03).
const lockTimeout = 5 * time.Second

// OrderIndex is the #988 order store, control path (design 3).
type OrderIndex interface {
	PeekOrderScope(ctx context.Context, q dbq.Querier, orderRef string, tenants []string) (orders.Scope, error)
	LockOrderForControl(ctx context.Context, tx pgx.Tx, orderRef string, tenants []string) (*orders.Order, error)
	Snapshot(ctx context.Context, q dbq.Querier, sc orders.Scope, orderRef string, seq int) (*orders.Snapshot, error)
	MarkDispatched(ctx context.Context, tx pgx.Tx, o *orders.Order, commandID string, a orders.Actor) error
	MarkCancelled(ctx context.Context, tx pgx.Tx, o *orders.Order, a orders.Actor) error
	MarkUnknown(ctx context.Context, tx pgx.Tx, o *orders.Order, a orders.Actor) error
	MarkClosed(ctx context.Context, tx pgx.Tx, o *orders.Order, a orders.Actor) error
}

// Receipts is the #989 approval ledger (internal/workitems), tx-scoped.
type Receipts interface {
	LockGlovoApprovalTx(ctx context.Context, tx pgx.Tx, id string) (*workitems.ActionApprovalRequest, *workitems.GlovoBinding, error)
	ReserveGlovoApprovalTx(ctx context.Context, tx pgx.Tx, id string, cmd workitems.ReserveCommand) (bool, error)
	RevokeGlovoApprovalTx(ctx context.Context, tx pgx.Tx, id, actor string) error
	MarkGlovoApprovalUnknownTx(ctx context.Context, tx pgx.Tx, id, commandID string) error
	GlovoApprovalStatus(ctx context.Context, q dbq.Querier, tenants []string, id string) (*workitems.GlovoApprovalStatus, error)
}

// Connections is the #959 store on the shared transaction.
type Connections interface {
	LockOwnerShared(ctx context.Context, tx pgx.Tx, tenant, principal string) error
	LiveConnectionTx(ctx context.Context, tx pgx.Tx, owner glovo.Owner) (*glovo.Connection, error)
}

// Membership is the GitOps membership read, best effort.
type Membership interface {
	IsMember(ctx context.Context, tenant, principalID string) (bool, error)
}

// JoinRefs resolves the opaque tnr_ and prr_ refs of the bridge payload.
type JoinRefs interface {
	LookupJoinRefTx(ctx context.Context, q dbq.Querier, kind orders.JoinKind, tenant, principalID, subjectID string) (string, error)
}

// Executions is the #989 work-items execution read.
type Executions interface {
	ExecutionBindingTx(ctx context.Context, q dbq.Querier, executionID string) (tenant, ownerPrincipalID, workItemID, workflowID string, err error)
}

// Bridge is the part of bridge.Store dispatch and cancel use.
type Bridge interface {
	Enqueue(ctx context.Context, tx pgx.Tx, in bridge.EnqueueInput) (string, bool, error)
	Cancel(ctx context.Context, tx pgx.Tx, commandID, actor string) error
	CommandEffect(ctx context.Context, q dbq.Querier, tenants []string, commandID string) (status, effectState string, err error)
	CommandResultFor(ctx context.Context, q dbq.Querier, tenants []string, commandID string) (*bridge.CommandResult, error)
}

// DB is the one shared glovo_runtime pool.
type DB interface {
	dbq.Querier
	BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error)
}

// ControlStartFunc is glovojoin.ControlStartTx.
type ControlStartFunc func(ctx context.Context, q dbq.Querier, orderRef string) (workflowID, runID string, err error)

// Dispatcher is the control-worker slice. Every collaborator is required: a
// missing one makes Ready (and so every route) not_ready.
type Dispatcher struct {
	DB           DB
	Bridge       Bridge
	Orders       OrderIndex
	Receipts     Receipts
	Conns        Connections
	Members      Membership
	Joins        JoinRefs
	Execs        Executions
	ControlStart ControlStartFunc
	// ReadyCheck is the aggregate of the proof, the #959 and #989 readiness and
	// the bridge wire-version gate. It is evaluated on every call.
	ReadyCheck func(ctx context.Context) error
	// ReadyTTL caches a positive readiness answer; zero checks every call. A
	// negative answer is never cached.
	ReadyTTL time.Duration

	mu      sync.Mutex
	okUntil time.Time
}

// Ready is nil only when every collaborator is present and ReadyCheck passes.
// Any error is a not_ready refusal.
func (d *Dispatcher) Ready(ctx context.Context) error {
	if d == nil || d.ReadyCheck == nil || glovo.IsNil(d.DB) || glovo.IsNil(d.Bridge) || glovo.IsNil(d.Orders) ||
		glovo.IsNil(d.Receipts) || glovo.IsNil(d.Conns) || glovo.IsNil(d.Members) || glovo.IsNil(d.Joins) ||
		glovo.IsNil(d.Execs) || d.ControlStart == nil {
		return refuse(glovo.CodeNotReady, "a collaborator is missing")
	}
	d.mu.Lock()
	cached := d.ReadyTTL > 0 && time.Now().Before(d.okUntil)
	d.mu.Unlock()
	if cached {
		return nil
	}
	if err := d.ReadyCheck(ctx); err != nil {
		return refuse(glovo.CodeNotReady, err.Error())
	}
	if d.ReadyTTL > 0 {
		d.mu.Lock()
		d.okUntil = time.Now().Add(d.ReadyTTL)
		d.mu.Unlock()
	}
	return nil
}

// TenantFor resolves the tenant a ref addresses (an ordr_, cmd_ or aar_), for
// the per-tenant rate limit. It is an unlocked read inside the worker's tenants
// bound; "" means it could not be resolved (absent, foreign or a failed read),
// which the limiter puts in one shared bucket of its own.
func (d *Dispatcher) TenantFor(ctx context.Context, tenants []string, ref string) string {
	if d == nil || glovo.IsNil(d.DB) || len(tenants) == 0 {
		return ""
	}
	switch {
	case strings.HasPrefix(ref, "ordr_"):
		if sc, err := d.Orders.PeekOrderScope(ctx, d.DB, ref, tenants); err == nil {
			return sc.Tenant
		}
	case strings.HasPrefix(ref, "cmd_"):
		if r, err := d.Bridge.CommandResultFor(ctx, d.DB, tenants, ref); err == nil {
			return r.Tenant
		}
	case strings.HasPrefix(ref, "aar_"):
		if st, err := d.Receipts.GlovoApprovalStatus(ctx, d.DB, tenants, ref); err == nil {
			if sc, err := d.Orders.PeekOrderScope(ctx, d.DB, st.OrderRef, tenants); err == nil {
				return sc.Tenant
			}
		}
	}
	return ""
}

// Result is the 200 body of dispatch and cancel.
type Result struct {
	OrderRef    string
	CommandID   string
	OrderState  string
	EffectState string
	// Replayed is true for a dispatch the order already had a command for.
	Replayed bool
}

// begin starts the READ COMMITTED transaction with SET LOCAL lock_timeout.
func (d *Dispatcher) begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := d.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("control: begin: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`, strconv.FormatInt(lockTimeout.Milliseconds(), 10)+"ms"); err != nil {
		_ = tx.Rollback(ctx)
		return nil, fmt.Errorf("control: lock timeout: %w", err)
	}
	return tx, nil
}

// scoped is steps 1 to 4 of design 5, shared by dispatch, cancel and the
// command read: peek the scope, take L1 and L2 shared, lock the order (L3) and
// re-check the scope. The caller rolls tx back on any error it returns.
func (d *Dispatcher) scoped(ctx context.Context, orderRef string, tenants []string) (pgx.Tx, *orders.Order, orders.Scope, error) {
	sc, err := d.Orders.PeekOrderScope(ctx, d.DB, orderRef, tenants)
	if err != nil {
		return nil, nil, sc, err
	}
	tx, err := d.begin(ctx)
	if err != nil {
		return nil, nil, sc, err
	}
	fail := func(err error) (pgx.Tx, *orders.Order, orders.Scope, error) {
		_ = tx.Rollback(ctx)
		return nil, nil, sc, err
	}
	if err := d.Conns.LockOwnerShared(ctx, tx, sc.Tenant, sc.PrincipalID); err != nil {
		return fail(err)
	}
	o, err := d.Orders.LockOrderForControl(ctx, tx, orderRef, tenants)
	if err != nil {
		return fail(err)
	}
	// Tenant and owner are write-once: a difference is an invariant violation.
	if o.Tenant != sc.Tenant || o.OwnerPrincipalID != sc.PrincipalID {
		return fail(refuse(glovo.CodeUnavailable, "order scope changed between peek and lock"))
	}
	return tx, o, sc, nil
}

// effectOf reads the effect_state of the order's command with CommandEffect.
// An order with no command has effect none. A failed or absent read is
// unavailable, never a made-up "none".
func (d *Dispatcher) effectOf(ctx context.Context, q dbq.Querier, o *orders.Order) (status, effect string, err error) {
	if o.CommandID == "" {
		return "", bridge.EffectNone, nil
	}
	status, effect, err = d.Bridge.CommandEffect(ctx, q, []string{o.Tenant}, o.CommandID)
	if err != nil {
		return "", "", unavailable("read command effect: ", err)
	}
	return status, effect, nil
}

// Dispatch turns a finalized, approved order into one place_order_fake bridge
// command in a single transaction (design 5). Every refusal rolls back.
func (d *Dispatcher) Dispatch(ctx context.Context, tenants []string, orderRef, approvalRef, fingerprint string) (*Result, error) {
	if err := d.Ready(ctx); err != nil {
		return nil, err
	}
	if len(tenants) == 0 {
		return nil, glovo.ErrNotFound
	}
	tx, o, sc, err := d.scoped(ctx, orderRef, tenants)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Step 5: replay before any receipt check.
	if o.CommandID != "" {
		if o.ApprovalRef != approvalRef {
			return nil, refuse(glovo.CodeApprovalReplayed, "a different approval names a dispatched order")
		}
		if o.FinalBasketFingerprint != fingerprint {
			return nil, refuse(glovo.CodeBasketChanged, "replay with a different fingerprint")
		}
		_, effect, err := d.effectOf(ctx, tx, o)
		if err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, unavailable("commit: ", err)
		}
		return &Result{OrderRef: o.OrderRef, CommandID: o.CommandID, OrderState: o.State, EffectState: effect, Replayed: true}, nil
	}
	if o.State != orders.StateFinalized {
		return nil, refuse(glovo.CodeInvalidTransition, "order is "+o.State)
	}
	// Step 6.
	if fingerprint != o.FinalBasketFingerprint {
		return nil, refuse(glovo.CodeBasketChanged, "body fingerprint differs from the order")
	}
	if o.ApprovalRef == "" {
		return nil, refuse(glovo.CodeApprovalInvalid, "the order has no approval")
	}
	if approvalRef != o.ApprovalRef {
		return nil, refuse(glovo.CodeIntentMismatch, "body approval is not the order's")
	}
	// Step 7: L4 and the binding.
	a, b, err := d.Receipts.LockGlovoApprovalTx(ctx, tx, o.ApprovalRef)
	if err != nil {
		if errors.Is(err, glovo.ErrNotFound) || errors.Is(err, workitems.ErrNotFound) {
			return nil, refuse(glovo.CodeApprovalInvalid, "not a Glovo approval")
		}
		return nil, err
	}
	if err := approvalUsable(a, b); err != nil {
		return nil, err
	}
	var live, hasFresh bool
	var left float64
	if err := tx.QueryRow(ctx, `SELECT expires_at > clock_timestamp(), fresh_until IS NOT NULL,
		COALESCE(EXTRACT(EPOCH FROM (fresh_until - clock_timestamp())), 0)::float8
		FROM public.action_approval_requests WHERE id = $1`, a.ID).Scan(&live, &hasFresh, &left); err != nil {
		return nil, unavailable("read approval window: ", err)
	}
	if !hasFresh {
		return nil, refuse(glovo.CodeApprovalInvalid, "an approved receipt has no freshness bound")
	}
	// The receipt must stay fresh past the reserve margin: Reserve refuses a
	// fresh_until closer than ReservePermitMargin, and by then the command row
	// would already exist. Refuse here, before the enqueue.
	if !live || left <= workitems.ReservePermitMargin.Seconds() {
		return nil, refuse(glovo.CodeApprovalExpired, "past expires_at, or fresh_until within the reserve margin")
	}
	if err := bindingMatches(o, a, b); err != nil {
		return nil, err
	}
	// Step 8: the live connection, then step 9 membership.
	conn, err := d.Conns.LiveConnectionTx(ctx, tx, glovo.Owner{TenantID: o.Tenant, PrincipalID: o.OwnerPrincipalID})
	if err != nil {
		return nil, err
	}
	if conn.State != glovo.Active {
		return nil, refuse(glovo.CodeNoConnection, "the connection is not active")
	}
	if conn.ConnectionID != o.ConnectionID {
		return nil, refuse(glovo.CodeConnectionRevoked, "the live connection is not the order's")
	}
	if conn.InstallRevision != o.InstallRevision {
		return nil, refuse(glovo.CodeStaleInstall, "the install revision moved")
	}
	member, err := glovo.BoundedMembership(ctx, 0, func(c context.Context) (bool, error) {
		return d.Members.IsMember(c, o.Tenant, o.OwnerPrincipalID)
	})
	if err != nil {
		return nil, unavailable("membership read: ", err)
	}
	if !member {
		return nil, refuse(glovo.CodeNoTenant, "the owner is no longer a tenant member")
	}
	// Step 10: sequence under L3 (every command of this execution is created
	// under the order lock); the unique (execution_id, sequence) index is the
	// backstop, and a collision is unavailable and retryable.
	var sequence int64
	if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(sequence), 0) + 1 FROM bridge_commands WHERE execution_id = $1`, o.ExecutionID).Scan(&sequence); err != nil {
		return nil, unavailable("read sequence: ", err)
	}
	// Step 11: the snapshot is the payload, byte for byte.
	snap, err := d.Orders.Snapshot(ctx, tx, sc, o.OrderRef, o.FinalSnapshotSeq)
	if err != nil {
		return nil, unavailable("read final snapshot: ", err)
	}
	if _, canonical, perr := basket.Parse(snap.Canonical); perr != nil || basket.Fingerprint(canonical) != o.FinalBasketFingerprint ||
		snap.Fingerprint != o.FinalBasketFingerprint {
		return nil, refuse(glovo.CodeBasketChanged, "the final snapshot does not hash to the order fingerprint")
	}
	tenantRef, err := d.Joins.LookupJoinRefTx(ctx, tx, orders.JoinTenant, o.Tenant, "", o.Tenant)
	if err != nil {
		return nil, unavailable("tenant ref: ", err)
	}
	principalRef, err := d.Joins.LookupJoinRefTx(ctx, tx, orders.JoinPrincipal, o.Tenant, o.OwnerPrincipalID, o.OwnerPrincipalID)
	if err != nil {
		return nil, unavailable("principal ref: ", err)
	}
	execTenant, execOwner, workItemID, workflowID, err := d.Execs.ExecutionBindingTx(ctx, tx, o.ExecutionID)
	if err != nil {
		return nil, unavailable("execution binding: ", err)
	}
	if execTenant != o.Tenant || execOwner != o.OwnerPrincipalID || workItemID != b.WorkItemID {
		return nil, refuse(glovo.CodeIntentMismatch, "the execution is not this order's")
	}
	startWorkflow, runID, err := d.ControlStart(ctx, tx, o.OrderRef)
	if err != nil {
		return nil, unavailable("control start: ", err)
	}
	if startWorkflow != workflowID {
		return nil, refuse(glovo.CodeIntentMismatch, "the control start names another workflow")
	}
	ttl := DispatchCommandTTL
	if capped := time.Duration(math.Floor(left)) * time.Second; capped < ttl {
		ttl = capped
	}
	cmdID, created, err := d.Bridge.Enqueue(ctx, tx, bridge.EnqueueInput{
		ExecutionID: o.ExecutionID, WorkItemID: workItemID, WorkflowID: workflowID, RunID: runID,
		Tenant: o.Tenant, OwnerPrincipalID: o.OwnerPrincipalID, TenantRef: tenantRef, PrincipalRef: principalRef,
		OrderRef: o.OrderRef, ConnectionRef: o.ConnectionID, InstallRevision: b.InstallRevision, ProviderRef: b.Provider,
		Kind: bridge.KindPlaceOrderFake, Attempt: 1, IntentHash: a.IntentHash, ApprovalRef: o.ApprovalRef,
		OperationKey: "glovo-dispatch:" + o.OrderRef, Sequence: sequence, Payload: snap.Canonical, TTL: ttl,
		WireVersion: bridge.WireV1alpha2,
	})
	if err != nil {
		return nil, err
	}
	if !created {
		return nil, refuse(glovo.CodeUnavailable, "enqueue found an existing command for a finalized order")
	}
	// Steps 12 to 14.
	replayed, err := d.Receipts.ReserveGlovoApprovalTx(ctx, tx, o.ApprovalRef, workitems.ReserveCommand{
		CommandID: cmdID, Tenant: o.Tenant, OwnerPrincipalID: o.OwnerPrincipalID, ExecutionID: o.ExecutionID,
		OrderRef: o.OrderRef, ConnectionRef: o.ConnectionID, InstallRevision: b.InstallRevision,
		IntentHash: a.IntentHash, BasketFingerprint: o.FinalBasketFingerprint,
	})
	if err != nil {
		return nil, err
	}
	if replayed {
		return nil, refuse(glovo.CodeUnavailable, "a fresh command found its receipt already reserved")
	}
	if err := d.Orders.MarkDispatched(ctx, tx, o, cmdID, actor); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, unavailable("commit: ", err)
	}
	return &Result{OrderRef: o.OrderRef, CommandID: cmdID, OrderState: o.State, EffectState: bridge.EffectNone}, nil
}

// approvalUsable is the state half of design 5 step 7: only an approved
// Glovo receipt can be reserved.
func approvalUsable(a *workitems.ActionApprovalRequest, b *workitems.GlovoBinding) error {
	switch a.State {
	case workitems.ApprovalApproved:
		return nil
	case workitems.ApprovalReserved, workitems.ApprovalConsumed:
		if b.CommandID != "" {
			return refuse(glovo.CodeApprovalReplayed, "the receipt is reserved or consumed for another command")
		}
	}
	return refuse(glovo.CodeApprovalInvalid, "the receipt is "+a.State)
}

// bindingMatches requires the receipt's binding to equal the locked order
// row; the fingerprint is basket_changed, every other field intent_mismatch.
func bindingMatches(o *orders.Order, a *workitems.ActionApprovalRequest, b *workitems.GlovoBinding) error {
	if b.Tenant != o.Tenant || b.OwnerPrincipalID != o.OwnerPrincipalID || b.ExecutionID != o.ExecutionID ||
		b.OrderRef != o.OrderRef || b.ConnectionRef != o.ConnectionID || b.InstallID != o.InstallID ||
		b.InstallRevision != strconv.FormatInt(o.InstallRevision, 10) {
		return refuse(glovo.CodeIntentMismatch, "the receipt binding differs from the order")
	}
	if b.BasketFingerprint != o.FinalBasketFingerprint {
		return refuse(glovo.CodeBasketChanged, "the receipt fingerprint differs from the order")
	}
	if workitems.IntentHash(workitems.GlovoIntent(*b)) != a.IntentHash {
		return refuse(glovo.CodeIntentMismatch, "the receipt intent hash is not its binding's")
	}
	return nil
}

// Cancel cancels an order on the path its state decides (design 6). A terminal
// order is a no-op answer; a cancel of a dispatched order reads the command
// pair once and lets reconcileOrder decide, so the order is never cancelled
// while a permit may have been issued.
func (d *Dispatcher) Cancel(ctx context.Context, tenants []string, orderRef string) (*Result, error) {
	if err := d.Ready(ctx); err != nil {
		return nil, err
	}
	if len(tenants) == 0 {
		return nil, glovo.ErrNotFound
	}
	tx, o, _, err := d.scoped(ctx, orderRef, tenants)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	res := &Result{OrderRef: o.OrderRef, CommandID: o.CommandID, EffectState: bridge.EffectNone}
	switch o.State {
	case orders.StateOpen:
		if err := d.Orders.MarkCancelled(ctx, tx, o, actor); err != nil {
			return nil, err
		}
	case orders.StateFinalized:
		if o.ApprovalRef != "" {
			if err := d.Receipts.RevokeGlovoApprovalTx(ctx, tx, o.ApprovalRef, ActorID); err != nil {
				return nil, err
			}
		}
		if err := d.Orders.MarkCancelled(ctx, tx, o, actor); err != nil {
			return nil, err
		}
	case orders.StateDispatched:
		if o.CommandID == "" || o.ApprovalRef == "" {
			return nil, refuse(glovo.CodeUnavailable, "a dispatched order has no command or approval")
		}
		// L4 before L5 (Store.Cancel locks the command).
		if _, _, err := d.Receipts.LockGlovoApprovalTx(ctx, tx, o.ApprovalRef); err != nil {
			return nil, err
		}
		if err := d.Bridge.Cancel(ctx, tx, o.CommandID, ActorID); err != nil && !errors.Is(err, bridge.ErrAlreadyCompleted) {
			return nil, unavailable("bridge cancel", err)
		}
		status, effect, err := d.effectOf(ctx, tx, o)
		if err != nil {
			return nil, err
		}
		if err := d.reconcileOrder(ctx, tx, o, o.CommandID, status, effect); err != nil {
			return nil, err
		}
		res.EffectState = effect
	default:
		// closed, cancelled, unknown: no write and no bridge call.
		_, effect, err := d.effectOf(ctx, tx, o)
		if err != nil {
			return nil, err
		}
		res.EffectState = effect
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, unavailable("commit: ", err)
	}
	res.OrderState = o.State
	return res, nil
}

// CommandView is the 200 body of the command read: ids, enums and the digest.
type CommandView struct {
	CommandID, OrderRef, Status, EffectState         string
	Outcome, ProviderEffect, ErrorCode, ResultDigest string
}

// ReadCommand answers read_command_result (design 2a): L1, L2 and L3, one read
// of the pair, and reconcileOrder, so the stored order catches up with a
// command nobody cancelled. Only a Glovo place_order_fake command inside the
// tenants bound is answered; anything else is not_found.
func (d *Dispatcher) ReadCommand(ctx context.Context, tenants []string, commandID string) (*CommandView, error) {
	if err := d.Ready(ctx); err != nil {
		return nil, err
	}
	if len(tenants) == 0 || !bridge.IsCommandID(commandID) {
		return nil, glovo.ErrNotFound
	}
	first, err := d.Bridge.CommandResultFor(ctx, d.DB, tenants, commandID)
	if err != nil {
		if errors.Is(err, bridge.ErrCommandNotFound) {
			return nil, glovo.ErrNotFound
		}
		return nil, unavailable("read command: ", err)
	}
	tx, o, _, err := d.scoped(ctx, first.OrderRef, tenants)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if o.CommandID != commandID {
		return nil, refuse(glovo.CodeUnavailable, "the command is not the order's command")
	}
	// The pair is read once, under L3, before L4.
	r, err := d.Bridge.CommandResultFor(ctx, tx, tenants, commandID)
	if err != nil {
		if errors.Is(err, bridge.ErrCommandNotFound) {
			return nil, glovo.ErrNotFound
		}
		return nil, unavailable("read command: ", err)
	}
	if err := d.reconcileOrder(ctx, tx, o, commandID, r.Status, r.EffectState); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, unavailable("commit: ", err)
	}
	return &CommandView{CommandID: r.CommandID, OrderRef: r.OrderRef, Status: r.Status, EffectState: r.EffectState,
		Outcome: r.Outcome, ProviderEffect: r.ProviderEffect, ErrorCode: r.ErrorCode, ResultDigest: r.ResultDigest}, nil
}

// ReadApproval answers the approval poll: ids and enums only, on the shared
// pool, never the work-items pool.
func (d *Dispatcher) ReadApproval(ctx context.Context, tenants []string, approvalRef string) (*workitems.GlovoApprovalStatus, error) {
	if err := d.Ready(ctx); err != nil {
		return nil, err
	}
	if len(tenants) == 0 {
		return nil, glovo.ErrNotFound
	}
	st, err := d.Receipts.GlovoApprovalStatus(ctx, d.DB, tenants, approvalRef)
	if err != nil {
		if errors.Is(err, workitems.ErrNotFound) {
			return nil, glovo.ErrNotFound
		}
		return nil, err
	}
	return st, nil
}
