package receipt

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/basket"
	"github.com/mctlhq/mctl-api/internal/glovo/orders"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Approvals is the approval ledger (workitems.Store).
type Approvals interface {
	LockGlovoApprovalTx(ctx context.Context, tx pgx.Tx, id string) (*workitems.ActionApprovalRequest, *workitems.GlovoBinding, error)
	ConsumeGlovoApprovalTx(ctx context.Context, tx pgx.Tx, id, commandID string) error
}

// Orders is the #988 order store.
type Orders interface {
	LockOrderForControl(ctx context.Context, tx pgx.Tx, orderRef string, tenants []string) (*orders.Order, error)
}

// Conns is the #959 connection store.
type Conns interface {
	LockOwnerShared(ctx context.Context, tx pgx.Tx, tenant, principal string) error
	LiveConnectionTx(ctx context.Context, tx pgx.Tx, owner glovo.Owner) (*glovo.Connection, error)
}

// Membership is the live tenant membership read, with the method set of the
// #985 section 3 Membership so that no #989 package imports #985's. It is a
// GitOps read, best effort, taken outside any row lock; the transactional
// guarantee is #985 section 7.3.
type Membership interface {
	IsMember(tenant, principalID string) (bool, error)
}

// preLockTTL bounds how long a PreLock record waits for its Check. A permit
// that fails between the two (stale lease, cancelled command) never reaches
// Check; its record is swept by the next PreLock.
const preLockTTL = 10 * time.Minute

type preLocked struct {
	commandID, tenant, owner, orderRef, approvalRef string
	// unfenced marks a command this fence does not authorize (another kind, or
	// no order or approval reference): no lock was taken and Check refuses it
	// permanently with approval_invalid, not with a retryable unavailable.
	unfenced bool
	at       time.Time
}

// Fence is the bridge.WriteFence of the Glovo write path. Every collaborator
// is required; with one missing every method refuses with not_ready.
type Fence struct {
	approvals Approvals
	orders    Orders
	conns     Conns
	members   Membership

	mu  sync.Mutex
	pre map[pgx.Tx]preLocked
	now func() time.Time
}

var _ bridge.WriteFence = (*Fence)(nil)

// NewFence returns the fence. It installs nothing: only #985 task 9 calls
// bridge.Store.SetFence, after Ready is nil.
func NewFence(a Approvals, o Orders, c Conns, m Membership) *Fence {
	return &Fence{approvals: a, orders: o, conns: c, members: m, pre: map[pgx.Tx]preLocked{}, now: time.Now}
}

func isNil(v any) bool { return glovo.IsNil(v) }

func (f *Fence) complete() bool {
	return f != nil && !isNil(f.approvals) && !isNil(f.orders) && !isNil(f.conns) && !isNil(f.members)
}

const kindPlaceOrderFake = "place_order_fake"

// PreLock is step 0-4 of design section 6, before the bridge locks the
// command (L5). It takes no lock for a command it does not fence.
func (f *Fence) PreLock(ctx context.Context, tx pgx.Tx, c bridge.Caller, commandID string) error {
	if !f.complete() {
		return refuse(glovo.CodeNotReady)
	}
	// Step 0: scope first, no lock. An absent id, another provider and a
	// tenant outside the caller's bound are one answer, before any L1-L4.
	var tenant, owner, orderRef, approvalRef, provider, kind string
	err := tx.QueryRow(ctx, `SELECT tenant, owner_principal_id, order_ref, approval_ref, provider_ref, operation_kind
		FROM bridge_commands WHERE command_id=$1`, commandID).Scan(&tenant, &owner, &orderRef, &approvalRef, &provider, &kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return bridge.ErrCommandNotFound
	}
	if err != nil {
		return refusalOf(fmt.Errorf("receipt: read command: %w", err))
	}
	if provider != c.ProviderRef || !c.AllowsTenant(tenant) {
		return bridge.ErrCommandNotFound
	}
	if kind != kindPlaceOrderFake || orderRef == "" || approvalRef == "" {
		f.remember(tx, preLocked{commandID: commandID, tenant: tenant, owner: owner, unfenced: true})
		return nil
	}
	// Steps 2-4: L1 and L2 shared, L3, L4.
	if err := f.conns.LockOwnerShared(ctx, tx, tenant, owner); err != nil {
		return refusalOf(err)
	}
	if _, err := f.orders.LockOrderForControl(ctx, tx, orderRef, []string{tenant}); err != nil {
		return refusalOf(err)
	}
	if _, _, err := f.approvals.LockGlovoApprovalTx(ctx, tx, approvalRef); err != nil {
		return refusalOf(err)
	}
	f.remember(tx, preLocked{commandID: commandID, tenant: tenant, owner: owner, orderRef: orderRef, approvalRef: approvalRef})
	return nil
}

func (f *Fence) remember(tx pgx.Tx, p preLocked) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	for k, v := range f.pre {
		if now.Sub(v.at) > preLockTTL {
			delete(f.pre, k)
		}
	}
	p.at = now
	f.pre[tx] = p
}

// Release forgets what PreLock recorded for tx. permitTx calls it when it
// fails between PreLock and Check, so no entry outlives its transaction.
func (f *Fence) Release(tx pgx.Tx) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.pre, tx)
}

// pending is the number of transactions with a recorded PreLock (tests).
func (f *Fence) pending() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.pre)
}

func (f *Fence) take(tx pgx.Tx) (preLocked, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.pre[tx]
	delete(f.pre, tx)
	return p, ok
}

// FenceRef is the opaque reference recorded with the permit: a hash of ids.
func FenceRef(approvalID, commandID string, leaseEpoch int64) string {
	sum := sha256.Sum256([]byte(approvalID + "|" + commandID + "|" + strconv.FormatInt(leaseEpoch, 10)))
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])
	return "afr_" + strings.ToLower(enc)[:26]
}

// Check is steps 1-9 of design section 6, inside the permit transaction
// (the command row is locked, L1-L4 are held by PreLock). Everything is
// recomputed from what is written; nothing the caller presents is trusted
// beyond the ids that select the rows.
func (f *Fence) Check(ctx context.Context, tx pgx.Tx, b bridge.FenceBinding) (string, error) {
	if !f.complete() {
		return "", refuse(glovo.CodeNotReady)
	}
	pre, ok := f.take(tx)
	if !ok || pre.commandID != b.CommandID {
		// PreLock did not run for this transaction and command: the lock order
		// cannot be trusted. Refuse rather than lock out of order.
		return "", refuse(glovo.CodeUnavailable)
	}
	if pre.unfenced {
		return "", refuse(glovo.CodeApprovalInvalid)
	}
	// Step 1: the locked command row, against what PreLock read and what the
	// bridge presented.
	var (
		cmdTenant, cmdOwner, cmdOrder, cmdApproval, cmdConn, cmdRevision, cmdProvider, cmdKind, cmdIntent string
		payload                                                                                           []byte
	)
	err := tx.QueryRow(ctx, `SELECT tenant, owner_principal_id, order_ref, approval_ref, connection_ref, install_revision,
		provider_ref, operation_kind, intent_hash, payload FROM bridge_commands WHERE command_id=$1`, b.CommandID).
		Scan(&cmdTenant, &cmdOwner, &cmdOrder, &cmdApproval, &cmdConn, &cmdRevision, &cmdProvider, &cmdKind, &cmdIntent, &payload)
	if err != nil {
		return "", refusalOf(fmt.Errorf("receipt: re-read command: %w", err))
	}
	if cmdTenant != pre.tenant || cmdOwner != pre.owner || cmdOrder != pre.orderRef || cmdApproval != pre.approvalRef ||
		cmdApproval != b.ApprovalRef || cmdTenant != b.Tenant || cmdOwner != b.OwnerPrincipalID ||
		cmdConn != b.ConnectionRef || cmdRevision != b.InstallRevision || cmdIntent != b.IntentHash {
		return "", refuse(glovo.CodeIntentMismatch)
	}
	if cmdKind != kindPlaceOrderFake {
		return "", refuse(glovo.CodeApprovalInvalid)
	}
	// Step 2: a Glovo kind, reserved for this command.
	a, bind, err := f.approvals.LockGlovoApprovalTx(ctx, tx, b.ApprovalRef)
	if err != nil {
		return "", refusalOf(err)
	}
	if a.State != workitems.ApprovalReserved || bind.CommandID != b.CommandID {
		if bind.CommandID != "" && bind.CommandID != b.CommandID {
			return "", refuse(glovo.CodeApprovalReplayed)
		}
		return "", refuse(glovo.CodeApprovalInvalid)
	}
	// Step 3: expiry by statement time, not the permit transaction's start.
	var live bool
	if err := tx.QueryRow(ctx, `SELECT expires_at > clock_timestamp() AND fresh_until IS NOT NULL AND fresh_until > clock_timestamp()
		FROM public.action_approval_requests WHERE id=$1`, a.ID).Scan(&live); err != nil {
		return "", refusalOf(fmt.Errorf("receipt: read expiry: %w", err))
	}
	if !live {
		return "", refuse(glovo.CodeApprovalExpired)
	}
	// Step 4: the whole payload is exactly the approval basket.
	_, canonical, perr := basket.Parse(payload)
	if perr != nil {
		return "", refuse(glovo.CodeBasketChanged)
	}
	fp := basket.Fingerprint(canonical)
	order, err := f.orders.LockOrderForControl(ctx, tx, cmdOrder, []string{cmdTenant})
	if err != nil {
		return "", refusalOf(err)
	}
	if fp != bind.BasketFingerprint || fp != order.FinalBasketFingerprint {
		return "", refuse(glovo.CodeBasketChanged)
	}
	// Step 5: the binding, then the intent hash recomputed from the command.
	if cmdProvider != bind.Provider || cmdOrder != bind.OrderRef {
		return "", refuse(glovo.CodeIntentMismatch)
	}
	if a.DecidedByPrincipalID != bind.OwnerPrincipalID || a.AuthorityBasis != workitems.GlovoAuthorityBasis {
		return "", refuse(glovo.CodeApprovalInvalid)
	}
	if b.ExecutionID != bind.ExecutionID || b.WorkItemID != bind.WorkItemID || b.Tenant != bind.Tenant ||
		b.OwnerPrincipalID != bind.OwnerPrincipalID || b.ConnectionRef != bind.ConnectionRef || b.InstallRevision != bind.InstallRevision {
		return "", refuse(glovo.CodeIntentMismatch)
	}
	ih := workitems.IntentHash(workitems.GlovoIntent(workitems.GlovoBinding{
		Tenant: cmdTenant, OwnerPrincipalID: cmdOwner, ExecutionID: b.ExecutionID, WorkItemID: b.WorkItemID,
		OrderRef: cmdOrder, ConnectionRef: cmdConn, InstallID: bind.InstallID, InstallRevision: cmdRevision,
		BasketFingerprint: fp, Provider: cmdProvider,
	}))
	if ih != a.IntentHash || ih != b.IntentHash {
		return "", refuse(glovo.CodeIntentMismatch)
	}
	// Step 6: live membership, best effort.
	member, err := f.members.IsMember(cmdTenant, cmdOwner)
	if err != nil {
		return "", refuse(glovo.CodeUnavailable)
	}
	if !member {
		return "", refuse(glovo.CodeNoTenant)
	}
	// Step 7: the live connection.
	conn, err := f.conns.LiveConnectionTx(ctx, tx, glovo.Owner{TenantID: cmdTenant, PrincipalID: cmdOwner})
	if err != nil {
		return "", refusalOf(err)
	}
	if conn.ConnectionID != b.ConnectionRef {
		return "", refuse(glovo.CodeConnectionRevoked)
	}
	if conn.State != glovo.Active {
		return "", refuse(glovo.CodeNoConnection)
	}
	if strconv.FormatInt(conn.InstallRevision, 10) != b.InstallRevision {
		return "", refuse(glovo.CodeStaleInstall)
	}
	// Step 8: the order was dispatched with this command.
	if order.State != orders.StateDispatched || order.CommandID != b.CommandID {
		return "", refuse(glovo.CodeInvalidTransition)
	}
	// Step 9: spend the approval, in this same transaction as the permit.
	if err := f.approvals.ConsumeGlovoApprovalTx(ctx, tx, a.ID, b.CommandID); err != nil {
		return "", refusalOf(err)
	}
	return FenceRef(a.ID, b.CommandID, b.LeaseEpoch), nil
}
