package workitems

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Glovo action approvals (mctl-api#989, tasks 2 and 3).
//
// A Glovo approval is an ordinary action_approval_requests row (aar_) of kind
// glovo.place_order_fake, bound to one order by a row of
// glovo.approval_bindings. The row is the single authority: stored states
// pending, approved, reserved, consumed, unknown and denied; "expired" is
// derived and never stored. Everything below runs on the caller's
// transaction; none of it begins or commits one or takes an advisory lock, so
// the global lock order of mctl-api#957 design 6b stays the caller's.
//
// Cross-slice notes (task 9):
//   - #957 prepare calls CreateGlovoExecutionTx and CreateGlovoApprovalTx
//     while holding the order lock (L3).
//   - #985 uses the Reserve/Consume/Revoke/MarkUnknown/Status methods, and
//     calls MarkGlovoApprovalUnknownTx when it cancels a command that never
//     got a permit.
//   - The lock order is the one of #957 design 6b: L1 and L2 (connection
//     owner, shared), L3 (order), L4 (this row), L5 (the command row).
//   - GlovoControlInput carries approval_ref and the basket fingerprint; the
//     dispatch compares the fingerprint and answers basket_changed.
//   - The provider writes only the payload's lines (OPEN-989-4); the fence
//     recomputes the fingerprint from the stored payload.

// Glovo action kinds. M1 has exactly one: a cancel before dispatch revokes the
// existing aar_, and a cancel after dispatch needs no approval (#985 section 6).
const (
	ActionKindGlovoPlaceOrderFake = "glovo.place_order_fake"

	// ActionKindGlovoBasketApproval is the owner's approval of one frozen
	// revision of a synthetic basket (mctl-api#1006). It authorizes nothing
	// beyond its own approved state: no order, command or provider effect
	// can spend it (the generic spend paths refuse every glovo.* kind, and
	// the database admits only pending -> approved | denied for it).
	ActionKindGlovoBasketApproval = "glovo.basket_approval"

	// glovoKindPrefix is the namespace of Glovo kinds. The database CHECK
	// action_approval_requests_glovo_kind_chk makes "starts with glovo." and
	// "is in GlovoActionKinds" the same predicate.
	glovoKindPrefix = "glovo."
)

// Stored states added by #989, Glovo rows only.
const (
	// ApprovalReserved: the dispatch bound this aar_ to one bridge command;
	// the permit has not been issued yet.
	ApprovalReserved = "reserved"
	// ApprovalUnknown: the command ended, or the provider reported unknown,
	// without a permit spending the approval. Final.
	ApprovalUnknown = "unknown"
)

// Policy identity of the owner approval (design section 3).
const (
	GlovoPolicyRuleID  = "glovo.order.owner-approval"
	GlovoPolicyVersion = "1"
	// GlovoRequester is the only requested_by of a Glovo approval.
	GlovoRequester = "service:glovo-prepare"
	// GlovoAuthorityBasis is what the decision of the order's owner records.
	GlovoAuthorityBasis = "resource_owner"
	// glovoIdempotencyPrefix scopes the global UNIQUE (requested_by,
	// idempotency_key) to one order.
	glovoIdempotencyPrefix = "glovo-prepare:"
)

// ReservePermitMargin is how long fresh_until must still hold at Reserve, so
// a dispatch that could not be permitted any more is refused while the aar_
// is still approved and nothing is burned (OPEN-989-7: 120s recommended).
const ReservePermitMargin = 120 * time.Second

// GlovoActionKinds is the exact list of Glovo kinds.
var GlovoActionKinds = []string{ActionKindGlovoPlaceOrderFake, ActionKindGlovoBasketApproval}

// glovoKindPredicate is the one SQL predicate for "this row is a Glovo
// approval". It is parenthesized, so it can be ANDed or negated as it stands.
const glovoKindPredicate = `(action_kind LIKE 'glovo.%')`

// GlovoKindPredicate is glovoKindPredicate for SQL outside this package (the
// receipt sweeper); there is one definition.
const GlovoKindPredicate = glovoKindPredicate

// IsGlovoKind reports whether kind is in the Glovo namespace. The prefix is the
// predicate on purpose: "glovo.other" is a Glovo kind the generic paths must
// refuse, not a generic kind that merely looks similar.
func IsGlovoKind(kind string) bool { return strings.HasPrefix(kind, glovoKindPrefix) }

// ErrApprovalKindNotSpendable: a generic spend or settle path met a Glovo row
// (409 approval_kind_not_spendable_here).
var ErrApprovalKindNotSpendable = errors.New("glovo action approvals are not spendable through the generic routes")

// ErrApprovalKindNotCreatable: the generic create route was given a Glovo kind
// (400 approval_kind_not_creatable_here).
var ErrApprovalKindNotCreatable = errors.New("glovo action approvals are not creatable through the generic route")

// GlovoBinding is one row of glovo.approval_bindings: what the owner's
// approval is bound to. Every field except CommandID is immutable once written.
type GlovoBinding struct {
	ApprovalID        string
	Tenant            string
	OwnerPrincipalID  string
	ExecutionID       string
	WorkItemID        string
	OrderRef          string
	ConnectionRef     string
	InstallID         string
	InstallRevision   string
	BasketFingerprint string
	Provider          string
	CommandID         string
	CreatedAt         time.Time
	// BasketID and BasketRevision are set only on the projection of a basket
	// approval binding (GlovoBasketBinding.AsGlovoBinding); an order binding
	// leaves them empty.
	BasketID       string
	BasketRevision int64
}

// glovoTarget is "glovo:v1:" plus the length-prefixed binding fields, so no
// two bindings share a target and the encoding is unambiguous for any bytes.
func glovoTarget(b GlovoBinding) string {
	var sb strings.Builder
	sb.WriteString("glovo:v1:")
	for _, f := range []string{b.Tenant, b.OwnerPrincipalID, b.OrderRef, b.ConnectionRef, b.InstallID, b.InstallRevision, b.Provider} {
		sb.WriteString(strconv.Itoa(len(f)))
		sb.WriteByte(':')
		sb.WriteString(f)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// GlovoIntent is what the owner approves: the length-prefixed binding as the
// target and the basket fingerprint as the args digest. ArtifactHash stays
// empty (the row's artifact_hash holds the same fingerprint for the decision
// binding gate, but IntentHash does not cover it, so it cannot drift from
// ArgsDigest on its own). The fence recomputes this from written content.
func GlovoIntent(b GlovoBinding) ActionIntent {
	return ActionIntent{
		ExecutionID:   b.ExecutionID,
		ActionKind:    ActionKindGlovoPlaceOrderFake,
		Target:        glovoTarget(b),
		ArgsDigest:    b.BasketFingerprint,
		PolicyRuleID:  GlovoPolicyRuleID,
		PolicyVersion: GlovoPolicyVersion,
		WorkItemID:    b.WorkItemID,
	}
}

// Exposed receipt vocabulary of a Glovo approval.
const (
	GlovoStatePending  = "pending"
	GlovoStateApproved = "approved"
	GlovoStateReserved = "reserved"
	GlovoStateConsumed = "consumed"
	GlovoStateUnknown  = "unknown"
	GlovoStateRefused  = "refused"
	GlovoStateExpired  = "expired"
)

// GlovoReceiptState maps a stored state to the exposed one. pending, approved
// and reserved read as expired past expires_at or past fresh_until; consumed,
// unknown and denied (exposed as refused) are final records and never read as
// expired. A reserved row past expiry can still move to unknown (forensics)
// but never to consumed: the fence refuses it.
func GlovoReceiptState(stored string, expiresAt time.Time, freshUntil *time.Time, now time.Time) string {
	switch stored {
	case ApprovalPending, ApprovalApproved, ApprovalReserved:
		if !expiresAt.After(now) || (freshUntil != nil && !freshUntil.After(now)) {
			return GlovoStateExpired
		}
		return stored
	case ApprovalDenied:
		return GlovoStateRefused
	case ApprovalConsumed:
		return GlovoStateConsumed
	case ApprovalUnknown:
		return GlovoStateUnknown
	}
	// Any other stored state on a Glovo row is outside the machine: say so
	// rather than guessing a benign one.
	return stored
}

func newUUID() string { return uuid.NewString() }
