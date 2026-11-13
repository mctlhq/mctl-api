package workitems

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
)

// Glovo basket approvals (mctl-api#1006).
//
// A basket approval is an ordinary action_approval_requests row (aar_) of
// kind glovo.basket_approval, bound by one row of
// glovo.basket_approval_bindings to exactly one frozen revision of one
// synthetic basket: tenant, owner, basket id, revision and the basket
// fingerprint. It needs no work item, execution, order, connection or
// Temporal workflow: the aar_ table has no foreign key to any of them, and
// execution_id holds the basket id (the database checks it against the
// binding). Its only transitions are pending -> approved | denied, decided by
// the bound owner through the existing POST /api/v1/action-approvals/{id}/decision
// route. Nothing spends it: the generic consume, reserve and settle paths
// refuse every glovo.* kind, and the database refuses any transition out of
// a decided basket approval.

// Policy identity of the basket owner approval.
const (
	GlovoBasketPolicyRuleID  = "glovo.basket.owner-approval"
	GlovoBasketPolicyVersion = "1"
	// GlovoBasketRequester is the only requested_by of a basket approval.
	GlovoBasketRequester = "service:glovo-basket"
	// glovoBasketIdempotencyPrefix scopes the global UNIQUE (requested_by,
	// idempotency_key) to one basket revision.
	glovoBasketIdempotencyPrefix = "glovo-basket:"
)

// GlovoBasketIDRE is the shape of a basket id.
var GlovoBasketIDRE = regexp.MustCompile(`^gbk_[A-Za-z0-9]{26}$`)

// GlovoBasketBinding is one row of glovo.basket_approval_bindings. Every
// field is immutable once written.
type GlovoBasketBinding struct {
	ApprovalID        string
	Tenant            string
	OwnerPrincipalID  string
	BasketID          string
	Revision          int64
	BasketFingerprint string
	CreatedAt         time.Time
}

// AsGlovoBinding projects the basket binding onto the GlovoBinding shape the
// decision route reads (owner, tenant, fingerprint). The order fields stay
// empty: there is no order.
func (b *GlovoBasketBinding) AsGlovoBinding() *GlovoBinding {
	if b == nil {
		return nil
	}
	return &GlovoBinding{
		ApprovalID: b.ApprovalID, Tenant: b.Tenant, OwnerPrincipalID: b.OwnerPrincipalID,
		ExecutionID: b.BasketID, BasketFingerprint: b.BasketFingerprint, CreatedAt: b.CreatedAt,
		BasketID: b.BasketID, BasketRevision: b.Revision,
	}
}

// GlovoBasketApprovalInput creates the approval of one frozen basket
// revision. Every field is required.
type GlovoBasketApprovalInput struct {
	Tenant, OwnerPrincipalID, BasketID, BasketFingerprint string
	Revision                                              int64
	// ExpiresIn: 0 < ExpiresIn <= MaxApprovalTTL; the stored expires_at is
	// clock_timestamp() + ExpiresIn.
	ExpiresIn time.Duration
}

func (in GlovoBasketApprovalInput) validate() error {
	if err := checkIdentity("tenant", in.Tenant); err != nil {
		return err
	}
	if len(in.OwnerPrincipalID) <= len("prn_") || in.OwnerPrincipalID[:4] != "prn_" {
		return invalid("owner_principal_id must be a prn_ id")
	}
	if err := checkIdentity("owner_principal_id", in.OwnerPrincipalID); err != nil {
		return err
	}
	if !GlovoBasketIDRE.MatchString(in.BasketID) {
		return invalid("basket_id is malformed")
	}
	if in.Revision < 1 {
		return invalid("revision must be positive")
	}
	if !glovoFingerprintRE.MatchString(in.BasketFingerprint) {
		return invalid("basket_fingerprint is malformed")
	}
	if in.ExpiresIn <= 0 || in.ExpiresIn > MaxApprovalTTL {
		return invalid("expires_in must be positive and at most %s", MaxApprovalTTL)
	}
	return nil
}

func (in GlovoBasketApprovalInput) binding() GlovoBasketBinding {
	return GlovoBasketBinding{Tenant: in.Tenant, OwnerPrincipalID: in.OwnerPrincipalID, BasketID: in.BasketID,
		Revision: in.Revision, BasketFingerprint: in.BasketFingerprint}
}

// glovoBasketTarget is "glovo-basket:v1:" plus the length-prefixed binding
// fields, so no two revisions share a target.
func glovoBasketTarget(b GlovoBasketBinding) string {
	var sb strings.Builder
	sb.WriteString("glovo-basket:v1:")
	for _, f := range []string{b.Tenant, b.OwnerPrincipalID, b.BasketID, strconv.FormatInt(b.Revision, 10)} {
		sb.WriteString(strconv.Itoa(len(f)))
		sb.WriteByte(':')
		sb.WriteString(f)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// GlovoBasketIntent is what the owner approves: the length-prefixed binding
// as the target and the basket fingerprint as the args digest.
func GlovoBasketIntent(b GlovoBasketBinding) ActionIntent {
	return ActionIntent{
		ExecutionID:   b.BasketID,
		ActionKind:    ActionKindGlovoBasketApproval,
		Target:        glovoBasketTarget(b),
		ArgsDigest:    b.BasketFingerprint,
		PolicyRuleID:  GlovoBasketPolicyRuleID,
		PolicyVersion: GlovoBasketPolicyVersion,
	}
}

const glovoBasketBindingColumns = `approval_id, tenant, owner_principal_id, basket_id, revision, basket_fingerprint, created_at`

func scanGlovoBasketBinding(row pgx.Row) (*GlovoBasketBinding, error) {
	var b GlovoBasketBinding
	if err := row.Scan(&b.ApprovalID, &b.Tenant, &b.OwnerPrincipalID, &b.BasketID, &b.Revision, &b.BasketFingerprint, &b.CreatedAt); err != nil {
		return nil, err
	}
	b.CreatedAt = b.CreatedAt.UTC()
	return &b, nil
}

// readGlovoBasketApproval reads the basket aar_ and its binding, FOR UPDATE
// of the aar_ when lock is set. A missing row, another kind or a missing
// binding is glovo.ErrNotFound; any other failure is an error, never "not
// found".
func readGlovoBasketApproval(ctx context.Context, q dbq.Querier, id string, lock bool, now time.Time) (*ActionApprovalRequest, *GlovoBasketBinding, error) {
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	a, err := scanActionApproval(q.QueryRow(ctx, `SELECT `+actionApprovalColumns+`
		FROM public.action_approval_requests WHERE id=$1 AND action_kind=$2`+suffix, id, ActionKindGlovoBasketApproval), now)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, glovo.ErrNotFound
	}
	if err != nil {
		return nil, nil, mapGlovoPgErr("read glovo basket approval", err)
	}
	b, err := scanGlovoBasketBinding(q.QueryRow(ctx, `SELECT `+glovoBasketBindingColumns+`
		FROM glovo.basket_approval_bindings WHERE approval_id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, glovo.ErrNotFound
	}
	if err != nil {
		return nil, nil, mapGlovoPgErr("read glovo basket binding", err)
	}
	return a, b, nil
}

// CreateGlovoBasketApprovalTx stores the pending aar_ of one frozen basket
// revision and its binding, on the caller's transaction (the basket store,
// which already holds the basket row lock). It is idempotent on
// "glovo-basket:" + basket id + "@" + revision: the same intent returns the
// stored row (created=false), a different one is approval_replayed. It
// writes no order, command, control start or work item.
func CreateGlovoBasketApprovalTx(ctx context.Context, tx pgx.Tx, in GlovoBasketApprovalInput) (*ActionApprovalRequest, bool, error) {
	if err := in.validate(); err != nil {
		return nil, false, err
	}
	b := in.binding()
	hash := IntentHash(GlovoBasketIntent(b))
	key := glovoBasketIdempotencyPrefix + in.BasketID + "@" + strconv.FormatInt(in.Revision, 10)
	existing, err := scanActionApproval(tx.QueryRow(ctx, `SELECT `+actionApprovalColumns+`
		FROM public.action_approval_requests WHERE requested_by=$1 AND idempotency_key=$2`, GlovoBasketRequester, key), time.Time{})
	switch {
	case err == nil:
		if existing.IntentHash != hash {
			return nil, false, glovo.Refuse(glovo.CodeApprovalReplayed)
		}
		return existing, false, nil
	case !errors.Is(err, pgx.ErrNoRows):
		return nil, false, mapGlovoPgErr("find glovo basket approval", err)
	}
	id := ActionApprovalIDPrefix + strings.ReplaceAll(newUUID(), "-", "")
	a, err := scanActionApproval(tx.QueryRow(ctx, `INSERT INTO public.action_approval_requests (
			id, execution_id, action_kind, target, args_digest, policy_rule_id, policy_version,
			artifact_hash, work_item_id, idempotency_key, requested_by, intent_hash, state,
			expires_at, created_at, schema_version, requested_by_principal_id, via_principal_id,
			actor_kind, actor_name, subject_principal_id, subject_kind, agent_run_id,
			risk_level, side_effect, intent_source, policy_decision, policy_reasons)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'',$9,$10,$11,'pending',
			clock_timestamp() + ($12::bigint * interval '1 microsecond'), clock_timestamp(), $13, '', '',
			'service', 'glovo-basket', $14, 'human', '', 'medium', 'none', $15, 'require_approval', $16)
		RETURNING `+actionApprovalColumns,
		id, in.BasketID, ActionKindGlovoBasketApproval, glovoBasketTarget(b), in.BasketFingerprint,
		GlovoBasketPolicyRuleID, GlovoBasketPolicyVersion, in.BasketFingerprint, key, GlovoBasketRequester, hash,
		in.ExpiresIn.Microseconds(), ActionApprovalSchemaVersion, in.OwnerPrincipalID,
		"basket:"+in.BasketID+"@"+strconv.FormatInt(in.Revision, 10), []string{GlovoBasketPolicyRuleID}), time.Time{})
	if err != nil {
		return nil, false, mapGlovoPgErr("insert glovo basket approval", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO glovo.basket_approval_bindings (`+glovoBasketBindingColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,clock_timestamp())`,
		id, in.Tenant, in.OwnerPrincipalID, in.BasketID, in.Revision, in.BasketFingerprint); err != nil {
		return nil, false, mapGlovoPgErr("insert glovo basket binding", err)
	}
	return a, true, nil
}

// GlovoBasketApprovalForDecision is the pre-read of the decision route and
// of the owner read: the aar_ with its effective state and its binding, on
// the caller's Querier (the Glovo pool). A missing or non-basket id is
// ErrApprovalNotFound. It takes no lock; DecideGlovoBasketApprovalTx
// re-checks under the row lock.
func GlovoBasketApprovalForDecision(ctx context.Context, q dbq.Querier, id string, now time.Time) (*ActionApprovalRequest, *GlovoBasketBinding, error) {
	a, b, err := readGlovoBasketApproval(ctx, q, id, false, now)
	if errors.Is(err, glovo.ErrNotFound) {
		return nil, nil, fmt.Errorf("%w: %s", ErrApprovalNotFound, id)
	}
	return a, b, err
}

// DecideGlovoBasketApprovalTx is the basket owner's decision: the aar_ row
// FOR UPDATE, nothing else. The decider must be the bound owner under
// authority_basis resource_owner (an approve) or the bound owner (a deny),
// else ErrNotGlovoOwner. Past expiry is ErrApprovalExpired, a decided row
// ErrApprovalAlreadyDecided, a missing or non-basket row ErrApprovalNotFound.
func DecideGlovoBasketApprovalTx(ctx context.Context, tx pgx.Tx, in ActionDecisionInput) (*ActionApprovalRequest, error) {
	if err := ValidateDecisionInput(in.Decision, in.Reason); err != nil {
		return nil, err
	}
	if err := checkText("decided_by", in.DecidedBy, MaxExternalIDBytes, true); err != nil {
		return nil, err
	}
	a, b, err := readGlovoBasketApproval(ctx, tx, in.ID, true, time.Time{})
	if errors.Is(err, glovo.ErrNotFound) {
		return nil, fmt.Errorf("%w: %s", ErrApprovalNotFound, in.ID)
	}
	if err != nil {
		return nil, err
	}
	if in.DecidedByPrincipalID == "" || in.DecidedByPrincipalID != b.OwnerPrincipalID {
		return nil, ErrNotGlovoOwner
	}
	if in.Decision == DecisionApprove && in.AuthorityBasis != GlovoAuthorityBasis {
		return nil, ErrNotGlovoOwner
	}
	if a.State != ApprovalPending {
		return nil, fmt.Errorf("%w: %s is %s", ErrApprovalAlreadyDecided, a.ID, a.State)
	}
	to := ApprovalDenied
	if in.Decision == DecisionApprove {
		to = ApprovalApproved
	}
	var fresh *int64
	if to == ApprovalApproved && in.FreshFor > 0 {
		us := in.FreshFor.Microseconds()
		fresh = &us
	}
	out, err := scanActionApproval(tx.QueryRow(ctx, `UPDATE public.action_approval_requests
		SET state=$2, decided_by=$3, decided_at=clock_timestamp(), reason=$4,
		    decided_by_principal_id=$5, decided_via_principal_id=$6,
		    decided_context_digest=$7, authority_basis=$8, authz_mode=$9,
		    fresh_until = CASE WHEN $2 = 'approved' THEN
		        LEAST(expires_at, CASE WHEN $10::bigint IS NULL THEN expires_at
		                               ELSE clock_timestamp() + ($10::bigint * interval '1 microsecond') END)
		        ELSE NULL END
		WHERE id=$1 AND action_kind=$11 AND state='pending' AND expires_at > clock_timestamp()
		RETURNING `+actionApprovalColumns,
		a.ID, to, in.DecidedBy, in.Reason, in.DecidedByPrincipalID, in.DecidedViaPrincipalID,
		in.ContextDigest, in.AuthorityBasis, in.AuthzMode, fresh, ActionKindGlovoBasketApproval), time.Time{})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrApprovalExpired, a.ID)
	}
	if err != nil {
		return nil, mapGlovoPgErr("decide glovo basket approval", err)
	}
	return out, nil
}

// Exposed states of a basket approval.
const (
	GlovoBasketStatePending  = "pending"
	GlovoBasketStateApproved = "approved"
	GlovoBasketStateRejected = "rejected"
	GlovoBasketStateExpired  = "expired"
)

// GlovoBasketReceiptState maps a stored state to the exposed one. A pending
// row past expires_at, or an approved one past expires_at or fresh_until,
// reads as expired; denied reads as rejected. Any other stored state is
// outside the basket machine and is returned as it is, never as a benign one.
func GlovoBasketReceiptState(stored string, expiresAt time.Time, freshUntil *time.Time, now time.Time) string {
	switch stored {
	case ApprovalPending:
		if !expiresAt.After(now) {
			return GlovoBasketStateExpired
		}
		return GlovoBasketStatePending
	case ApprovalApproved:
		if !expiresAt.After(now) || (freshUntil != nil && !freshUntil.After(now)) {
			return GlovoBasketStateExpired
		}
		return GlovoBasketStateApproved
	case ApprovalDenied:
		return GlovoBasketStateRejected
	}
	return stored
}

// GlovoBasketApprovalStatus is what glovo_approval_status returns: ids and
// enums only.
type GlovoBasketApprovalStatus struct {
	ApprovalRef       string     `json:"approval_ref"`
	State             string     `json:"state"`
	BasketID          string     `json:"basket_id"`
	Revision          int64      `json:"revision"`
	BasketFingerprint string     `json:"basket_fingerprint"`
	ExpiresAt         time.Time  `json:"expires_at"`
	DecidedAt         *time.Time `json:"decided_at,omitempty"`
}

// ReadGlovoBasketApprovalStatus reads one basket approval of (tenant, owner)
// on the caller's Querier. A missing id, another kind, another tenant and
// another owner are one glovo.ErrNotFound, so the answer is no existence
// oracle; a failed read is an error.
func ReadGlovoBasketApprovalStatus(ctx context.Context, q dbq.Querier, tenant, owner, id string) (*GlovoBasketApprovalStatus, error) {
	var (
		st      GlovoBasketApprovalStatus
		stored  string
		fresh   *time.Time
		decided *time.Time
		expires time.Time
		now     time.Time
	)
	err := q.QueryRow(ctx, `SELECT a.id, a.state, a.expires_at, a.fresh_until, a.decided_at,
			b.basket_id, b.revision, b.basket_fingerprint, clock_timestamp()
		FROM public.action_approval_requests a JOIN glovo.basket_approval_bindings b ON b.approval_id = a.id
		WHERE a.id=$1 AND a.action_kind=$2 AND b.tenant=$3 AND b.owner_principal_id=$4`,
		id, ActionKindGlovoBasketApproval, tenant, owner).
		Scan(&st.ApprovalRef, &stored, &expires, &fresh, &decided, &st.BasketID, &st.Revision, &st.BasketFingerprint, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, glovo.ErrNotFound
	}
	if err != nil {
		return nil, mapGlovoPgErr("read glovo basket approval status", err)
	}
	st.ExpiresAt = expires.UTC()
	if decided != nil {
		d := decided.UTC()
		st.DecidedAt = &d
	}
	st.State = GlovoBasketReceiptState(stored, expires, fresh, now)
	return &st, nil
}

// GlovoBasketDecisions is the ledger side of an owner decision on a basket
// approval, for the decision route (api.GlovoApprovalDecisions). It reads
// and writes on the Glovo pool only: the binding lives in schema glovo.
type GlovoBasketDecisions struct {
	// Reader is the Glovo pool (glovo_runtime).
	Reader dbq.Querier
	// Begin opens a transaction of the Glovo pool.
	Begin func(ctx context.Context) (pgx.Tx, error)
	// ReadyFn is the basket MCP's own readiness (enabled, schema verified).
	ReadyFn func(ctx context.Context) error
	// Now is the clock of the pre-read; nil is time.Now.
	Now func() time.Time
}

func (d *GlovoBasketDecisions) complete() bool {
	return d != nil && !glovo.IsNil(d.Reader) && d.Begin != nil && d.ReadyFn != nil
}

// Ready is nil only when every dependency is wired and ReadyFn passes.
func (d *GlovoBasketDecisions) Ready(ctx context.Context) error {
	if !d.complete() {
		return glovo.Refuse(glovo.CodeNotReady)
	}
	return d.ReadyFn(ctx)
}

// ForDecision is GlovoBasketApprovalForDecision with the binding projected
// onto the GlovoBinding shape the decision route reads.
func (d *GlovoBasketDecisions) ForDecision(ctx context.Context, id string) (*ActionApprovalRequest, *GlovoBinding, error) {
	if !d.complete() {
		return nil, nil, glovo.Refuse(glovo.CodeNotReady)
	}
	now := time.Now()
	if d.Now != nil {
		now = d.Now()
	}
	a, b, err := GlovoBasketApprovalForDecision(ctx, d.Reader, id, now)
	if err != nil {
		return nil, nil, err
	}
	return a, b.AsGlovoBinding(), nil
}

// Decide runs DecideGlovoBasketApprovalTx in its own transaction.
func (d *GlovoBasketDecisions) Decide(ctx context.Context, in ActionDecisionInput) (*ActionApprovalRequest, error) {
	if !d.complete() {
		return nil, glovo.Refuse(glovo.CodeNotReady)
	}
	tx, err := d.Begin(ctx)
	if err != nil {
		return nil, mapGlovoPgErr("begin glovo basket decision", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	a, err := DecideGlovoBasketApprovalTx(ctx, tx, in)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapGlovoPgErr("commit glovo basket decision", err)
	}
	return a, nil
}
