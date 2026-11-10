package workitems

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
	"github.com/mctlhq/mctl-api/internal/glovo/orders"
)

// GlovoOrders is the #988 order store as CreateGlovoApprovalTx uses it: the
// write-once approval_ref of a finalized order.
type GlovoOrders interface {
	BindApproval(ctx context.Context, tx pgx.Tx, sc orders.Scope, a orders.Actor, orderRef, approvalRef string) error
}

// WithGlovoOrders gives the store the #988 collaborator. Without it every
// Glovo approval method that needs it answers not_ready.
func WithGlovoOrders(o GlovoOrders) StoreOption { return func(s *Store) { s.glovoOrders = o } }

var (
	glovoOrderRefRE      = regexp.MustCompile(`^ordr_[A-Za-z0-9]{16,40}$`)
	glovoConnectionRefRE = regexp.MustCompile(`^gcn_[A-Za-z0-9]{16,40}$`)
	glovoRevisionRE      = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
	glovoFingerprintRE   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	glovoCommandIDRE     = regexp.MustCompile(`^cmd_[A-Za-z0-9]{26}$`)
)

// ErrReserveIncomplete: a ReserveCommand field is empty. It is an
// intent_mismatch refusal, never a skipped comparison.
var ErrReserveIncomplete = glovo.Refuse(glovo.CodeIntentMismatch)

// ErrNotGlovoOwner: DecideGlovoApprovalTx was handed a decider that is not the
// order's owner, or an authority basis other than resource_owner. The HTTP
// layer answers it with its one uniform 403.
var ErrNotGlovoOwner = errors.New("the decider is not the bound owner of the glovo approval")

// GlovoApprovalInput creates the approval of one order. Every field is
// required.
type GlovoApprovalInput struct {
	Tenant, OwnerPrincipalID, WorkItemID, ExecutionID, OrderRef, ConnectionRef string
	InstallID, InstallRevision, BasketFingerprint, Provider                    string
	// ExpiresIn is chosen by #957 prepare (GlovoApprovalTTL):
	// 0 < ExpiresIn <= MaxApprovalTTL. The stored expires_at is
	// clock_timestamp() + ExpiresIn.
	ExpiresIn time.Duration
}

func (in GlovoApprovalInput) binding() GlovoBinding {
	return GlovoBinding{
		Tenant: in.Tenant, OwnerPrincipalID: in.OwnerPrincipalID, ExecutionID: in.ExecutionID,
		WorkItemID: in.WorkItemID, OrderRef: in.OrderRef, ConnectionRef: in.ConnectionRef,
		InstallID: in.InstallID, InstallRevision: in.InstallRevision, BasketFingerprint: in.BasketFingerprint,
		Provider: in.Provider,
	}
}

func (in GlovoApprovalInput) validate() error {
	if err := checkIdentity("tenant", in.Tenant); err != nil {
		return err
	}
	if len(in.OwnerPrincipalID) <= len("prn_") || in.OwnerPrincipalID[:4] != "prn_" {
		return invalid("owner_principal_id must be a prn_ id")
	}
	if err := checkIdentity("owner_principal_id", in.OwnerPrincipalID); err != nil {
		return err
	}
	for _, f := range []struct {
		name, value string
		re          *regexp.Regexp
	}{
		{"work_item_id", in.WorkItemID, glovoWorkItemIDRE},
		{"execution_id", in.ExecutionID, glovoExecutionRE},
		{"order_ref", in.OrderRef, glovoOrderRefRE},
		{"connection_ref", in.ConnectionRef, glovoConnectionRefRE},
		{"install_revision", in.InstallRevision, glovoRevisionRE},
		{"basket_fingerprint", in.BasketFingerprint, glovoFingerprintRE},
	} {
		if !f.re.MatchString(f.value) {
			return invalid("%s is malformed", f.name)
		}
	}
	if err := checkIdentity("install_id", in.InstallID); err != nil {
		return err
	}
	if err := checkIdentity("provider", in.Provider); err != nil {
		return err
	}
	if in.ExpiresIn <= 0 || in.ExpiresIn > MaxApprovalTTL {
		return invalid("expires_in must be positive and at most %s", MaxApprovalTTL)
	}
	return nil
}

// ReserveCommand binds an approved aar_ to one bridge command. Every field is
// required and must equal the binding.
type ReserveCommand struct {
	CommandID, Tenant, OwnerPrincipalID, ExecutionID, OrderRef, ConnectionRef string
	InstallRevision, IntentHash, BasketFingerprint                            string
}

// GlovoApprovalStatus is what the control reads return: ids and enums only.
type GlovoApprovalStatus struct {
	ApprovalRef string    `json:"approval_ref"`
	State       string    `json:"state"`
	ExpiresAt   time.Time `json:"expires_at"`
	OrderRef    string    `json:"order_ref"`
	CommandID   string    `json:"command_id,omitempty"`
}

const glovoBindingColumns = `approval_id, tenant, owner_principal_id, execution_id, work_item_id, order_ref,
	connection_ref, install_id, install_revision, basket_fingerprint, provider, command_id, created_at`

func scanGlovoBinding(row pgx.Row) (*GlovoBinding, error) {
	var b GlovoBinding
	if err := row.Scan(&b.ApprovalID, &b.Tenant, &b.OwnerPrincipalID, &b.ExecutionID, &b.WorkItemID, &b.OrderRef,
		&b.ConnectionRef, &b.InstallID, &b.InstallRevision, &b.BasketFingerprint, &b.Provider, &b.CommandID, &b.CreatedAt); err != nil {
		return nil, err
	}
	b.CreatedAt = b.CreatedAt.UTC()
	return &b, nil
}

func (s *Store) glovoReady() error {
	if s == nil || s.glovoOrders == nil {
		return glovo.Refuse(glovo.CodeNotReady)
	}
	return nil
}

// mapGlovoPgErr turns the database's refusal of a Glovo write into a typed
// refusal where one exists, and leaves any other error as an I/O failure.
func mapGlovoPgErr(op string, err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		switch pg.Code {
		case "23505":
			return glovo.Refuse(glovo.CodeApprovalReplayed)
		case "55P03":
			return glovo.Refuse(glovo.CodeTenantBusy)
		}
	}
	return fmt.Errorf("workitems: %s: %w", op, err)
}

// lockGlovoApproval reads the row and its binding FOR UPDATE of the aar_ (L4).
// The returned state is the stored one.
func lockGlovoApproval(ctx context.Context, q dbq.Querier, id string) (*ActionApprovalRequest, *GlovoBinding, error) {
	a, err := scanActionApproval(q.QueryRow(ctx, `SELECT `+actionApprovalColumns+`
		FROM public.action_approval_requests WHERE id=$1 AND `+glovoKindPredicate+` FOR UPDATE`, id), time.Time{})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, glovo.ErrNotFound
	}
	if err != nil {
		return nil, nil, mapGlovoPgErr("lock glovo approval", err)
	}
	b, err := scanGlovoBinding(q.QueryRow(ctx, `SELECT `+glovoBindingColumns+` FROM glovo.approval_bindings WHERE approval_id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, glovo.ErrNotFound
	}
	if err != nil {
		return nil, nil, mapGlovoPgErr("read glovo binding", err)
	}
	return a, b, nil
}

// LockGlovoApprovalTx is L4 of the lock order: the aar_ row FOR UPDATE, with
// its binding. The state is the stored one (never the derived "expired").
func (s *Store) LockGlovoApprovalTx(ctx context.Context, tx pgx.Tx, id string) (*ActionApprovalRequest, *GlovoBinding, error) {
	return lockGlovoApproval(ctx, tx, id)
}

// CreateGlovoApprovalTx stores the pending aar_ of one order, its binding and
// the order's approval_ref, on the caller's transaction (#957 prepare, which
// already holds L3 on the order). It is idempotent on "glovo-prepare:" +
// order_ref: the same intent returns the stored row (created=false), a
// different one is approval_replayed, as is a second aar_ for the order.
func (s *Store) CreateGlovoApprovalTx(ctx context.Context, tx pgx.Tx, in GlovoApprovalInput) (*ActionApprovalRequest, bool, error) {
	if err := s.glovoReady(); err != nil {
		return nil, false, err
	}
	if err := in.validate(); err != nil {
		return nil, false, err
	}
	b := in.binding()
	hash := IntentHash(GlovoIntent(b))
	// The execution must be the Glovo one of this tenant and owner.
	tenant, owner, workItem, _, err := s.ExecutionBindingTx(ctx, tx, in.ExecutionID)
	if errors.Is(err, ErrNotFound) {
		return nil, false, glovo.ErrNotFound
	}
	if err != nil {
		return nil, false, err
	}
	if tenant != in.Tenant || owner != in.OwnerPrincipalID || workItem != in.WorkItemID {
		return nil, false, glovo.Refuse(glovo.CodeIntentMismatch)
	}
	key := glovoIdempotencyPrefix + in.OrderRef
	existing, err := scanActionApproval(tx.QueryRow(ctx, `SELECT `+actionApprovalColumns+`
		FROM public.action_approval_requests WHERE requested_by=$1 AND idempotency_key=$2`, GlovoRequester, key), time.Time{})
	switch {
	case err == nil:
		if existing.IntentHash != hash {
			return nil, false, glovo.Refuse(glovo.CodeApprovalReplayed)
		}
		return existing, false, nil
	case !errors.Is(err, pgx.ErrNoRows):
		return nil, false, mapGlovoPgErr("find glovo approval", err)
	}
	id := ActionApprovalIDPrefix + strings.ReplaceAll(newUUID(), "-", "")
	a, err := scanActionApproval(tx.QueryRow(ctx, `INSERT INTO public.action_approval_requests (
			id, execution_id, action_kind, target, args_digest, policy_rule_id, policy_version,
			artifact_hash, work_item_id, idempotency_key, requested_by, intent_hash, state,
			expires_at, created_at, schema_version, requested_by_principal_id, via_principal_id,
			actor_kind, actor_name, subject_principal_id, subject_kind, agent_run_id,
			risk_level, side_effect, intent_source, policy_decision, policy_reasons)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'pending',
			clock_timestamp() + ($13::bigint * interval '1 microsecond'), clock_timestamp(), $14, '', '',
			'service', 'glovo-prepare', $15, 'human', '', 'high', 'write', $16, 'require_approval', $17)
		RETURNING `+actionApprovalColumns,
		id, in.ExecutionID, ActionKindGlovoPlaceOrderFake, glovoTarget(b), in.BasketFingerprint,
		GlovoPolicyRuleID, GlovoPolicyVersion, in.BasketFingerprint, in.WorkItemID, key, GlovoRequester, hash,
		in.ExpiresIn.Microseconds(), ActionApprovalSchemaVersion, in.OwnerPrincipalID,
		"execution:"+in.ExecutionID, []string{GlovoPolicyRuleID}), time.Time{})
	if err != nil {
		return nil, false, mapGlovoPgErr("insert glovo approval", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO glovo.approval_bindings (`+glovoBindingColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'',clock_timestamp())`,
		id, in.Tenant, in.OwnerPrincipalID, in.ExecutionID, in.WorkItemID, in.OrderRef, in.ConnectionRef,
		in.InstallID, in.InstallRevision, in.BasketFingerprint, in.Provider); err != nil {
		return nil, false, mapGlovoPgErr("insert glovo binding", err)
	}
	if err := s.glovoOrders.BindApproval(ctx, tx, orders.Scope{Tenant: in.Tenant, PrincipalID: in.OwnerPrincipalID},
		orders.Actor{Kind: orders.ActorSystem, ID: GlovoRequester}, in.OrderRef, id); err != nil {
		return nil, false, err
	}
	return a, true, nil
}

func (c ReserveCommand) complete() bool {
	for _, f := range []string{c.CommandID, c.Tenant, c.OwnerPrincipalID, c.ExecutionID, c.OrderRef,
		c.ConnectionRef, c.InstallRevision, c.IntentHash, c.BasketFingerprint} {
		if f == "" {
			return false
		}
	}
	return true
}

// ReserveGlovoApprovalTx binds an approved aar_ to one command (#985
// dispatch, under L3 and L4). Every ReserveCommand field is required and must
// equal the binding: a field that differs is intent_mismatch, the fingerprint
// is basket_changed. A row already reserved (or consumed) for the same
// command is replayed=true and nothing changes. Otherwise one CAS approved ->
// reserved, with expires_at in the future and fresh_until beyond
// ReservePermitMargin, plus the binding's command_id, on the caller's
// transaction. Any error leaves that transaction to be rolled back by the
// caller; nothing here begins, commits or savepoints one.
func (s *Store) ReserveGlovoApprovalTx(ctx context.Context, tx pgx.Tx, id string, cmd ReserveCommand) (bool, error) {
	if !cmd.complete() {
		return false, ErrReserveIncomplete
	}
	if !glovoCommandIDRE.MatchString(cmd.CommandID) {
		return false, glovo.Refuse(glovo.CodeInvalidRequest)
	}
	a, b, err := lockGlovoApproval(ctx, tx, id)
	if err != nil {
		return false, err
	}
	if cmd.Tenant != b.Tenant || cmd.OwnerPrincipalID != b.OwnerPrincipalID || cmd.ExecutionID != b.ExecutionID ||
		cmd.OrderRef != b.OrderRef || cmd.ConnectionRef != b.ConnectionRef || cmd.InstallRevision != b.InstallRevision {
		return false, glovo.Refuse(glovo.CodeIntentMismatch)
	}
	if cmd.BasketFingerprint != b.BasketFingerprint || cmd.BasketFingerprint != a.ArtifactHash {
		return false, glovo.Refuse(glovo.CodeBasketChanged)
	}
	if cmd.IntentHash != IntentHash(GlovoIntent(*b)) || cmd.IntentHash != a.IntentHash {
		return false, glovo.Refuse(glovo.CodeIntentMismatch)
	}
	switch a.State {
	case ApprovalApproved:
	case ApprovalReserved, ApprovalConsumed:
		if b.CommandID == cmd.CommandID {
			return true, nil
		}
		return false, glovo.Refuse(glovo.CodeApprovalReplayed)
	default:
		return false, glovo.Refuse(glovo.CodeApprovalInvalid)
	}
	if b.CommandID != "" && b.CommandID != cmd.CommandID {
		return false, glovo.Refuse(glovo.CodeApprovalReplayed)
	}
	var live bool
	if err := tx.QueryRow(ctx, `SELECT expires_at > clock_timestamp()
		   AND fresh_until IS NOT NULL AND fresh_until > clock_timestamp() + ($2::bigint * interval '1 microsecond')
		FROM public.action_approval_requests WHERE id=$1`, id, ReservePermitMargin.Microseconds()).Scan(&live); err != nil {
		return false, mapGlovoPgErr("check reserve window", err)
	}
	if !live {
		return false, glovo.Refuse(glovo.CodeApprovalExpired)
	}
	if b.CommandID == "" {
		tag, err := tx.Exec(ctx, `UPDATE glovo.approval_bindings SET command_id=$2 WHERE approval_id=$1 AND command_id=''`, id, cmd.CommandID)
		if err != nil {
			return false, mapGlovoPgErr("bind command", err)
		}
		if tag.RowsAffected() != 1 {
			return false, glovo.Refuse(glovo.CodeApprovalReplayed)
		}
	}
	tag, err := tx.Exec(ctx, `UPDATE public.action_approval_requests SET state='reserved', reserved_at=clock_timestamp()
		WHERE id=$1 AND state='approved' AND expires_at > clock_timestamp()
		  AND fresh_until > clock_timestamp() + ($2::bigint * interval '1 microsecond')`, id, ReservePermitMargin.Microseconds())
	if err != nil {
		return false, mapGlovoPgErr("reserve glovo approval", err)
	}
	if tag.RowsAffected() != 1 {
		return false, glovo.Refuse(glovo.CodeApprovalExpired)
	}
	return false, nil
}

// ConsumeGlovoApprovalTx spends a reserved aar_ for its command (the fence
// only): one CAS reserved -> consumed guarded by the bound command and by
// expires_at and fresh_until, by clock_timestamp() and not the transaction
// start. A reserved row past expiry is approval_expired and stays reserved
// for the sweeper.
func (s *Store) ConsumeGlovoApprovalTx(ctx context.Context, tx pgx.Tx, id, commandID string) error {
	a, b, err := lockGlovoApproval(ctx, tx, id)
	if err != nil {
		return err
	}
	if a.State != ApprovalReserved {
		if (a.State == ApprovalConsumed) && b.CommandID != commandID {
			return glovo.Refuse(glovo.CodeApprovalReplayed)
		}
		return glovo.Refuse(glovo.CodeApprovalInvalid)
	}
	if b.CommandID != commandID {
		return glovo.Refuse(glovo.CodeApprovalReplayed)
	}
	tag, err := tx.Exec(ctx, `UPDATE public.action_approval_requests SET state='consumed', consumed_at=clock_timestamp()
		WHERE id=$1 AND state='reserved' AND expires_at > clock_timestamp()
		  AND fresh_until IS NOT NULL AND fresh_until > clock_timestamp()`, id)
	if err != nil {
		return mapGlovoPgErr("consume glovo approval", err)
	}
	if tag.RowsAffected() != 1 {
		return glovo.Refuse(glovo.CodeApprovalExpired)
	}
	return nil
}

// RevokeGlovoApprovalTx is the cancel before dispatch: pending or approved ->
// denied (exposed as refused), recording the actor and the reason
// order_cancelled. A row already denied is success (idempotent retry); any
// other state is invalid_transition.
func (s *Store) RevokeGlovoApprovalTx(ctx context.Context, tx pgx.Tx, id, actor string) error {
	if err := checkIdentity("actor", actor); err != nil {
		return err
	}
	a, _, err := lockGlovoApproval(ctx, tx, id)
	if err != nil {
		return err
	}
	switch a.State {
	case ApprovalDenied:
		return nil
	case ApprovalPending, ApprovalApproved:
	default:
		return glovo.Refuse(glovo.CodeInvalidTransition)
	}
	tag, err := tx.Exec(ctx, `UPDATE public.action_approval_requests
		SET state='denied', decided_by=$2, decided_at=clock_timestamp(), reason='order_cancelled'
		WHERE id=$1 AND state IN ('pending','approved')`, id, actor)
	if err != nil {
		return mapGlovoPgErr("revoke glovo approval", err)
	}
	if tag.RowsAffected() != 1 {
		return glovo.Refuse(glovo.CodeInvalidTransition)
	}
	return nil
}

// MarkGlovoApprovalUnknownTx records that the bound command ended without a
// permit: reserved for commandID -> unknown, allowed past expiry. It is a
// no-op returning nil, with no write, when the aar_ is in any other state
// (already unknown, consumed because a permit existed, ...): it never fails
// the transaction in which an order moves. A commandID that is not the one
// bound to the row is ErrNotFound.
func (s *Store) MarkGlovoApprovalUnknownTx(ctx context.Context, tx pgx.Tx, id, commandID string) error {
	a, b, err := lockGlovoApproval(ctx, tx, id)
	if err != nil {
		return err
	}
	if b.CommandID == "" || b.CommandID != commandID {
		return glovo.ErrNotFound
	}
	if a.State != ApprovalReserved {
		return nil
	}
	if _, err := tx.Exec(ctx, `UPDATE public.action_approval_requests SET state='unknown'
		WHERE id=$1 AND state='reserved'`, id); err != nil {
		return mapGlovoPgErr("mark glovo approval unknown", err)
	}
	return nil
}

// DecideGlovoApprovalTx is the owner's decision (design section 5): the aar_
// row only, FOR UPDATE under L4, no order row. The decider must be the bound
// owner under authority_basis resource_owner, else ErrNotGlovoOwner. An
// approval is spendable for FreshFor (never past expires_at; none means
// until expires_at). Past expiry is ErrApprovalExpired, a decided row
// ErrApprovalAlreadyDecided, a missing or non-Glovo row ErrApprovalNotFound.
func (s *Store) DecideGlovoApprovalTx(ctx context.Context, tx pgx.Tx, in ActionDecisionInput) (*ActionApprovalRequest, error) {
	if err := ValidateDecisionInput(in.Decision, in.Reason); err != nil {
		return nil, err
	}
	if err := checkText("decided_by", in.DecidedBy, MaxExternalIDBytes, true); err != nil {
		return nil, err
	}
	a, b, err := lockGlovoApproval(ctx, tx, in.ID)
	if errors.Is(err, glovo.ErrNotFound) {
		return nil, fmt.Errorf("%w: %s", ErrApprovalNotFound, in.ID)
	}
	if err != nil {
		return nil, err
	}
	if in.DecidedByPrincipalID == "" || in.DecidedByPrincipalID != b.OwnerPrincipalID || in.AuthorityBasis != GlovoAuthorityBasis {
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
		WHERE id=$1 AND state='pending' AND expires_at > clock_timestamp()
		RETURNING `+actionApprovalColumns,
		a.ID, to, in.DecidedBy, in.Reason, in.DecidedByPrincipalID, in.DecidedViaPrincipalID,
		in.ContextDigest, in.AuthorityBasis, in.AuthzMode, fresh), time.Time{})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrApprovalExpired, a.ID)
	}
	if err != nil {
		return nil, mapGlovoPgErr("decide glovo approval", err)
	}
	return out, nil
}

// GlovoApprovalStatus is a read on the caller's Querier (the Glovo pool as
// glovo_runtime, or the caller's tx), never the work-items pool, which has no
// privilege in schema glovo. It returns ids and enums only; a missing,
// non-Glovo or foreign-tenant approval is one glovo.ErrNotFound.
func (s *Store) GlovoApprovalStatus(ctx context.Context, q dbq.Querier, tenants []string, id string) (*GlovoApprovalStatus, error) {
	var (
		st      GlovoApprovalStatus
		stored  string
		fresh   *time.Time
		now     time.Time
		expires time.Time
	)
	err := q.QueryRow(ctx, `SELECT a.id, a.state, a.expires_at, a.fresh_until, b.order_ref, b.command_id, clock_timestamp()
		FROM public.action_approval_requests a JOIN glovo.approval_bindings b ON b.approval_id = a.id
		WHERE a.id=$1 AND `+strings.ReplaceAll(glovoKindPredicate, "action_kind", "a.action_kind")+` AND b.tenant = ANY($2)`, id, tenants).
		Scan(&st.ApprovalRef, &stored, &expires, &fresh, &st.OrderRef, &st.CommandID, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, glovo.ErrNotFound
	}
	if err != nil {
		return nil, mapGlovoPgErr("read glovo approval status", err)
	}
	st.ExpiresAt = expires.UTC()
	st.State = GlovoReceiptState(stored, expires, fresh, now)
	return &st, nil
}

// GlovoApprovalForDecision is the Glovo-kind pre-read of the decision route
// and of canSeeActionApproval: the aar_ with its effective state and the
// binding, on the caller's Querier (the Glovo pool). A missing or non-Glovo
// id is ErrApprovalNotFound. It takes no lock; DecideGlovoApprovalTx re-checks
// under L4.
func (s *Store) GlovoApprovalForDecision(ctx context.Context, q dbq.Querier, id string) (*ActionApprovalRequest, *GlovoBinding, error) {
	a, err := scanActionApproval(q.QueryRow(ctx, `SELECT `+actionApprovalColumns+`
		FROM public.action_approval_requests WHERE id=$1 AND `+glovoKindPredicate, id), s.now())
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, fmt.Errorf("%w: %s", ErrApprovalNotFound, id)
	}
	if err != nil {
		return nil, nil, mapGlovoPgErr("pre-read glovo approval", err)
	}
	b, err := scanGlovoBinding(q.QueryRow(ctx, `SELECT `+glovoBindingColumns+` FROM glovo.approval_bindings WHERE approval_id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, fmt.Errorf("%w: %s", ErrApprovalNotFound, id)
	}
	if err != nil {
		return nil, nil, mapGlovoPgErr("pre-read glovo binding", err)
	}
	return a, b, nil
}
