package workitems

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Action approval requests (mctl-api#366).
//
// An ActionApprovalRequest authorizes ONE concrete, hashed side effect of one
// runtime execution (mctl-agents#197/#198). It is a sibling of the
// work-item approval (#353), not a variant of it: an execution may hold many
// at once, and each is single use.
//
//   - Immutable once created apart from its state transitions:
//     pending -> approved | denied, approved -> consumed. `expired` is never
//     stored: a pending or approved request past expires_at reads as expired
//     (lazy expiry), and a decision or consume on it is refused.
//   - intent_hash binds the action: the server computes it from the bound
//     fields (IntentHash) and a client-sent value must match.
//   - Idempotent per (requested_by, idempotency_key): the same key with the
//     same intent is the stored request, a different intent is
//     ErrApprovalIdempotencyConflict.
//   - Consume is one compare-and-set UPDATE, approved -> consumed, guarded by
//     the state, the intent hash and the expiry together, so a receipt can
//     authorize exactly one side effect however many callers race.
//
// Who may create, decide, consume or read is decided by the HTTP layer from
// authentication; the store records the principals it is handed and refuses
// only what it can check itself (a requester deciding its own request).

// ActionApprovalIDPrefix labels action approval ids.
const ActionApprovalIDPrefix = "aar_"

// ActionApprovalSchemaVersion labels every action approval payload.
const ActionApprovalSchemaVersion = "actionapproval/v1"

// intentEncodingVersion opens the canonical intent encoding, so a future
// encoding can never hash equal to this one.
const intentEncodingVersion = "mctl-action-intent/v1"

// Action approval states. ApprovalExpired is read-only: derived, never stored.
const (
	ApprovalPending  = "pending"
	ApprovalApproved = "approved"
	ApprovalDenied   = "denied"
	ApprovalConsumed = "consumed"
	ApprovalExpired  = "expired"
)

// Decisions accepted by DecideActionApproval.
const (
	DecisionApprove = "approve"
	DecisionDeny    = "deny"
)

// Bounds.
const (
	MaxApprovalFieldBytes  = 512
	MaxApprovalTargetBytes = 2048
	MaxApprovalReasonBytes = 1024
	// MaxApprovalTTL caps how far ahead a request may expire.
	MaxApprovalTTL = 7 * 24 * time.Hour
	// MaxApprovalList bounds one listing.
	MaxApprovalList     = 500
	defaultApprovalList = 100
)

var (
	// ErrApprovalNotFound: no such action approval request.
	ErrApprovalNotFound = errors.New("action approval request not found")
	// ErrApprovalIdempotencyConflict: the key already names a request with a
	// different intent.
	ErrApprovalIdempotencyConflict = errors.New("idempotency key already names a request with a different intent")
	// ErrApprovalIntentHash: a client-sent intent_hash is not the hash of
	// the fields it came with.
	ErrApprovalIntentHash = errors.New("intent_hash does not match the request fields")
	// ErrApprovalAlreadyDecided: a decision on a request that is no longer
	// pending.
	ErrApprovalAlreadyDecided = errors.New("action approval request is already decided")
	// ErrApprovalSelfDecision: the requester tried to decide its own request.
	ErrApprovalSelfDecision = errors.New("the requester cannot decide its own action approval request")
	// Consume refusals, one per reason.
	ErrApprovalNotApproved    = errors.New("action approval request is not approved")
	ErrApprovalDenied         = errors.New("action approval request was denied")
	ErrApprovalExpired        = errors.New("action approval request has expired")
	ErrApprovalIntentMismatch = errors.New("presented intent_hash does not match the approved intent")
	ErrApprovalConsumed       = errors.New("action approval request was already consumed")
)

const actionApprovalSchema = `
CREATE TABLE IF NOT EXISTS action_approval_requests (
    id              TEXT PRIMARY KEY,
    execution_id    TEXT NOT NULL,
    action_kind     TEXT NOT NULL,
    target          TEXT NOT NULL,
    args_digest     TEXT NOT NULL,
    policy_rule_id  TEXT NOT NULL,
    policy_version  TEXT NOT NULL,
    artifact_hash   TEXT NOT NULL DEFAULT '',
    work_item_id    TEXT NOT NULL DEFAULT '',
    idempotency_key TEXT NOT NULL,
    requested_by    TEXT NOT NULL,
    intent_hash     TEXT NOT NULL,
    state           TEXT NOT NULL CHECK (state IN ('pending', 'approved', 'denied', 'consumed')),
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    decided_by      TEXT NOT NULL DEFAULT '',
    decided_at      TIMESTAMPTZ,
    reason          TEXT NOT NULL DEFAULT '',
    consumed_at     TIMESTAMPTZ,
    schema_version  TEXT NOT NULL,
    UNIQUE (requested_by, idempotency_key)
);
CREATE INDEX IF NOT EXISTS action_approval_requests_execution
    ON action_approval_requests (execution_id, created_at DESC);
CREATE INDEX IF NOT EXISTS action_approval_requests_state
    ON action_approval_requests (state, created_at DESC);
-- Canonical principal ids (mctl-api#373), dual-written next to the strings.
ALTER TABLE action_approval_requests ADD COLUMN IF NOT EXISTS requested_by_principal_id TEXT NOT NULL DEFAULT '';
ALTER TABLE action_approval_requests ADD COLUMN IF NOT EXISTS via_principal_id TEXT NOT NULL DEFAULT '';
ALTER TABLE action_approval_requests ADD COLUMN IF NOT EXISTS decided_by_principal_id TEXT NOT NULL DEFAULT '';
ALTER TABLE action_approval_requests ADD COLUMN IF NOT EXISTS decided_via_principal_id TEXT NOT NULL DEFAULT '';
`

const actionApprovalColumns = `id, execution_id, action_kind, target, args_digest, policy_rule_id,
	policy_version, artifact_hash, work_item_id, idempotency_key, requested_by, intent_hash, state,
	expires_at, created_at, decided_by, decided_at, reason, consumed_at, schema_version`

// ActionApprovalRequest is one durable approval of one hashed side effect.
// State is the effective state: `expired` for a pending or approved request
// past ExpiresAt.
type ActionApprovalRequest struct {
	ID             string     `json:"id"`
	ExecutionID    string     `json:"execution_id"`
	ActionKind     string     `json:"action_kind"`
	Target         string     `json:"target"`
	ArgsDigest     string     `json:"args_digest"`
	PolicyRuleID   string     `json:"policy_rule_id"`
	PolicyVersion  string     `json:"policy_version"`
	ArtifactHash   string     `json:"artifact_hash,omitempty"`
	WorkItemID     string     `json:"work_item_id,omitempty"`
	IdempotencyKey string     `json:"idempotency_key"`
	RequestedBy    string     `json:"requested_by"`
	IntentHash     string     `json:"intent_hash"`
	State          string     `json:"state"`
	ExpiresAt      time.Time  `json:"expires_at"`
	CreatedAt      time.Time  `json:"created_at"`
	DecidedBy      string     `json:"decided_by,omitempty"`
	DecidedAt      *time.Time `json:"decided_at,omitempty"`
	Reason         string     `json:"reason,omitempty"`
	ConsumedAt     *time.Time `json:"consumed_at,omitempty"`
	SchemaVersion  string     `json:"schema_version"`
}

// ActionIntent is what an approval binds: the fields intent_hash covers.
type ActionIntent struct {
	ExecutionID   string
	ActionKind    string
	Target        string
	ArgsDigest    string
	PolicyRuleID  string
	PolicyVersion string
	ArtifactHash  string
	WorkItemID    string
}

// IntentHash is sha256 over the canonical encoding of the intent:
//
//	mctl-action-intent/v1\n
//	<field>:<byte length>:<value>\n   (once per field, in this order)
//
// execution_id, action_kind, target, args_digest, policy_rule_id,
// policy_version, artifact_hash, work_item_id; an absent optional field is
// the empty string. The length prefix makes the encoding unambiguous for any
// bytes, and no JSON escaping is involved, so any client reproduces it. The
// result is "sha256:<hex>".
func IntentHash(in ActionIntent) string {
	var b strings.Builder
	b.WriteString(intentEncodingVersion)
	b.WriteByte('\n')
	for _, f := range [][2]string{
		{"execution_id", in.ExecutionID},
		{"action_kind", in.ActionKind},
		{"target", in.Target},
		{"args_digest", in.ArgsDigest},
		{"policy_rule_id", in.PolicyRuleID},
		{"policy_version", in.PolicyVersion},
		{"artifact_hash", in.ArtifactHash},
		{"work_item_id", in.WorkItemID},
	} {
		b.WriteString(f[0])
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(len(f[1])))
		b.WriteByte(':')
		b.WriteString(f[1])
		b.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ActionApprovalInput creates a request.
type ActionApprovalInput struct {
	ActionIntent
	// RequestedBy is the authenticated principal; never from a body.
	RequestedBy string
	// RequestedByPrincipalID and ViaPrincipalID are recorded only
	// (mctl-api#373 phase 1); see Mutation.
	RequestedByPrincipalID string
	ViaPrincipalID         string
	IdempotencyKey         string
	ExpiresAt              time.Time
	// IntentHash, when set, must equal IntentHash(ActionIntent).
	IntentHash string
}

func (in ActionApprovalInput) validate() error {
	for _, f := range []struct {
		name, value string
		max         int
		required    bool
	}{
		{"requested_by", in.RequestedBy, MaxExternalIDBytes, true},
		{"execution_id", in.ExecutionID, MaxExternalIDBytes, true},
		{"action_kind", in.ActionKind, MaxApprovalFieldBytes, true},
		{"target", in.Target, MaxApprovalTargetBytes, true},
		{"args_digest", in.ArgsDigest, MaxApprovalFieldBytes, true},
		{"policy_rule_id", in.PolicyRuleID, MaxApprovalFieldBytes, true},
		{"policy_version", in.PolicyVersion, MaxApprovalFieldBytes, true},
		{"artifact_hash", in.ArtifactHash, MaxApprovalFieldBytes, false},
		{"work_item_id", in.WorkItemID, MaxExternalIDBytes, false},
		{"idempotency_key", in.IdempotencyKey, MaxKeyBytes, true},
	} {
		if err := checkText(f.name, f.value, f.max, f.required); err != nil {
			return err
		}
		// Every field is persisted and read back, and target is pinned
		// into intent_hash: none may carry a credential.
		if err := scanSecrets(f.name, f.value); err != nil {
			return err
		}
	}
	if in.WorkItemID != "" && !strings.HasPrefix(in.WorkItemID, WorkItemIDPrefix) {
		return invalid("work_item_id must be a %s id", WorkItemIDPrefix)
	}
	if in.ExpiresAt.IsZero() {
		return invalid("expires_at is required")
	}
	if in.IntentHash != "" && in.IntentHash != IntentHash(in.ActionIntent) {
		return fmt.Errorf("%w: sent %q, computed %s", ErrApprovalIntentHash, in.IntentHash, IntentHash(in.ActionIntent))
	}
	return nil
}

// effectiveState applies lazy expiry.
func effectiveState(stored string, expiresAt, now time.Time) string {
	if (stored == ApprovalPending || stored == ApprovalApproved) && !expiresAt.After(now) {
		return ApprovalExpired
	}
	return stored
}

func scanActionApproval(row pgx.Row, now time.Time) (*ActionApprovalRequest, error) {
	var a ActionApprovalRequest
	if err := row.Scan(&a.ID, &a.ExecutionID, &a.ActionKind, &a.Target, &a.ArgsDigest, &a.PolicyRuleID,
		&a.PolicyVersion, &a.ArtifactHash, &a.WorkItemID, &a.IdempotencyKey, &a.RequestedBy, &a.IntentHash,
		&a.State, &a.ExpiresAt, &a.CreatedAt, &a.DecidedBy, &a.DecidedAt, &a.Reason, &a.ConsumedAt,
		&a.SchemaVersion); err != nil {
		return nil, err
	}
	a.ExpiresAt = a.ExpiresAt.UTC()
	a.CreatedAt = a.CreatedAt.UTC()
	if a.DecidedAt != nil {
		t := a.DecidedAt.UTC()
		a.DecidedAt = &t
	}
	if a.ConsumedAt != nil {
		t := a.ConsumedAt.UTC()
		a.ConsumedAt = &t
	}
	a.State = effectiveState(a.State, a.ExpiresAt, now)
	return &a, nil
}

func (s *Store) getActionApproval(ctx context.Context, q querier, id, lock string) (*ActionApprovalRequest, error) {
	a, err := scanActionApproval(q.QueryRow(ctx, `SELECT `+actionApprovalColumns+`
		FROM action_approval_requests WHERE id=$1`+lock, id), s.now())
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("workitems: action approval %s: %w", id, ErrApprovalNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("workitems: get action approval: %w", err)
	}
	return a, nil
}

// CreateActionApproval stores a new pending request, or returns the one this
// requester's idempotency key already names with the same intent
// (created=false).
func (s *Store) CreateActionApproval(ctx context.Context, in ActionApprovalInput) (*ActionApprovalRequest, bool, error) {
	if err := in.validate(); err != nil {
		return nil, false, err
	}
	hash := IntentHash(in.ActionIntent)
	var out *ActionApprovalRequest
	created := false
	// One lock per (requester, key): the lookup and the insert are one
	// decision; the UNIQUE constraint is the backstop.
	err := s.withTx(ctx, fmt.Sprintf("action-approval-create:%d:%s:%s", len(in.RequestedBy), in.RequestedBy, in.IdempotencyKey), func(tx pgx.Tx) error {
		now := s.now()
		existing, err := scanActionApproval(tx.QueryRow(ctx, `SELECT `+actionApprovalColumns+`
			FROM action_approval_requests WHERE requested_by=$1 AND idempotency_key=$2`,
			in.RequestedBy, in.IdempotencyKey), now)
		switch {
		case err == nil:
			if existing.IntentHash != hash {
				return fmt.Errorf("%w: key %q names %s with intent %s, not %s",
					ErrApprovalIdempotencyConflict, in.IdempotencyKey, existing.ID, existing.IntentHash, hash)
			}
			out = existing
			return nil
		case !errors.Is(err, pgx.ErrNoRows):
			return fmt.Errorf("workitems: find action approval: %w", err)
		}
		// The expiry window is checked for a new request only: a retry of
		// one already stored is answered with it, expired or not.
		if !in.ExpiresAt.After(now) {
			return invalid("expires_at must be in the future")
		}
		if in.ExpiresAt.Sub(now) > MaxApprovalTTL {
			return invalid("expires_at must be at most %s ahead", MaxApprovalTTL)
		}
		if in.WorkItemID != "" {
			if _, err := getItem(ctx, tx, in.WorkItemID); errors.Is(err, ErrNotFound) {
				return invalid("work_item_id names no work item")
			} else if err != nil {
				return err
			}
		}
		out, err = scanActionApproval(tx.QueryRow(ctx, `INSERT INTO action_approval_requests (
				id, execution_id, action_kind, target, args_digest, policy_rule_id, policy_version,
				artifact_hash, work_item_id, idempotency_key, requested_by, intent_hash, state,
				expires_at, created_at, schema_version, requested_by_principal_id, via_principal_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) RETURNING `+actionApprovalColumns,
			ActionApprovalIDPrefix+strings.ReplaceAll(uuid.NewString(), "-", ""), in.ExecutionID, in.ActionKind,
			in.Target, in.ArgsDigest, in.PolicyRuleID, in.PolicyVersion, in.ArtifactHash, in.WorkItemID,
			in.IdempotencyKey, in.RequestedBy, hash, ApprovalPending, in.ExpiresAt.UTC(), now,
			ActionApprovalSchemaVersion, in.RequestedByPrincipalID, in.ViaPrincipalID), now)
		if err != nil {
			return fmt.Errorf("workitems: insert action approval: %w", err)
		}
		created = true
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return out, created, nil
}

// ActionApproval returns one request with its effective state.
func (s *Store) ActionApproval(ctx context.Context, id string) (*ActionApprovalRequest, error) {
	return s.getActionApproval(ctx, s.pool, id, "")
}

// ActionApprovalFilter narrows a listing. RequestedBy, when set, limits it
// to one requester's requests (the HTTP layer's visibility rule).
type ActionApprovalFilter struct {
	State       string
	ExecutionID string
	RequestedBy string
	Limit       int
}

// ValidApprovalState reports whether state is a listable effective state.
func ValidApprovalState(state string) bool {
	switch state {
	case ApprovalPending, ApprovalApproved, ApprovalDenied, ApprovalConsumed, ApprovalExpired:
		return true
	}
	return false
}

// ActionApprovals lists requests, newest first, filtered on the effective
// state.
func (s *Store) ActionApprovals(ctx context.Context, f ActionApprovalFilter) ([]ActionApprovalRequest, error) {
	if f.State != "" && !ValidApprovalState(f.State) {
		return nil, invalid("state must be one of pending, approved, denied, consumed, expired")
	}
	if f.Limit <= 0 {
		f.Limit = defaultApprovalList
	}
	if f.Limit > MaxApprovalList {
		f.Limit = MaxApprovalList
	}
	now := s.now()
	where := []string{"TRUE"}
	args := []any{}
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	// The effective state: pending and approved hold only until expires_at.
	switch f.State {
	case "":
	case ApprovalExpired:
		where = append(where, "state IN ('pending', 'approved') AND expires_at <= "+arg(now))
	case ApprovalPending, ApprovalApproved:
		where = append(where, "state = "+arg(f.State)+" AND expires_at > "+arg(now))
	default:
		where = append(where, "state = "+arg(f.State))
	}
	if f.ExecutionID != "" {
		where = append(where, "execution_id = "+arg(f.ExecutionID))
	}
	if f.RequestedBy != "" {
		where = append(where, "requested_by = "+arg(f.RequestedBy))
	}
	// Finish the query first: arg appends to args, and the evaluation order
	// of a call operand against a plain variable operand is unspecified.
	query := `SELECT ` + actionApprovalColumns + ` FROM action_approval_requests
		WHERE ` + strings.Join(where, " AND ") + ` ORDER BY created_at DESC, id LIMIT ` + arg(f.Limit)
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("workitems: list action approvals: %w", err)
	}
	defer rows.Close()
	out := []ActionApprovalRequest{}
	for rows.Next() {
		a, err := scanActionApproval(rows, now)
		if err != nil {
			return nil, fmt.Errorf("workitems: list action approvals: %w", err)
		}
		out = append(out, *a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("workitems: list action approvals: %w", err)
	}
	return out, nil
}

// ActionDecisionInput decides a pending request.
type ActionDecisionInput struct {
	ID string
	// DecidedBy is the authenticated human principal; never from a body.
	DecidedBy string
	// DecidedByPrincipalID and ViaPrincipalID are recorded only
	// (mctl-api#373 phase 1); see Mutation.
	DecidedByPrincipalID string
	ViaPrincipalID       string
	Decision             string
	Reason               string
}

// DecideActionApproval moves a pending request to approved or denied. A
// request that is decided, consumed or expired is refused, and the
// requester can never decide its own request.
func (s *Store) DecideActionApproval(ctx context.Context, in ActionDecisionInput) (*ActionApprovalRequest, error) {
	if err := checkText("decided_by", in.DecidedBy, MaxExternalIDBytes, true); err != nil {
		return nil, err
	}
	if err := checkText("reason", in.Reason, MaxApprovalReasonBytes, false); err != nil {
		return nil, err
	}
	if err := scanSecrets("reason", in.Reason); err != nil {
		return nil, err
	}
	var to string
	switch in.Decision {
	case DecisionApprove:
		to = ApprovalApproved
	case DecisionDeny:
		to = ApprovalDenied
	default:
		return nil, invalid("decision must be %q or %q", DecisionApprove, DecisionDeny)
	}
	var out *ActionApprovalRequest
	err := s.withTx(ctx, "action-approval:"+in.ID, func(tx pgx.Tx) error {
		cur, err := s.getActionApproval(ctx, tx, in.ID, " FOR UPDATE")
		if err != nil {
			return err
		}
		if cur.RequestedBy == in.DecidedBy {
			return fmt.Errorf("%w: %s requested %s", ErrApprovalSelfDecision, in.DecidedBy, cur.ID)
		}
		switch cur.State {
		case ApprovalPending:
		case ApprovalExpired:
			return fmt.Errorf("%w: %s expired at %s", ErrApprovalExpired, cur.ID, cur.ExpiresAt.Format(time.RFC3339))
		default:
			return fmt.Errorf("%w: %s is %s", ErrApprovalAlreadyDecided, cur.ID, cur.State)
		}
		now := s.now()
		out, err = scanActionApproval(tx.QueryRow(ctx, `UPDATE action_approval_requests
			SET state=$2, decided_by=$3, decided_at=$4, reason=$5,
			    decided_by_principal_id=$6, decided_via_principal_id=$7
			WHERE id=$1 AND state='pending' RETURNING `+actionApprovalColumns,
			cur.ID, to, in.DecidedBy, now, in.Reason, in.DecidedByPrincipalID, in.ViaPrincipalID), now)
		if err != nil {
			return fmt.Errorf("workitems: decide action approval: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ConsumeActionApproval spends an approved request: one atomic
// compare-and-set from approved to consumed that holds only while the stored
// intent hash equals the presented one and the request has not expired. On
// a refusal the request is read back to name the reason; the refusal itself
// never depends on that read.
func (s *Store) ConsumeActionApproval(ctx context.Context, id, intentHash string) (*ActionApprovalRequest, error) {
	if err := checkText("intent_hash", intentHash, MaxApprovalFieldBytes, true); err != nil {
		return nil, err
	}
	now := s.now()
	out, err := scanActionApproval(s.pool.QueryRow(ctx, `UPDATE action_approval_requests
		SET state='consumed', consumed_at=$3
		WHERE id=$1 AND state='approved' AND intent_hash=$2 AND expires_at > $3
		RETURNING `+actionApprovalColumns, id, intentHash, now), now)
	if err == nil {
		return out, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("workitems: consume action approval: %w", err)
	}
	cur, err := s.getActionApproval(ctx, s.pool, id, "")
	if err != nil {
		return nil, err
	}
	switch cur.State {
	case ApprovalConsumed:
		return nil, fmt.Errorf("%w: %s", ErrApprovalConsumed, id)
	case ApprovalDenied:
		return nil, fmt.Errorf("%w: %s", ErrApprovalDenied, id)
	case ApprovalExpired:
		return nil, fmt.Errorf("%w: %s", ErrApprovalExpired, id)
	case ApprovalPending:
		return nil, fmt.Errorf("%w: %s is pending", ErrApprovalNotApproved, id)
	}
	if cur.IntentHash != intentHash {
		return nil, fmt.Errorf("%w: %s", ErrApprovalIntentMismatch, id)
	}
	// Approved, matching and unexpired now, but the UPDATE saw otherwise:
	// the clock moved between the two statements. Refuse rather than
	// retry; the caller re-presents.
	return nil, fmt.Errorf("%w: %s changed while consuming", ErrApprovalNotApproved, id)
}
