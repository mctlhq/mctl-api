package workitems

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Execution requests (mctl-api#368).
//
// SURFACE REQUESTS EXECUTION; SURFACE DOES NOT DECLARE EXECUTION IDENTITY.
//
// An ExecutionRequest is a durable "the user asked for this work item to
// run": a surface (or a person) creates it with only the item, the expected
// state_version, the kind (start or resume), an optional intent and
// resumed-from reference, and its idempotency key. It never names an
// execution id, an engine or an engine run. The execution platform (a
// service principal) claims it under a lease and fulfils it by attaching
// the canonical execution in the same transaction; only then does the
// request carry an execution_id.
//
//   - States: pending -> claimed -> fulfilled | rejected. A claim whose
//     lease has lapsed stays stored as claimed and is claimable again; the
//     lapsed holder can no longer fulfil or reject it.
//   - At most one open (pending or claimed) request per work item, decided
//     under the item's advisory lock and backed by a partial unique index.
//   - Claim is a compare-and-set under the item's lock: however many
//     claimants race, one moves a request to claimed. Every claim mints a
//     new claim_token, the fencing token fulfil and reject must present, so
//     a lapsed holder is refused even when the new holder is the same
//     service principal.
//   - Fulfil runs AttachExecution's (start) or Resume's (resume) decision in
//     the same transaction as the request's move to fulfilled.
//
// Who may create, claim, fulfil, reject or read is decided by the HTTP layer
// from authentication; the store records the principals it is handed.

// ExecutionRequestIDPrefix labels execution request ids.
const ExecutionRequestIDPrefix = "xr_"

// Kinds.
const (
	ExecutionRequestStart  = "start"
	ExecutionRequestResume = "resume"
)

// Stored states.
const (
	ExecutionRequestPending   = "pending"
	ExecutionRequestClaimed   = "claimed"
	ExecutionRequestFulfilled = "fulfilled"
	ExecutionRequestRejected  = "rejected"
)

// Event kinds of the request lifecycle.
const (
	EventExecutionRequested        = "execution_requested"
	EventExecutionRequestClaimed   = "execution_request_claimed"
	EventExecutionRequestFulfilled = "execution_request_fulfilled"
	EventExecutionRequestRejected  = "execution_request_rejected"
)

// Bounds.
const (
	MinClaimLease               = 5 * time.Second
	MaxClaimLease               = 15 * time.Minute
	DefaultClaimLease           = time.Minute
	MaxExecutionRequestReason   = 1024
	maxExecutionRequestList     = 100
	claimCandidates             = 8
	opExecutionRequest          = "execution_request"
	executionRequestClaimPrefix = "xc_"
)

var (
	// ErrExecutionRequestNotFound: no such request on this work item.
	ErrExecutionRequestNotFound = errors.New("execution request not found")
	// ErrExecutionRequestNotClaimed: the caller does not hold an unexpired
	// claim on the request (never claimed, claimed by another, lapsed, or
	// a stale claim token).
	ErrExecutionRequestNotClaimed = errors.New("the caller does not hold an unexpired claim on this execution request")
	// ErrExecutionRequestClosed: the request is already fulfilled (by a
	// different engine run) or rejected.
	ErrExecutionRequestClosed = errors.New("execution request is already closed")
	// ErrIntentNotFound: intent_id names no intent of this work item.
	ErrIntentNotFound = errors.New("intent not found")
)

// OpenRequestError refuses a new request while one is open, naming it so the
// client can follow it instead.
type OpenRequestError struct {
	Open *ExecutionRequest
}

// ErrExecutionRequestOpen is what an OpenRequestError unwraps to.
var ErrExecutionRequestOpen = errors.New("the work item already has an open execution request")

func (e *OpenRequestError) Error() string {
	return fmt.Sprintf("%s: %s is %s", ErrExecutionRequestOpen, e.Open.ID, e.Open.State)
}
func (e *OpenRequestError) Unwrap() error { return ErrExecutionRequestOpen }

// ClosedRequestError carries the closed request, so a 409 can name how it
// closed.
type ClosedRequestError struct {
	Request *ExecutionRequest
}

func (e *ClosedRequestError) Error() string {
	return fmt.Sprintf("%s: %s is %s", ErrExecutionRequestClosed, e.Request.ID, e.Request.State)
}
func (e *ClosedRequestError) Unwrap() error { return ErrExecutionRequestClosed }

const executionRequestSchema = `
CREATE TABLE IF NOT EXISTS work_item_execution_requests (
    id                        TEXT PRIMARY KEY,
    work_item_id              TEXT NOT NULL REFERENCES work_items (id) ON DELETE CASCADE,
    kind                      TEXT NOT NULL CHECK (kind IN ('start', 'resume')),
    expected_state_version    BIGINT NOT NULL,
    resumed_from_execution_id TEXT NOT NULL DEFAULT '',
    intent_id                 BIGINT,
    surface                   TEXT NOT NULL,
    requested_by              TEXT NOT NULL,
    acting_principal          TEXT NOT NULL DEFAULT '',
    idempotency_key           TEXT NOT NULL DEFAULT '',
    state                     TEXT NOT NULL CHECK (state IN ('pending', 'claimed', 'fulfilled', 'rejected')),
    claimed_by                TEXT NOT NULL DEFAULT '',
    claim_token               TEXT NOT NULL DEFAULT '',
    claimed_at                TIMESTAMPTZ,
    claim_expires_at          TIMESTAMPTZ,
    execution_id              TEXT NOT NULL DEFAULT '',
    reason                    TEXT NOT NULL DEFAULT '',
    created_at                TIMESTAMPTZ NOT NULL,
    updated_at                TIMESTAMPTZ NOT NULL,
    closed_at                 TIMESTAMPTZ,
    schema_version            TEXT NOT NULL
);
-- At most one open request per work item. The store decides it under the
-- item's advisory lock; this index is the backstop.
CREATE UNIQUE INDEX IF NOT EXISTS work_item_execution_requests_one_open
    ON work_item_execution_requests (work_item_id)
    WHERE state IN ('pending', 'claimed');
-- The claim scan: open requests, oldest first.
CREATE INDEX IF NOT EXISTS work_item_execution_requests_claimable
    ON work_item_execution_requests (created_at, id)
    WHERE state IN ('pending', 'claimed');
CREATE INDEX IF NOT EXISTS work_item_execution_requests_item
    ON work_item_execution_requests (work_item_id, created_at DESC);
`

const executionRequestColumns = `id, work_item_id, kind, expected_state_version, resumed_from_execution_id,
	intent_id, surface, requested_by, acting_principal, idempotency_key, state, claimed_by, claim_token,
	claimed_at, claim_expires_at, execution_id, reason, created_at, updated_at, closed_at, schema_version`

// ExecutionRequest is one durable request that a work item run.
type ExecutionRequest struct {
	ID                     string `json:"id"`
	WorkItemID             string `json:"work_item_id"`
	Kind                   string `json:"kind"`
	ExpectedStateVersion   int64  `json:"expected_state_version"`
	ResumedFromExecutionID string `json:"resumed_from_execution_id,omitempty"`
	IntentID               *int64 `json:"intent_id,omitempty"`
	Surface                string `json:"surface"`
	// RequestedBy is the principal the request was made as: the linked
	// human on a relayed call, never a body field.
	RequestedBy     string `json:"requested_by"`
	ActingPrincipal string `json:"acting_principal,omitempty"`
	IdempotencyKey  string `json:"idempotency_key,omitempty"`
	State           string `json:"state"`
	ClaimedBy       string `json:"claimed_by,omitempty"`
	// ClaimToken fences the current claim. It is returned to the claimant
	// alone (by ClaimExecutionRequest) and never serialized in a read.
	ClaimToken     string     `json:"-"`
	ClaimedAt      *time.Time `json:"claimed_at,omitempty"`
	ClaimExpiresAt *time.Time `json:"claim_expires_at,omitempty"`
	// ExecutionID is set only by fulfilment, from the platform.
	ExecutionID   string     `json:"execution_id,omitempty"`
	Reason        string     `json:"reason,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	ClosedAt      *time.Time `json:"closed_at,omitempty"`
	SchemaVersion string     `json:"schema_version"`
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

func scanExecutionRequest(row pgx.Row) (*ExecutionRequest, error) {
	var x ExecutionRequest
	if err := row.Scan(&x.ID, &x.WorkItemID, &x.Kind, &x.ExpectedStateVersion, &x.ResumedFromExecutionID,
		&x.IntentID, &x.Surface, &x.RequestedBy, &x.ActingPrincipal, &x.IdempotencyKey, &x.State, &x.ClaimedBy,
		&x.ClaimToken, &x.ClaimedAt, &x.ClaimExpiresAt, &x.ExecutionID, &x.Reason, &x.CreatedAt, &x.UpdatedAt,
		&x.ClosedAt, &x.SchemaVersion); err != nil {
		return nil, err
	}
	x.CreatedAt, x.UpdatedAt = x.CreatedAt.UTC(), x.UpdatedAt.UTC()
	x.ClaimedAt, x.ClaimExpiresAt, x.ClosedAt = utcPtr(x.ClaimedAt), utcPtr(x.ClaimExpiresAt), utcPtr(x.ClosedAt)
	return &x, nil
}

func getExecutionRequest(ctx context.Context, q querier, itemID, id, lock string) (*ExecutionRequest, error) {
	query := `SELECT ` + executionRequestColumns + ` FROM work_item_execution_requests WHERE id=$1`
	args := []any{id}
	if itemID != "" {
		query += ` AND work_item_id=$2`
		args = append(args, itemID)
	}
	x, err := scanExecutionRequest(q.QueryRow(ctx, query+lock, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("workitems: execution request %s: %w", id, ErrExecutionRequestNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("workitems: get execution request: %w", err)
	}
	return x, nil
}

// ExecutionRequestInput creates a request. There is deliberately no engine,
// engine run or execution id here: the platform supplies those at fulfil.
type ExecutionRequestInput struct {
	Mutation
	WorkItemID             string
	Kind                   string
	ExpectedStateVersion   int64
	ResumedFromExecutionID string
	IntentID               *int64
}

func (in ExecutionRequestInput) validate() error {
	if err := in.Mutation.validate(); err != nil {
		return err
	}
	if in.WorkItemID == "" {
		return invalid("work item id is required")
	}
	switch in.Kind {
	case ExecutionRequestStart:
		if in.ResumedFromExecutionID != "" {
			return invalid("resumed_from_execution_id is only valid with kind %q", ExecutionRequestResume)
		}
	case ExecutionRequestResume:
	default:
		return invalid("kind must be %q or %q", ExecutionRequestStart, ExecutionRequestResume)
	}
	if in.ExpectedStateVersion <= 0 {
		return invalid("expected_state_version is required")
	}
	if in.IntentID != nil && *in.IntentID <= 0 {
		return invalid("intent_id must be a positive intent id")
	}
	if in.Surface == "" {
		return invalid("surface is required")
	}
	return checkText("resumed_from_execution_id", in.ResumedFromExecutionID, MaxExternalIDBytes, false)
}

// checkRunnable is the request-time half of what fulfil will decide: a
// request the platform could never fulfil is refused now, with the same
// typed errors fulfil would give. One exception: a resumed_from_execution_id
// that is not an execution of the item is a 404 execution_not_found here,
// because the requester named it; fulfil (resumeTx) reports the same fault
// as invalid_request. Executions are never deleted, so a reference valid at
// create stays valid at fulfil and the second answer is not reachable.
func checkRunnable(cur *WorkItem, execs []Execution, kind, from string) error {
	if IsTerminal(cur.State) {
		return &ConflictError{Err: fmt.Errorf("%w: execution request on %s", ErrInvalidTransition, cur.State), Current: cur}
	}
	for i := range execs {
		if !IsTerminalPhase(execs[i].Phase) {
			return &ConflictError{Err: ErrExecutionActive, Current: cur}
		}
	}
	switch kind {
	case ExecutionRequestStart:
		// Start is the first run of an active item. A waiting item leaves
		// waiting only by resume, and an item that has run resumes.
		if cur.State != StateActive {
			return &ConflictError{Err: fmt.Errorf("%w: start from %s; request kind resume", ErrInvalidTransition, cur.State), Current: cur}
		}
		if len(execs) > 0 {
			return &ConflictError{Err: fmt.Errorf("%w: %s already ran; request kind resume", ErrInvalidTransition, cur.ID), Current: cur}
		}
	case ExecutionRequestResume:
		// Resume's own rule (resumeTx): an active item with no execution
		// starts instead.
		if len(execs) == 0 && cur.State == StateActive {
			return invalid("%s has no execution to resume; request kind start", cur.ID)
		}
		if from != "" && !containsExecution(execs, from) {
			return fmt.Errorf("workitems: resumed_from_execution_id %s of %s: %w", from, cur.ID, ErrExecutionNotFound)
		}
	}
	return nil
}

func openExecutionRequest(ctx context.Context, q querier, itemID string) (*ExecutionRequest, error) {
	x, err := scanExecutionRequest(q.QueryRow(ctx, `SELECT `+executionRequestColumns+`
		FROM work_item_execution_requests WHERE work_item_id=$1 AND state IN ('pending','claimed')`, itemID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("workitems: find open execution request: %w", err)
	}
	return x, nil
}

// CreateExecutionRequest records a pending request, or returns the one this
// actor's idempotency key already names with the same body (created=false).
func (s *Store) CreateExecutionRequest(ctx context.Context, in ExecutionRequestInput) (*ExecutionRequest, bool, error) {
	if err := in.validate(); err != nil {
		return nil, false, err
	}
	var out *ExecutionRequest
	created := false
	err := s.withTx(ctx, "workitem:"+in.WorkItemID, func(tx pgx.Tx) error {
		cur, err := getItem(ctx, tx, in.WorkItemID)
		if err != nil {
			return err
		}
		if result, ok, err := replayed(ctx, tx, cur.ID, opExecutionRequest, in.Mutation); err != nil {
			return err
		} else if ok {
			out, err = getExecutionRequest(ctx, tx, cur.ID, result, "")
			return err
		}
		if cur.StateVersion != in.ExpectedStateVersion {
			return &ConflictError{Err: ErrVersionConflict, Current: cur}
		}
		if open, err := openExecutionRequest(ctx, tx, cur.ID); err != nil {
			return err
		} else if open != nil {
			return &OpenRequestError{Open: open}
		}
		execs, err := listExecutions(ctx, tx, cur.ID)
		if err != nil {
			return err
		}
		if err := checkRunnable(cur, execs, in.Kind, in.ResumedFromExecutionID); err != nil {
			return err
		}
		if in.IntentID != nil {
			var found bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM work_item_intents WHERE work_item_id=$1 AND id=$2)`,
				cur.ID, *in.IntentID).Scan(&found); err != nil {
				return fmt.Errorf("workitems: find intent: %w", err)
			}
			if !found {
				return fmt.Errorf("workitems: intent %d of %s: %w", *in.IntentID, cur.ID, ErrIntentNotFound)
			}
		}
		now := s.now()
		out, err = scanExecutionRequest(tx.QueryRow(ctx, `INSERT INTO work_item_execution_requests (
				id, work_item_id, kind, expected_state_version, resumed_from_execution_id, intent_id, surface,
				requested_by, acting_principal, idempotency_key, state, created_at, updated_at, schema_version)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'`+ExecutionRequestPending+`',$11,$11,$12)
			RETURNING `+executionRequestColumns,
			ExecutionRequestIDPrefix+strings.ReplaceAll(uuid.NewString(), "-", ""), cur.ID, in.Kind,
			in.ExpectedStateVersion, in.ResumedFromExecutionID, in.IntentID, in.Surface, in.Actor,
			in.ActingPrincipal, in.IdempotencyKey, now, SchemaVersion))
		if err != nil {
			return fmt.Errorf("workitems: insert execution request: %w", err)
		}
		detail := map[string]any{"execution_request_id": out.ID, "kind": out.Kind}
		if out.IntentID != nil {
			detail["intent_id"] = *out.IntentID
		}
		if out.ResumedFromExecutionID != "" {
			detail["resumed_from_execution_id"] = out.ResumedFromExecutionID
		}
		if err := appendEvent(ctx, tx, cur.ID, EventExecutionRequested, "", "", in.Mutation, detail, now); err != nil {
			return err
		}
		if err := remember(ctx, tx, cur.ID, opExecutionRequest, out.ID, in.Mutation, now); err != nil {
			return err
		}
		created = true
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return out, created, nil
}

// ExecutionRequest returns one request of a work item. No authorization:
// the caller checks the item's tenant and visibility first.
func (s *Store) ExecutionRequest(ctx context.Context, itemID, id string) (*ExecutionRequest, error) {
	return getExecutionRequest(ctx, s.pool, itemID, id, "")
}

// ExecutionRequests lists a work item's requests, newest first, at most
// 100. No authorization, as ExecutionRequest.
func (s *Store) ExecutionRequests(ctx context.Context, itemID string) ([]ExecutionRequest, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+executionRequestColumns+` FROM work_item_execution_requests
		WHERE work_item_id=$1 ORDER BY created_at DESC, id LIMIT $2`, itemID, maxExecutionRequestList)
	if err != nil {
		return nil, fmt.Errorf("workitems: list execution requests: %w", err)
	}
	defer rows.Close()
	out := []ExecutionRequest{}
	for rows.Next() {
		x, err := scanExecutionRequest(rows)
		if err != nil {
			return nil, fmt.Errorf("workitems: list execution requests: %w", err)
		}
		out = append(out, *x)
	}
	return out, rows.Err()
}

// ClaimInput claims the oldest claimable request.
type ClaimInput struct {
	// Mutation.Actor is the claimant: the authenticated service principal.
	Mutation
	Lease time.Duration
}

// ClaimExecutionRequest claims the oldest request that is pending or whose
// claim lease has lapsed, for in.Lease, and returns it with a fresh
// ClaimToken, plus its work item. It returns nil, nil, nil when nothing is
// claimable.
//
// Each candidate is claimed in its own transaction under the item's
// advisory lock, the lock every other request and item mutation takes
// first, so the lock order is always item then row and no claim can
// deadlock a concurrent fulfil. The UPDATE is the compare-and-set that makes
// one claimant win: it re-checks claimability under the lock, so racing
// claimants of one request serialize and all but the first match nothing.
func (s *Store) ClaimExecutionRequest(ctx context.Context, in ClaimInput) (*ExecutionRequest, *WorkItem, error) {
	if err := in.validate(); err != nil {
		return nil, nil, err
	}
	if in.Lease < MinClaimLease || in.Lease > MaxClaimLease {
		return nil, nil, invalid("lease must be from %s to %s", MinClaimLease, MaxClaimLease)
	}
	rows, err := s.pool.Query(ctx, `SELECT id, work_item_id FROM work_item_execution_requests
		WHERE state='pending' OR (state='claimed' AND claim_expires_at <= $1)
		ORDER BY created_at, id LIMIT $2`, s.now(), claimCandidates)
	if err != nil {
		return nil, nil, fmt.Errorf("workitems: find claimable execution requests: %w", err)
	}
	type candidate struct{ id, itemID string }
	var candidates []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.id, &c.itemID); err != nil {
			rows.Close()
			return nil, nil, fmt.Errorf("workitems: find claimable execution requests: %w", err)
		}
		candidates = append(candidates, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("workitems: find claimable execution requests: %w", err)
	}
	for _, c := range candidates {
		var out *ExecutionRequest
		var item *WorkItem
		err := s.withTx(ctx, "workitem:"+c.itemID, func(tx pgx.Tx) error {
			now := s.now()
			token := executionRequestClaimPrefix + strings.ReplaceAll(uuid.NewString(), "-", "")
			x, err := scanExecutionRequest(tx.QueryRow(ctx, `UPDATE work_item_execution_requests
				SET state='claimed', claimed_by=$2, claim_token=$3, claimed_at=$4, claim_expires_at=$5, updated_at=$4
				WHERE id=$1 AND (state='pending' OR (state='claimed' AND claim_expires_at <= $4))
				RETURNING `+executionRequestColumns, c.id, in.Actor, token, now, now.Add(in.Lease)))
			if errors.Is(err, pgx.ErrNoRows) {
				return nil // another claimant won it, or it closed
			}
			if err != nil {
				return fmt.Errorf("workitems: claim execution request: %w", err)
			}
			if item, err = getItem(ctx, tx, c.itemID); err != nil {
				return err
			}
			if err := appendEvent(ctx, tx, c.itemID, EventExecutionRequestClaimed, "", "", in.Mutation,
				map[string]any{"execution_request_id": x.ID, "claim_expires_at": x.ClaimExpiresAt}, now); err != nil {
				return err
			}
			out = x
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
		if out != nil {
			return out, item, nil
		}
	}
	return nil, nil, nil
}

// ClaimRef names the claim a fulfil or reject acts under.
type ClaimRef struct {
	// Mutation.Actor is the caller; it must be the claimant.
	Mutation
	RequestID  string
	ClaimToken string
}

func (in ClaimRef) validate() error {
	if err := in.Mutation.validate(); err != nil {
		return err
	}
	if in.RequestID == "" {
		return invalid("execution request id is required")
	}
	return checkText("claim_token", in.ClaimToken, MaxExternalIDBytes, true)
}

// holds reports whether ref names x's current claim: the same claimant and
// the claim token that claim minted. Expiry is checked separately.
func (ref ClaimRef) holds(x *ExecutionRequest) bool {
	return x.ClaimedBy == ref.Actor &&
		subtle.ConstantTimeCompare([]byte(x.ClaimToken), []byte(ref.ClaimToken)) == 1
}

// lockedRequest reads the request's work item id, then runs fn under that
// item's lock with the request and item re-read inside it.
func (s *Store) lockedRequest(ctx context.Context, id string, fn func(pgx.Tx, *ExecutionRequest, *WorkItem, time.Time) error) error {
	x, err := getExecutionRequest(ctx, s.pool, "", id, "")
	if err != nil {
		return err
	}
	return s.withTx(ctx, "workitem:"+x.WorkItemID, func(tx pgx.Tx) error {
		cur, err := getItem(ctx, tx, x.WorkItemID)
		if err != nil {
			return err
		}
		x, err := getExecutionRequest(ctx, tx, x.WorkItemID, id, " FOR UPDATE")
		if err != nil {
			return err
		}
		return fn(tx, x, cur, s.now())
	})
}

// FulfilInput fulfils a claimed request with the engine run the platform
// started for it.
type FulfilInput struct {
	ClaimRef
	Engine    string
	EngineRef string
}

// FulfilExecutionRequest attaches the request's canonical execution and
// records it, in one transaction. kind=start attaches a Running execution
// (AttachExecution's rule); kind=resume runs Resume's rule with the
// request's expected_state_version and resumed_from_execution_id. A retry by
// the holder with the same engine run returns the same execution
// (created=false); a different run is ErrExecutionRequestClosed.
func (s *Store) FulfilExecutionRequest(ctx context.Context, in FulfilInput) (*ExecutionRequest, *WorkItem, *Execution, bool, error) {
	if err := in.validate(); err != nil {
		return nil, nil, nil, false, err
	}
	if err := validateEngine(in.Engine, in.EngineRef); err != nil {
		return nil, nil, nil, false, err
	}
	var out *ExecutionRequest
	var item *WorkItem
	var exec *Execution
	created := false
	err := s.lockedRequest(ctx, in.RequestID, func(tx pgx.Tx, x *ExecutionRequest, cur *WorkItem, now time.Time) error {
		switch x.State {
		case ExecutionRequestFulfilled:
			if !in.holds(x) {
				return fmt.Errorf("%w: %s", ErrExecutionRequestNotClaimed, x.ID)
			}
			e, err := getExecution(ctx, tx, cur.ID, x.ExecutionID)
			if err != nil {
				return err
			}
			if e.Engine != in.Engine || e.EngineRef != in.EngineRef {
				return &ClosedRequestError{Request: x}
			}
			out, item, exec = x, cur, e
			return nil
		case ExecutionRequestRejected:
			return &ClosedRequestError{Request: x}
		}
		if x.State != ExecutionRequestClaimed || !in.holds(x) || x.ClaimExpiresAt == nil || !x.ClaimExpiresAt.After(now) {
			return fmt.Errorf("%w: %s", ErrExecutionRequestNotClaimed, x.ID)
		}
		var err error
		switch x.Kind {
		case ExecutionRequestStart:
			item = cur
			if err = checkStart(ctx, tx, cur, x, in); err == nil {
				exec, err = attachNewTx(ctx, tx, cur, ExecutionInput{
					Mutation: in.Mutation, WorkItemID: cur.ID, Engine: in.Engine, EngineRef: in.EngineRef, Phase: PhaseRunning,
				}, now)
			}
		case ExecutionRequestResume:
			item, exec, err = resumeTx(ctx, tx, cur, ResumeInput{
				Mutation: in.Mutation, WorkItemID: cur.ID, ExpectedStateVersion: x.ExpectedStateVersion,
				ResumedFromExecutionID: x.ResumedFromExecutionID, Engine: in.Engine, EngineRef: in.EngineRef,
			}, now)
		default:
			err = fmt.Errorf("workitems: execution request %s has unknown kind %q", x.ID, x.Kind)
		}
		if err != nil {
			return err
		}
		out, err = scanExecutionRequest(tx.QueryRow(ctx, `UPDATE work_item_execution_requests
			SET state='fulfilled', execution_id=$2, updated_at=$3, closed_at=$3
			WHERE id=$1 AND state='claimed' RETURNING `+executionRequestColumns, x.ID, exec.ID, now))
		if err != nil {
			return fmt.Errorf("workitems: fulfil execution request: %w", err)
		}
		if err := appendEvent(ctx, tx, cur.ID, EventExecutionRequestFulfilled, "", "", in.Mutation,
			map[string]string{"execution_request_id": x.ID, "execution_id": exec.ID, "requested_by": x.RequestedBy}, now); err != nil {
			return err
		}
		created = true
		return nil
	})
	if err != nil {
		return nil, nil, nil, false, err
	}
	return out, item, exec, created, nil
}

// checkStart re-decides a start at fulfilment: the item is still at the
// version the request expected, still startable, and the engine run is not
// already one of its executions.
func checkStart(ctx context.Context, tx pgx.Tx, cur *WorkItem, x *ExecutionRequest, in FulfilInput) error {
	if cur.StateVersion != x.ExpectedStateVersion {
		return &ConflictError{Err: ErrVersionConflict, Current: cur}
	}
	execs, err := listExecutions(ctx, tx, cur.ID)
	if err != nil {
		return err
	}
	for i := range execs {
		if execs[i].Engine == in.Engine && execs[i].EngineRef == in.EngineRef {
			return invalid("%s %s is already execution %s of %s; a start attaches a new run",
				in.Engine, in.EngineRef, execs[i].ID, cur.ID)
		}
	}
	return checkRunnable(cur, execs, ExecutionRequestStart, "")
}

// RejectInput rejects a claimed request.
type RejectInput struct {
	ClaimRef
	Reason string
}

// RejectExecutionRequest closes a claimed request without an execution. A
// retry by the holder with the same reason returns the rejected request
// (created=false).
func (s *Store) RejectExecutionRequest(ctx context.Context, in RejectInput) (*ExecutionRequest, *WorkItem, bool, error) {
	if err := in.validate(); err != nil {
		return nil, nil, false, err
	}
	if err := checkText("reason", in.Reason, MaxExecutionRequestReason, true); err != nil {
		return nil, nil, false, err
	}
	if err := scanSecrets("reason", in.Reason); err != nil {
		return nil, nil, false, err
	}
	var out *ExecutionRequest
	var item *WorkItem
	rejected := false
	err := s.lockedRequest(ctx, in.RequestID, func(tx pgx.Tx, x *ExecutionRequest, cur *WorkItem, now time.Time) error {
		switch x.State {
		case ExecutionRequestRejected:
			if !in.holds(x) {
				return fmt.Errorf("%w: %s", ErrExecutionRequestNotClaimed, x.ID)
			}
			if x.Reason != in.Reason {
				return &ClosedRequestError{Request: x}
			}
			out, item = x, cur
			return nil
		case ExecutionRequestFulfilled:
			return &ClosedRequestError{Request: x}
		}
		if x.State != ExecutionRequestClaimed || !in.holds(x) || x.ClaimExpiresAt == nil || !x.ClaimExpiresAt.After(now) {
			return fmt.Errorf("%w: %s", ErrExecutionRequestNotClaimed, x.ID)
		}
		var err error
		out, err = scanExecutionRequest(tx.QueryRow(ctx, `UPDATE work_item_execution_requests
			SET state='rejected', reason=$2, updated_at=$3, closed_at=$3
			WHERE id=$1 AND state='claimed' RETURNING `+executionRequestColumns, x.ID, in.Reason, now))
		if err != nil {
			return fmt.Errorf("workitems: reject execution request: %w", err)
		}
		// The event names the request only; the reason stays on the row.
		if err := appendEvent(ctx, tx, cur.ID, EventExecutionRequestRejected, "", "", in.Mutation,
			map[string]string{"execution_request_id": x.ID, "requested_by": x.RequestedBy}, now); err != nil {
			return err
		}
		item, rejected = cur, true
		return nil
	})
	if err != nil {
		return nil, nil, false, err
	}
	return out, item, rejected, nil
}
