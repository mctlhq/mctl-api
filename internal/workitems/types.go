// Package workitems is the durable owner of "the piece of work a human asked
// for" (docs/work-context-contract.md, workitem/v1). Surfaces are adapters:
// they correlate to a WorkItem, they never hold its lifecycle.
//
// The package owns the schema, the transition table and the store. Who may
// call it, and as whom, is decided by the HTTP layer from authentication; the
// store records the principal it is handed and never derives one from a
// request body.
package workitems

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// SchemaVersion labels every work-item payload. A breaking change ships as a
// new label, never as a silent change to this one.
const SchemaVersion = "workitem/v1"

// ID prefixes (contract "ID scheme").
const (
	WorkItemIDPrefix  = "wi_"
	ExecutionIDPrefix = "we_"
)

// States. `resumed` is deliberately not one: it is only ever an event kind.
const (
	StateActive     = "active"
	StateWaiting    = "waiting"
	StateCompleted  = "completed"
	StateSuperseded = "superseded"
	StateArchived   = "archived"
)

// FilterOpen is the virtual list filter for every non-terminal state, the
// default when a list names no state (mirrors alerts.StatusActive).
const FilterOpen = "open"

// Waiting reasons.
const (
	WaitingInput    = "input"
	WaitingApproval = "approval"
)

// Visibility.
const (
	VisibilityTenant  = "tenant"
	VisibilityPrivate = "private"
)

// Lifecycle actions accepted by Transition.
const (
	ActionWait      = "wait"
	ActionResume    = "resume"
	ActionComplete  = "complete"
	ActionSupersede = "supersede"
	ActionArchive   = "archive"
)

// Event kinds recorded by this slice. The contract also names
// approval_requested and approval_decided; they arrive with the approval
// projection.
const (
	EventCreated           = "created"
	EventStateChanged      = "state_changed"
	EventResumed           = "resumed"
	EventIntentAppended    = "intent_appended"
	EventExecutionAttached = "execution_attached"
	EventSurfaceLinked     = "surface_linked"
	EventSnapshotSealed    = "snapshot_sealed"
)

// Execution engines and phases.
const (
	EngineTemporal = "temporal"
	EngineArgo     = "argo"

	PhasePending   = "Pending"
	PhaseRunning   = "Running"
	PhaseSucceeded = "Succeeded"
	PhaseFailed    = "Failed"
	PhaseError     = "Error"
)

// Bounds. Intent text is capped by the contract; the rest keep a correlation
// field from turning into a place to park content.
const (
	MaxIntentBytes      = 8 << 10
	MaxIntentParamBytes = 8 << 10
	MaxTitleBytes       = 256
	MaxKeyBytes         = 512
	MaxExternalIDBytes  = 256
	MaxEngineRefBytes   = 256
)

// Transitions is the single enforcement point for lifecycle rules: from
// state, action -> to state. Anything not listed, including every move out of
// a terminal state, is rejected.
var Transitions = map[string]map[string]string{
	StateActive: {
		ActionWait:      StateWaiting,
		ActionComplete:  StateCompleted,
		ActionSupersede: StateSuperseded,
		ActionArchive:   StateArchived,
	},
	StateWaiting: {
		ActionResume:    StateActive,
		ActionComplete:  StateCompleted,
		ActionSupersede: StateSuperseded,
		ActionArchive:   StateArchived,
	},
}

// Next returns the state action leads to from `from`, or
// ErrInvalidTransition.
func Next(from, action string) (string, error) {
	if to, ok := Transitions[from][action]; ok {
		return to, nil
	}
	return "", fmt.Errorf("%w: %s from %s", ErrInvalidTransition, action, from)
}

// IsTerminal reports whether no transition leaves state.
func IsTerminal(state string) bool {
	_, ok := Transitions[state]
	return !ok
}

// IsTerminalPhase reports whether an execution in phase has finished.
func IsTerminalPhase(phase string) bool {
	return phase == PhaseSucceeded || phase == PhaseFailed || phase == PhaseError
}

func validPhase(phase string) bool {
	return phase == PhasePending || phase == PhaseRunning || IsTerminalPhase(phase)
}

func validState(state string) bool {
	switch state {
	case StateActive, StateWaiting, StateCompleted, StateSuperseded, StateArchived:
		return true
	}
	return false
}

// surfacePattern bounds a surface label: a short lowercase token such as
// "telegram", "mcp", "cli" or "web". It is a label, never an identity.
var surfacePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// Sentinel errors. The HTTP layer maps each to one status and typed reason.
var (
	ErrNotFound            = errors.New("work item not found")
	ErrInvalid             = errors.New("invalid work item request")
	ErrInvalidTransition   = errors.New("transition not allowed")
	ErrVersionConflict     = errors.New("state_version does not match")
	ErrExecutionActive     = errors.New("work item already has a non-terminal execution")
	ErrIdempotencyKeyReuse = errors.New("idempotency key was already used for a different request")
	ErrSecretInText        = errors.New("text matches a secret pattern")
	ErrExternalKeyInUse    = errors.New("external_key already names open work this request cannot share")
)

// ConflictError carries the item as it is now, so a 409 can tell the caller
// the current state and version instead of making it re-read.
type ConflictError struct {
	Err     error
	Current *WorkItem
}

func (e *ConflictError) Error() string { return e.Err.Error() }
func (e *ConflictError) Unwrap() error { return e.Err }

// WorkItem is one piece of work a human asked for.
type WorkItem struct {
	ID             string     `json:"id"`
	Tenant         string     `json:"tenant"`
	OwnerPrincipal string     `json:"owner_principal"`
	Visibility     string     `json:"visibility"`
	OriginSurface  string     `json:"origin_surface"`
	Title          string     `json:"title"`
	ExternalKey    string     `json:"external_key,omitempty"`
	State          string     `json:"state"`
	WaitingReason  string     `json:"waiting_reason,omitempty"`
	SupersededBy   string     `json:"superseded_by,omitempty"`
	StateVersion   int64      `json:"state_version"`
	CreatedBy      string     `json:"created_by"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
	SchemaVersion  string     `json:"schema_version"`
}

// Event is one append-only lifecycle record.
type Event struct {
	WorkItemID     string `json:"work_item_id"`
	Seq            int64  `json:"seq"`
	Kind           string `json:"kind"`
	FromState      string `json:"from_state,omitempty"`
	ToState        string `json:"to_state,omitempty"`
	ActorPrincipal string `json:"actor_principal"`
	// ActingPrincipal is the surface principal that relayed the change for
	// ActorPrincipal, when it was relayed.
	ActingPrincipal string          `json:"acting_principal,omitempty"`
	Surface         string          `json:"surface,omitempty"`
	RequestID       string          `json:"request_id,omitempty"`
	Detail          json.RawMessage `json:"detail,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
}

// Intent is a bounded statement of what was asked for. Never a transcript.
type Intent struct {
	ID             int64           `json:"id"`
	WorkItemID     string          `json:"work_item_id"`
	ActorPrincipal string          `json:"actor_principal"`
	Surface        string          `json:"surface,omitempty"`
	Text           string          `json:"text"`
	Params         json.RawMessage `json:"params,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
}

// Execution correlates the work item to one engine run. The engine keeps the
// execution detail; this is only the reference to it.
type Execution struct {
	ID                     string     `json:"id"`
	WorkItemID             string     `json:"work_item_id"`
	Engine                 string     `json:"engine"`
	EngineRef              string     `json:"engine_ref"`
	Attempt                int        `json:"attempt"`
	ResumedFromExecutionID string     `json:"resumed_from_execution_id,omitempty"`
	Phase                  string     `json:"phase"`
	StartedAt              time.Time  `json:"started_at"`
	EndedAt                *time.Time `json:"ended_at,omitempty"`
}

// SurfaceRef correlates a work item to a surface-native conversation for
// reply routing. ActorExternalID is correlation metadata, never identity: it
// resolves to a principal only through a SurfaceIdentityLink (mctl-api#350).
type SurfaceRef struct {
	WorkItemID      string    `json:"work_item_id"`
	Surface         string    `json:"surface"`
	ExternalID      string    `json:"external_id"`
	ActorExternalID string    `json:"actor_external_id,omitempty"`
	FirstSeenAt     time.Time `json:"first_seen_at"`
	LastSeenAt      time.Time `json:"last_seen_at"`
}
