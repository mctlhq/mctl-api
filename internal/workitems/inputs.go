package workitems

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/mctlhq/mctl-api/internal/secretscan"
)

// Mutation is what every write carries besides its own fields. Actor is the
// authenticated principal the HTTP layer derived; the store records it and
// never looks for one anywhere else.
type Mutation struct {
	Actor     string
	Surface   string
	RequestID string
	// IdempotencyKey deduplicates the request: per tenant for Create, per
	// work item for everything else. RequestHash is the digest of the
	// request that key was first used with; a replay with the same key and a
	// different hash is ErrIdempotencyKeyReuse, never a silent replay.
	IdempotencyKey string
	RequestHash    string
}

// CreateInput opens a work item in state active.
type CreateInput struct {
	Mutation
	Tenant        string
	Visibility    string
	OriginSurface string
	Title         string
	// ExternalKey (for example a GitHub issue URL) dedupes open work: while
	// a non-terminal item in the tenant carries it, Create returns that item.
	ExternalKey string
}

// TransitionInput moves a work item along Transitions.
type TransitionInput struct {
	Mutation
	WorkItemID           string
	Action               string
	WaitingReason        string // required for wait, forbidden otherwise
	SupersededBy         string // required for supersede, forbidden otherwise
	ExpectedStateVersion int64
}

// ResumeInput starts a new execution continuing a prior one. A waiting item
// moves back to active; either way a resumed event is recorded.
type ResumeInput struct {
	Mutation
	WorkItemID           string
	ExpectedStateVersion int64
	// ResumedFromExecutionID names the execution being continued. Empty
	// means the latest one, if the item has any.
	ResumedFromExecutionID string
	Engine                 string
	EngineRef              string
}

// IntentInput appends a bounded intent.
type IntentInput struct {
	Mutation
	WorkItemID string
	Text       string
	Params     json.RawMessage
}

// ExecutionInput attaches an execution, or correlates a later phase of one
// already attached under the same (engine, engine_ref).
type ExecutionInput struct {
	Mutation
	WorkItemID string
	Engine     string
	EngineRef  string
	Phase      string
}

// SurfaceRefInput correlates a surface-native conversation.
type SurfaceRefInput struct {
	Mutation
	WorkItemID      string
	ExternalID      string
	ActorExternalID string
}

// ListFilter selects work items. Tenancy fails closed: an empty Tenants
// matches nothing unless AllTenants is set (admins only; the HTTP layer
// decides). Named Tenants always narrow, AllTenants or not. Viewer, when set, hides
// private items owned by anyone else.
type ListFilter struct {
	Tenants    []string
	AllTenants bool
	State      string // "" or FilterOpen: non-terminal; otherwise one state
	Owner      string
	Viewer     string
	Limit      int
}

const (
	defaultListLimit = 100
	maxListLimit     = 500
)

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

func checkText(field, value string, max int, required bool) error {
	if required && strings.TrimSpace(value) == "" {
		return invalid("%s is required", field)
	}
	if len(value) > max {
		return invalid("%s exceeds %d bytes", field, max)
	}
	if !utf8.ValidString(value) {
		return invalid("%s is not valid UTF-8", field)
	}
	return nil
}

// checkIdentity is checkText for values matched exactly later (principals,
// tenants): stored as given, padding would make them miss every match, a
// private item invisible to its own owner.
func checkIdentity(field, value string) error {
	if err := checkText(field, value, MaxExternalIDBytes, true); err != nil {
		return err
	}
	if value != strings.TrimSpace(value) {
		return invalid("%s has leading or trailing whitespace", field)
	}
	return nil
}

func (m Mutation) validate() error {
	if err := checkIdentity("actor", m.Actor); err != nil {
		return err
	}
	if err := checkText("request_id", m.RequestID, MaxExternalIDBytes, false); err != nil {
		return err
	}
	if m.Surface != "" && !surfacePattern.MatchString(m.Surface) {
		return invalid("surface must match %s", surfacePattern)
	}
	if err := checkText("idempotency_key", m.IdempotencyKey, MaxKeyBytes, false); err != nil {
		return err
	}
	if m.IdempotencyKey != "" && m.RequestHash == "" {
		return invalid("an idempotency key needs the request hash it was used with")
	}
	return nil
}

func (in CreateInput) validate() error {
	if err := in.Mutation.validate(); err != nil {
		return err
	}
	if err := checkIdentity("tenant", in.Tenant); err != nil {
		return err
	}
	if in.Visibility != VisibilityTenant && in.Visibility != VisibilityPrivate {
		return invalid("visibility must be %q or %q", VisibilityTenant, VisibilityPrivate)
	}
	if !surfacePattern.MatchString(in.OriginSurface) {
		return invalid("origin_surface must match %s", surfacePattern)
	}
	if err := checkText("title", in.Title, MaxTitleBytes, true); err != nil {
		return err
	}
	if err := checkText("external_key", in.ExternalKey, MaxKeyBytes, false); err != nil {
		return err
	}
	if err := scanSecrets("title", in.Title); err != nil {
		return err
	}
	return scanSecrets("external_key", in.ExternalKey)
}

func (in TransitionInput) validate() error {
	if err := in.Mutation.validate(); err != nil {
		return err
	}
	if in.WorkItemID == "" {
		return invalid("work item id is required")
	}
	switch in.Action {
	case ActionWait, ActionComplete, ActionSupersede, ActionArchive:
	case ActionResume:
		// Resume starts an execution and has its own route.
		return invalid("resume is its own operation")
	default:
		return invalid("unknown action %q", in.Action)
	}
	if in.Action == ActionWait {
		if in.WaitingReason != WaitingInput && in.WaitingReason != WaitingApproval {
			return invalid("wait needs waiting_reason %q or %q", WaitingInput, WaitingApproval)
		}
	} else if in.WaitingReason != "" {
		return invalid("waiting_reason is only valid with wait")
	}
	if in.Action == ActionSupersede {
		if in.SupersededBy == "" || in.SupersededBy == in.WorkItemID {
			return invalid("supersede needs superseded_by naming another work item")
		}
	} else if in.SupersededBy != "" {
		return invalid("superseded_by is only valid with supersede")
	}
	if in.ExpectedStateVersion <= 0 {
		return invalid("expected_state_version is required")
	}
	return nil
}

func (in ResumeInput) validate() error {
	if err := in.Mutation.validate(); err != nil {
		return err
	}
	if in.WorkItemID == "" {
		return invalid("work item id is required")
	}
	if in.ExpectedStateVersion <= 0 {
		return invalid("expected_state_version is required")
	}
	return validateEngine(in.Engine, in.EngineRef)
}

func (in IntentInput) validate() error {
	if err := in.Mutation.validate(); err != nil {
		return err
	}
	if in.WorkItemID == "" {
		return invalid("work item id is required")
	}
	if err := checkText("text", in.Text, MaxIntentBytes, true); err != nil {
		return err
	}
	if len(in.Params) > 0 {
		if len(in.Params) > MaxIntentParamBytes {
			return invalid("params exceed %d bytes", MaxIntentParamBytes)
		}
		var obj map[string]any
		if err := json.Unmarshal(in.Params, &obj); err != nil || obj == nil {
			return invalid("params must be a JSON object")
		}
	}
	if err := scanSecrets("text", in.Text); err != nil {
		return err
	}
	return scanSecrets("params", string(in.Params))
}

func (in ExecutionInput) validate() error {
	if err := in.Mutation.validate(); err != nil {
		return err
	}
	if in.WorkItemID == "" {
		return invalid("work item id is required")
	}
	if !validPhase(in.Phase) {
		return invalid("phase %q is not one of Pending, Running, Succeeded, Failed, Error", in.Phase)
	}
	return validateEngine(in.Engine, in.EngineRef)
}

func (in SurfaceRefInput) validate() error {
	if err := in.Mutation.validate(); err != nil {
		return err
	}
	if in.WorkItemID == "" {
		return invalid("work item id is required")
	}
	if in.Surface == "" {
		return invalid("surface is required")
	}
	if err := checkText("external_id", in.ExternalID, MaxExternalIDBytes, true); err != nil {
		return err
	}
	if err := checkText("actor_external_id", in.ActorExternalID, MaxExternalIDBytes, false); err != nil {
		return err
	}
	if err := scanSecrets("external_id", in.ExternalID); err != nil {
		return err
	}
	return scanSecrets("actor_external_id", in.ActorExternalID)
}

func validateEngine(engine, ref string) error {
	if engine != EngineTemporal && engine != EngineArgo {
		return invalid("engine must be %q or %q", EngineTemporal, EngineArgo)
	}
	return checkText("engine_ref", ref, MaxEngineRefBytes, true)
}

// scanSecrets is the contract's gate on free text: a match is rejected and
// never persisted.
func scanSecrets(field, value string) error {
	if value == "" {
		return nil
	}
	if pattern, found := secretscan.Scan([]byte(value)); found {
		return fmt.Errorf("%w: %s (%s)", ErrSecretInText, field, pattern)
	}
	return nil
}
