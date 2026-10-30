package deployplan

import (
	"errors"
	"time"
)

// SchemaVersion labels every stored plan and opens its digest encoding.
const SchemaVersion = "mctl-deploy-plan/v1"

// Action is what a plan does to the service.
type Action string

const (
	// ActionUpdate changes a service that already exists in gitops. It is
	// the only action this package produces.
	ActionUpdate Action = "update"
	// ActionOnboard is reserved for the preview-onboard item and is never
	// produced here.
	ActionOnboard Action = "onboard"
)

// Environment is the only environment a plan may target.
const EnvironmentPreview = "preview"

// Approval names the approval a plan will need before anything is applied.
type Approval struct {
	Required bool   `json:"required"`
	Role     string `json:"role"`
	Reason   string `json:"reason"`
}

// Plan is one stored, immutable deploy plan. Every field except ID,
// CreatedAt, ExpiresAt, CreatedBy, Surface and IdempotencyKey is bound by
// Digest.
type Plan struct {
	ID                 string    `json:"id"`
	Digest             string    `json:"digest"`
	SchemaVersion      string    `json:"schema_version"`
	Tenant             string    `json:"tenant"`
	Service            string    `json:"service"`
	Environment        string    `json:"environment"`
	Intent             []byte    `json:"-"`
	IntentCanonical    string    `json:"-"`
	Revision           string    `json:"revision"`
	GitopsBaseSHA      string    `json:"gitops_base_sha"`
	Action             Action    `json:"action"`
	PreviewID          string    `json:"preview_id"`
	ValuesBeforeSHA256 string    `json:"values_before_sha256"`
	ValuesAfter        string    `json:"values_after"`
	Diff               string    `json:"diff"`
	Host               string    `json:"host"`
	RequiresApproval   bool      `json:"requires_approval"`
	RequiredRole       string    `json:"required_role"`
	ApprovalReason     string    `json:"approval_reason"`
	CreatedBy          string    `json:"created_by"`
	Surface            string    `json:"surface"`
	IdempotencyKey     string    `json:"-"`
	CreatedAt          time.Time `json:"created_at"`
	ExpiresAt          time.Time `json:"expires_at"`
}

// Approval returns the approval recorded on the plan.
func (p *Plan) Approval() Approval {
	return Approval{Required: p.RequiresApproval, Role: p.RequiredRole, Reason: p.ApprovalReason}
}

// Expired computes expiry lazily; it is never stored.
func (p *Plan) Expired(now time.Time) bool { return !now.Before(p.ExpiresAt) }

var (
	// ErrIntentInvalid: the intent is not a valid DeployIntent.
	ErrIntentInvalid = errors.New("deployplan: invalid deploy intent")
	// ErrValuesUnparseable: the base values are not a YAML mapping.
	ErrValuesUnparseable = errors.New("deployplan: base values are not a parseable YAML mapping")
	// ErrPreviewValuesRefused: the preview rewrite refuses the base values,
	// as rewrite_preview_values.py would.
	ErrPreviewValuesRefused = errors.New("deployplan: preview values refused")
	// ErrNotFound: no plan with that id.
	ErrNotFound = errors.New("deployplan: plan not found")
	// ErrIdempotencyConflict: the idempotency key was used for a different plan.
	ErrIdempotencyConflict = errors.New("deployplan: idempotency key reused with a different plan")
)

// IdempotencyConflictError names the stored plan.
type IdempotencyConflictError struct{ PlanID string }

func (e *IdempotencyConflictError) Error() string {
	return ErrIdempotencyConflict.Error() + " (" + e.PlanID + ")"
}
func (e *IdempotencyConflictError) Is(target error) bool { return target == ErrIdempotencyConflict }
