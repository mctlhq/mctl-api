// Copyright 2025 MCTL Authors
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

// Package securityfindings is the durable SecurityFinding v1 store
// (mctlhq/.github#209, mctl-api#774): a provider-neutral lifecycle that
// deduplicates observations, binds remediation to exact affected and fixed
// revisions, verifies the fix and reopens on regression. The normative
// contract is docs/security-findings.md.
//
// Three levels: SecurityFinding (canonical problem identity) ->
// SecurityOccurrence (one concrete affected subject; the only level that owns
// lifecycle state) -> RemediationAttempt[] (the history of fix cycles).
// ProviderObservations and VerificationRecords are append-only evidence.
package securityfindings

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// SchemaVersion labels every row this package writes.
const SchemaVersion = "securityfinding/v1"

// ID prefixes.
const (
	FindingIDPrefix      = "sf_"
	OccurrenceIDPrefix   = "soc_"
	ObservationIDPrefix  = "sob_"
	AttemptIDPrefix      = "sra_"
	VerificationIDPrefix = "svr_"
)

// Occurrence states. Lifecycle state lives only on the occurrence.
const (
	StateOpen                 = "open"
	StateTriaged              = "triaged"
	StateFixing               = "fixing"
	StateAwaitingVerification = "awaiting_verification"
	StateResolved             = "resolved"
	StateReopened             = "reopened"
	StateUnverifiable         = "unverifiable"
	StateDismissed            = "dismissed"
)

// States lists every occurrence state.
var States = []string{
	StateOpen, StateTriaged, StateFixing, StateAwaitingVerification,
	StateResolved, StateReopened, StateUnverifiable, StateDismissed,
}

// Transition actions. There is deliberately no generic set-state action.
const (
	ActionTriage             = "triage"
	ActionStartRemediation   = "start_remediation"
	ActionRecordFix          = "record_fix"
	ActionVerifyPassed       = "verify_passed"
	ActionVerifyFailed       = "verify_failed"
	ActionVerifyInconclusive = "verify_inconclusive"
	ActionVerifyUnverifiable = "verify_unverifiable"
	ActionRegress            = "regress"
	ActionDismiss            = "dismiss"
)

// Transitions maps state -> action -> next state. It is the single
// enforcement point for lifecycle rules, like workitems.Transitions: any move
// not listed here is refused with ErrInvalidTransition.
var Transitions = map[string]map[string]string{
	StateOpen: {
		ActionTriage:           StateTriaged,
		ActionStartRemediation: StateFixing,
		ActionDismiss:          StateDismissed,
	},
	StateTriaged: {
		ActionStartRemediation: StateFixing,
		ActionDismiss:          StateDismissed,
	},
	StateReopened: {
		ActionTriage:           StateTriaged,
		ActionStartRemediation: StateFixing,
		ActionDismiss:          StateDismissed,
	},
	StateUnverifiable: {
		ActionStartRemediation: StateFixing,
		ActionDismiss:          StateDismissed,
	},
	StateFixing: {
		ActionRecordFix: StateAwaitingVerification,
		ActionDismiss:   StateDismissed,
	},
	StateAwaitingVerification: {
		ActionVerifyPassed:       StateResolved,
		ActionVerifyFailed:       StateFixing,
		ActionVerifyInconclusive: StateAwaitingVerification,
		ActionVerifyUnverifiable: StateUnverifiable,
		ActionDismiss:            StateDismissed,
	},
	StateResolved: {
		ActionRegress: StateReopened,
	},
	StateDismissed: {},
}

// Next returns the state reached by action from state, or
// ErrInvalidTransition.
func Next(state, action string) (string, error) {
	to, ok := Transitions[state][action]
	if !ok {
		return "", fmt.Errorf("%w: %s from %s", ErrInvalidTransition, action, state)
	}
	return to, nil
}

// Claimed actions of a provider observation.
const (
	ClaimPresent   = "present"
	ClaimFixed     = "fixed"
	ClaimAbsent    = "absent"
	ClaimWithdrawn = "withdrawn"
)

// Attempt outcomes. A nil outcome is an active attempt.
const (
	OutcomeResolved           = "resolved"
	OutcomeSuperseded         = "superseded"
	OutcomeCancelledDismissed = "cancelled_dismissed"
)

// Verification results.
const (
	ResultPassed       = "passed"
	ResultFailed       = "failed"
	ResultUnavailable  = "unavailable"
	ResultError        = "error"
	ResultTimeout      = "timeout"
	ResultUnverifiable = "unverifiable"
)

// Dismissal reasons.
const (
	DismissFalsePositive     = "false_positive"
	DismissAcceptedRisk      = "accepted_risk"
	DismissDuplicate         = "duplicate"
	DismissNotApplicable     = "not_applicable"
	DismissProviderWithdrawn = "provider_withdrawn"
)

var dismissalReasons = map[string]bool{
	DismissFalsePositive: true, DismissAcceptedRisk: true, DismissDuplicate: true,
	DismissNotApplicable: true, DismissProviderWithdrawn: true,
}

// Strength is the strength of a verification, ordered strongest first below.
type Strength string

// Verification strengths, strongest to weakest.
const (
	StrengthDeterministicRegressionTest Strength = "deterministic_regression_test"
	StrengthAssuranceReplay             Strength = "assurance_replay"
	StrengthScannerRerunExactRevision   Strength = "scanner_rerun_exact_revision"
	StrengthProviderClaim               Strength = "provider_claim"
	StrengthManual                      Strength = "manual"
)

var strengthRank = map[Strength]int{
	StrengthDeterministicRegressionTest: 5,
	StrengthAssuranceReplay:             4,
	StrengthScannerRerunExactRevision:   3,
	StrengthProviderClaim:               2,
	StrengthManual:                      1,
}

// DefaultMinStrength is the weakest verification that may resolve an
// occurrence unless configured otherwise.
const DefaultMinStrength = StrengthScannerRerunExactRevision

// ParseStrength validates a strength name.
func ParseStrength(s string) (Strength, error) {
	st := Strength(strings.TrimSpace(s))
	if _, ok := strengthRank[st]; !ok {
		return "", fmt.Errorf("%w: unknown verification strength %q", ErrInvalid, s)
	}
	return st, nil
}

// AtLeast reports whether s is at least as strong as other.
func (s Strength) AtLeast(other Strength) bool { return strengthRank[s] >= strengthRank[other] }

// MinStrength returns the weaker of two strengths.
func MinStrength(a, b Strength) Strength {
	if strengthRank[a] <= strengthRank[b] {
		return a
	}
	return b
}

// Sentinel errors. Each maps to one status and typed code in the API.
var (
	ErrNotFound            = errors.New("securityfindings: not found")
	ErrInvalid             = errors.New("securityfindings: invalid request")
	ErrInvalidTransition   = errors.New("securityfindings: invalid transition")
	ErrAttemptActive       = errors.New("securityfindings: remediation attempt already active")
	ErrNotBound            = errors.New("securityfindings: verification not bound to the landed revision or artifact")
	ErrSubjectTooWeak      = errors.New("securityfindings: subject too weak to identify one occurrence")
	ErrAliasConflict       = errors.New("securityfindings: aliases resolve to different findings")
	ErrIdempotencyKeyReuse = errors.New("securityfindings: idempotency key reused with a different request or actor")
	ErrVersionConflict     = errors.New("securityfindings: state version conflict")
	ErrWorkItemNotFound    = errors.New("securityfindings: work item not found")
	ErrWorkItemsUnavail    = errors.New("securityfindings: work items store unavailable")
	ErrTenantNotAllowed    = errors.New("securityfindings: tenant not allowed for this provider")
)

// Size caps for the bounded untrusted object and request fields.
const (
	MaxBatchItems          = 100
	MaxUntrustedTitle      = 256
	MaxUntrustedSeverity   = 32
	MaxUntrustedDescripton = 4096
	MaxUntrustedProvider   = 128
	MaxEvidenceRefs        = 32
	MaxRefLen              = 512
	MaxAliases             = 16
	maxFieldLen            = 512
)

// Untrusted is the provider's free text. It is inert data: no transition,
// policy or authorization code reads it, and no transition input type has
// a field of this type.
type Untrusted struct {
	Title           string `json:"title,omitempty"`
	Description     string `json:"description,omitempty"`
	Severity        string `json:"severity,omitempty"`
	ClaimedProvider string `json:"claimed_provider,omitempty"`
}

func (u Untrusted) validate() error {
	switch {
	case len(u.Title) > MaxUntrustedTitle:
		return fmt.Errorf("%w: untrusted.title exceeds %d bytes", ErrInvalid, MaxUntrustedTitle)
	case len(u.Severity) > MaxUntrustedSeverity:
		return fmt.Errorf("%w: untrusted.severity exceeds %d bytes", ErrInvalid, MaxUntrustedSeverity)
	case len(u.Description) > MaxUntrustedDescripton:
		return fmt.Errorf("%w: untrusted.description exceeds %d bytes", ErrInvalid, MaxUntrustedDescripton)
	case len(u.ClaimedProvider) > MaxUntrustedProvider:
		return fmt.Errorf("%w: untrusted.claimed_provider exceeds %d bytes", ErrInvalid, MaxUntrustedProvider)
	}
	return nil
}

// Subject is the concrete thing an occurrence is about.
type Subject struct {
	Repository     string `json:"repository,omitempty"`
	Resource       string `json:"resource,omitempty"`
	PackagePURL    string `json:"package_purl,omitempty"`
	Path           string `json:"path,omitempty"`
	Location       string `json:"location,omitempty"`
	ArtifactDigest string `json:"artifact_digest,omitempty"`
	Service        string `json:"service,omitempty"`
	RuleID         string `json:"rule_id,omitempty"`
}

// EvidenceRef points at evidence held elsewhere; the store keeps references,
// never scanner or code payloads.
type EvidenceRef struct {
	Kind   string `json:"kind"`
	Ref    string `json:"ref"`
	Digest string `json:"digest,omitempty"`
}

func validateRefs(refs []EvidenceRef) error {
	if len(refs) > MaxEvidenceRefs {
		return fmt.Errorf("%w: more than %d evidence refs", ErrInvalid, MaxEvidenceRefs)
	}
	for _, r := range refs {
		if strings.TrimSpace(r.Kind) == "" || strings.TrimSpace(r.Ref) == "" {
			return fmt.Errorf("%w: evidence ref needs kind and ref", ErrInvalid)
		}
		if len(r.Kind) > maxFieldLen || len(r.Ref) > MaxRefLen || len(r.Digest) > maxFieldLen {
			return fmt.Errorf("%w: evidence ref too long", ErrInvalid)
		}
	}
	return nil
}

// ObservationInput is one item of an ingest batch. Its provider identity is
// deliberately absent: it comes from the authenticated channel.
type ObservationInput struct {
	Tenant                 string        `json:"tenant"`
	Identity               string        `json:"identity"`
	Aliases                []string      `json:"aliases,omitempty"`
	Subject                Subject       `json:"subject"`
	SourceFindingID        string        `json:"source_finding_id,omitempty"`
	ClaimedAction          string        `json:"claimed_action,omitempty"`
	ObservedRevision       string        `json:"observed_revision,omitempty"`
	ObservedArtifactDigest string        `json:"observed_artifact_digest,omitempty"`
	EvidenceRefs           []EvidenceRef `json:"evidence_refs,omitempty"`
	ObservedAt             *time.Time    `json:"observed_at,omitempty"`
	Untrusted              Untrusted     `json:"untrusted,omitempty"`
}

func (o *ObservationInput) validate() error {
	o.Tenant = strings.TrimSpace(o.Tenant)
	o.Identity = strings.TrimSpace(o.Identity)
	o.SourceFindingID = strings.TrimSpace(o.SourceFindingID)
	o.ObservedRevision = strings.TrimSpace(o.ObservedRevision)
	o.ObservedArtifactDigest = strings.ToLower(strings.TrimSpace(o.ObservedArtifactDigest))
	if o.ClaimedAction == "" {
		o.ClaimedAction = ClaimPresent
	}
	switch {
	case o.Tenant == "":
		return fmt.Errorf("%w: tenant is required", ErrInvalid)
	case o.Identity == "":
		return fmt.Errorf("%w: identity is required", ErrInvalid)
	case len(o.Identity) > maxFieldLen || len(o.SourceFindingID) > maxFieldLen ||
		len(o.ObservedRevision) > maxFieldLen || len(o.ObservedArtifactDigest) > maxFieldLen:
		return fmt.Errorf("%w: field too long", ErrInvalid)
	case len(o.Aliases) > MaxAliases:
		return fmt.Errorf("%w: more than %d aliases", ErrInvalid, MaxAliases)
	}
	switch o.ClaimedAction {
	case ClaimPresent, ClaimFixed, ClaimAbsent, ClaimWithdrawn:
	default:
		return fmt.Errorf("%w: unsupported claimed_action %q", ErrInvalid, o.ClaimedAction)
	}
	if err := validateRefs(o.EvidenceRefs); err != nil {
		return err
	}
	return o.Untrusted.validate()
}

// Batch is one delivery of observations.
type Batch struct {
	DeliveryID   string             `json:"delivery_id,omitempty"`
	Observations []ObservationInput `json:"observations"`
}

// ProviderContext is what the server knows about the authenticated provider.
// None of it comes from the request body.
type ProviderContext struct {
	Ref         string
	MaxStrength Strength
	Tenants     []string
	// AnyTenant is set only for an admin ingesting directly.
	AnyTenant   bool
	PrincipalID string
}

func (p ProviderContext) allowsTenant(t string) bool {
	if p.AnyTenant {
		return true
	}
	for _, a := range p.Tenants {
		if a == t {
			return true
		}
	}
	return false
}

// Actor records who made a mutation. Every transition stores all of it.
type Actor struct {
	Principal   string // e.g. github:alice, service:..., agent:name, provider:trivy
	PrincipalID string // canonical prn_ id when resolved
	ViaID       string // relaying principal, when any
	Source      string // provider:<ref>, api, agent:<name>
}

func (a Actor) validate() error {
	if strings.TrimSpace(a.Principal) == "" {
		return fmt.Errorf("%w: actor principal is required", ErrInvalid)
	}
	return nil
}

// Item result statuses of an ingest batch.
const (
	ItemCreated   = "created"
	ItemDuplicate = "duplicate"
	ItemRejected  = "rejected"
)

// Reject codes of an ingest item.
const (
	CodeSubjectTooWeak = "subject_too_weak"
	CodeAliasConflict  = "finding_alias_conflict"
	CodeInvalid        = "invalid_request"
	CodeTenantDenied   = "tenant_not_allowed"
	CodeInternal       = "internal_error"
)

// ItemResult is the outcome of one batch item.
type ItemResult struct {
	Status        string `json:"status"`
	Code          string `json:"code,omitempty"`
	Message       string `json:"message,omitempty"`
	FindingID     string `json:"finding_id,omitempty"`
	OccurrenceID  string `json:"occurrence_id,omitempty"`
	ObservationID string `json:"observation_id,omitempty"`
	Transition    string `json:"transition,omitempty"`
}

// MutationResult is the outcome of a remediation-side mutation. It is stored
// with the idempotency key so a replay returns the original answer.
type MutationResult struct {
	OccurrenceID   string `json:"occurrence_id"`
	AttemptID      string `json:"attempt_id,omitempty"`
	VerificationID string `json:"verification_id,omitempty"`
	State          string `json:"state"`
	StateVersion   int64  `json:"state_version"`
	Transition     string `json:"transition,omitempty"`
	Replayed       bool   `json:"replayed,omitempty"`
}

// TriageInput moves an occurrence to triaged.
type TriageInput struct {
	OccurrenceID    string
	ExpectedVersion *int64
	IdempotencyKey  string
	Reason          string
	Actor           Actor
}

// StartRemediationInput starts a new attempt bound to a WorkItem.
type StartRemediationInput struct {
	OccurrenceID      string `json:"-"`
	WorkItemID        string `json:"work_item_id"`
	ExecutionID       string `json:"execution_id,omitempty"`
	DevloopWorkflowID string `json:"devloop_workflow_id,omitempty"`
	StartSource       string `json:"start_source,omitempty"`
	ExpectedVersion   *int64 `json:"expected_state_version,omitempty"`
	IdempotencyKey    string `json:"-"`
	Actor             Actor  `json:"-"`
}

// RecordFixInput records a candidate or landed fix on the active attempt.
type RecordFixInput struct {
	AttemptID            string `json:"-"`
	CandidateRevision    string `json:"candidate_revision,omitempty"`
	Landed               bool   `json:"landed"`
	LandedRevision       string `json:"landed_revision,omitempty"`
	LandedArtifactDigest string `json:"landed_artifact_digest,omitempty"`
	LandedRef            string `json:"landed_ref,omitempty"`
	ExpectedVersion      *int64 `json:"expected_state_version,omitempty"`
	IdempotencyKey       string `json:"-"`
	Actor                Actor  `json:"-"`
}

// RecordVerificationInput records a verification of the landed fix.
type RecordVerificationInput struct {
	AttemptID       string        `json:"-"`
	Mechanism       Strength      `json:"mechanism"`
	Result          string        `json:"result"`
	Revision        string        `json:"revision,omitempty"`
	ArtifactDigest  string        `json:"artifact_digest,omitempty"`
	EvidenceRefs    []EvidenceRef `json:"evidence_refs,omitempty"`
	ExpectedVersion *int64        `json:"expected_state_version,omitempty"`
	IdempotencyKey  string        `json:"-"`
	Actor           Actor         `json:"-"`
	// Ceiling is the strongest strength the authenticated recorder may
	// assert. Set by the server from the recorder's identity, never from
	// the request.
	Ceiling Strength `json:"-"`
}

// DismissInput dismisses an occurrence. The API admits it for a human only.
type DismissInput struct {
	OccurrenceID    string `json:"-"`
	Reason          string `json:"reason"`
	AuthorityRef    string `json:"authority_ref"`
	Note            string `json:"note,omitempty"`
	ExpectedVersion *int64 `json:"expected_state_version,omitempty"`
	IdempotencyKey  string `json:"-"`
	Actor           Actor  `json:"-"`
}

func validResult(r string) bool {
	switch r {
	case ResultPassed, ResultFailed, ResultUnavailable, ResultError, ResultTimeout, ResultUnverifiable:
		return true
	}
	return false
}

func (in *RecordVerificationInput) validate() error {
	in.Revision = strings.TrimSpace(in.Revision)
	in.ArtifactDigest = strings.ToLower(strings.TrimSpace(in.ArtifactDigest))
	if !validResult(in.Result) {
		return fmt.Errorf("%w: unsupported result %q", ErrInvalid, in.Result)
	}
	if _, err := ParseStrength(string(in.Mechanism)); err != nil {
		return err
	}
	if in.Ceiling == "" {
		return fmt.Errorf("%w: recorder ceiling is required", ErrInvalid)
	}
	if len(in.Revision) > maxFieldLen || len(in.ArtifactDigest) > maxFieldLen {
		return fmt.Errorf("%w: field too long", ErrInvalid)
	}
	if err := validateRefs(in.EvidenceRefs); err != nil {
		return err
	}
	return in.Actor.validate()
}

func (in *RecordFixInput) validate() error {
	in.CandidateRevision = strings.TrimSpace(in.CandidateRevision)
	in.LandedRevision = strings.TrimSpace(in.LandedRevision)
	in.LandedArtifactDigest = strings.ToLower(strings.TrimSpace(in.LandedArtifactDigest))
	in.LandedRef = strings.TrimSpace(in.LandedRef)
	if len(in.CandidateRevision) > maxFieldLen || len(in.LandedRevision) > maxFieldLen ||
		len(in.LandedArtifactDigest) > maxFieldLen || len(in.LandedRef) > MaxRefLen {
		return fmt.Errorf("%w: field too long", ErrInvalid)
	}
	if in.Landed && in.LandedRevision == "" && in.LandedArtifactDigest == "" {
		return fmt.Errorf("%w: a landed fix needs landed_revision or landed_artifact_digest", ErrInvalid)
	}
	if !in.Landed && (in.LandedRevision != "" || in.LandedArtifactDigest != "" || in.LandedRef != "") {
		return fmt.Errorf("%w: landed_* fields require landed=true", ErrInvalid)
	}
	if !in.Landed && in.CandidateRevision == "" {
		return fmt.Errorf("%w: nothing to record", ErrInvalid)
	}
	return in.Actor.validate()
}

func (in *DismissInput) validate() error {
	in.AuthorityRef = strings.TrimSpace(in.AuthorityRef)
	in.Note = strings.TrimSpace(in.Note)
	if !dismissalReasons[in.Reason] {
		return fmt.Errorf("%w: dismissal reason must be one of false_positive, accepted_risk, duplicate, not_applicable, provider_withdrawn", ErrInvalid)
	}
	if in.AuthorityRef == "" {
		return fmt.Errorf("%w: authority_ref is required", ErrInvalid)
	}
	if len(in.AuthorityRef) > MaxRefLen || len(in.Note) > MaxUntrustedDescripton {
		return fmt.Errorf("%w: field too long", ErrInvalid)
	}
	return in.Actor.validate()
}

func (in *StartRemediationInput) validate() error {
	in.WorkItemID = strings.TrimSpace(in.WorkItemID)
	in.ExecutionID = strings.TrimSpace(in.ExecutionID)
	in.DevloopWorkflowID = strings.TrimSpace(in.DevloopWorkflowID)
	in.StartSource = strings.TrimSpace(in.StartSource)
	if !strings.HasPrefix(in.WorkItemID, "wi_") {
		return fmt.Errorf("%w: work_item_id must be a wi_ id", ErrInvalid)
	}
	if in.ExecutionID != "" && !strings.HasPrefix(in.ExecutionID, "we_") {
		return fmt.Errorf("%w: execution_id must be a we_ id", ErrInvalid)
	}
	if len(in.DevloopWorkflowID) > maxFieldLen || len(in.StartSource) > maxFieldLen {
		return fmt.Errorf("%w: field too long", ErrInvalid)
	}
	return in.Actor.validate()
}

// Read models.

// Finding is the canonical problem identity.
type Finding struct {
	ID             string       `json:"id"`
	Tenant         string       `json:"tenant"`
	IdentityKind   string       `json:"identity_kind"`
	IdentityKey    string       `json:"identity_key"`
	CreatedAt      time.Time    `json:"created_at"`
	LastObservedAt time.Time    `json:"last_observed_at"`
	SchemaVersion  string       `json:"schema_version"`
	Aliases        []string     `json:"aliases,omitempty"`
	Occurrences    []Occurrence `json:"occurrences,omitempty"`
}

// Occurrence is one concrete affected subject and owns the lifecycle.
type Occurrence struct {
	ID                      string    `json:"id"`
	FindingID               string    `json:"finding_id"`
	Tenant                  string    `json:"tenant"`
	SubjectFingerprint      string    `json:"subject_fingerprint"`
	Subject                 Subject   `json:"subject"`
	State                   string    `json:"state"`
	StateVersion            int64     `json:"state_version"`
	ActiveAttemptID         string    `json:"active_attempt_id,omitempty"`
	CurrentAffectedRevision string    `json:"current_affected_revision,omitempty"`
	CurrentAffectedArtifact string    `json:"current_affected_artifact,omitempty"`
	DismissalReason         string    `json:"dismissal_reason,omitempty"`
	DismissalAuthorityRef   string    `json:"dismissal_authority_ref,omitempty"`
	DismissedBy             string    `json:"dismissed_by,omitempty"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
	LastObservedAt          time.Time `json:"last_observed_at"`

	Observations  []Observation  `json:"observations,omitempty"`
	Attempts      []Attempt      `json:"remediation_attempts,omitempty"`
	Verifications []Verification `json:"verifications,omitempty"`
	Events        []Event        `json:"events,omitempty"`
}

// Observation is append-only evidence on an occurrence.
type Observation struct {
	ID                     string        `json:"id"`
	OccurrenceID           string        `json:"occurrence_id"`
	ProviderRef            string        `json:"provider_ref"`
	ObservationHash        string        `json:"observation_hash"`
	DeliveryID             string        `json:"delivery_id,omitempty"`
	SourceFindingID        string        `json:"source_finding_id,omitempty"`
	ClaimedAction          string        `json:"claimed_action"`
	ObservedRevision       string        `json:"observed_revision,omitempty"`
	ObservedArtifactDigest string        `json:"observed_artifact_digest,omitempty"`
	EvidenceRefs           []EvidenceRef `json:"evidence_refs,omitempty"`
	Untrusted              Untrusted     `json:"untrusted"`
	ObservedAt             time.Time     `json:"observed_at"`
	IngestedAt             time.Time     `json:"ingested_at"`
}

// Attempt is one remediation cycle.
type Attempt struct {
	ID                   string     `json:"id"`
	OccurrenceID         string     `json:"occurrence_id"`
	Seq                  int        `json:"seq"`
	WorkItemID           string     `json:"work_item_id"`
	ExecutionID          string     `json:"execution_id,omitempty"`
	DevloopWorkflowID    string     `json:"devloop_workflow_id,omitempty"`
	StartedBy            string     `json:"started_by"`
	StartSource          string     `json:"start_source,omitempty"`
	AffectedRevisions    []string   `json:"affected_revisions"`
	CandidateRevision    string     `json:"candidate_revision,omitempty"`
	LandedRevision       string     `json:"landed_revision,omitempty"`
	LandedArtifactDigest string     `json:"landed_artifact_digest,omitempty"`
	LandedRef            string     `json:"landed_ref,omitempty"`
	Outcome              string     `json:"outcome,omitempty"`
	StartedAt            time.Time  `json:"started_at"`
	LandedAt             *time.Time `json:"landed_at,omitempty"`
	EndedAt              *time.Time `json:"ended_at,omitempty"`
}

// Verification is an immutable record of one verification.
type Verification struct {
	ID                  string        `json:"id"`
	AttemptID           string        `json:"attempt_id"`
	OccurrenceID        string        `json:"occurrence_id"`
	Mechanism           Strength      `json:"mechanism"`
	DeclaredStrength    Strength      `json:"declared_strength"`
	DerivedStrength     Strength      `json:"derived_strength"`
	Result              string        `json:"result"`
	Revision            string        `json:"revision,omitempty"`
	ArtifactDigest      string        `json:"artifact_digest,omitempty"`
	EvidenceRefs        []EvidenceRef `json:"evidence_refs,omitempty"`
	RecordedBy          string        `json:"recorded_by"`
	SourceObservationID string        `json:"source_observation_id,omitempty"`
	RecordedAt          time.Time     `json:"recorded_at"`
}

// Event is one append-only lifecycle record of an occurrence.
type Event struct {
	OccurrenceID     string            `json:"occurrence_id"`
	Seq              int               `json:"seq"`
	Kind             string            `json:"kind"`
	FromState        string            `json:"from_state,omitempty"`
	ToState          string            `json:"to_state,omitempty"`
	ActorPrincipal   string            `json:"actor_principal"`
	ActorPrincipalID string            `json:"actor_principal_id,omitempty"`
	ViaPrincipalID   string            `json:"via_principal_id,omitempty"`
	Source           string            `json:"source"`
	Reason           string            `json:"reason,omitempty"`
	Refs             map[string]string `json:"refs,omitempty"`
	CreatedAt        time.Time         `json:"created_at"`
}

// Visibility limits reads to the tenants a caller can access. Admins use All.
type Visibility struct {
	All     bool
	Tenants []string
}

func (v Visibility) allows(tenant string) bool {
	if v.All {
		return true
	}
	for _, t := range v.Tenants {
		if t == tenant {
			return true
		}
	}
	return false
}

// ListFilter selects findings or occurrences.
type ListFilter struct {
	Tenant     string
	State      string
	Repository string
	Identity   string
	FindingID  string
	Limit      int
	Cursor     string
}
