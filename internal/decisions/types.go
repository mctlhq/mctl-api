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

// Package decisions is the durable decision record (mctl-api#701, audit
// finding G8 of mctlhq/.github#182): one immutable row per policy decision
// and an append-only list of execution-attempt events under it, so that a
// decision id alone reconstructs intent -> policy -> authority/approval ->
// exact action -> each attempt -> terminal result.
//
// It composes existing identifiers rather than introducing a parallel
// approval framework. A decision mirrors mctl-agents
// orchestrator/policy_checkpoint.py's Decision field for field (verdict,
// code, policy_version, rule_id, action_digest, approval_ref); its approval
// is an existing action approval request (aar_, internal/workitems) whose
// binding is checked, not copied; an attempt references sealed execution
// evidence (ev-, internal/evidence), a runtime execution (ex-) and a
// commerce invocation (inv_) by id.
//
// Digests and references only: no arguments, no target text, no error
// messages, no copies of other records. Retention deletes whole decisions
// (attempts cascade); nothing is ever updated in place.
package decisions

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mctlhq/mctl-api/internal/secretscan"
)

// DecisionIDPrefix labels decision ids.
const DecisionIDPrefix = "dec_"

// SchemaVersion labels every decision payload.
const SchemaVersion = "decisionrecord/v1"

// recordEncodingVersion opens the canonical content encoding, so a future
// encoding can never digest equal to this one.
const recordEncodingVersion = "mctl-decision-record/v1"

// Verdicts, exactly policy_checkpoint.py's ALLOW / DENY / REQUIRE_APPROVAL.
const (
	VerdictAllow           = "allow"
	VerdictDeny            = "deny"
	VerdictRequireApproval = "require_approval"
)

// Decision codes, exactly policy_checkpoint.py's CODE_* constants. Only
// CodeAllowed and CodeApproved permit (Decision.permitted).
const (
	CodeAllowed                = "allowed"
	CodeApproved               = "approved"
	CodeDenied                 = "denied_by_rule"
	CodeApprovalRequired       = "approval_required"
	CodeNoRule                 = "no_matching_rule"
	CodeGrantMissing           = "grant_missing"
	CodeEvaluatorError         = "evaluator_error"
	CodeIdentityUnavailable    = "identity_unavailable"
	CodeApprovalLookupError    = "approval_lookup_error"
	CodeInvalidRequest         = "invalid_request"
	CodeApprovalPending        = "approval_pending"
	CodeApprovalDenied         = "approval_denied"
	CodeApprovalExpired        = "approval_expired"
	CodeApprovalConsumed       = "approval_consumed"
	CodeApprovalIntentMismatch = "approval_intent_mismatch"
	CodeApprovalRefused        = "approval_refused"
)

var validCodes = map[string]bool{
	CodeAllowed: true, CodeApproved: true, CodeDenied: true, CodeApprovalRequired: true,
	CodeNoRule: true, CodeGrantMissing: true, CodeEvaluatorError: true,
	CodeIdentityUnavailable: true, CodeApprovalLookupError: true, CodeInvalidRequest: true,
	CodeApprovalPending: true, CodeApprovalDenied: true, CodeApprovalExpired: true,
	CodeApprovalConsumed: true, CodeApprovalIntentMismatch: true, CodeApprovalRefused: true,
}

// Permitted reports whether code lets the side effect run, the same rule as
// policy_checkpoint.Decision.permitted.
func Permitted(code string) bool {
	return code == CodeAllowed || code == CodeApproved
}

// Attempt event phases. An attempt is opened by one PhaseStarted event and
// closed by at most one terminal event.
const (
	PhaseStarted   = "started"
	PhaseSucceeded = "succeeded"
	PhaseFailed    = "failed"
	// PhasePartial: the attempt ended with some, not all, of its effect
	// applied.
	PhasePartial = "partial"
)

// IsTerminalPhase reports whether phase closes an attempt.
func IsTerminalPhase(phase string) bool {
	return phase == PhaseSucceeded || phase == PhaseFailed || phase == PhasePartial
}

// Derived statuses, never stored.
const (
	// Attempt statuses: a terminal phase, or one of these two for an
	// attempt without a terminal event.
	AttemptInProgress = "in_progress"
	// AttemptUnknown: the attempt never reported an end and a later attempt
	// has started. It is not "failed": its outcome was never observed.
	AttemptUnknown = "unknown"

	// Decision results.
	ResultRefused    = "refused"
	ResultPending    = "pending"
	ResultInProgress = "in_progress"
	ResultSucceeded  = "succeeded"
	ResultFailed     = "failed"
	ResultPartial    = "partial"
)

// Bounds.
const (
	MaxFieldBytes     = 256
	MaxPolicyReasons  = 8
	MaxReasonBytes    = 128
	MaxKeyBytes       = 128
	MaxList           = 200
	defaultList       = 50
	maxAttemptsPerDec = 100
)

var (
	// ErrNotFound: no such decision.
	ErrNotFound = errors.New("decision not found")
	// ErrInvalid: the input fails validation.
	ErrInvalid = errors.New("decision record is invalid")
	// ErrIdempotencyConflict: the idempotency key already names a record
	// with different content.
	ErrIdempotencyConflict = errors.New("idempotency key already names a different record")
	// ErrApprovalBinding: the referenced aar_ is not bound to this action,
	// or is in a state that cannot authorize it.
	ErrApprovalBinding = errors.New("referenced action approval does not authorize this decision")
	// ErrApprovalNotFound: the referenced aar_ does not exist.
	ErrApprovalNotFound = errors.New("referenced action approval not found")
	// ErrUnobservable: a reference could not be read (no store wired, or the
	// read failed). Never reported as absent.
	ErrUnobservable = errors.New("referenced record could not be observed")
	// Attempt refusals, one per reason.
	ErrNotPermitted     = errors.New("decision does not permit execution")
	ErrAlreadySucceeded = errors.New("decision already has a succeeded attempt")
	ErrAttemptNotFound  = errors.New("attempt not found")
	ErrAttemptClosed    = errors.New("attempt already has a terminal event")
	ErrTooManyAttempts  = errors.New("decision has reached its attempt limit")
)

var (
	idRE          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$`)
	reasonRE      = regexp.MustCompile(`^[a-z0-9._:-]+$`)
	codeRE        = regexp.MustCompile(`^[a-z0-9._:-]{1,64}$`)
	digestRE      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	evidenceIDRE  = regexp.MustCompile(`^ev-[0-9a-f]{16}$`)
	runtimeExecRE = regexp.MustCompile(`^ex-[0-9a-f]{16}$`)
)

// Decision is one immutable policy decision.
type Decision struct {
	ID string `json:"id"`

	// Intent: what the decision was about.
	ExecutionID  string `json:"execution_id"`
	WorkItemID   string `json:"work_item_id,omitempty"`
	IntentSource string `json:"intent_source,omitempty"`
	TraceID      string `json:"trace_id,omitempty"`

	// Policy: which rule of which policy said what, and why (reason codes).
	PolicyVersion string   `json:"policy_version"`
	RuleID        string   `json:"rule_id,omitempty"`
	Verdict       string   `json:"verdict"`
	Code          string   `json:"code"`
	PolicyReasons []string `json:"policy_reasons,omitempty"`
	// Permitted is derived from Code, never stored.
	Permitted bool `json:"permitted"`

	// Authority: who acted, for which tenant, under which approval.
	Actor          string `json:"actor"`
	PrincipalID    string `json:"principal_id,omitempty"`
	Tenant         string `json:"tenant,omitempty"`
	ApprovalID     string `json:"approval_id,omitempty"`
	AuthorityBasis string `json:"authority_basis,omitempty"`

	// Exact action, as digests.
	ActionKind   string `json:"action_kind"`
	Operation    string `json:"operation"`
	TargetDigest string `json:"target_digest"`
	ArgsDigest   string `json:"args_digest"`
	ActionDigest string `json:"action_digest"`
	// IntentHash is copied from the referenced aar_ as observed at record
	// time, never taken from the caller. Empty without an approval.
	IntentHash string `json:"intent_hash,omitempty"`

	DecidedAt time.Time `json:"decided_at"`

	// Provenance, server-owned.
	ContentDigest         string    `json:"content_digest"`
	IdempotencyKey        string    `json:"idempotency_key"`
	RecordedBy            string    `json:"recorded_by"`
	RecordedByPrincipalID string    `json:"recorded_by_principal_id,omitempty"`
	RecordedAt            time.Time `json:"recorded_at"`
	SchemaVersion         string    `json:"schema_version"`
}

// DecisionInput records a decision. RecordedBy/RecordedByPrincipalID come
// from authentication, never from a body.
type DecisionInput struct {
	ExecutionID    string
	WorkItemID     string
	IntentSource   string
	TraceID        string
	PolicyVersion  string
	RuleID         string
	Verdict        string
	Code           string
	PolicyReasons  []string
	Actor          string
	PrincipalID    string
	Tenant         string
	ApprovalID     string
	AuthorityBasis string
	ActionKind     string
	Operation      string
	TargetDigest   string
	ArgsDigest     string
	ActionDigest   string
	DecidedAt      time.Time
	IdempotencyKey string

	RecordedBy            string
	RecordedByPrincipalID string
}

// AttemptEvent is one immutable, append-only event of one attempt.
type AttemptEvent struct {
	DecisionID string `json:"decision_id"`
	// Seq orders every event of the decision, gap-free from 1.
	Seq       int    `json:"seq"`
	AttemptNo int    `json:"attempt_no"`
	Phase     string `json:"phase"`

	EvidenceID           string `json:"evidence_id,omitempty"`
	RuntimeExecutionID   string `json:"runtime_execution_id,omitempty"`
	CommerceInvocationID string `json:"commerce_invocation_id,omitempty"`
	ErrorCode            string `json:"error_code,omitempty"`
	ResultDigest         string `json:"result_digest,omitempty"`

	OccurredAt            time.Time `json:"occurred_at"`
	IdempotencyKey        string    `json:"idempotency_key"`
	RecordedBy            string    `json:"recorded_by"`
	RecordedByPrincipalID string    `json:"recorded_by_principal_id,omitempty"`
	RecordedAt            time.Time `json:"recorded_at"`
}

// AttemptInput appends one event. A started event opens attempt n+1 (the
// server assigns the number; AttemptNo must be zero); a terminal event
// names the open attempt it closes.
type AttemptInput struct {
	DecisionID           string
	AttemptNo            int
	Phase                string
	EvidenceID           string
	RuntimeExecutionID   string
	CommerceInvocationID string
	ErrorCode            string
	ResultDigest         string
	OccurredAt           time.Time
	IdempotencyKey       string

	RecordedBy            string
	RecordedByPrincipalID string
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// checkID validates an identifier-shaped field: bounded, no whitespace, no
// free text, and never a credential.
func checkID(field, value string, required bool) error {
	if value == "" {
		if required {
			return invalid("%s is required", field)
		}
		return nil
	}
	if !idRE.MatchString(value) {
		return invalid("%s must be 1-%d bytes of [A-Za-z0-9._:/@+-]", field, MaxFieldBytes)
	}
	if pattern, found := secretscan.Scan([]byte(value)); found {
		return invalid("%s matches a secret pattern (%s)", field, pattern)
	}
	return nil
}

func checkPrefixed(field, value, prefix string, required bool) error {
	if err := checkID(field, value, required); err != nil {
		return err
	}
	if value != "" && !strings.HasPrefix(value, prefix) {
		return invalid("%s must start with %q", field, prefix)
	}
	return nil
}

func checkDigest(field, value string, required bool) error {
	if value == "" && !required {
		return nil
	}
	if !digestRE.MatchString(value) {
		return invalid("%s must be sha256:<64 lowercase hex>", field)
	}
	return nil
}

func (in *DecisionInput) validate() error {
	for _, f := range []struct {
		name, value string
		required    bool
	}{
		{"execution_id", in.ExecutionID, true},
		{"intent_source", in.IntentSource, false},
		{"trace_id", in.TraceID, false},
		{"policy_version", in.PolicyVersion, true},
		{"rule_id", in.RuleID, false},
		{"actor", in.Actor, true},
		{"tenant", in.Tenant, false},
		{"authority_basis", in.AuthorityBasis, false},
		{"action_kind", in.ActionKind, true},
		{"operation", in.Operation, true},
		{"idempotency_key", in.IdempotencyKey, true},
		{"recorded_by", in.RecordedBy, true},
	} {
		if err := checkID(f.name, f.value, f.required); err != nil {
			return err
		}
	}
	if len(in.IdempotencyKey) > MaxKeyBytes {
		return invalid("idempotency_key exceeds %d bytes", MaxKeyBytes)
	}
	if err := checkPrefixed("work_item_id", in.WorkItemID, "wi_", false); err != nil {
		return err
	}
	if err := checkPrefixed("principal_id", in.PrincipalID, "prn_", false); err != nil {
		return err
	}
	if err := checkPrefixed("approval_id", in.ApprovalID, "aar_", false); err != nil {
		return err
	}
	for _, f := range [][2]string{
		{"target_digest", in.TargetDigest}, {"args_digest", in.ArgsDigest}, {"action_digest", in.ActionDigest},
	} {
		if err := checkDigest(f[0], f[1], true); err != nil {
			return err
		}
	}
	switch in.Verdict {
	case VerdictAllow, VerdictDeny, VerdictRequireApproval:
	default:
		return invalid("verdict must be allow, deny or require_approval")
	}
	if !validCodes[in.Code] {
		return invalid("code %q is not a policy checkpoint decision code", in.Code)
	}
	// A permitting code needs a permitting verdict: allowed comes only from
	// an ALLOW rule, approved only from a REQUIRE_APPROVAL rule a human
	// approved. Every refusal code is reachable from any verdict (an
	// evaluator error refuses an ALLOW rule's action too).
	if in.Code == CodeAllowed && in.Verdict != VerdictAllow {
		return invalid("code allowed requires verdict allow")
	}
	if in.Code == CodeApproved && in.Verdict != VerdictRequireApproval {
		return invalid("code approved requires verdict require_approval")
	}
	// approved is exactly the code an approval authorizes; every approval_*
	// refusal may name the approval it refers to; nothing else carries one.
	switch {
	case in.Code == CodeApproved && in.ApprovalID == "":
		return invalid("code approved requires approval_id")
	case in.ApprovalID != "" && in.Code != CodeApproved && !strings.HasPrefix(in.Code, "approval_"):
		return invalid("approval_id is only recorded with code approved or an approval_* code")
	}
	if len(in.PolicyReasons) > MaxPolicyReasons {
		return invalid("policy_reasons must have at most %d entries", MaxPolicyReasons)
	}
	for _, r := range in.PolicyReasons {
		if len(r) > MaxReasonBytes || !reasonRE.MatchString(r) {
			return invalid("policy_reasons entries must be 1-%d bytes of [a-z0-9._:-]", MaxReasonBytes)
		}
	}
	if in.DecidedAt.IsZero() {
		return invalid("decided_at is required")
	}
	return nil
}

func (in *AttemptInput) validate() error {
	if err := checkPrefixed("decision_id", in.DecisionID, DecisionIDPrefix, true); err != nil {
		return err
	}
	if err := checkID("idempotency_key", in.IdempotencyKey, true); err != nil {
		return err
	}
	if len(in.IdempotencyKey) > MaxKeyBytes {
		return invalid("idempotency_key exceeds %d bytes", MaxKeyBytes)
	}
	if err := checkID("recorded_by", in.RecordedBy, true); err != nil {
		return err
	}
	if in.EvidenceID != "" && !evidenceIDRE.MatchString(in.EvidenceID) {
		return invalid("evidence_id must match %s", evidenceIDRE)
	}
	if in.RuntimeExecutionID != "" && !runtimeExecRE.MatchString(in.RuntimeExecutionID) {
		return invalid("runtime_execution_id must match %s", runtimeExecRE)
	}
	if err := checkPrefixed("commerce_invocation_id", in.CommerceInvocationID, "inv_", false); err != nil {
		return err
	}
	if in.ErrorCode != "" && !codeRE.MatchString(in.ErrorCode) {
		return invalid("error_code must be 1-64 bytes of [a-z0-9._:-]: a code, never a message")
	}
	if err := checkDigest("result_digest", in.ResultDigest, false); err != nil {
		return err
	}
	if in.OccurredAt.IsZero() {
		return invalid("occurred_at is required")
	}
	switch in.Phase {
	case PhaseStarted:
		if in.AttemptNo != 0 {
			return invalid("a started event must not name attempt_no: the server assigns it")
		}
		// An opening event has no outcome yet. runtime_execution_id is the
		// one reference known at start.
		if in.EvidenceID != "" || in.ErrorCode != "" || in.ResultDigest != "" || in.CommerceInvocationID != "" {
			return invalid("evidence_id, error_code, result_digest and commerce_invocation_id belong on the terminal event")
		}
	case PhaseSucceeded:
		if in.AttemptNo < 1 {
			return invalid("a terminal event must name the attempt_no it closes")
		}
		if in.ErrorCode != "" {
			return invalid("a succeeded event carries no error_code")
		}
	case PhaseFailed, PhasePartial:
		if in.AttemptNo < 1 {
			return invalid("a terminal event must name the attempt_no it closes")
		}
		if in.ErrorCode == "" {
			return invalid("a %s event requires error_code", in.Phase)
		}
	default:
		return invalid("phase must be started, succeeded, failed or partial")
	}
	return nil
}

// canonicalDigest is sha256 over a length-prefixed encoding of fields, the
// same shape as workitems.IntentHash: unambiguous for any bytes, and
// reproducible by any client without a JSON library.
func canonicalDigest(version string, fields [][2]string) string {
	var b strings.Builder
	b.WriteString(version)
	b.WriteByte('\n')
	for _, f := range fields {
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

// contentDigest identifies a decision's recorded content: every field a
// replay must match (provenance and server-derived fields excluded).
func (in *DecisionInput) contentDigest() string {
	return canonicalDigest(recordEncodingVersion, [][2]string{
		{"execution_id", in.ExecutionID},
		{"work_item_id", in.WorkItemID},
		{"intent_source", in.IntentSource},
		{"trace_id", in.TraceID},
		{"policy_version", in.PolicyVersion},
		{"rule_id", in.RuleID},
		{"verdict", in.Verdict},
		{"code", in.Code},
		{"policy_reasons", strings.Join(in.PolicyReasons, ",")},
		{"actor", in.Actor},
		{"principal_id", in.PrincipalID},
		{"tenant", in.Tenant},
		{"approval_id", in.ApprovalID},
		{"authority_basis", in.AuthorityBasis},
		{"action_kind", in.ActionKind},
		{"operation", in.Operation},
		{"target_digest", in.TargetDigest},
		{"args_digest", in.ArgsDigest},
		{"action_digest", in.ActionDigest},
		{"decided_at", in.DecidedAt.UTC().Format(time.RFC3339Nano)},
	})
}

// TargetDigest is the digest a decision records in place of its target:
// "sha256:" + hex(sha256(target)). Exported so a writer and a reader agree.
func TargetDigest(target string) string {
	sum := sha256.Sum256([]byte(target))
	return "sha256:" + hex.EncodeToString(sum[:])
}
