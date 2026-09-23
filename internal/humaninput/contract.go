// Package humaninput is mctl-api's side of the durable agent-clarification
// contract (mctl-api#261). The contract itself is owned by mctl-agents
// (`orchestrator/human_input.py`, ADR 013): an investigator seals ONE
// HumanInputRequest into mctl-gitops, the DevLoopWorkflow parks in
// WAITING_FOR_INPUT, and a HumanInputResponse signal resumes it.
//
// This package mirrors that contract exactly -- same keys, same
// strictness, same request_hash -- so the API can verify a request it reads
// from gitops before exposing it, and build a response the workflow will
// accept. It owns no state machine: whether a request is still pending is
// always read from the workflow (see temporalclient.QueryHumanInputState).
package humaninput

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Contract constants, mirrored from orchestrator/human_input.py.
const (
	APIVersion   = "humaninput.mctl.ai/v1alpha1"
	RequestKind  = "HumanInputRequest"
	ResponseKind = "HumanInputResponse"
	// MaxRequestTTL bounds expires_at - created_at.
	MaxRequestTTL = 604800 * time.Second
)

// Response types, audiences and context-ref prefixes are closed vocabularies.
var (
	ResponseTypes      = []string{"free_text", "single_choice", "multi_choice", "structured"}
	Audiences          = []string{"work_item_owner", "repo_operators", "tenant_operators"}
	ContextRefPrefixes = []string{"github:", "gitops-file:", "context_snapshot:", "evidence:"}
)

// ErrInvalid wraps every contract violation, so callers can tell a
// malformed or tampered document from an I/O error.
var ErrInvalid = errors.New("invalid human-input document")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Execution is ExecutionCorrelation (orchestrator/context_snapshot.py): the
// execution that asked. TemporalWorkflowID/RunID name the DevLoopWorkflow
// that is waiting for the answer.
type Execution struct {
	Agent                 string  `json:"agent"`
	Environment           string  `json:"environment"`
	TemporalWorkflowID    string  `json:"temporal_workflow_id"`
	TemporalRunID         *string `json:"temporal_run_id"`
	ArgoWorkflowName      *string `json:"argo_workflow_name"`
	TargetRepositorySHA   string  `json:"target_repository_sha"`
	DefinitionVersion     string  `json:"definition_version"`
	DefinitionContentHash string  `json:"definition_content_hash"`
	ProfileVersion        string  `json:"profile_version"`
	ProfileContentHash    string  `json:"profile_content_hash"`
	ReleaseRevision       *int    `json:"release_revision"`
}

// ResponseSpec is the shape of answer a request expects.
type ResponseSpec struct {
	Type      string   `json:"type"`
	Options   []string `json:"options"`
	SchemaRef *string  `json:"schema_ref"`
}

// RequestedFrom is who may answer: Audience is informational, ActorRefs is
// the exact allow-list ("<actor_type>:<actor_id>") a respondent must be in.
type RequestedFrom struct {
	Audience  string   `json:"audience"`
	ActorRefs []string `json:"actor_refs"`
}

// Request is a sealed HumanInputRequest.
type Request struct {
	APIVersion     string         `json:"api_version"`
	Kind           string         `json:"kind"`
	RequestID      string         `json:"request_id"`
	RequestHash    string         `json:"request_hash"`
	QuestionHash   string         `json:"question_hash"`
	RequestVersion *int           `json:"request_version"`
	CreatedAt      string         `json:"created_at"`
	ExpiresAt      string         `json:"expires_at"`
	WorkItemID     string         `json:"work_item_id"`
	Execution      *Execution     `json:"execution"`
	Question       string         `json:"question"`
	Reason         string         `json:"reason"`
	Response       *ResponseSpec  `json:"response"`
	RequestedFrom  *RequestedFrom `json:"requested_from"`
	ContextRefs    []string       `json:"context_refs"`
	Round          *int           `json:"round"`
}

// Respondent identifies who answered.
type Respondent struct {
	ActorType string `json:"actor_type"`
	ActorID   string `json:"actor_id"`
}

// Reference is "actor_type:actor_id", the form requested_from.actor_refs
// entries are compared in.
func (r Respondent) Reference() string { return r.ActorType + ":" + r.ActorID }

// Response is a HumanInputResponse, exactly the payload the DevLoopWorkflow's
// human_input_response signal accepts.
type Response struct {
	APIVersion  string     `json:"api_version"`
	Kind        string     `json:"kind"`
	RequestID   string     `json:"request_id"`
	RequestHash string     `json:"request_hash"`
	Respondent  Respondent `json:"respondent"`
	Surface     string     `json:"surface"`
	Value       any        `json:"value"`
	ReceivedAt  string     `json:"received_at"`
}

// ParseRequest decodes and fully validates a sealed request: unknown keys
// anywhere are rejected (as the Python side does), every required field
// must be present, and request_hash and request_id are recomputed from the
// content. A document that fails any of this was malformed or altered after
// sealing and must not be shown or answered.
func ParseRequest(raw []byte) (*Request, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var r Request
	if err := dec.Decode(&r); err != nil {
		return nil, invalid("decode request: %v", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, invalid("trailing data after the request document")
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

// Validate checks the request's internal consistency and its seal.
func (r *Request) Validate() error {
	if r.APIVersion != APIVersion {
		return invalid("api_version %q, want %q", r.APIVersion, APIVersion)
	}
	if r.Kind != RequestKind {
		return invalid("kind %q, want %q", r.Kind, RequestKind)
	}
	for name, v := range map[string]string{
		"request_id": r.RequestID, "request_hash": r.RequestHash, "question_hash": r.QuestionHash,
		"work_item_id": r.WorkItemID, "question": r.Question, "reason": r.Reason,
	} {
		if v == "" {
			return invalid("%s must be a non-empty string", name)
		}
	}
	if r.RequestVersion == nil {
		return invalid("request_version is required")
	}
	if r.Round == nil {
		one := 1
		r.Round = &one
	}
	if *r.Round < 1 {
		return invalid("round must be >= 1, got %d", *r.Round)
	}
	if r.ContextRefs == nil {
		r.ContextRefs = []string{}
	}
	for _, ref := range r.ContextRefs {
		if !hasAnyPrefix(ref, ContextRefPrefixes) {
			return invalid("context_refs entry %q has no allowed prefix", ref)
		}
	}
	if err := r.Execution.validate(); err != nil {
		return err
	}
	if err := r.Response.validate(); err != nil {
		return err
	}
	if err := r.RequestedFrom.validate(); err != nil {
		return err
	}
	created, err := ParseTime(r.CreatedAt)
	if err != nil {
		return invalid("created_at: %v", err)
	}
	expires, err := ParseTime(r.ExpiresAt)
	if err != nil {
		return invalid("expires_at: %v", err)
	}
	if !expires.After(created) {
		return invalid("expires_at must be strictly after created_at")
	}
	if expires.Sub(created) > MaxRequestTTL {
		return invalid("expires_at is more than %s after created_at", MaxRequestTTL)
	}
	if !strings.HasPrefix(r.RequestHash, "sha256:") {
		return invalid("request_hash must start with sha256:")
	}
	want, err := r.computeHash()
	if err != nil {
		return err
	}
	if want != r.RequestHash {
		return invalid("request_hash does not match the request content (altered after sealing)")
	}
	if r.RequestID != "hir-"+r.RequestHash[7:23] {
		return invalid("request_id does not derive from request_hash")
	}
	return nil
}

// Expires returns the parsed expires_at (the request validated it).
func (r *Request) Expires() time.Time {
	t, _ := ParseTime(r.ExpiresAt)
	return t
}

// computeHash is `_content_payload` + `_hash_bytes(_canonical_json(...))`:
// every field except request_id, request_hash and created_at.
func (r *Request) computeHash() (string, error) {
	e := r.Execution
	options := r.Response.Options
	if options == nil {
		options = []string{}
	}
	payload := map[string]any{
		"api_version":     APIVersion,
		"kind":            RequestKind,
		"request_version": *r.RequestVersion,
		"expires_at":      r.ExpiresAt,
		"work_item_id":    r.WorkItemID,
		"execution": map[string]any{
			"agent":                   e.Agent,
			"environment":             e.Environment,
			"temporal_workflow_id":    e.TemporalWorkflowID,
			"temporal_run_id":         optString(e.TemporalRunID),
			"argo_workflow_name":      optString(e.ArgoWorkflowName),
			"target_repository_sha":   e.TargetRepositorySHA,
			"definition_version":      e.DefinitionVersion,
			"definition_content_hash": e.DefinitionContentHash,
			"profile_version":         e.ProfileVersion,
			"profile_content_hash":    e.ProfileContentHash,
			"release_revision":        *e.ReleaseRevision,
		},
		"question": r.Question,
		"reason":   r.Reason,
		"response": map[string]any{
			"type":       r.Response.Type,
			"options":    options,
			"schema_ref": optString(r.Response.SchemaRef),
		},
		"requested_from": map[string]any{
			"audience":   r.RequestedFrom.Audience,
			"actor_refs": r.RequestedFrom.ActorRefs,
		},
		"context_refs": r.ContextRefs,
		"round":        *r.Round,
	}
	raw, err := canonicalJSON(payload)
	if err != nil {
		return "", err
	}
	return hashBytes(raw), nil
}

func (e *Execution) validate() error {
	if e == nil {
		return invalid("execution is required")
	}
	for name, v := range map[string]string{
		"agent": e.Agent, "environment": e.Environment, "temporal_workflow_id": e.TemporalWorkflowID,
		"target_repository_sha": e.TargetRepositorySHA, "definition_version": e.DefinitionVersion,
		"profile_version": e.ProfileVersion,
	} {
		if v == "" {
			return invalid("execution.%s must be a non-empty string", name)
		}
	}
	for name, v := range map[string]string{
		"definition_content_hash": e.DefinitionContentHash, "profile_content_hash": e.ProfileContentHash,
	} {
		if !strings.HasPrefix(v, "sha256:") {
			return invalid("execution.%s must start with sha256:", name)
		}
	}
	if e.ReleaseRevision == nil {
		return invalid("execution.release_revision is required")
	}
	for name, v := range map[string]*string{"temporal_run_id": e.TemporalRunID, "argo_workflow_name": e.ArgoWorkflowName} {
		if v != nil && *v == "" {
			return invalid("execution.%s must be null or a non-empty string", name)
		}
	}
	return nil
}

func (s *ResponseSpec) validate() error {
	if s == nil {
		return invalid("response is required")
	}
	if !contains(ResponseTypes, s.Type) {
		return invalid("response.type %q is not one of %v", s.Type, ResponseTypes)
	}
	if (s.Type == "single_choice" || s.Type == "multi_choice") && len(s.Options) == 0 {
		return invalid("response.type %q requires a non-empty options list", s.Type)
	}
	if s.SchemaRef != nil && *s.SchemaRef == "" {
		return invalid("response.schema_ref must be null or a non-empty string")
	}
	return nil
}

func (f *RequestedFrom) validate() error {
	if f == nil {
		return invalid("requested_from is required")
	}
	if !contains(Audiences, f.Audience) {
		return invalid("requested_from.audience %q is not one of %v", f.Audience, Audiences)
	}
	if len(f.ActorRefs) == 0 {
		return invalid("requested_from.actor_refs must name at least one actor")
	}
	return nil
}

// ValidateValue is `_validate_value`: the typed check of an answer against
// the request's ResponseSpec.
func ValidateValue(spec ResponseSpec, value any) error {
	switch spec.Type {
	case "free_text":
		s, ok := value.(string)
		if !ok || strings.TrimSpace(s) == "" {
			return invalid("free_text answer must be a non-empty string")
		}
	case "single_choice":
		s, ok := value.(string)
		if !ok || !contains(spec.Options, s) {
			return invalid("single_choice answer must be one of %v", spec.Options)
		}
	case "multi_choice":
		list, ok := value.([]any)
		if !ok || len(list) == 0 {
			return invalid("multi_choice answer must be a non-empty list")
		}
		for _, v := range list {
			s, ok := v.(string)
			if !ok || !contains(spec.Options, s) {
				return invalid("multi_choice answer items must be among %v", spec.Options)
			}
		}
	case "structured":
		if _, ok := value.(map[string]any); !ok {
			return invalid("structured answer must be an object")
		}
	default:
		return invalid("unknown response type %q", spec.Type)
	}
	return nil
}

// CanRespond reports whether ref is in the request's explicit allow-list.
// Exact, case-sensitive match -- the same rule validate_response applies.
func (r *Request) CanRespond(ref string) bool {
	return contains(r.RequestedFrom.ActorRefs, ref)
}

// ParseTime accepts what Python's datetime.fromisoformat accepts in these
// documents: RFC 3339 with Z or an offset, or a naive timestamp (UTC).
func ParseTime(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("%q is not an ISO-8601 timestamp", s)
}

func optString(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
