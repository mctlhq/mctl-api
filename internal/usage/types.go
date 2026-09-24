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

// Package usage is the durable model-usage and cost ledger (mctl-api#266).
//
// The contract it implements is ADR-012 in mctlhq/mctl-agents
// (docs/adr/012-model-usage-cost-attribution-contract.md). Two of that ADR's
// rules shape every type in this file and are easy to undo by accident:
//
//   - Absent is not zero. A provider that does not report cache tokens and a
//     run that read no cache are different facts. Every counter is therefore a
//     *int64, not an int64, and a consumer summing a column can tell "nothing
//     was spent" from "nothing was measured".
//   - The record has no field that can hold prompt or completion text. That is
//     enforced by construction here, not by a redaction pass somewhere else: if
//     there is nowhere to put it, no producer can leak it.
package usage

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SchemaVersion is the envelope compatibility gate from ADR-012. A consumer
// that does not understand a version refuses the record rather than silently
// misreading it.
const SchemaVersion = 1

// Terminal outcomes of a model invocation.
const (
	OutcomeSuccess     = "success"
	OutcomeError       = "error"
	OutcomeInterrupted = "interrupted"
)

// Cost classifications. They are separate fields on the record rather than one
// number with a label, because the whole point is that an estimate must never
// be readable as invoice truth.
const (
	CostProviderReported  = "provider_reported"
	CostCalculated        = "calculated"
	CostInvoiceReconciled = "invoice_reconciled"
)

// Providers as served by the Claude Agent SDK's ModelUsage.provider.
const (
	ProviderFirstParty = "firstParty"
	ProviderBedrock    = "bedrock"
	ProviderVertex     = "vertex"
)

var (
	// ErrUnsupportedSchema is returned for a record whose schema_version this
	// build does not understand.
	ErrUnsupportedSchema = errors.New("usage: unsupported schema version")
	// ErrInvalidRecord is returned when a record cannot be identified or
	// violates an invariant that the store would otherwise persist.
	ErrInvalidRecord = errors.New("usage: invalid record")
	// ErrNoPricing is returned when no pricing entry matches a record at its
	// recorded_at instant.
	ErrNoPricing = errors.New("usage: no pricing entry for model at that time")
)

// Record is one paid model invocation, at the grain (run, model).
//
// The grain follows the SDK: a ResultMessage carries model_usage keyed by
// model, so a run that spans two models produces two records sharing a
// temporal_workflow_id and differing in ModelKey.
type Record struct {
	SchemaVersion int `json:"schema_version"`

	// Identity and dedupe.
	ID             string `json:"id"`
	SessionID      string `json:"session_id"`
	ResultUUID     string `json:"result_uuid,omitempty"`
	ModelKey       string `json:"model_key"`
	CanonicalModel string `json:"canonical_model,omitempty"`
	Provider       string `json:"provider,omitempty"`

	// Correlation.
	TemporalWorkflowID string `json:"temporal_workflow_id,omitempty"`
	ArgoWorkflowName   string `json:"argo_workflow_name,omitempty"`
	Agent              string `json:"agent,omitempty"`
	DevLoopStage       string `json:"devloop_stage,omitempty"`
	TargetRepo         string `json:"target_repo,omitempty"`
	IssueNumber        *int64 `json:"issue_number,omitempty"`
	PRNumber           *int64 `json:"pr_number,omitempty"`
	WorkItemID         string `json:"work_item_id,omitempty"`
	TraceID            string `json:"trace_id,omitempty"`
	SpanID             string `json:"span_id,omitempty"`

	// Usage. Nil means the provider did not report it — see the package doc.
	InputTokens       *int64 `json:"input_tokens,omitempty"`
	OutputTokens      *int64 `json:"output_tokens,omitempty"`
	CacheReadTokens   *int64 `json:"cache_read_tokens,omitempty"`
	CacheWriteTokens  *int64 `json:"cache_write_tokens,omitempty"`
	ReasoningTokens   *int64 `json:"reasoning_tokens,omitempty"`
	WebSearchRequests *int64 `json:"web_search_requests,omitempty"`

	// Cost. ProviderReportedCost is null for every record produced under the
	// subscription decision; it exists so that a future provider that does
	// report cost is not forced through the calculated path.
	ProviderReportedCost  *float64 `json:"provider_reported_cost,omitempty"`
	CalculatedCost        *float64 `json:"calculated_cost,omitempty"`
	PricingVersion        string   `json:"pricing_version,omitempty"`
	InvoiceReconciledCost *float64 `json:"invoice_reconciled_cost,omitempty"`

	// Outcome.
	Outcome        string `json:"outcome,omitempty"`
	APIErrorStatus string `json:"api_error_status,omitempty"`
	StopReason     string `json:"stop_reason,omitempty"`
	TerminalReason string `json:"terminal_reason,omitempty"`
	NumTurns       *int64 `json:"num_turns,omitempty"`
	DurationAPIMs  *int64 `json:"duration_api_ms,omitempty"`
	RetryAttempt   *int64 `json:"retry_attempt,omitempty"`

	RecordedAt time.Time `json:"recorded_at"`

	// Attribution (mctlhq/.github#50): who appended the row. Set by the
	// server from the authenticated caller; a producer cannot choose it.
	IngestedBy            string `json:"ingested_by,omitempty"`
	IngestedByPrincipalID string `json:"ingested_by_principal_id,omitempty"`
}

// DeterministicID is the dedupe key from ADR-012:
//
//	id = sha256(session_id | result_uuid | model_key)
//
// It is deterministic on purpose. A random id would make every replay a new
// row, which is exactly the double-count this ledger exists to prevent.
//
// result_uuid is nullable on older CLIs. When it is absent the id falls back to
// sha256(session_id | model_key | num_turns): session_id plus the model is
// already unique per run, and num_turns keeps two records from colliding if a
// single session ever emits two results for one model.
//
// The parts are length-prefixed and the two shapes carry different
// discriminators, so no combination of field values can produce the digest of a
// different combination. Joining on a bare separator would let ("a", "b|c", "d")
// and ("a", "b", "c|d") collide, and the three-part fallback would collide with
// the three-part uuid form. A collision here is not a corrupted read: it is a
// paid invocation that ON CONFLICT DO NOTHING silently discards, so it is worth
// ruling out by construction rather than by how unlikely the inputs look.
//
// Note what is NOT in the key: retry_attempt. A Temporal retry that re-runs the
// model is a genuinely different invocation carrying a new session_id and a
// real new charge, so it lands on a different id and is counted. A retry that
// merely re-records the same result carries the same session_id and collapses.
func DeterministicID(sessionID, resultUUID, modelKey string, numTurns *int64) string {
	h := sha256.New()
	// hash.Hash.Write never returns an error, but errcheck cannot know that.
	write := func(part string) {
		_, _ = fmt.Fprintf(h, "%d:%s|", len(part), part)
	}
	if resultUUID != "" {
		write("v1.uuid")
		write(sessionID)
		write(resultUUID)
		write(modelKey)
	} else {
		write("v1.noresult")
		write(sessionID)
		write(modelKey)
		if numTurns != nil {
			write(strconv.FormatInt(*numTurns, 10))
		} else {
			write("")
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// EnsureID derives the record's id and validates the fields it is derived from.
//
// The id is recomputed unconditionally rather than trusted from the wire. A
// producer that sends its own id would otherwise opt out of the entire
// idempotency guarantee: a fresh uuid per delivery makes every retry a new row
// and double-counts a paid invocation, and an id that happens to collide with a
// future real invocation makes ON CONFLICT DO NOTHING drop that charge silently.
// The field is still serialised on read; it is only the ingest direction that
// must not trust it.
//
// A supplied id that disagrees with the derived one is an error rather than a
// silent overwrite, so a producer computing the key wrongly finds out.
func (r *Record) EnsureID() error {
	if r == nil {
		return fmt.Errorf("%w: record must not be nil", ErrInvalidRecord)
	}
	if r.SchemaVersion == 0 {
		r.SchemaVersion = SchemaVersion
	}
	if r.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: got %d, want %d", ErrUnsupportedSchema, r.SchemaVersion, SchemaVersion)
	}
	if strings.TrimSpace(r.SessionID) == "" {
		return fmt.Errorf("%w: session_id is required", ErrInvalidRecord)
	}
	if strings.TrimSpace(r.ModelKey) == "" {
		return fmt.Errorf("%w: model_key is required", ErrInvalidRecord)
	}
	derived := DeterministicID(r.SessionID, r.ResultUUID, r.ModelKey, r.NumTurns)
	if r.ID != "" && r.ID != derived {
		return fmt.Errorf("%w: id %q does not match the key derived from session_id/result_uuid/model_key", ErrInvalidRecord, r.ID)
	}
	r.ID = derived
	if r.RecordedAt.IsZero() {
		r.RecordedAt = time.Now().UTC()
	}
	return nil
}

// Validate enforces the invariants the database also enforces, so a producer
// gets a 400 with a reason instead of a constraint violation.
func (r *Record) Validate() error {
	if r == nil {
		return fmt.Errorf("%w: record must not be nil", ErrInvalidRecord)
	}
	if r.CalculatedCost != nil && strings.TrimSpace(r.PricingVersion) == "" {
		// ADR-012 invariant 6. Without the version, the number cannot be
		// reproduced after a price change, which makes it worse than absent.
		return fmt.Errorf("%w: calculated_cost requires pricing_version", ErrInvalidRecord)
	}
	switch r.Outcome {
	case "", OutcomeSuccess, OutcomeError, OutcomeInterrupted:
	default:
		return fmt.Errorf("%w: unknown outcome %q", ErrInvalidRecord, r.Outcome)
	}
	for name, v := range map[string]*int64{
		"input_tokens":        r.InputTokens,
		"output_tokens":       r.OutputTokens,
		"cache_read_tokens":   r.CacheReadTokens,
		"cache_write_tokens":  r.CacheWriteTokens,
		"reasoning_tokens":    r.ReasoningTokens,
		"web_search_requests": r.WebSearchRequests,
	} {
		if v != nil && *v < 0 {
			return fmt.Errorf("%w: %s must not be negative", ErrInvalidRecord, name)
		}
	}
	return nil
}
