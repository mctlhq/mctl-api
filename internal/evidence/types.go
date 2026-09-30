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

// Package evidence is the durable home for sealed execution-evidence
// envelopes (evidence.mctl.ai/v1alpha1, mctl-agents#199/#520, ADR 018 and
// its Amendment 1, mctlhq/mctl-agents#539/#540). It is Tier B of that
// contract: Tier A (orchestrator/execution_evidence.py in mctl-agents)
// defines the envelope schema and its sealing algorithm; this package gives
// a sealed envelope a durable home next to the canonical platform state it
// references (work_items, work_item_executions, work_item_context_snapshots,
// action_approval_requests, model_usage_records) — references and hashes
// only, never a second copy of execution or work-item state.
//
// The server never invents its own identity rule: CanonicalContentJSON,
// ContentHash and EvidenceIDFor reproduce Tier A's seal() exactly, so that a
// real Tier A envelope is accepted and a retried, re-sealed envelope with a
// different created_at is recognised as the same evidence.
package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

// EvidenceIDPrefix labels evidence ids (contract "ID scheme").
const EvidenceIDPrefix = "ev-"

// APIVersionV1Alpha1 is the one envelope version this store understands.
const APIVersionV1Alpha1 = "evidence.mctl.ai/v1alpha1"

// KindV1Alpha1 is the envelope kind that must accompany APIVersionV1Alpha1.
const KindV1Alpha1 = "ExecutionEvidence"

// SupportedAPIVersions maps every api_version this build accepts to its
// required kind. A document declaring anything else is rejected outright,
// mirroring Tier A's SUPPORTED_API_VERSIONS.
var SupportedAPIVersions = map[string]string{
	APIVersionV1Alpha1: KindV1Alpha1,
}

// MaxEvidenceBytes bounds one envelope's canonical bytes.
const MaxEvidenceBytes = 256 << 10

// ID prefixes and shapes this layer validates, mirroring
// orchestrator/execution_evidence.py and ADR 018 Amendment 1
// (mctlhq/mctl-agents#539).
const (
	// WorkExecutionIDPrefix is the canonical work-execution id shape
	// (EXECUTION_ID_PREFIX in Tier A, ExecutionIDPrefix in
	// internal/workitems).
	WorkExecutionIDPrefix = "we_"
	// RuntimeExecutionIDPrefix is the ADR 011 runtime ExecutionContext id
	// shape.
	RuntimeExecutionIDPrefix = "ex-"
)

// runtimeExecutionIDPattern is the exact shape execution_identity.seal()
// derives: "ex-" followed by 16 lowercase hex characters.
var runtimeExecutionIDPattern = regexp.MustCompile(`^ex-[0-9a-f]{16}$`)

// createdAtPattern is Tier A's _CREATED_AT_PATTERN
// (orchestrator/execution_evidence.py): the exact UTC shape seal() writes.
// created_at is excluded from the content hash but is still part of the
// record, so it is validated the way Tier A validates it rather than
// accepted as any string.
var createdAtPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$`)

// Sentinel errors. The HTTP layer maps each to one status and typed code.
var (
	// ErrEvidenceNotFound: no evidence exists for the requested id or
	// filter.
	ErrEvidenceNotFound = errors.New("evidence not found")
	// ErrEvidenceDivergence: the same ev- id already names different
	// content (a 64-bit id-prefix collision).
	ErrEvidenceDivergence = errors.New("evidence id already names different content")
	// ErrUnsupportedAPIVersion: api_version is not one this build accepts.
	ErrUnsupportedAPIVersion = errors.New("unsupported evidence api_version")
	// ErrEvidenceHashMismatch: the envelope's own evidence_id/content_hash
	// does not equal the server's recomputation.
	ErrEvidenceHashMismatch = errors.New("evidence_id or content_hash does not match the recomputed value")
	// ErrInvalidExecutionRef: the execution join violates ADR 018's rules.
	ErrInvalidExecutionRef = errors.New("execution reference is invalid")
	// ErrEvidenceInvalid: the envelope is not well-formed JSON, or carries
	// unknown or duplicate keys.
	ErrEvidenceInvalid = errors.New("evidence envelope is invalid")
	// ErrEvidenceTooLarge: the envelope exceeds MaxEvidenceBytes.
	ErrEvidenceTooLarge = errors.New("evidence envelope exceeds the maximum size")
	// ErrEvidenceSecret: the envelope's canonical bytes match a secret
	// pattern.
	ErrEvidenceSecret = errors.New("evidence envelope matches a secret pattern")
)

// evidenceEnvelopeKeys is the complete set of top-level keys Tier A's
// ExecutionEvidence accepts. Anything else is rejected.
var evidenceEnvelopeKeys = map[string]bool{
	"api_version": true, "kind": true, "evidence_id": true, "content_hash": true,
	"created_at": true, "execution": true, "outcome": true, "policy_decisions": true,
	"snapshot_refs": true, "execution_request": true, "usage": true, "approvals": true,
	"artifacts": true, "gaps": true,
}

// executionJoinKeys is the complete set of keys ExecutionJoin.from_dict
// accepts (ADR 018 Amendment 1, mctlhq/mctl-agents#539): execution_id,
// work_item_id, trace_id and the new runtime_execution_id.
var executionJoinKeys = map[string]bool{
	"execution_id": true, "work_item_id": true, "trace_id": true, "runtime_execution_id": true,
}

// blocksAllowingEmptyOmission are the optional top-level blocks that enter
// the hashed payload only when present and non-empty (Tier A's
// _content_payload rule, unchanged by Amendment 1).
var optionalBlockKeys = []string{
	"policy_decisions", "snapshot_refs", "execution_request", "usage", "approvals", "artifacts",
}

// Evidence is one stored, sealed execution-evidence envelope. Envelope is
// served verbatim, base64-encoded, so its bytes — and therefore its hash —
// survive JSON re-encoding.
type Evidence struct {
	ID          string `json:"id"`
	ContentHash string `json:"content_hash"`
	APIVersion  string `json:"api_version"`
	// Envelope carries the exact bytes first received, serialised as
	// envelope_b64.
	Envelope []byte `json:"envelope_b64"`

	// Join columns: exactly the ADR 018 Amendment 1 ExecutionJoin fields,
	// copied verbatim, never classified or translated.
	ExecutionID        string `json:"execution_id"`
	RuntimeExecutionID string `json:"runtime_execution_id,omitempty"`
	WorkItemID         string `json:"work_item_id,omitempty"`
	TraceID            string `json:"trace_id,omitempty"`

	CreatedAt time.Time `json:"created_at"`

	IngestedBy            string    `json:"ingested_by"`
	IngestedByPrincipalID string    `json:"ingested_by_principal_id,omitempty"`
	IngestedAt            time.Time `json:"ingested_at"`

	// PrimaryRefKind/PrimaryRefID are derived at read time, never stored:
	// ("work", execution_id) when execution_id is set, else
	// ("runtime", runtime_execution_id).
	PrimaryRefKind string `json:"primary_ref_kind,omitempty"`
	PrimaryRefID   string `json:"primary_ref_id,omitempty"`

	// Ref is the rebuildable derived projection, nil when it has not been
	// (or could not be) resolved.
	Ref *EvidenceRef `json:"ref,omitempty"`
}

// PrimaryExecutionRef derives ("work", execution_id) when ExecutionID is
// set, else ("runtime", runtime_execution_id), else ("", ""). Never stored:
// computed fresh on every read (design.md section 4).
func (e *Evidence) PrimaryExecutionRef() (kind, id string) {
	if e == nil {
		return "", ""
	}
	if e.ExecutionID != "" {
		return "work", e.ExecutionID
	}
	if e.RuntimeExecutionID != "" {
		return "runtime", e.RuntimeExecutionID
	}
	return "", ""
}

// EvidenceRef is the rebuildable, non-authoritative retrieval projection
// derived from canonical state at ingest time (internal/evidence/derive.go).
// Disagreement with canonical state means this row is stale, never that it
// is an answer: RebuildRefs recomputes it losslessly.
type EvidenceRef struct {
	EvidenceID      string    `json:"evidence_id"`
	WorkExecutionID string    `json:"work_execution_id,omitempty"`
	WorkItemID      string    `json:"work_item_id,omitempty"`
	Tenant          string    `json:"tenant,omitempty"`
	Engine          string    `json:"engine,omitempty"`
	EngineRef       string    `json:"engine_ref,omitempty"`
	Repository      string    `json:"repository,omitempty"`
	IssueNumber     *int64    `json:"issue_number,omitempty"`
	PRNumber        *int64    `json:"pr_number,omitempty"`
	DerivedAt       time.Time `json:"derived_at"`
}

// IngestInput is one ingest request: the envelope's bytes exactly as
// received, plus server-owned provenance.
type IngestInput struct {
	// EnvelopeBytes are the raw, received JSON bytes of the sealed
	// envelope, decoded from the wrapper's envelope_b64. Stored verbatim.
	EnvelopeBytes         []byte
	IngestedBy            string
	IngestedByPrincipalID string
}

// parsedEnvelope is the decoded, minimally-typed shape this layer needs to
// validate and hash an envelope, without reconstructing every Tier A block
// (policy_decisions, snapshot_refs, ... travel through untouched as
// json.RawMessage, canonicalised generically).
type parsedEnvelope struct {
	apiVersion  string
	kind        string
	evidenceID  string
	contentHash string
	// createdAt is the envelope's own seal time. Excluded from the hash,
	// stored as the record's created_at (the ingest clock is ingested_at).
	createdAt time.Time
	execution executionJoin
	// contentFields holds every top-level key that participates in the
	// content hash, in their original (already unmarshalled to
	// interface{}) form, EXCEPT execution (rebuilt from executionJoin so
	// the leaf/omission rule applies) and the three excluded keys
	// (evidence_id, content_hash, created_at).
	contentFields map[string]any
}

// executionJoin is ADR 018 Amendment 1's ExecutionJoin: two distinct, typed
// identity fields plus two unvalidated correlation strings. Mirrored,
// never classified: this layer stores both identities verbatim and derives
// nothing from one into the other.
type executionJoin struct {
	ExecutionID        string `json:"execution_id"`
	WorkItemID         string `json:"work_item_id"`
	TraceID            string `json:"trace_id"`
	RuntimeExecutionID string `json:"runtime_execution_id,omitempty"`
}

// toDict renders the join exactly as Tier A's ExecutionJoin.to_dict() does:
// execution_id/work_item_id/trace_id always present (as "" when blank),
// runtime_execution_id present only when non-blank (Amendment 1).
func (j executionJoin) toDict() map[string]any {
	d := map[string]any{
		"execution_id": j.ExecutionID,
		"work_item_id": j.WorkItemID,
		"trace_id":     j.TraceID,
	}
	if j.RuntimeExecutionID != "" {
		d["runtime_execution_id"] = j.RuntimeExecutionID
	}
	return d
}

// validateJoin enforces Tier A's typed-identity rules, as amended by
// mctlhq/mctl-agents#539:
//
//   - execution_id is blank or starts with WorkExecutionIDPrefix;
//   - runtime_execution_id is blank or "ex-" + 16 lowercase hex;
//   - neither field may hold the other's shape;
//   - at least one of the two must be non-blank.
func (j executionJoin) validate() error {
	if j.ExecutionID != "" && !strings.HasPrefix(j.ExecutionID, WorkExecutionIDPrefix) {
		return fmt.Errorf("%w: execution.execution_id must start with %q, got %q",
			ErrInvalidExecutionRef, WorkExecutionIDPrefix, j.ExecutionID)
	}
	if j.RuntimeExecutionID != "" && !runtimeExecutionIDPattern.MatchString(j.RuntimeExecutionID) {
		return fmt.Errorf("%w: execution.runtime_execution_id must match %q, got %q",
			ErrInvalidExecutionRef, runtimeExecutionIDPattern.String(), j.RuntimeExecutionID)
	}
	if j.ExecutionID == "" && j.RuntimeExecutionID == "" {
		return fmt.Errorf("%w: execution.execution_id and execution.runtime_execution_id are both blank", ErrInvalidExecutionRef)
	}
	return nil
}

// parseEnvelope strictly decodes raw as one JSON object, rejecting unknown
// or duplicate keys at every level this layer inspects, mirroring Tier A's
// _reject_unknown_keys / ExecutionEvidence.from_dict.
func parseEnvelope(raw []byte) (*parsedEnvelope, error) {
	top, err := decodeStrictObject(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrEvidenceInvalid, err)
	}
	if err := rejectUnknownKeys(top, evidenceEnvelopeKeys, "envelope"); err != nil {
		return nil, err
	}

	apiVersion, _ := top["api_version"].(string)
	kind, _ := top["kind"].(string)
	expectedKind, supported := SupportedAPIVersions[apiVersion]
	if !supported {
		return nil, fmt.Errorf("%w: %q (supported: %s)", ErrUnsupportedAPIVersion, apiVersion, supportedVersionsList())
	}
	if kind != expectedKind {
		return nil, fmt.Errorf("%w: kind must be %q for api_version %q, got %q", ErrEvidenceInvalid, expectedKind, apiVersion, kind)
	}

	evidenceID, _ := top["evidence_id"].(string)
	contentHash, _ := top["content_hash"].(string)
	createdAtRaw, _ := top["created_at"].(string)
	if !createdAtPattern.MatchString(createdAtRaw) {
		return nil, fmt.Errorf("%w: created_at must be a UTC timestamp of the form YYYY-MM-DDTHH:MM:SS[.ffffff]Z, got %q",
			ErrEvidenceInvalid, createdAtRaw)
	}
	createdAt, err := time.Parse(time.RFC3339Nano, createdAtRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: created_at: %s", ErrEvidenceInvalid, err)
	}

	execRaw, ok := top["execution"]
	if !ok {
		return nil, fmt.Errorf("%w: execution block is required", ErrEvidenceInvalid)
	}
	execMap, err := asObject(execRaw, "execution")
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrEvidenceInvalid, err)
	}
	if err := rejectUnknownKeys(execMap, executionJoinKeys, "execution"); err != nil {
		return nil, err
	}
	join := executionJoin{
		ExecutionID:        stringField(execMap, "execution_id"),
		WorkItemID:         stringField(execMap, "work_item_id"),
		TraceID:            stringField(execMap, "trace_id"),
		RuntimeExecutionID: stringField(execMap, "runtime_execution_id"),
	}

	contentFields := map[string]any{
		"api_version": apiVersion,
		"kind":        kind,
	}
	if outcome, ok := top["outcome"]; ok {
		contentFields["outcome"] = outcome
	} else {
		return nil, fmt.Errorf("%w: outcome block is required", ErrEvidenceInvalid)
	}
	for _, key := range optionalBlockKeys {
		v, present := top[key]
		if !present {
			continue
		}
		if isEmptyBlock(v) {
			continue
		}
		contentFields[key] = v
	}
	if gaps, ok := top["gaps"]; ok && !isEmptyBlock(gaps) {
		contentFields["gaps"] = gaps
	}

	return &parsedEnvelope{
		apiVersion:    apiVersion,
		kind:          kind,
		evidenceID:    evidenceID,
		contentHash:   contentHash,
		createdAt:     createdAt.UTC(),
		execution:     join,
		contentFields: contentFields,
	}, nil
}

// isEmptyBlock reports whether an optional block is present but empty
// (an empty list, or a null object), which Tier A's _content_payload
// treats as absent.
//
// An empty OBJECT ({}) is deliberately not empty here. Tier A tests list
// blocks by truthiness (`if policy_decisions:`) but object blocks by
// presence (`if execution_request is not None:`, `if usage is not None:`),
// so a present object block always enters the payload. Tier A's seal()
// never writes `{}` for one either: from_dict fills the block's full shape
// (empty strings, nulls), which is what gets hashed. Treating `{}` as absent
// would make this layer hash something Tier A never does.
func isEmptyBlock(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case []any:
		return len(t) == 0
	}
	return false
}

// CanonicalContentJSON builds the exact byte sequence Tier A hashes: the
// envelope's content payload (every field except evidence_id, content_hash
// and created_at, with the execution join rebuilt through toDict() so a
// blank runtime_execution_id is omitted), serialised with Tier A's
// canonical-JSON rule — sorted keys, "," / ":" separators, ASCII-escaped
// (no raw UTF-8 multibyte output), and never HTML-escaped.
func CanonicalContentJSON(p *parsedEnvelope) ([]byte, error) {
	payload := make(map[string]any, len(p.contentFields)+1)
	for k, v := range p.contentFields {
		payload[k] = v
	}
	payload["execution"] = p.execution.toDict()
	return canonicalJSON(payload)
}

// ContentHash is "sha256:" + hex(sha256(canonical)), Tier A's hash_bytes.
func ContentHash(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// EvidenceIDFor derives "ev-" + the first 16 hex characters after the
// "sha256:" prefix, exactly as Tier A's seal().
func EvidenceIDFor(contentHash string) string {
	if len(contentHash) < 23 {
		return EvidenceIDPrefix
	}
	return EvidenceIDPrefix + contentHash[7:23]
}

// canonicalJSON serialises payload with Tier A's exact rule
// (orchestrator/context_snapshot.py's _canonical_json):
//
//	json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
//
// Python's json.dumps defaults to ensure_ascii=True (every non-ASCII
// character becomes \uXXXX, surrogate pairs above the BMP) and never
// HTML-escapes '<', '>' or '&'. encoding/json does the opposite on both
// counts by default, so both are corrected here.
func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encodeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encodeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
		return nil
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
		return nil
	case string:
		encodeCanonicalString(buf, t)
		return nil
	case json.Number:
		buf.WriteString(t.String())
		return nil
	case float64:
		return encodeCanonicalFloat(buf, t)
	case int:
		fmt.Fprintf(buf, "%d", t)
		return nil
	case int64:
		fmt.Fprintf(buf, "%d", t)
		return nil
	case []any:
		buf.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			encodeCanonicalString(buf, k)
			buf.WriteByte(':')
			if err := encodeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	default:
		return fmt.Errorf("evidence: canonical json: unsupported type %T", v)
	}
}

// encodeCanonicalFloat rejects non-integer numbers (Tier A carries no
// floats in this contract; reject rather than guess at Python's repr) and
// renders an integral float without a decimal point or exponent, matching
// Python's json.dumps(int).
func encodeCanonicalFloat(buf *bytes.Buffer, f float64) error {
	if f != float64(int64(f)) {
		return fmt.Errorf("evidence: canonical json: non-integer number %v is not part of this contract", f)
	}
	fmt.Fprintf(buf, "%d", int64(f))
	return nil
}

// encodeCanonicalString writes a JSON string the way Python's
// json.dumps(..., ensure_ascii=True) does: every byte below 0x20 and every
// rune above 0x7E is escaped as \uXXXX (with a UTF-16 surrogate pair above
// the BMP), '"' and '\\' are escaped, and '<'/'>'/'&' are NOT escaped
// (unlike encoding/json's HTMLEscape default).
func encodeCanonicalString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		default:
			switch {
			case r < 0x20:
				fmt.Fprintf(buf, `\u%04x`, r)
			case r < 0x7F:
				buf.WriteRune(r)
			case r <= 0xFFFF:
				fmt.Fprintf(buf, `\u%04x`, r)
			default:
				// Surrogate pair, matching Python's ensure_ascii for
				// characters above the BMP.
				r -= 0x10000
				hi := 0xD800 + (r >> 10)
				lo := 0xDC00 + (r & 0x3FF)
				fmt.Fprintf(buf, `\u%04x\u%04x`, hi, lo)
			}
		}
	}
	buf.WriteByte('"')
}

// decodeStrictObject decodes raw as exactly one JSON object, rejecting
// duplicate keys, trailing data and non-object top-level values.
func decodeStrictObject(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return nil, errors.New("envelope must be a JSON object")
	}
	obj, err := decodeObjectBody(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF { //nolint:errorlint // io.EOF is a sentinel, never wrapped, by json.Decoder.Token's contract
		if err == nil {
			return nil, errors.New("trailing data after JSON object")
		}
		return nil, err
	}
	return obj, nil
}

// decodeObjectBody reads key/value pairs until the closing '}', rejecting a
// key seen twice — json.Decoder does not do this itself (the standard
// library silently keeps the last value), and a duplicate key is exactly
// the kind of ambiguity Tier A's from_dict refuses.
func decodeObjectBody(dec *json.Decoder) (map[string]any, error) {
	obj := map[string]any{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, errors.New("object key must be a string")
		}
		if _, dup := obj[key]; dup {
			return nil, fmt.Errorf("duplicate key %q", key)
		}
		val, err := decodeValue(dec)
		if err != nil {
			return nil, err
		}
		obj[key] = val
	}
	// Consume the closing '}'.
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	return obj, nil
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			return decodeObjectBody(dec)
		case '[':
			var arr []any
			for dec.More() {
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			if arr == nil {
				arr = []any{}
			}
			return arr, nil
		default:
			return nil, fmt.Errorf("unexpected delimiter %q", t)
		}
	default:
		return t, nil
	}
}

func rejectUnknownKeys(obj map[string]any, allowed map[string]bool, where string) error {
	var unknown []string
	for k := range obj {
		if !allowed[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("%w: %s: unknown key(s) %v", ErrEvidenceInvalid, where, unknown)
	}
	return nil
}

func asObject(v any, where string) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a JSON object", where)
	}
	return m, nil
}

func stringField(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func supportedVersionsList() string {
	versions := make([]string, 0, len(SupportedAPIVersions))
	for v := range SupportedAPIVersions {
		versions = append(versions, v)
	}
	sort.Strings(versions)
	return strings.Join(versions, ", ")
}

// Validate fully validates in and returns the parsed envelope plus its
// recomputed content_hash/evidence_id. It is the single entry point every
// caller (Store.Ingest, and any future dry-run check) must use: it never
// trusts the envelope's own evidence_id/content_hash without recomputing
// and comparing them.
func Validate(in IngestInput) (parsed *parsedEnvelope, contentHash, evidenceID string, err error) {
	if len(in.EnvelopeBytes) == 0 {
		return nil, "", "", fmt.Errorf("%w: envelope must not be empty", ErrEvidenceInvalid)
	}
	if len(in.EnvelopeBytes) > MaxEvidenceBytes {
		return nil, "", "", fmt.Errorf("%w: envelope exceeds %d bytes", ErrEvidenceTooLarge, MaxEvidenceBytes)
	}
	p, err := parseEnvelope(in.EnvelopeBytes)
	if err != nil {
		return nil, "", "", err
	}
	if err := p.execution.validate(); err != nil {
		return nil, "", "", err
	}
	canonical, err := CanonicalContentJSON(p)
	if err != nil {
		return nil, "", "", fmt.Errorf("%w: %s", ErrEvidenceInvalid, err)
	}
	gotHash := ContentHash(canonical)
	gotID := EvidenceIDFor(gotHash)
	if p.contentHash != gotHash || p.evidenceID != gotID {
		return nil, "", "", fmt.Errorf("%w: submitted evidence_id=%s content_hash=%s, recomputed evidence_id=%s content_hash=%s",
			ErrEvidenceHashMismatch, p.evidenceID, p.contentHash, gotID, gotHash)
	}
	return p, gotHash, gotID, nil
}

// ExecutionID returns the parsed envelope's we_ join value, if any.
func (p *parsedEnvelope) ExecutionID() string { return p.execution.ExecutionID }

// RuntimeExecutionID returns the parsed envelope's ex- join value, if any.
func (p *parsedEnvelope) RuntimeExecutionID() string { return p.execution.RuntimeExecutionID }

// WorkItemID returns the parsed envelope's work_item_id join value.
func (p *parsedEnvelope) WorkItemID() string { return p.execution.WorkItemID }

// TraceID returns the parsed envelope's trace_id join value.
func (p *parsedEnvelope) TraceID() string { return p.execution.TraceID }

// APIVersion returns the parsed envelope's api_version.
func (p *parsedEnvelope) APIVersion() string { return p.apiVersion }

// CreatedAt is the envelope's own seal time (UTC), not the ingest time.
func (p *parsedEnvelope) CreatedAt() time.Time { return p.createdAt }
