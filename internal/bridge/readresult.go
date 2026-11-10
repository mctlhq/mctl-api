// Copyright 2026 MCTL Authors
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

package bridge

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/mctlhq/mctl-api/internal/glovo/basket"
	"github.com/mctlhq/mctl-api/internal/jcs"
)

// Read command kinds of the v1alpha2 contract (mctl-agents#1059). Prepare is
// not a read kind: it is the #957 write.
const (
	KindReadHistory = "read_history"
	KindReadPreview = "read_preview"
	KindReadBasket  = "read_basket"

	// MaxReadPayload is the #1059 cap on JCS(payload).
	MaxReadPayload = 12288
	// MaxReadTTLSeconds is the #1059 ceiling of a read command's ttl_seconds and
	// of the stored result's lifetime.
	MaxReadTTLSeconds = 300
)

// IsReadKind reports whether kind is one of the v1alpha2 read kinds.
func IsReadKind(kind string) bool {
	switch kind {
	case KindReadHistory, KindReadPreview, KindReadBasket:
		return true
	}
	return false
}

// ReadResultDoc is the v1alpha2 read-result wire document. It carries no
// tenant_ref, principal_ref, connection_ref or install_revision_ref:
// bindings come only from the stored command row.
type ReadResultDoc struct {
	SchemaVersion  string          `json:"schema_version"`
	CommandID      string          `json:"command_id"`
	RequestID      string          `json:"request_id"`
	Kind           string          `json:"kind"`
	LeaseToken     string          `json:"lease_token"`
	Attempt        int             `json:"attempt"`
	WorkerIdentity string          `json:"worker_identity"`
	Outcome        string          `json:"outcome"`
	ProviderEffect string          `json:"provider_effect"`
	ErrorCode      string          `json:"error_code,omitempty"`
	ErrorDetail    string          `json:"error_detail,omitempty"`
	CompletedAt    string          `json:"completed_at"`
	Payload        json.RawMessage `json:"payload,omitempty"`
	PayloadDigest  string          `json:"payload_digest,omitempty"`

	body []byte
}

// parsedResult is a result document of either version.
type parsedResult struct {
	v1 *Result
	v2 *ReadResultDoc
}

// parseAnyResult selects the schema by the document's schema_version
// (design 2a). A v1alpha2 body runs the raw-bytes pre-check before it is
// parsed; a v1alpha1 body takes today's path untouched.
func parseAnyResult(body []byte) (*parsedResult, error) {
	marked := bytes.Contains(body, []byte(WireV1alpha2))
	var markedErr error
	if marked {
		markedErr = rawCheck(body)
	}
	var peek struct {
		SchemaVersion string `json:"schema_version"`
	}
	peekErr := json.Unmarshal(body, &peek)
	if markedErr != nil && (peekErr != nil || peek.SchemaVersion == WireV1alpha2) {
		return nil, markedErr
	}
	if peekErr == nil && peek.SchemaVersion == WireV1alpha2 {
		if !marked {
			if err := rawCheck(body); err != nil {
				return nil, err
			}
		}
		r, err := parseReadResult(body)
		if err != nil {
			return nil, err
		}
		return &parsedResult{v2: r}, nil
	}
	r, err := ParseResult(body)
	if err != nil {
		return nil, err
	}
	return &parsedResult{v1: r}, nil
}

// ParseReadResult validates raw against the vendored v1alpha2 read-result
// schema (after the raw-bytes pre-check) and decodes it strictly.
func ParseReadResult(raw []byte) (*ReadResultDoc, error) {
	if err := rawCheck(raw); err != nil {
		return nil, err
	}
	return parseReadResult(raw)
}

func parseReadResult(raw []byte) (*ReadResultDoc, error) {
	if err := compileSchemas(); err != nil {
		return nil, err
	}
	if err := validateAgainst(readResSchema, raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var r ReadResultDoc
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDocument, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data", ErrInvalidDocument)
	}
	r.body = raw
	return &r, nil
}

// Digest is the server-computed digest of a read result: sha256 over the RFC
// 8785 form of the body without its lease_token, so key order and whitespace
// do not matter and the bearer token never feeds anything stored.
func (r *ReadResultDoc) Digest() (string, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(r.body, &m); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidDocument, err)
	}
	delete(m, "lease_token")
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	canon, err := jcs.Canonicalize(b)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidDocument, err)
	}
	return "sha256:" + sha256Hex(canon), nil
}

// canonicalPayload canonicalizes the payload with RFC 8785, enforces the
// 12288 byte cap and verifies payload_digest. A payload over the cap is
// ErrPayloadTooLarge, a digest that does not match is ErrBindingMismatch.
func (r *ReadResultDoc) canonicalPayload() ([]byte, error) {
	canon, err := jcs.Canonicalize(r.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDocument, err)
	}
	if len(canon) > MaxReadPayload {
		return nil, ErrPayloadTooLarge
	}
	if !digestEqual("sha256:"+sha256Hex(canon), r.PayloadDigest) {
		return nil, fmt.Errorf("%w: payload_digest does not match the canonical payload", ErrBindingMismatch)
	}
	return canon, nil
}

func digestEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// digestOf is "sha256:" plus the lowercase hex sha256 of b.
func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// checkBasketRules runs #988's basket validation (basket.Parse: sorted unique
// lines, subtotal and total identities) on one approval_basket. JSON Schema
// cannot express these rules and the contract README says every consumer MUST
// check them, so a result or command that carries a basket never reaches the
// store without them. There is no second implementation here.
func checkBasketRules(raw []byte) (basket.Approval, error) {
	a, _, err := basket.Parse(raw)
	if err != nil {
		return basket.Approval{}, fmt.Errorf("%w: approval_basket: %v", ErrInvalidDocument, err)
	}
	return a, nil
}

// checkReadPayloadRules enforces the cross-field rules of a succeeded
// read_preview or read_basket payload: the basket rules above, every display
// item_code a line of the basket, and (preview) unavailable_items disjoint
// from the basket lines. read_history carries no basket and is not checked.
func checkReadPayloadRules(kind string, payload []byte) error {
	if kind != KindReadPreview && kind != KindReadBasket {
		return nil
	}
	var p struct {
		Display []struct {
			ItemCode string `json:"item_code"`
		} `json:"display"`
		Unavailable    []string        `json:"unavailable_items"`
		ApprovalBasket json.RawMessage `json:"approval_basket"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidDocument, err)
	}
	if len(p.ApprovalBasket) == 0 {
		// empty reads have no basket; the schema forbids a missing basket
		// on a non-empty read, so nothing is left to cross-check.
		return nil
	}
	a, err := checkBasketRules(p.ApprovalBasket)
	if err != nil {
		return err
	}
	lines := make(map[string]struct{}, len(a.Lines))
	for _, l := range a.Lines {
		lines[l.ItemCode] = struct{}{}
	}
	for _, d := range p.Display {
		if _, ok := lines[d.ItemCode]; !ok {
			return fmt.Errorf("%w: display item_code is not a basket line", ErrInvalidDocument)
		}
	}
	for _, u := range p.Unavailable {
		if _, ok := lines[u]; ok {
			return fmt.Errorf("%w: unavailable item_code is a basket line", ErrInvalidDocument)
		}
	}
	return nil
}
