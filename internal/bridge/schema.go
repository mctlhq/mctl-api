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

// Package bridge is the authenticated command bridge between the trusted
// mctl-assistants control orchestration and a low-trust provider worker
// (mctl-api#962): a Postgres command outbox, short leases and an exactly-once
// fenced result callback. It ships dark: nothing here authorizes a real-world
// effect, and the default write fence refuses every permit.
package bridge

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/mctlhq/mctl-api/internal/glovo/basket"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The v1alpha1 wire schemas are vendored UNCHANGED from mctl-agents PR #1045
// (merge 14645f93fd4eb425a3ac5adeae497209431b8342). schema/PROVENANCE records
// the pinned digests; TestVendoredSchemasMatchProvenance enforces them.
//
// The v1alpha2 schemas (mctl-agents#1059) are vendored unchanged under
// schema/v1alpha2 and pinned by schema/v1alpha2/PROVENANCE and SHA256SUMS.
//
//go:embed schema/command.schema.json schema/result.schema.json schema/PROVENANCE
//go:embed schema/v1alpha2/read-command.schema.json schema/v1alpha2/read-result.schema.json
//go:embed schema/v1alpha2/command-place-order-fake.schema.json schema/v1alpha2/claim-response.schema.json
//go:embed schema/v1alpha2/PROVENANCE schema/v1alpha2/SHA256SUMS
var schemaFS embed.FS

const (
	commandSchemaURL = "https://mctl.ai/schemas/bridge/v1alpha1/command.schema.json"
	resultSchemaURL  = "https://mctl.ai/schemas/bridge/v1alpha1/result.schema.json"

	readCommandSchemaURL  = "https://mctl.ai/schemas/bridge/v1alpha2/read-command.schema.json"
	readResultSchemaURL   = "https://mctl.ai/schemas/bridge/v1alpha2/read-result.schema.json"
	writeV2CommandURL     = "https://mctl.ai/schemas/bridge/v1alpha2/command-place-order-fake.schema.json"
	claimResponseSchemaID = "https://mctl.ai/schemas/bridge/v1alpha2/claim-response.schema.json"

	// SchemaVersion is the wire version of both documents.
	SchemaVersion = "bridge.mctl.ai/v1alpha1"

	// WireV1alpha1 and WireV1alpha2 are the per-command wire versions.
	WireV1alpha1 = SchemaVersion
	WireV1alpha2 = "bridge.mctl.ai/v1alpha2"

	// ClaimEnvelopeV1alpha2 is the claim envelope for a provider that declares
	// v1alpha2; a v1alpha1-only provider keeps the v1alpha1 envelope.
	ClaimEnvelopeV1alpha2 = "bridge.mctl.ai/claim/v1alpha2"
)

var (
	schemaOnce sync.Once
	cmdSchema  *jsonschema.Schema
	resSchema  *jsonschema.Schema
	schemaErr  error

	readCmdSchema   *jsonschema.Schema
	readResSchema   *jsonschema.Schema
	writeV2Schema   *jsonschema.Schema
	claimRespSchema *jsonschema.Schema
)

func compileSchemas() error {
	schemaOnce.Do(func() {
		c := jsonschema.NewCompiler()
		c.AssertFormat()
		for _, f := range []struct{ file, url string }{
			{"schema/command.schema.json", commandSchemaURL},
			{"schema/result.schema.json", resultSchemaURL},
			{"schema/v1alpha2/read-command.schema.json", readCommandSchemaURL},
			{"schema/v1alpha2/read-result.schema.json", readResultSchemaURL},
			{"schema/v1alpha2/command-place-order-fake.schema.json", writeV2CommandURL},
			{"schema/v1alpha2/claim-response.schema.json", claimResponseSchemaID},
		} {
			raw, err := schemaFS.ReadFile(f.file)
			if err != nil {
				schemaErr = fmt.Errorf("bridge: read %s: %w", f.file, err)
				return
			}
			if schemaErr = addSchema(c, f.url, raw); schemaErr != nil {
				schemaErr = fmt.Errorf("bridge: %s: %w", f.file, schemaErr)
				return
			}
		}
		// The approval basket is #988's one vendored copy; the v1alpha2 schemas
		// reach it by $ref.
		basketRaw, err := basket.SchemaJSON()
		if err != nil {
			schemaErr = fmt.Errorf("bridge: read approval-basket schema: %w", err)
			return
		}
		if schemaErr = addSchema(c, basket.SchemaID, basketRaw); schemaErr != nil {
			return
		}
		for _, t := range []struct {
			url string
			dst **jsonschema.Schema
		}{
			{commandSchemaURL, &cmdSchema}, {resultSchemaURL, &resSchema},
			{readCommandSchemaURL, &readCmdSchema}, {readResultSchemaURL, &readResSchema},
			{writeV2CommandURL, &writeV2Schema}, {claimResponseSchemaID, &claimRespSchema},
		} {
			if *t.dst, schemaErr = c.Compile(t.url); schemaErr != nil {
				return
			}
		}
	})
	return schemaErr
}

func addSchema(c *jsonschema.Compiler, url string, raw []byte) error {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	if err := c.AddResource(url, doc); err != nil {
		return fmt.Errorf("add: %w", err)
	}
	return nil
}

// SchemaDigests returns the sha256 of the embedded command and result schema
// bytes, for the provenance check.
func SchemaDigests() (command, result string, err error) {
	for _, f := range []struct {
		file string
		out  *string
	}{{"schema/command.schema.json", &command}, {"schema/result.schema.json", &result}} {
		raw, rerr := schemaFS.ReadFile(f.file)
		if rerr != nil {
			return "", "", rerr
		}
		sum := sha256.Sum256(raw)
		*f.out = hex.EncodeToString(sum[:])
	}
	return command, result, nil
}

func validateAgainst(s *jsonschema.Schema, raw []byte) error {
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidDocument, err)
	}
	if err := s.Validate(inst); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidDocument, err)
	}
	return nil
}

// ValidateCommand checks raw against the vendored command schema.
func ValidateCommand(raw []byte) error {
	if err := compileSchemas(); err != nil {
		return err
	}
	return validateAgainst(cmdSchema, raw)
}

// ValidateReadCommand checks raw against the vendored v1alpha2 read-command schema.
func ValidateReadCommand(raw []byte) error {
	if err := compileSchemas(); err != nil {
		return err
	}
	return validateAgainst(readCmdSchema, raw)
}

// ValidateWriteV2Command checks raw against the vendored v1alpha2
// place_order_fake command schema.
func ValidateWriteV2Command(raw []byte) error {
	if err := compileSchemas(); err != nil {
		return err
	}
	return validateAgainst(writeV2Schema, raw)
}

// ValidateClaimResponse checks raw against the vendored claim-response schema.
func ValidateClaimResponse(raw []byte) error {
	if err := compileSchemas(); err != nil {
		return err
	}
	return validateAgainst(claimRespSchema, raw)
}

// Result is the v1alpha1 result wire projection. It carries no epoch, nonce,
// tenant, operation key, approval or workflow id: those are private DB
// bindings and are never accepted from the provider.
type Result struct {
	SchemaVersion  string `json:"schema_version"`
	CommandID      string `json:"command_id"`
	ExecutionID    string `json:"execution_id"`
	LeaseToken     string `json:"lease_token"`
	Attempt        int    `json:"attempt"`
	WorkerIdentity string `json:"worker_identity"`
	Outcome        string `json:"outcome"`
	ProviderEffect string `json:"provider_effect"`
	ResultRef      string `json:"result_ref,omitempty"`
	ErrorCode      string `json:"error_code,omitempty"`
	ErrorDetail    string `json:"error_detail,omitempty"`
	CompletedAt    string `json:"completed_at"`
}

// ParseResult validates raw against the vendored result schema and decodes it
// strictly. Anything the schema does not name is refused.
func ParseResult(raw []byte) (*Result, error) {
	if err := compileSchemas(); err != nil {
		return nil, err
	}
	if err := validateAgainst(resSchema, raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var r Result
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDocument, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data", ErrInvalidDocument)
	}
	return &r, nil
}

// Digest is the server-computed digest of a result: sha256 over the
// canonical (struct-ordered) JSON of the parsed projection, so key order and
// whitespace in the caller's body do not matter.
func (r *Result) Digest() string {
	b, _ := json.Marshal(r)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// storedResult is the persisted form of a Result: identical field order, no
// lease_token. The bearer token must never sit in bridge_commands.result.
type storedResult struct {
	SchemaVersion  string `json:"schema_version"`
	CommandID      string `json:"command_id"`
	ExecutionID    string `json:"execution_id"`
	Attempt        int    `json:"attempt"`
	WorkerIdentity string `json:"worker_identity"`
	Outcome        string `json:"outcome"`
	ProviderEffect string `json:"provider_effect"`
	ResultRef      string `json:"result_ref,omitempty"`
	ErrorCode      string `json:"error_code,omitempty"`
	ErrorDetail    string `json:"error_detail,omitempty"`
	CompletedAt    string `json:"completed_at"`
}

// redacted returns the JSON stored in bridge_commands.result. Digest() is
// unaffected: it still covers the full projection.
func (r *Result) redacted() ([]byte, error) {
	return json.Marshal(storedResult{
		SchemaVersion: r.SchemaVersion, CommandID: r.CommandID, ExecutionID: r.ExecutionID,
		Attempt: r.Attempt, WorkerIdentity: r.WorkerIdentity, Outcome: r.Outcome,
		ProviderEffect: r.ProviderEffect, ResultRef: r.ResultRef, ErrorCode: r.ErrorCode,
		ErrorDetail: r.ErrorDetail, CompletedAt: r.CompletedAt,
	})
}
