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

// Package contract is the machine-checkable form of the AutomationDefinition
// v1 contract described in docs/automation-contract.md. It is contract-only:
// pure validation and decision helpers, no I/O, no store, and no production
// caller. Claim class for everything here: isolated-model.
package contract

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
)

// SchemaVersion is the value of the optional schema_version marker.
const SchemaVersion = "automation/v1"

const schemaBase = "https://mctl.ai/schemas/automation/v1/"

//go:embed schema/v1/*.schema.json
var schemaFS embed.FS

// Code is a member of the automation-error.v1 vocabulary. Codes are only ever
// added; an existing code's meaning never changes.
type Code string

// The automation-error.v1 vocabulary.
const (
	CodeInvalid              = Code("automation_invalid")
	CodeUnknownField         = Code("automation_unknown_field")
	CodeServerOwnedField     = Code("automation_server_owned_field")
	CodeTemplateNotAllowed   = Code("automation_template_not_allowed")
	CodeTriggerUnsupported   = Code("automation_trigger_unsupported")
	CodeTimeAmbiguous        = Code("automation_time_ambiguous")
	CodeSupportConstraint    = Code("automation_support_constraint")
	CodeNotFound             = Code("automation_not_found")
	CodeVersionConflict      = Code("automation_version_conflict")
	CodeIdempotencyKeyReused = Code("automation_idempotency_key_reused")
	CodeOccurrenceDuplicate  = Code("automation_occurrence_duplicate")
	CodeIdentityUnlinked     = Code("automation_identity_unlinked")
	CodePolicyDrift          = Code("automation_policy_drift")
	CodeBudgetExhausted      = Code("automation_budget_exhausted")
	CodeApprovalRequired     = Code("automation_approval_required")
	CodeApprovalNotReusable  = Code("automation_approval_not_reusable")
	CodePaused               = Code("automation_paused")
	CodeAuthorityUnavailable = Code("automation_authority_unavailable")
)

var httpStatus = map[Code]int{
	CodeInvalid: 400, CodeUnknownField: 400, CodeServerOwnedField: 400,
	CodeTemplateNotAllowed: 400, CodeTriggerUnsupported: 400, CodeTimeAmbiguous: 400,
	CodeSupportConstraint: 400, CodeNotFound: 404, CodeVersionConflict: 409,
	CodeIdempotencyKeyReused: 409, CodeOccurrenceDuplicate: 409, CodeIdentityUnlinked: 403,
	CodePolicyDrift: 409, CodeBudgetExhausted: 409, CodeApprovalRequired: 409,
	CodeApprovalNotReusable: 409, CodePaused: 409, CodeAuthorityUnavailable: 503,
}

// Codes returns the whole vocabulary, sorted.
func Codes() []Code {
	out := make([]Code, 0, len(httpStatus))
	for c := range httpStatus {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// HTTPStatus is the status the contract assigns to c.
func (c Code) HTTPStatus() int { return httpStatus[c] }

// ContractError is the typed failure of every validation in this package.
type ContractError struct {
	Code   Code
	Detail string
}

func (e *ContractError) Error() string {
	if e.Detail == "" {
		return string(e.Code)
	}
	return string(e.Code) + ": " + e.Detail
}

func fail(c Code, format string, a ...any) error {
	return &ContractError{Code: c, Detail: fmt.Sprintf(format, a...)}
}

// CodeOf returns the contract code of err, or "" if err is not a ContractError.
func CodeOf(err error) Code {
	var ce *ContractError
	if errors.As(err, &ce) {
		return ce.Code
	}
	return ""
}

// ErrorBody renders the automation-error.v1 envelope for c. The message is a
// fixed string per code, so two refusals with the same code are byte-identical
// (no existence oracle for automation_not_found).
func ErrorBody(c Code) []byte {
	b, _ := json.Marshal(map[string]any{"error": map[string]string{"code": string(c), "message": string(c)}})
	return b
}

// serverOwned are the fields a client may never supply.
var serverOwned = []string{
	"id", "tenant", "owner_principal", "created_by", "actor", "surface",
	"origin_client_id", "version", "state", "lifecycle", "provenance",
	"created_at", "updated_at", "template_binding", "capability", "task_queue",
	"workflow_type", "namespace", "signal",
}

var (
	once     sync.Once
	compiler *jsonschema.Compiler
	loadErr  error
	cache    sync.Map
)

func load() error {
	once.Do(func() {
		entries, err := schemaFS.ReadDir("schema/v1")
		if err != nil {
			loadErr = err
			return
		}
		c := jsonschema.NewCompiler()
		for _, e := range entries {
			raw, err := schemaFS.ReadFile("schema/v1/" + e.Name())
			if err != nil {
				loadErr = err
				return
			}
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				loadErr = fmt.Errorf("parsing %s: %w", e.Name(), err)
				return
			}
			if err := c.AddResource(schemaBase+e.Name(), doc); err != nil {
				loadErr = fmt.Errorf("adding %s: %w", e.Name(), err)
				return
			}
		}
		compiler = c
	})
	return loadErr
}

func schema(name string) (*jsonschema.Schema, error) {
	if err := load(); err != nil {
		return nil, err
	}
	if s, ok := cache.Load(name); ok {
		return s.(*jsonschema.Schema), nil
	}
	s, err := compiler.Compile(schemaBase + name)
	if err != nil {
		return nil, fmt.Errorf("compiling %s: %w", name, err)
	}
	cache.Store(name, s)
	return s, nil
}

func hasUnknownField(ve *jsonschema.ValidationError) bool {
	if _, ok := ve.ErrorKind.(*kind.AdditionalProperties); ok {
		return true
	}
	for _, c := range ve.Causes {
		if hasUnknownField(c) {
			return true
		}
	}
	return false
}

// validateAgainst validates inst against the named schema and maps failures to
// automation_unknown_field or automation_invalid.
func validateAgainst(name string, inst any) error {
	s, err := schema(name)
	if err != nil {
		return err
	}
	if err := s.Validate(inst); err != nil {
		var ve *jsonschema.ValidationError
		if errors.As(err, &ve) {
			if hasUnknownField(ve) {
				return fail(CodeUnknownField, "%s", name)
			}
			return fail(CodeInvalid, "%s", name)
		}
		return err
	}
	return nil
}

func parseObject(raw []byte) (map[string]any, error) {
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, fail(CodeInvalid, "malformed JSON")
	}
	obj, ok := inst.(map[string]any)
	if !ok {
		return nil, fail(CodeInvalid, "body must be a JSON object")
	}
	if v, ok := obj["schema_version"]; ok && v != SchemaVersion {
		// Research v0 documents have no compatibility promise.
		return nil, fail(CodeInvalid, "unsupported schema_version")
	}
	return obj, nil
}

func checkServerOwned(obj map[string]any) error {
	for _, k := range serverOwned {
		if _, ok := obj[k]; ok {
			return fail(CodeServerOwnedField, "%s", k)
		}
	}
	return nil
}

// ValidateCreate checks a create request body: parse, server-owned prepass,
// schema, then template, trigger and Support semantics.
func ValidateCreate(raw []byte) error {
	obj, err := parseObject(raw)
	if err != nil {
		return err
	}
	if err := checkServerOwned(obj); err != nil {
		return err
	}
	if err := validateAgainst("automation-create-request.schema.json", obj); err != nil {
		return err
	}
	tmplID, _ := obj["template_id"].(string)
	tmpl, ok := LookupTemplate(tmplID)
	if !ok {
		return fail(CodeTemplateNotAllowed, "%q", tmplID)
	}
	if err := validateAgainst(tmpl.ParamsSchema, obj["params"]); err != nil {
		return err
	}
	trig, _ := obj["trigger"].(map[string]any)
	if err := CheckTrigger(trig, tmpl); err != nil {
		return err
	}
	if tmplID == "reminder.v1" {
		if err := checkReminderText(obj["params"].(map[string]any)); err != nil {
			return err
		}
	}
	if tmpl.Scope == ScopeSupport {
		return CheckSupport(supportInputsFromBody(obj, tmpl))
	}
	return nil
}

// ValidatePatch checks a patch body (JSON Merge Patch over client-writable
// fields, guarded by expected_version).
func ValidatePatch(raw []byte) error {
	obj, err := parseObject(raw)
	if err != nil {
		return err
	}
	if err := checkServerOwned(obj); err != nil {
		return err
	}
	if err := validateAgainst("automation-patch.schema.json", obj); err != nil {
		return err
	}
	if trig, ok := obj["trigger"].(map[string]any); ok {
		return CheckTrigger(trig, Template{AllowedTriggers: []string{"at", "schedule", "event", "dependency"}})
	}
	return nil
}

// ValidateDefinition checks a returned AutomationDefinition resource.
func ValidateDefinition(raw []byte) error {
	obj, err := parseObject(raw)
	if err != nil {
		return err
	}
	return validateAgainst("automation-definition.schema.json", obj)
}

// ValidateRun checks an AutomationRun view.
func ValidateRun(raw []byte) error {
	obj, err := parseObject(raw)
	if err != nil {
		return err
	}
	return validateAgainst("automation-run.schema.json", obj)
}
