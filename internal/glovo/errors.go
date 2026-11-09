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

// Package glovo holds the Glovo MCP facade's fail-closed authorization gate
// and the tenant/principal connection store (types.go, store.go). No route,
// MCP tool or startup wiring uses the store yet.
package glovo

import (
	"encoding/json"
	"net/http"
)

// Code is a stable Glovo error code. The set below is closed: it is the
// refusal enum of the joint #959/#960/#961 contract and mctl-api#957 design
// section 4.1, and glovo.Status maps every member to exactly one HTTP status.
type Code string

const (
	CodeNotReady           Code = "not_ready"
	CodeUnavailable        Code = "unavailable"
	CodeNotAuthorized      Code = "not_authorized"
	CodeInvalidRequest     Code = "invalid_request"
	CodeNotFound           Code = "not_found"
	CodeNoInstall          Code = "no_install"
	CodeAmbiguousTenant    Code = "ambiguous_tenant"
	CodeNoTenant           Code = "no_tenant"
	CodeScopeUnsupported   Code = "scope_unsupported"
	CodeNotInPilot         Code = "not_in_pilot"
	CodeStaleInstall       Code = "stale_install"
	CodeStaleVersion       Code = "stale_version"
	CodeNoConnection       Code = "no_connection"
	CodeConnectionExists   Code = "connection_exists"
	CodeConnectionRevoked  Code = "connection_revoked"
	CodeConnectionExpired  Code = "connection_expired"
	CodeInvalidTransition  Code = "invalid_transition"
	CodeIdempotencyReused  Code = "idempotency_key_reused"
	CodeRateLimited        Code = "rate_limited"
	CodeFingerprintChanged Code = "fingerprint_changed"
	CodeApprovalInvalid    Code = "approval_invalid"
	CodeApprovalExpired    Code = "approval_expired"
	CodeApprovalReplayed   Code = "approval_replayed"
	CodeIntentMismatch     Code = "intent_mismatch"
	CodeBasketChanged      Code = "basket_changed"
	CodeTenantBusy         Code = "tenant_busy"
)

// codeInfo is the single registry: one fixed description and one HTTP status
// per code. A description never carries an identifier or owner data.
var codeInfo = map[Code]struct {
	status int
	desc   string
}{
	CodeNotReady:           {http.StatusServiceUnavailable, "the glovo facade is not ready"},
	CodeUnavailable:        {http.StatusServiceUnavailable, "a dependency is unavailable"},
	CodeNotAuthorized:      {http.StatusForbidden, "not authorized for the glovo facade"},
	CodeInvalidRequest:     {http.StatusBadRequest, "the request is invalid"},
	CodeNotFound:           {http.StatusNotFound, "not found"},
	CodeNoInstall:          {http.StatusForbidden, "the team has no current glovo install"},
	CodeAmbiguousTenant:    {http.StatusForbidden, "no team was selected"},
	CodeNoTenant:           {http.StatusForbidden, "no team is available for this caller"},
	CodeScopeUnsupported:   {http.StatusForbidden, "the scope is not supported"},
	CodeNotInPilot:         {http.StatusForbidden, "the caller is not in the pilot"},
	CodeStaleInstall:       {http.StatusForbidden, "the install revision is stale"},
	CodeStaleVersion:       {http.StatusConflict, "the version is stale"},
	CodeNoConnection:       {http.StatusNotFound, "there is no connection"},
	CodeConnectionExists:   {http.StatusConflict, "a live connection already exists"},
	CodeConnectionRevoked:  {http.StatusConflict, "the connection was revoked"},
	CodeConnectionExpired:  {http.StatusConflict, "the connection expired"},
	CodeInvalidTransition:  {http.StatusConflict, "the transition is not allowed"},
	CodeIdempotencyReused:  {http.StatusConflict, "the idempotency key was used with different arguments"},
	CodeRateLimited:        {http.StatusTooManyRequests, "rate limited"},
	CodeFingerprintChanged: {http.StatusConflict, "the fingerprint changed"},
	CodeApprovalInvalid:    {http.StatusConflict, "the approval is invalid"},
	CodeApprovalExpired:    {http.StatusConflict, "the approval expired"},
	CodeApprovalReplayed:   {http.StatusConflict, "the approval was already used"},
	CodeIntentMismatch:     {http.StatusConflict, "the intent does not match"},
	CodeBasketChanged:      {http.StatusConflict, "the basket changed"},
	CodeTenantBusy:         {http.StatusConflict, "the team is busy"},
}

// Registered reports whether c is a member of the closed enum.
func Registered(c Code) bool { _, ok := codeInfo[c]; return ok }

// Codes returns every registered code (unordered).
func Codes() []Code {
	out := make([]Code, 0, len(codeInfo))
	for c := range codeInfo {
		out = append(out, c)
	}
	return out
}

// Status is the single HTTP status mapping of a code. An unregistered code is
// 503: the enum is closed and an unknown code must fail closed. not_authorized
// is 403 here; the 401 is written only by WriteUnauthenticated.
func Status(c Code) int {
	if i, ok := codeInfo[c]; ok {
		return i.status
	}
	return http.StatusServiceUnavailable
}

// Error is a typed Glovo refusal.
type Error struct {
	Code        Code
	Description string
}

func (e *Error) Error() string { return string(e.Code) + ": " + e.Description }

// Is matches another *Error with the same code.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t != nil && e != nil && t.Code == e.Code
}

// refuse returns a refusal with the fixed description of c and nothing else.
func refuse(c Code) *Error {
	return &Error{Code: c, Description: codeInfo[c].desc}
}

// ErrNotFound is the one value for a missing and a foreign entity, so the two
// cannot be told apart.
var ErrNotFound = refuse(CodeNotFound)

func writeBody(w http.ResponseWriter, status int, code Code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             string(code),
		"error_description": desc,
	})
}

// WriteError writes e as {"error","error_description"} with the status of
// Status(e.Code). A code outside the registry is written as 503 with the body
// code "unavailable", never as a status that could read as a decision.
func WriteError(w http.ResponseWriter, e *Error) {
	if e == nil || !Registered(e.Code) {
		writeBody(w, http.StatusServiceUnavailable, CodeUnavailable, codeInfo[CodeUnavailable].desc)
		return
	}
	writeBody(w, Status(e.Code), e.Code, e.Description)
}

// WriteUnauthenticated is the one 401 writer: the body code is not_authorized
// and WWW-Authenticate is set only when wwwAuthenticate is non-empty.
func WriteUnauthenticated(w http.ResponseWriter, wwwAuthenticate string) {
	if wwwAuthenticate != "" {
		w.Header().Set("WWW-Authenticate", wwwAuthenticate)
	}
	writeBody(w, http.StatusUnauthorized, CodeNotAuthorized, codeInfo[CodeNotAuthorized].desc)
}
