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

package bridge

import "errors"

// Typed refusals. Every one is returned with the transaction rolled back, so
// a refused call leaves every bridge row exactly as it found it. Code maps an
// error to the stable wire code the HTTP layer reports.
var (
	ErrInvalidDocument       = errors.New("invalid_document")
	ErrInvalidInput          = errors.New("invalid_input")
	ErrCommandNotFound       = errors.New("command_not_found")
	ErrLeaseStale            = errors.New("lease_stale")
	ErrBindingMismatch       = errors.New("binding_mismatch")
	ErrCommandCancelled      = errors.New("command_cancelled")
	ErrCommandExpired        = errors.New("command_expired")
	ErrResultConflict        = errors.New("result_conflict")
	ErrResultInconsistent    = errors.New("result_inconsistent")
	ErrAlreadyCompleted      = errors.New("already_completed")
	ErrNotMutating           = errors.New("not_mutating")
	ErrPermitExists          = errors.New("permit_already_issued")
	ErrWriteFenceUnavailable = errors.New("write_fence_unavailable")
	ErrWriteFenceRefused     = errors.New("write_fence_refused")
	// ErrPayloadTooLarge is JCS(payload) over the #1059 cap of 12288 bytes.
	ErrPayloadTooLarge = errors.New("payload_too_large")
	// ErrReadUnavailable is the fail-closed answer of the read path: read schema
	// level missing, deadline passed, integrity failure or a checker error.
	ErrReadUnavailable = errors.New("read_unavailable")
	// ErrReadNotAuthorized is a fetch without the glovo:read scope.
	ErrReadNotAuthorized = errors.New("read_not_authorized")
	// ErrSignalTargetNotFound is what a BridgeSignaler returns when the stored
	// workflow/run no longer exists.
	ErrSignalTargetNotFound = errors.New("signal_target_not_found")
)

var codedErrors = []error{
	ErrInvalidDocument, ErrInvalidInput, ErrCommandNotFound, ErrLeaseStale,
	ErrBindingMismatch, ErrCommandCancelled, ErrCommandExpired, ErrResultConflict,
	ErrResultInconsistent, ErrAlreadyCompleted, ErrNotMutating, ErrPermitExists,
	ErrWriteFenceUnavailable, ErrWriteFenceRefused,
	ErrPayloadTooLarge, ErrReadUnavailable, ErrReadNotAuthorized,
}

// Code is the stable error code of err, or "" when err is not a typed bridge
// refusal (a store failure, say).
func Code(err error) string {
	for _, e := range codedErrors {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	return ""
}
