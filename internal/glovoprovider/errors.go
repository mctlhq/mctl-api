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

package glovoprovider

import (
	"errors"
	"fmt"
)

// The error kinds keep "could not observe" and "observed absent" apart end to
// end. A read that failed, timed out, returned a malformed body or stopped
// after a partial page is ErrUnobserved, never an empty list or a zero. Only
// the provider's documented absence signal is ErrAbsent.
var (
	// ErrUnobserved: the read did not produce a trustworthy observation.
	ErrUnobserved = errors.New("glovoprovider: could not observe")
	// ErrAbsent: the provider positively reported that the thing does not exist.
	ErrAbsent = errors.New("glovoprovider: absent")
	// ErrNotSupported: the provider does not implement the operation.
	ErrNotSupported = errors.New("glovoprovider: not supported")
	// ErrInvalidRequest: the caller's request is out of bounds.
	ErrInvalidRequest = errors.New("glovoprovider: invalid request")
)

// ReadError carries the operation and the error kind. Its text names only
// the operation and the kind: a provider cause can echo request data, so it
// is reachable through errors.Is/As but never formatted into the message.
type ReadError struct {
	Op    string
	Kind  error
	Cause error
}

func (e *ReadError) Error() string { return fmt.Sprintf("%s: %s", e.Kind.Error(), e.Op) }

// Unwrap exposes both the kind and the cause to errors.Is.
func (e *ReadError) Unwrap() []error {
	if e.Cause == nil {
		return []error{e.Kind}
	}
	return []error{e.Kind, e.Cause}
}

// Unobserved wraps cause as a could-not-observe failure of op.
func Unobserved(op string, cause error) error {
	return &ReadError{Op: op, Kind: ErrUnobserved, Cause: cause}
}

// Absent reports a provider-confirmed absence for op.
func Absent(op string) error { return &ReadError{Op: op, Kind: ErrAbsent} }

// NotSupported reports that op is not implemented by the provider.
func NotSupported(op string) error { return &ReadError{Op: op, Kind: ErrNotSupported} }

// Invalid reports an out-of-bounds request to op.
func Invalid(op, reason string) error {
	return &ReadError{Op: op + ": " + reason, Kind: ErrInvalidRequest}
}
