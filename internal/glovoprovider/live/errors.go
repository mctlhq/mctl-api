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

package live

import (
	"errors"

	gp "github.com/mctlhq/mctl-api/internal/glovoprovider"
)

// Typed failure causes of the live adapter. Every read failure is wrapped as
// glovoprovider.ErrUnobserved with one of these as the cause, so callers can
// match either the contract kind or the specific cause with errors.Is. None
// of them ever carries response text, a URL, a header or a token.
var (
	// ErrUnavailable: transport failure, timeout, truncated body, redirect,
	// or a non-2xx status that is not an auth or rate-limit signal.
	ErrUnavailable = errors.New("glovolive: provider unavailable")
	// ErrSchemaDrift: a 2xx body that is malformed or lacks a field the
	// adapter requires. It is never reported as an empty result.
	ErrSchemaDrift = errors.New("glovolive: response schema drift")
	// ErrAuth: the session was refused (401 after the single refresh, 403,
	// or the TokenSource could not supply a token).
	ErrAuth = errors.New("glovolive: authentication failed")
	// ErrRateLimited: the provider answered 429. It is not retried.
	ErrRateLimited = errors.New("glovolive: rate limited")
	// ErrResponseTooLarge: the body exceeded the configured size cap.
	ErrResponseTooLarge = errors.New("glovolive: response too large")
	// ErrHostNotAllowed: a request or redirect targeted a host other than the
	// configured Glovo API host.
	ErrHostNotAllowed = errors.New("glovolive: host not allowed")
	// ErrLocationMismatch: the account has no saved address in the
	// configured delivery city.
	ErrLocationMismatch = errors.New("glovolive: configured delivery location not in account")

	// ErrPrecondition: the live cart version differs from the version the
	// caller read. Nothing was written.
	ErrPrecondition = errors.New("glovolive: cart version precondition failed")
	// ErrWriteRejected: the provider definitively refused the write (4xx).
	// Nothing was applied.
	ErrWriteRejected = errors.New("glovolive: write rejected")
	// ErrWriteUnknown: the write may or may not have landed (timeout, 5xx,
	// dropped connection). The caller must read the cart back; the write is
	// never retried by the adapter.
	ErrWriteUnknown = errors.New("glovolive: write outcome unknown")
	// ErrReconcileMismatch: the cart read back after the write does not match
	// the requested change.
	ErrReconcileMismatch = errors.New("glovolive: reconcile mismatch")
)

func unobserved(op string, cause error) error { return gp.Unobserved(op, cause) }

// kindErr builds a ReadError with kind as the primary kind.
func kindErr(op string, kind error) error { return &gp.ReadError{Op: op, Kind: kind} }
