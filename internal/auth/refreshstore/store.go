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

// Package refreshstore provides persistent storage for OAuth 2.0 refresh tokens.
// The default in-memory store in OAuthServer loses all tokens on pod restart.
// Injecting a Store implementation here makes refresh tokens durable across restarts.
package refreshstore

import (
	"errors"
	"time"
)

// ErrInvalidToken is returned when a refresh token is not found, expired, or revoked.
var ErrInvalidToken = errors.New("invalid or expired refresh token")

// ErrClientMismatch is returned when the client_id in a rotation request does not match
// the client_id that originally issued the token.
var ErrClientMismatch = errors.New("client_id mismatch")

// ErrReuseDetected is returned when a previously-rotated refresh token is presented again.
// When detected, the entire token family is revoked (RFC 6819 §5.2.2.3).
var ErrReuseDetected = errors.New("refresh token reuse detected; token family revoked")

// Store is the interface OAuthServer uses to persist refresh tokens.
// A nil Store means "use the in-memory fallback" — OAuthServer checks for nil before
// calling any method.
type Store interface {
	// Insert stores a brand-new refresh token (first issuance, not a rotation).
	// rawToken is the opaque string returned to the client; the store hashes it
	// with SHA-256 before writing so the raw value never rests in the database.
	Insert(rawToken, login, clientID string, groups []string, expiresAt time.Time) error

	// Rotate atomically invalidates oldRawToken and stores newRawToken with the same
	// family_id. Returns the login and groups from the original token so the caller
	// can issue a new access token.
	//
	// Errors:
	//   ErrInvalidToken   — token not found, expired, or already revoked
	//   ErrClientMismatch — client_id does not match the stored value
	//   ErrReuseDetected  — token was already rotated (reuse attack); whole family revoked
	Rotate(oldRawToken, newRawToken, clientID string, newExpiresAt time.Time) (login string, groups []string, err error)

	// RevokeFamily revokes all tokens that share a family_id with rawToken.
	// Idempotent: no error if the token does not exist.
	RevokeFamily(rawToken, reason string) error

	// GC hard-deletes rows where expires_at < now()-7d AND revoked_at IS NOT NULL.
	// Safe to call on a schedule; never deletes live tokens.
	GC() error
}
