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

package session

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Key binds a stored session to exactly one (tenant, principal, provider
// connection). Every Store operation requires all three to match the row; a
// mismatch is indistinguishable from "no such session" (ErrNotFound).
type Key struct {
	TenantID     string
	PrincipalID  string
	ConnectionID string
}

func (k Key) validate() error {
	if k.TenantID == "" || k.PrincipalID == "" || k.ConnectionID == "" {
		return ErrInvalid
	}
	return nil
}

// Secret is a token. It never formats itself: %v, %+v, %#v, %s and JSON all
// print a fixed placeholder, so a Secret that reaches a log line or an error
// by accident leaks nothing. Reveal is the only way out, and every call site
// of Reveal is a place a token leaves custody.
type Secret string

const redacted = "[redacted]"

func (Secret) String() string               { return redacted }
func (Secret) GoString() string             { return redacted }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// Reveal returns the token value.
func (s Secret) Reveal() string { return string(s) }

// Tokens is the credential pair of one session. It is the only secret
// payload: profile fields of the upstream session file (name, email,
// coordinates, device ids) are dropped at the parser and never stored.
type Tokens struct {
	Access          Secret
	Refresh         Secret
	AccessExpiresAt time.Time
}

// State is the lifecycle of a stored session.
type State string

const (
	// StateActive: tokens are present and usable (possibly after a refresh).
	StateActive State = "active"
	// StateReloginRequired: the provider rejected the refresh token, or the
	// outcome of a refresh is unrecoverable. Tokens are wiped. Terminal until
	// the owner loads a new session.
	StateReloginRequired State = "relogin_required"
	// StateRevoked: killed by the owner or an operator. Tokens are wiped.
	// Terminal until the owner loads a new session.
	StateRevoked State = "revoked"
)

// Record is one stored session. Tokens is zero unless State is active.
type Record struct {
	Key           Key
	State         State
	Tokens        Tokens
	Generation    int64
	FromRefresh   bool
	RefreshIntent bool
	ReloginReason string
	LeaseHolder   string
	LeaseUntil    time.Time
	UpdatedAt     time.Time
}

// Status is the secret-free view of a Record, safe to show to a user or an
// operator. A non-active state is explicit data, never an empty result.
type Status struct {
	State           State
	Generation      int64
	AccessExpiresAt time.Time
	ReloginReason   string
	UpdatedAt       time.Time
}

// Errors. None of their texts carries provider output or a token.
var (
	// ErrReloginRequired: the stored session cannot be used any more and only
	// the owner loading a new one fixes it. Always surfaced as an error to
	// the caller, never as empty data.
	ErrReloginRequired = errors.New("glovo session: relogin required")
	ErrRevoked         = errors.New("glovo session: revoked")
	ErrNotFound        = errors.New("glovo session: not found")
	ErrDisabled        = errors.New("glovo session: custody disabled")
	ErrInvalid         = errors.New("glovo session: invalid request")
	// ErrUnavailable: the session could not be observed or refreshed right
	// now (backend down, provider timeout). The stored session is unchanged
	// or its outcome is recorded; retry later. Never an empty token.
	ErrUnavailable = errors.New("glovo session: temporarily unavailable")
	// ErrLeaseHeld: another holder owns the refresh lease.
	ErrLeaseHeld = errors.New("glovo session: refresh lease held")
	// ErrLeaseLost: this holder's lease was taken over before it committed.
	ErrLeaseLost = errors.New("glovo session: refresh lease lost")
	// ErrStale: the compare-and-swap generation did not match.
	ErrStale = errors.New("glovo session: stale generation")
	// ErrCorrupt: a stored ciphertext did not authenticate (wrong key, wrong
	// binding or tampering).
	ErrCorrupt = errors.New("glovo session: stored session does not authenticate")
)

// ReloginError carries a stable reason code (never provider text).
type ReloginError struct{ Reason string }

func (e *ReloginError) Error() string {
	return fmt.Sprintf("%s (%s)", ErrReloginRequired.Error(), e.Reason)
}
func (e *ReloginError) Is(t error) bool { return t == ErrReloginRequired }

// Reason codes recorded with a relogin_required state.
const (
	ReasonRefreshRejected     = "refresh_rejected"
	ReasonAccessRejectedAfter = "access_rejected_after_refresh"
	ReasonRefreshOutcomeLost  = "refresh_outcome_unknown_then_rejected"
	ReasonExpiredNoRefresh    = "expired_without_refresh_token"
)

// Store is the persistence contract. Implementations must make AcquireLease
// and Commit atomic and must never write tokens of a revoked or
// relogin_required session.
type Store interface {
	// Put is the owner load: it replaces whatever is stored for key, sets the
	// state to active, bumps the generation and clears any lease, so an
	// in-flight refresh of the previous lineage fails its commit with ErrStale.
	Put(ctx context.Context, key Key, t Tokens) (Record, error)
	// Get returns the record. For a non-active state it returns the record
	// with zero Tokens and a nil error; callers must check State.
	Get(ctx context.Context, key Key) (Record, error)
	// AcquireLease takes the single-writer refresh lease for ttl and records a
	// refresh intent. It returns ErrLeaseHeld while another holder's lease is
	// unexpired. The holder may re-acquire its own lease. A non-active state
	// returns the record without a lease and a nil error.
	AcquireLease(ctx context.Context, key Key, holder string, ttl time.Duration) (Record, error)
	// Commit atomically replaces the tokens iff the generation is expected,
	// the lease is still held by holder and the state is active. It bumps the
	// generation, marks FromRefresh, clears the intent and the lease.
	Commit(ctx context.Context, key Key, holder string, expected int64, t Tokens) (Record, error)
	// Release drops holder's lease. When outcomeKnown the refresh intent is
	// cleared too (nothing was rotated); otherwise it stays set.
	Release(ctx context.Context, key Key, holder string, outcomeKnown bool) error
	// MarkRelogin wipes the tokens and records relogin_required, iff the
	// generation is expected and the state is active. holder may be empty for
	// a caller that holds no lease.
	MarkRelogin(ctx context.Context, key Key, expected int64, reason string) error
	// Revoke wipes the tokens and records revoked, from any state.
	Revoke(ctx context.Context, key Key) error
	// Status is Get without tokens.
	Status(ctx context.Context, key Key) (Status, error)
}
