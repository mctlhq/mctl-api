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

// Package glovoconsent keeps a principal's consent to link a real Glovo
// account (mctl-glovo epic #11, slice C2-1c; mctl-glovo design
// token-store.md 4.1 step 1 and real-glovo-accounts.md 9.4 step 1).
//
// A consent row names the principal, the consent text version, when it was
// recorded and, once withdrawn, when it was revoked. At most one row per
// principal is active. Revoked rows stay as history. The version is always
// Version, fixed here: a caller never chooses it.
//
// mctl-glovo reads the active consent through a service route and issues a
// link code only when the version it reads equals the version it shows.
package glovoconsent

import (
	"context"
	"errors"
	"time"
)

// Version is the consent text version mctl-api records. It must equal
// mctl-glovo's linkflow.ConsentVersion: a consent to another text is not a
// consent to the one mctl-glovo shows, and mctl-glovo refuses it.
const Version = "c2-link-v1"

// GrantC2 is the grant that lets a principal link a real Glovo account
// (real-glovo-accounts.md 9.2). A principal holds it while it has an active
// consent to Version (ConsentGrants); recording that consent claims a slot
// under the capacity cap.
const GrantC2 = "glovo:c2"

// Record is one consent row.
type Record struct {
	ID          string     `json:"consent_id"`
	PrincipalID string     `json:"principal_id"`
	Version     string     `json:"consent_version"`
	RecordedAt  time.Time  `json:"recorded_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

// Active reports whether the record is not revoked.
func (r Record) Active() bool { return r.RevokedAt == nil }

var (
	// ErrNoConsent is the documented absence: the principal has no active
	// consent (never recorded, or revoked). It is the only "no" answer;
	// every other error means the record could not be read.
	ErrNoConsent = errors.New("glovoconsent: no active consent")
	// ErrCapacityReached refuses a new consent because every slot under the
	// capacity cap is taken (or the cap is closed, 0). A fixed answer the
	// link page can show as a waitlist message.
	ErrCapacityReached = errors.New("glovoconsent: capacity reached")
	// ErrInvalid is a malformed principal id or actor.
	ErrInvalid = errors.New("glovoconsent: invalid request")
)

// Store keeps consent records.
type Store interface {
	// Record makes Version the principal's active consent. Every active
	// consent holds one slot, and at most capacity are active at once.
	// An active consent to Version is returned as it is (created false,
	// no second slot); an active consent to another version is revoked and
	// replaced in the same transaction, keeping its slot. A principal with
	// no active consent claims a slot atomically, or gets
	// ErrCapacityReached; capacity <= 0 is closed.
	Record(ctx context.Context, principalID, actor string, capacity int) (rec Record, created bool, err error)
	// Revoke withdraws the active consent, which frees its slot.
	// ErrNoConsent when there is none.
	Revoke(ctx context.Context, principalID, actor string) (Record, error)
	// Active is the principal's active consent, or ErrNoConsent.
	Active(ctx context.Context, principalID string) (Record, error)
}

// GrantSource decides whether a principal holds a grant. An error means the
// decision could not be made, which is never a grant.
type GrantSource interface {
	HasGrant(ctx context.Context, principalID, grant string) (bool, error)
}

// ConsentGrants is the GrantSource backed by the consent table: a
// principal holds GrantC2 while it has an active consent to Version, which
// it could only record by claiming a slot under the capacity cap. There is
// no list to maintain and no per-user step. It holds no other grant.
type ConsentGrants struct {
	Store Store
}

// HasGrant implements GrantSource. Only the documented absence
// (ErrNoConsent) is "no"; any other failure is an error, never a grant.
func (g ConsentGrants) HasGrant(ctx context.Context, principalID, grant string) (bool, error) {
	if g.Store == nil {
		return false, errors.New("glovoconsent: no consent store")
	}
	if grant != GrantC2 {
		return false, nil
	}
	rec, err := g.Store.Active(ctx, principalID)
	switch {
	case errors.Is(err, ErrNoConsent):
		return false, nil
	case err != nil:
		return false, err
	case rec.PrincipalID != principalID || !rec.Active():
		return false, errors.New("glovoconsent: inconsistent consent row")
	}
	return rec.Version == Version, nil
}

// HeldSince reports whether the principal holds GrantC2 through one active
// consent to Version that was recorded at or before at. A personal Glovo
// grant created at at is valid only while that holds: withdrawing the
// consent ends the grant, and consenting again records a new consent that
// is later than the grant, so it never revives one. Only the documented
// absence (ErrNoConsent) is "no"; any other failure is an error, never a
// grant.
func (g ConsentGrants) HeldSince(ctx context.Context, principalID string, at time.Time) (bool, error) {
	if g.Store == nil {
		return false, errors.New("glovoconsent: no consent store")
	}
	rec, err := g.Store.Active(ctx, principalID)
	switch {
	case errors.Is(err, ErrNoConsent):
		return false, nil
	case err != nil:
		return false, err
	case rec.PrincipalID != principalID || !rec.Active():
		return false, errors.New("glovoconsent: inconsistent consent row")
	}
	return rec.Version == Version && !rec.RecordedAt.After(at), nil
}
