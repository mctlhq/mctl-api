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

// Per-principal Glovo access request (mctl-glovo docs/design/
// self-service-onboarding.md sections 4 and 5.2, decisions D2, D3, D7).
//
// A principal asks for access, the owner approves or rejects, and an
// approved access can be revoked. One row per principal in
// glovo_access_requests holds the current status; every change also appends
// a row to glovo_access_events in the same transaction.
//
// Slot semantics are chosen by the AccessRequired store option:
//
//   - false (default, today's behaviour): a slot is an active consent.
//     Record claims it and counts active consents. The access methods work
//     but never touch capacity.
//   - true (owner decision D2, reserve the slot at approval): a slot is a
//     principal whose access is approved. Record no longer claims a slot (a
//     person consents before asking), ApproveAccess claims one and returns
//     ErrCapacityReached at the cap (capacity <= 0 is closed), RevokeAccess
//     frees it. The row is keyed by principal, so one principal never holds
//     two slots.
//
// A pending request lapses seven days after it was made. Lapsing is derived
// at read time from expires_at: a lapsed request reads as AccessNone and can
// be neither approved nor rejected. No sweeper is needed for correctness.
//
// Stage C adds an outbox of notifications and the one-time decide link; see
// notify.go. Both are off unless SetAccessNotify(true) was called.
//
// Mutating methods take the principal lock, then the capacity lock, the same
// order as Record. Reads are single statements and take no lock.
package glovoconsent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// AccessStatus is the state of a principal's access request.
type AccessStatus string

// Access states. A lapsed pending request is AccessNone, not a state.
const (
	AccessNone     AccessStatus = "none"
	AccessPending  AccessStatus = "pending"
	AccessApproved AccessStatus = "approved"
	AccessRejected AccessStatus = "rejected"
	AccessRevoked  AccessStatus = "revoked"
)

// AccessRequestTTL is how long a pending request stays open (decision D7).
const AccessRequestTTL = 7 * 24 * time.Hour

// Field length caps, mirrored by CHECKs in the schema.
const (
	maxActorLen  = 256
	maxReasonLen = 1000
)

// ActorBackfill is the decided_by of rows created from existing consents.
const ActorBackfill = "backfill"

var (
	// ErrAccessApproved refuses a new request from a principal whose access
	// is already approved.
	ErrAccessApproved = errors.New("glovoconsent: access already approved")
	// ErrAccessNotPending refuses approving or rejecting anything but a
	// live pending request (none, lapsed, decided already).
	ErrAccessNotPending = errors.New("glovoconsent: no pending access request")
	// ErrAccessNotApproved refuses revoking anything but approved access.
	ErrAccessNotApproved = errors.New("glovoconsent: access is not approved")
)

// Access is one principal's access row.
type Access struct {
	PrincipalID string       `json:"principal_id"`
	Status      AccessStatus `json:"status"`
	RequestedAt time.Time    `json:"requested_at"`
	ExpiresAt   time.Time    `json:"expires_at"`
	DecidedAt   *time.Time   `json:"decided_at,omitempty"`
	DecidedBy   string       `json:"decided_by,omitempty"`
	Reason      string       `json:"reason,omitempty"`
}

// effective is the state a reader sees: a pending request past its expiry is
// none. Strictly after: at exactly expires_at the request is still pending.
func (a Access) effective(now time.Time) AccessStatus {
	if a.Status == AccessPending && now.After(a.ExpiresAt) {
		return AccessNone
	}
	return a.Status
}

const accessSchema = `
CREATE TABLE IF NOT EXISTS glovo_access_requests (
	principal_id TEXT PRIMARY KEY CHECK (principal_id ~ '^prn_[0-9A-HJKMNP-TV-Z]{26}$'),
	status       TEXT NOT NULL CHECK (status IN ('pending','approved','rejected','revoked')),
	requested_at TIMESTAMPTZ NOT NULL,
	expires_at   TIMESTAMPTZ NOT NULL,
	decided_at   TIMESTAMPTZ,
	decided_by   TEXT NOT NULL DEFAULT '' CHECK (length(decided_by) <= 256),
	reason       TEXT NOT NULL DEFAULT '' CHECK (length(reason) <= 1000)
);
CREATE INDEX IF NOT EXISTS glovo_access_requests_status ON glovo_access_requests (status);
CREATE TABLE IF NOT EXISTS glovo_access_events (
	event_id     BIGSERIAL PRIMARY KEY,
	principal_id TEXT NOT NULL CHECK (principal_id ~ '^prn_[0-9A-HJKMNP-TV-Z]{26}$'),
	event        TEXT NOT NULL CHECK (event IN ('requested','lapsed','approved','rejected','revoked')),
	actor        TEXT NOT NULL CHECK (actor <> '' AND length(actor) <= 256),
	reason       TEXT NOT NULL DEFAULT '' CHECK (length(reason) <= 1000),
	at           TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS glovo_access_events_principal ON glovo_access_events (principal_id, event_id);
CREATE TABLE IF NOT EXISTS glovo_access_meta (
	key TEXT PRIMARY KEY,
	at  TIMESTAMPTZ NOT NULL
);
`

const backfillKey = "backfill-v1"

// backfillAccess gives every principal that has an active consent and no
// access row an approved row (decided_by 'backfill'), once. The marker row
// makes it one-shot: without it, a later restart would approve every person
// who had recorded consent but not yet asked, which AccessRequired mode
// expects. Idempotent: ON CONFLICT leaves existing rows alone, events are
// written only for rows actually inserted, and two concurrent starters
// serialise on the marker's primary key.
func (s *PostgresStore) backfillAccess(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("glovoconsent: backfill begin: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	now := s.now()
	tag, err := tx.Exec(ctx, `INSERT INTO glovo_access_meta (key, at) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`, backfillKey, now)
	if err != nil {
		return fmt.Errorf("glovoconsent: backfill marker: %w", err)
	}
	if tag.RowsAffected() == 1 {
		if _, err := tx.Exec(ctx, `
WITH ins AS (
	INSERT INTO glovo_access_requests (principal_id, status, requested_at, expires_at, decided_at, decided_by, reason)
	SELECT c.principal_id, 'approved', c.recorded_at, c.recorded_at, $1, $2, 'active consent at migration'
	FROM glovo_link_consents c
	WHERE c.revoked_at IS NULL
	ON CONFLICT (principal_id) DO NOTHING
	RETURNING principal_id
)
INSERT INTO glovo_access_events (principal_id, event, actor, reason, at)
SELECT principal_id, 'approved', $2, 'active consent at migration', $1 FROM ins`, now, ActorBackfill); err != nil {
			return fmt.Errorf("glovoconsent: backfill: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("glovoconsent: backfill commit: %w", err)
	}
	return nil
}

const selectAccess = `SELECT principal_id, status, requested_at, expires_at, decided_at, decided_by, reason
	FROM glovo_access_requests WHERE principal_id = $1`

// queryer is what pool and tx share for a single-row read.
type queryer interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// readAccess returns the row, found false only for pgx.ErrNoRows. Any other
// failure is an error.
func readAccess(ctx context.Context, q queryer, principalID string) (Access, bool, error) {
	var a Access
	var status string
	err := q.QueryRow(ctx, selectAccess, principalID).Scan(&a.PrincipalID, &status, &a.RequestedAt, &a.ExpiresAt, &a.DecidedAt, &a.DecidedBy, &a.Reason)
	if errors.Is(err, pgx.ErrNoRows) {
		return Access{}, false, nil
	}
	if err != nil {
		return Access{}, false, fmt.Errorf("glovoconsent: read access: %w", err)
	}
	a.Status = AccessStatus(status)
	switch a.Status {
	case AccessPending, AccessApproved, AccessRejected, AccessRevoked:
	default:
		return Access{}, false, fmt.Errorf("glovoconsent: read access: unknown status %q", status)
	}
	a.RequestedAt, a.ExpiresAt = a.RequestedAt.UTC(), a.ExpiresAt.UTC()
	if a.DecidedAt != nil {
		t := a.DecidedAt.UTC()
		a.DecidedAt = &t
	}
	return a, true, nil
}

// withSlotTx is withPrincipalTx plus the capacity lock, in Record's order.
func (s *PostgresStore) withSlotTx(ctx context.Context, principalID string, fn func(context.Context, pgx.Tx) error) error {
	return s.withPrincipalTx(ctx, principalID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('glovo-link-consent:capacity'))`); err != nil {
			return fmt.Errorf("glovoconsent: capacity lock: %w", err)
		}
		return fn(ctx, tx)
	})
}

func addEvent(ctx context.Context, tx pgx.Tx, principalID, event, actor, reason string, at time.Time) error {
	if _, err := tx.Exec(ctx, `INSERT INTO glovo_access_events (principal_id, event, actor, reason, at) VALUES ($1, $2, $3, $4, $5)`,
		principalID, event, actor, reason, at); err != nil {
		return fmt.Errorf("glovoconsent: access event: %w", err)
	}
	return nil
}

func validateDecision(principalID, actor, reason string) error {
	if !prnPattern.MatchString(principalID) || actor == "" || reason == "" ||
		len(actor) > maxActorLen || len(reason) > maxReasonLen {
		return ErrInvalid
	}
	return nil
}

// AccessState is the principal's current access state. A pending request
// past its expiry is AccessNone. A read that fails is an error with an empty
// status, never AccessNone.
func (s *PostgresStore) AccessState(ctx context.Context, principalID string) (AccessStatus, error) {
	if !prnPattern.MatchString(principalID) {
		return "", ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	a, found, err := readAccess(ctx, s.pool, principalID)
	if err != nil {
		return "", err
	}
	if !found {
		return AccessNone, nil
	}
	return a.effective(s.now()), nil
}

// GetAccess is the principal's access row as a reader sees it: Status is the
// effective state (a lapsed pending request is AccessNone), and the times are
// those of the row. With no row the answer is AccessNone and zero times. A
// read that fails is an error, never AccessNone.
func (s *PostgresStore) GetAccess(ctx context.Context, principalID string) (Access, error) {
	if !prnPattern.MatchString(principalID) {
		return Access{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	a, found, err := readAccess(ctx, s.pool, principalID)
	if err != nil {
		return Access{}, err
	}
	if !found {
		return Access{PrincipalID: principalID, Status: AccessNone}, nil
	}
	a.Status = a.effective(s.now())
	return a, nil
}

// RequestAccess opens a request for the principal, expiring after
// AccessRequestTTL. A live pending request is returned as it is (created
// false). Approved access is refused with ErrAccessApproved. A rejected,
// revoked or lapsed one is replaced by a new pending request.
func (s *PostgresStore) RequestAccess(ctx context.Context, principalID string) (Access, bool, error) {
	if !prnPattern.MatchString(principalID) {
		return Access{}, false, ErrInvalid
	}
	var out Access
	created := false
	err := s.withPrincipalTx(ctx, principalID, func(ctx context.Context, tx pgx.Tx) error {
		cur, found, err := readAccess(ctx, tx, principalID)
		if err != nil {
			return err
		}
		now := s.now()
		if found {
			switch cur.effective(now) {
			case AccessApproved:
				return ErrAccessApproved
			case AccessPending:
				out = cur
				return nil
			case AccessNone:
				if err := addEvent(ctx, tx, principalID, "lapsed", "system", "request expired", cur.ExpiresAt); err != nil {
					return err
				}
			}
		}
		out = Access{PrincipalID: principalID, Status: AccessPending, RequestedAt: now, ExpiresAt: now.Add(AccessRequestTTL)}
		if _, err := tx.Exec(ctx, `INSERT INTO glovo_access_requests (principal_id, status, requested_at, expires_at)
			VALUES ($1, 'pending', $2, $3)
			ON CONFLICT (principal_id) DO UPDATE SET status = 'pending', requested_at = EXCLUDED.requested_at,
				expires_at = EXCLUDED.expires_at, decided_at = NULL, decided_by = '', reason = ''`,
			principalID, out.RequestedAt, out.ExpiresAt); err != nil {
			return fmt.Errorf("glovoconsent: request access: %w", err)
		}
		created = true
		if err := addEvent(ctx, tx, principalID, "requested", principalID, "", now); err != nil {
			return err
		}
		// A new request replaces whatever a decide link was made for, and
		// (with the outbox on) tells the owner.
		if err := retireDecideTokens(ctx, tx, principalID, now); err != nil {
			return err
		}
		return s.enqueueNotification(ctx, tx, principalID, NotifyOwnerCard, out.RequestedAt, out.ExpiresAt, now)
	})
	if err != nil {
		return Access{}, false, err
	}
	return out, created, nil
}

// decide moves a row from one status to another and appends the event.
// tokenHash, when set, is a decide-link token consumed in the same
// transaction: an invalid one decides nothing (ErrDecideTokenInvalid).
func (s *PostgresStore) decide(ctx context.Context, principalID, actor, reason string, from, to AccessStatus, event string, notFrom error, capacity int, tokenHash string) (Access, error) {
	if err := validateDecision(principalID, actor, reason); err != nil {
		return Access{}, err
	}
	var out Access
	// Only an approval under AccessRequired counts slots, so only it takes the
	// capacity lock; the count runs after the lock and sees committed revokes.
	run := s.withPrincipalTx
	if to == AccessApproved && s.accessRequired {
		run = s.withSlotTx
	}
	err := run(ctx, principalID, func(ctx context.Context, tx pgx.Tx) error {
		cur, found, err := readAccess(ctx, tx, principalID)
		if err != nil {
			return err
		}
		now := s.now()
		if !found {
			return notFrom
		}
		if tokenHash != "" {
			if err := spendDecideToken(ctx, tx, principalID, tokenHash, cur.RequestedAt, now); err != nil {
				return err
			}
		}
		if cur.effective(now) != from {
			return notFrom
		}
		if to == AccessApproved && s.accessRequired {
			if capacity <= 0 {
				return ErrCapacityReached
			}
			var taken int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM glovo_access_requests WHERE status = 'approved'`).Scan(&taken); err != nil {
				return fmt.Errorf("glovoconsent: count access slots: %w", err)
			}
			if taken >= capacity {
				return ErrCapacityReached
			}
		}
		tag, err := tx.Exec(ctx, `UPDATE glovo_access_requests SET status = $2, decided_at = $3, decided_by = $4, reason = $5
			WHERE principal_id = $1 AND status = $6`, principalID, string(to), now, actor, reason, string(from))
		if err != nil {
			return fmt.Errorf("glovoconsent: %s: %w", event, err)
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("glovoconsent: %s: %d rows changed, want 1", event, tag.RowsAffected())
		}
		if err := addEvent(ctx, tx, principalID, event, actor, reason, now); err != nil {
			return err
		}
		if from == AccessPending {
			// The request is decided: every link made for it is dead.
			if err := retireDecideTokens(ctx, tx, principalID, now); err != nil {
				return err
			}
			// The owner's decision is emailed to the requester. A withdrawal
			// is a rejection by the requester themselves and sends nothing.
			if kind := NotifyKind(event); actor != principalID {
				if err := s.enqueueNotification(ctx, tx, principalID, kind, cur.RequestedAt, cur.ExpiresAt, now); err != nil {
					return err
				}
			}
		}
		out = cur
		out.Status, out.DecidedAt, out.DecidedBy, out.Reason = to, &now, actor, reason
		return nil
	})
	if err != nil {
		return Access{}, err
	}
	return out, nil
}

// ApproveAccess approves a live pending request. With AccessRequired it
// claims a slot atomically or returns ErrCapacityReached (capacity <= 0 is
// closed). Actor and reason are mandatory.
func (s *PostgresStore) ApproveAccess(ctx context.Context, principalID, actor, reason string, capacity int) (Access, error) {
	return s.decide(ctx, principalID, actor, reason, AccessPending, AccessApproved, "approved", ErrAccessNotPending, capacity, "")
}

// RejectAccess rejects a live pending request. Actor and reason are
// mandatory.
func (s *PostgresStore) RejectAccess(ctx context.Context, principalID, actor, reason string) (Access, error) {
	return s.decide(ctx, principalID, actor, reason, AccessPending, AccessRejected, "rejected", ErrAccessNotPending, 0, "")
}

// RevokeAccess revokes approved access, which frees its slot under
// AccessRequired. Actor and reason are mandatory.
func (s *PostgresStore) RevokeAccess(ctx context.Context, principalID, actor, reason string) (Access, error) {
	return s.decide(ctx, principalID, actor, reason, AccessApproved, AccessRevoked, "revoked", ErrAccessNotApproved, 0, "")
}

// ListPendingAccess lists live pending requests, oldest first. Lapsed ones
// are left out; a failed read is an error, never an empty list.
func (s *PostgresStore) ListPendingAccess(ctx context.Context) ([]Access, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	rows, err := s.pool.Query(ctx, `SELECT principal_id, requested_at, expires_at FROM glovo_access_requests
		WHERE status = 'pending' AND expires_at >= $1 ORDER BY requested_at, principal_id`, s.now())
	if err != nil {
		return nil, fmt.Errorf("glovoconsent: list pending: %w", err)
	}
	defer rows.Close()
	out := []Access{}
	for rows.Next() {
		a := Access{Status: AccessPending}
		if err := rows.Scan(&a.PrincipalID, &a.RequestedAt, &a.ExpiresAt); err != nil {
			return nil, fmt.Errorf("glovoconsent: list pending: %w", err)
		}
		a.RequestedAt, a.ExpiresAt = a.RequestedAt.UTC(), a.ExpiresAt.UTC()
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("glovoconsent: list pending: %w", err)
	}
	return out, nil
}
