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

// Access notifications and the one-time decide link (mctl-glovo
// docs/design/self-service-onboarding.md sections 5.4 and 5.5, decisions D1,
// D6, D7; stage C).
//
// Dark by default. Nothing here is written unless SetAccessNotify(true) was
// called: with it off RequestAccess, the decisions and the reads behave
// exactly as before. The requester's emails have a switch of their own,
// SetAccessEmail, so the owner card can run without them.
//
// With it on, the access methods append an outbox row to
// glovo_access_notifications in the SAME transaction as the change they
// describe, so a notification exists exactly when its cause was committed:
//
//   - owner_card: a request was opened; the owner is told, with a link.
//   - approved, rejected: the owner decided on the decision page. A
//     requester's own withdrawal (stored as a rejection by the requester) and
//     a revocation enqueue nothing.
//   - lapsed: a pending request passed its expiry undecided (EnqueueLapsed).
//
// A row is unique per (principal, requested_at, kind): one request causes at
// most one notification of each kind, however often it is retried. Rows are
// delivered by a leasing loop outside this package; a failed delivery never
// touches the access row.
//
// The decide link carries a one-time token. Only its SHA-256 is stored, bound
// to one request (principal and requested_at) with an expiry and a used time.
// Because the raw token cannot be read back, it is minted when a card is
// sent, one per attempt; every unused token of a request dies when the
// request is decided, withdrawn or replaced. The token never replaces the
// decider's sign-in: it only binds a link to one request.
package glovoconsent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// NotifyKind is what a notification tells and to whom.
type NotifyKind string

// Notification kinds. The owner card goes to the owner, the others are the
// requester's emails (design Appendix A).
const (
	NotifyOwnerCard NotifyKind = "owner_card"
	NotifyApproved  NotifyKind = "approved"
	NotifyRejected  NotifyKind = "rejected"
	NotifyLapsed    NotifyKind = "lapsed"
)

// Valid reports whether k is a known kind.
func (k NotifyKind) Valid() bool {
	switch k {
	case NotifyOwnerCard, NotifyApproved, NotifyRejected, NotifyLapsed:
		return true
	}
	return false
}

// NotifyWindow is how long a notification is retried after it was created.
// It stays under the mail provider's 24-hour idempotency window, so a retry
// can never send a second email.
const NotifyWindow = 23 * time.Hour

// notifyLease is how long one delivery attempt owns a row. A failed attempt
// is retried when the lease runs out.
const notifyLease = 2 * time.Minute

// Notification outcomes recorded on an abandoned row.
const (
	NotifyOutcomeExpired = "expired"
)

const maxDeliveryIDLen = 200

var (
	// ErrDecideTokenInvalid refuses a decision made through a decide link
	// whose token is unknown, used, expired or bound to another request.
	ErrDecideTokenInvalid = errors.New("glovoconsent: decide link token is not valid for this request")
	// ErrNotifyLeaseLost means the row is no longer leased to the caller: the
	// lease ran out and another attempt may own it.
	ErrNotifyLeaseLost = errors.New("glovoconsent: notification lease lost")
)

const notifySchema = `
CREATE TABLE IF NOT EXISTS glovo_access_notifications (
	notification_id BIGSERIAL PRIMARY KEY,
	principal_id    TEXT NOT NULL CHECK (principal_id ~ '^prn_[0-9A-HJKMNP-TV-Z]{26}$'),
	kind            TEXT NOT NULL CHECK (kind IN ('owner_card','approved','rejected','lapsed')),
	requested_at    TIMESTAMPTZ NOT NULL,
	expires_at      TIMESTAMPTZ NOT NULL,
	created_at      TIMESTAMPTZ NOT NULL,
	state           TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','sent','abandoned')),
	attempts        INTEGER NOT NULL DEFAULT 0,
	lease           TEXT NOT NULL DEFAULT '',
	leased_until    TIMESTAMPTZ,
	delivery_id     TEXT NOT NULL DEFAULT '' CHECK (length(delivery_id) <= 200),
	outcome         TEXT NOT NULL DEFAULT '' CHECK (length(outcome) <= 64),
	finished_at     TIMESTAMPTZ,
	UNIQUE (principal_id, requested_at, kind)
);
CREATE INDEX IF NOT EXISTS glovo_access_notifications_pending
	ON glovo_access_notifications (notification_id) WHERE state = 'pending';
CREATE TABLE IF NOT EXISTS glovo_access_decide_tokens (
	token_hash   TEXT PRIMARY KEY CHECK (token_hash ~ '^[0-9a-f]{64}$'),
	principal_id TEXT NOT NULL CHECK (principal_id ~ '^prn_[0-9A-HJKMNP-TV-Z]{26}$'),
	requested_at TIMESTAMPTZ NOT NULL,
	created_at   TIMESTAMPTZ NOT NULL,
	expires_at   TIMESTAMPTZ NOT NULL,
	used_at      TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS glovo_access_decide_tokens_request
	ON glovo_access_decide_tokens (principal_id, requested_at);
`

// SetAccessNotify switches the owner card on or off. Off is the default and
// queues no card. Safe to call at any time.
func (s *PostgresStore) SetAccessNotify(v bool) { s.accessNotify.Store(v) }

// AccessNotify reports whether the owner card is on.
func (s *PostgresStore) AccessNotify() bool { return s.accessNotify.Load() }

// SetAccessEmail switches the requester's emails (approved, rejected,
// lapsed) on or off, separately from the owner card. Off is the default and
// queues no email, so nothing ever asks for the requester's address. Safe to
// call at any time.
func (s *PostgresStore) SetAccessEmail(v bool) { s.accessEmail.Store(v) }

// AccessEmail reports whether the requester's emails are on.
func (s *PostgresStore) AccessEmail() bool { return s.accessEmail.Load() }

// notifyOn reports whether notifications of kind are queued at all: the
// owner card and the emails have a switch each.
func (s *PostgresStore) notifyOn(kind NotifyKind) bool {
	if kind == NotifyOwnerCard {
		return s.accessNotify.Load()
	}
	return s.accessEmail.Load()
}

// enqueueNotification appends one outbox row inside the caller's
// transaction. A second row for the same request and kind is left out.
func (s *PostgresStore) enqueueNotification(ctx context.Context, tx pgx.Tx, principalID string, kind NotifyKind, requestedAt, expiresAt, now time.Time) error {
	if !s.notifyOn(kind) {
		return nil
	}
	if _, err := tx.Exec(ctx, `INSERT INTO glovo_access_notifications (principal_id, kind, requested_at, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5) ON CONFLICT (principal_id, requested_at, kind) DO NOTHING`,
		principalID, string(kind), requestedAt, expiresAt, now); err != nil {
		return fmt.Errorf("glovoconsent: enqueue %s notification: %w", kind, err)
	}
	return nil
}

// retireDecideTokens spends every unused decide token of the principal. It
// runs whenever a request stops being the one a link was made for.
func retireDecideTokens(ctx context.Context, tx pgx.Tx, principalID string, now time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE glovo_access_decide_tokens SET used_at = $2
		WHERE principal_id = $1 AND used_at IS NULL`, principalID, now); err != nil {
		return fmt.Errorf("glovoconsent: retire decide tokens: %w", err)
	}
	return nil
}

var tokenHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// decideTokenPattern is the shape of a raw token: 32 random bytes,
// base64url without padding.
var decideTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// HashDecideToken is the stored form of a raw decide token, or "" when raw
// does not have a token's shape. Only the hash is ever kept or compared.
func HashDecideToken(raw string) string {
	if !decideTokenPattern.MatchString(raw) {
		return ""
	}
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// MintDecideToken makes a one-time token for the principal's live pending
// request made at requestedAt and stores its hash. The token expires with the
// request. A request that is not pending, has lapsed or is another request
// (a different requestedAt) is ErrAccessNotPending: no token is made.
func (s *PostgresStore) MintDecideToken(ctx context.Context, principalID string, requestedAt time.Time) (string, error) {
	if !prnPattern.MatchString(principalID) {
		return "", ErrInvalid
	}
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("glovoconsent: decide token: %w", err)
	}
	raw := base64.RawURLEncoding.EncodeToString(b[:])
	err := s.withPrincipalTx(ctx, principalID, func(ctx context.Context, tx pgx.Tx) error {
		cur, found, err := readAccess(ctx, tx, principalID)
		if err != nil {
			return err
		}
		now := s.now()
		if !found || cur.effective(now) != AccessPending || !cur.RequestedAt.Equal(requestedAt) {
			return ErrAccessNotPending
		}
		if _, err := tx.Exec(ctx, `INSERT INTO glovo_access_decide_tokens (token_hash, principal_id, requested_at, created_at, expires_at)
			VALUES ($1, $2, $3, $4, $5)`, HashDecideToken(raw), principalID, cur.RequestedAt, now, cur.ExpiresAt); err != nil {
			return fmt.Errorf("glovoconsent: store decide token: %w", err)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return raw, nil
}

// CheckDecideToken reports whether tokenHash is a live token of the
// principal's current request: unused, not expired, and bound to the request
// the access row holds now. It changes nothing. A failed read is an error,
// never false.
func (s *PostgresStore) CheckDecideToken(ctx context.Context, principalID, tokenHash string) (bool, error) {
	if !prnPattern.MatchString(principalID) {
		return false, ErrInvalid
	}
	if !tokenHashPattern.MatchString(tokenHash) {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM glovo_access_decide_tokens t
		JOIN glovo_access_requests r ON r.principal_id = t.principal_id AND r.requested_at = t.requested_at
		WHERE t.token_hash = $1 AND t.principal_id = $2 AND t.used_at IS NULL AND t.expires_at >= $3`,
		tokenHash, principalID, s.now()).Scan(&n); err != nil {
		return false, fmt.Errorf("glovoconsent: check decide token: %w", err)
	}
	return n == 1, nil
}

// DecideTokenPrincipal names the principal whose live request tokenHash was
// made for, under the conditions of CheckDecideToken. found false is a token
// that names nothing (malformed, unknown, used, expired, or of a request
// that is no longer the principal's); a failed read is an error.
func (s *PostgresStore) DecideTokenPrincipal(ctx context.Context, tokenHash string) (string, bool, error) {
	if !tokenHashPattern.MatchString(tokenHash) {
		return "", false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	now := s.now()
	var pid string
	err := s.pool.QueryRow(ctx, `SELECT t.principal_id FROM glovo_access_decide_tokens t
		JOIN glovo_access_requests r ON r.principal_id = t.principal_id AND r.requested_at = t.requested_at
		WHERE t.token_hash = $1 AND t.used_at IS NULL AND t.expires_at >= $2
			AND r.status = 'pending' AND r.expires_at >= $2`, tokenHash, now).Scan(&pid)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("glovoconsent: resolve decide token: %w", err)
	}
	if !prnPattern.MatchString(pid) {
		return "", false, fmt.Errorf("glovoconsent: resolve decide token: unusable row")
	}
	return pid, true, nil
}

// spendDecideToken consumes tokenHash for the request made at requestedAt, in
// the caller's transaction. Exactly one row must change: an unknown, used or
// expired token, or one bound to another request, is ErrDecideTokenInvalid.
func spendDecideToken(ctx context.Context, tx pgx.Tx, principalID, tokenHash string, requestedAt, now time.Time) error {
	if !tokenHashPattern.MatchString(tokenHash) {
		return ErrDecideTokenInvalid
	}
	tag, err := tx.Exec(ctx, `UPDATE glovo_access_decide_tokens SET used_at = $4
		WHERE token_hash = $1 AND principal_id = $2 AND requested_at = $3 AND used_at IS NULL AND expires_at >= $4`,
		tokenHash, principalID, requestedAt, now)
	if err != nil {
		return fmt.Errorf("glovoconsent: spend decide token: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrDecideTokenInvalid
	}
	return nil
}

// ApproveAccessByLink is ApproveAccess for a decision reached through a
// decide link: the token is consumed in the same transaction as the approval.
// An invalid token is ErrDecideTokenInvalid and approves nothing; a refused
// approval (capacity, not pending) leaves the token unused.
func (s *PostgresStore) ApproveAccessByLink(ctx context.Context, principalID, actor, reason string, capacity int, tokenHash string) (Access, error) {
	if !tokenHashPattern.MatchString(tokenHash) {
		return Access{}, ErrDecideTokenInvalid
	}
	return s.decide(ctx, principalID, actor, reason, AccessPending, AccessApproved, "approved", ErrAccessNotPending, capacity, tokenHash)
}

// RejectAccessByLink is RejectAccess for a decision reached through a decide
// link; see ApproveAccessByLink.
func (s *PostgresStore) RejectAccessByLink(ctx context.Context, principalID, actor, reason, tokenHash string) (Access, error) {
	if !tokenHashPattern.MatchString(tokenHash) {
		return Access{}, ErrDecideTokenInvalid
	}
	return s.decide(ctx, principalID, actor, reason, AccessPending, AccessRejected, "rejected", ErrAccessNotPending, 0, tokenHash)
}

// Notification is one outbox row as the delivery loop sees it.
type Notification struct {
	ID          int64
	PrincipalID string
	Kind        NotifyKind
	// RequestedAt and ExpiresAt are those of the request the row is about.
	RequestedAt time.Time
	ExpiresAt   time.Time
	CreatedAt   time.Time
	// Attempts counts this lease too.
	Attempts int
}

// DeliveryKey is the stable idempotency key of the notification: the same
// for every retry, different for every request and kind. It is a hash, so
// the receiver and the mail provider never see the principal id.
func (n Notification) DeliveryKey() string {
	sum := sha256.Sum256([]byte("glovo-access-notify-v1\n" + n.PrincipalID + "\n" + string(n.Kind) + "\n" +
		strconv.FormatInt(n.RequestedAt.UnixMicro(), 10)))
	return hex.EncodeToString(sum[:])
}

// LeaseNotification takes the oldest deliverable row for lease: pending, not
// leased by a live attempt, and created within NotifyWindow. found false
// means nothing is due; a failed read is an error, never "nothing due".
func (s *PostgresStore) LeaseNotification(ctx context.Context, lease string) (Notification, bool, error) {
	if lease == "" {
		return Notification{}, false, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	now := s.now()
	var n Notification
	var kind string
	err := s.pool.QueryRow(ctx, `UPDATE glovo_access_notifications SET lease = $1, leased_until = $2, attempts = attempts + 1
		WHERE notification_id = (
			SELECT notification_id FROM glovo_access_notifications
			WHERE state = 'pending' AND (leased_until IS NULL OR leased_until < $3) AND created_at > $4
			ORDER BY notification_id FOR UPDATE SKIP LOCKED LIMIT 1)
		RETURNING notification_id, principal_id, kind, requested_at, expires_at, created_at, attempts`,
		lease, now.Add(notifyLease), now, now.Add(-NotifyWindow)).
		Scan(&n.ID, &n.PrincipalID, &kind, &n.RequestedAt, &n.ExpiresAt, &n.CreatedAt, &n.Attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return Notification{}, false, nil
	}
	if err != nil {
		return Notification{}, false, fmt.Errorf("glovoconsent: lease notification: %w", err)
	}
	n.Kind = NotifyKind(kind)
	if !n.Kind.Valid() || !prnPattern.MatchString(n.PrincipalID) {
		return Notification{}, false, fmt.Errorf("glovoconsent: lease notification: unusable row %d", n.ID)
	}
	n.RequestedAt, n.ExpiresAt, n.CreatedAt = n.RequestedAt.UTC(), n.ExpiresAt.UTC(), n.CreatedAt.UTC()
	return n, true, nil
}

// finishNotification closes a leased row. The lease must still be the
// caller's and alive; otherwise ErrNotifyLeaseLost and nothing changes.
func (s *PostgresStore) finishNotification(ctx context.Context, id int64, lease, state, deliveryID, outcome string) error {
	if lease == "" || len(deliveryID) > maxDeliveryIDLen || len(outcome) > 64 {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	now := s.now()
	tag, err := s.pool.Exec(ctx, `UPDATE glovo_access_notifications
		SET state = $3, delivery_id = $4, outcome = $5, finished_at = $6, lease = '', leased_until = NULL
		WHERE notification_id = $1 AND state = 'pending' AND lease = $2 AND leased_until >= $6`,
		id, lease, state, deliveryID, outcome, now)
	if err != nil {
		return fmt.Errorf("glovoconsent: finish notification: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrNotifyLeaseLost
	}
	return nil
}

// AckNotification records a delivered notification with the receiver's
// delivery id.
func (s *PostgresStore) AckNotification(ctx context.Context, id int64, lease, deliveryID string) error {
	if deliveryID == "" {
		return ErrInvalid
	}
	return s.finishNotification(ctx, id, lease, "sent", deliveryID, "sent")
}

// AbandonNotification closes a row that will never be delivered, with the
// reason (a fixed code, never free text).
func (s *PostgresStore) AbandonNotification(ctx context.Context, id int64, lease, outcome string) error {
	if outcome == "" {
		return ErrInvalid
	}
	return s.finishNotification(ctx, id, lease, "abandoned", "", outcome)
}

// EnqueueLapsed appends a lapsed notification for every pending request whose
// expiry passed within NotifyWindow, and returns how many were added. The
// access row is left as it is: lapsing stays derived at read time. With the
// emails off it adds nothing.
func (s *PostgresStore) EnqueueLapsed(ctx context.Context) (int, error) {
	if !s.notifyOn(NotifyLapsed) {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	now := s.now()
	tag, err := s.pool.Exec(ctx, `INSERT INTO glovo_access_notifications (principal_id, kind, requested_at, expires_at, created_at)
		SELECT principal_id, 'lapsed', requested_at, expires_at, $1 FROM glovo_access_requests
		WHERE status = 'pending' AND expires_at < $1 AND expires_at >= $2
		ON CONFLICT (principal_id, requested_at, kind) DO NOTHING`, now, now.Add(-NotifyWindow))
	if err != nil {
		return 0, fmt.Errorf("glovoconsent: enqueue lapsed: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// ExpireNotifications abandons pending rows older than NotifyWindow that no
// live attempt holds, and returns how many. They can no longer be sent
// safely, and closing them makes the loss countable. It also drops decide
// tokens that were spent or expired more than NotifyWindow ago.
//
// The count is of rows already closed, so it is returned even when the token
// prune fails afterwards: an error here can come with a count above zero,
// and the caller must count those rows either way.
func (s *PostgresStore) ExpireNotifications(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	now := s.now()
	tag, err := s.pool.Exec(ctx, `UPDATE glovo_access_notifications
		SET state = 'abandoned', outcome = $3, finished_at = $1, lease = '', leased_until = NULL
		WHERE state = 'pending' AND created_at <= $2 AND (leased_until IS NULL OR leased_until < $1)`,
		now, now.Add(-NotifyWindow), NotifyOutcomeExpired)
	if err != nil {
		return 0, fmt.Errorf("glovoconsent: expire notifications: %w", err)
	}
	// Decide tokens that have been dead for a whole window are dropped: a
	// card retried against a failing bridge mints one per attempt, and
	// nothing else removes them. A dropped token reads as unknown, which is
	// refused exactly like a spent or expired one.
	if _, err := s.pool.Exec(ctx, `DELETE FROM glovo_access_decide_tokens
		WHERE expires_at < $1 OR (used_at IS NOT NULL AND used_at < $1)`, now.Add(-NotifyWindow)); err != nil {
		return int(tag.RowsAffected()), fmt.Errorf("glovoconsent: prune decide tokens: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
