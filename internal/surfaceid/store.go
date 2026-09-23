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

// Package surfaceid owns SurfaceIdentityLink (mctl-api#350): a verified
// binding between a surface-native identity (a Telegram user id, a portal
// session subject) and a human principal, so that a surface principal can
// relay a request that is then attributed to that human.
//
// A link is established by possession proof on both sides. The human, already
// authenticated, asks for a one-time challenge for one surface. The code
// travels through that surface, and the surface's own principal redeems it
// together with the external id it observed. Neither side alone can create a
// link: the human never names the external id, and the surface never names
// the human.
//
// This is not a principal model (mctlhq/.github#91). It maps exactly one
// surface-native id to exactly one human principal, and nothing else.
package surfaceid

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Surfaces a link may be created for, each with its own service principal.
const (
	SurfaceTelegram = "telegram"
	SurfacePortal   = "portal"
)

// ChallengeTTL is how long a challenge can be redeemed.
const ChallengeTTL = 10 * time.Minute

// MaxOpenChallenges bounds unredeemed, unexpired challenges per human.
const MaxOpenChallenges = 5

// IsSurface reports whether s is a surface this package links.
func IsSurface(s string) bool { return s == SurfaceTelegram || s == SurfacePortal }

var (
	ErrInvalid = errors.New("invalid surface identity request")
	// ErrChallengeInvalid is the single answer to every failed redemption:
	// unknown, used, expired or redeemed by the wrong surface. Telling them
	// apart to the caller would only help someone guessing codes; the reason
	// is kept for the audit trail (ChallengeError.Reason).
	ErrChallengeInvalid  = errors.New("challenge is not valid")
	ErrTooManyChallenges = errors.New("too many open challenges")
	ErrLinkConflict      = errors.New("this surface identity is already linked to another principal")
	ErrLinkNotFound      = errors.New("no surface identity link")
	ErrLinkRevoked       = errors.New("surface identity link revoked")
	ErrLinkExpired       = errors.New("surface identity link expired")
	ErrForbidden         = errors.New("not allowed to change this link")
)

// ChallengeError carries why a redemption failed, for audit only.
type ChallengeError struct{ Reason string }

func (e *ChallengeError) Error() string { return ErrChallengeInvalid.Error() + ": " + e.Reason }
func (e *ChallengeError) Unwrap() error { return ErrChallengeInvalid }

// Challenge reasons recorded on a consumed or refused challenge.
const (
	ReasonUnknown     = "unknown"
	ReasonUsed        = "already_used"
	ReasonExpired     = "expired"
	ReasonWrongSource = "wrong_surface"
	ReasonLinked      = "linked"
	ReasonConflict    = "link_conflict"
)

// Challenge is a freshly minted challenge. Code is returned once, to the
// human who asked; only its hash is stored.
type Challenge struct {
	ID        string    `json:"id"`
	Code      string    `json:"code"`
	Surface   string    `json:"surface"`
	Principal string    `json:"principal"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Link is one SurfaceIdentityLink.
type Link struct {
	ID         string     `json:"id"`
	Surface    string     `json:"surface"`
	ExternalID string     `json:"external_id"`
	Principal  string     `json:"principal"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	RevokedBy  string     `json:"revoked_by,omitempty"`
}

const schema = `
CREATE TABLE IF NOT EXISTS surface_identity_challenges (
	id           TEXT PRIMARY KEY,
	code_hash    TEXT NOT NULL UNIQUE,
	principal    TEXT NOT NULL,
	surface      TEXT NOT NULL,
	created_at   TIMESTAMPTZ NOT NULL,
	expires_at   TIMESTAMPTZ NOT NULL,
	consumed_at  TIMESTAMPTZ,
	outcome      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS surface_identity_challenges_open
	ON surface_identity_challenges (principal) WHERE consumed_at IS NULL;

CREATE TABLE IF NOT EXISTS surface_identity_links (
	id           TEXT PRIMARY KEY,
	surface      TEXT NOT NULL,
	external_id  TEXT NOT NULL,
	principal    TEXT NOT NULL,
	challenge_id TEXT NOT NULL,
	created_at   TIMESTAMPTZ NOT NULL,
	expires_at   TIMESTAMPTZ,
	revoked_at   TIMESTAMPTZ,
	revoked_by   TEXT NOT NULL DEFAULT ''
);
-- One live link per surface identity; revoked rows stay as history.
CREATE UNIQUE INDEX IF NOT EXISTS surface_identity_links_live
	ON surface_identity_links (surface, external_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS surface_identity_links_principal
	ON surface_identity_links (principal);
`

// Store is the Postgres-backed link store.
type Store struct {
	pool    *pgxpool.Pool
	now     func() time.Time
	linkTTL time.Duration
}

// NewStore connects and creates the schema. linkTTL > 0 gives every new link
// an expiry; 0 means links last until revoked.
func NewStore(ctx context.Context, connStr string, linkTTL time.Duration) (*Store, error) {
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("surfaceid: connect: %w", err)
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("surfaceid: create schema: %w", err)
	}
	slog.Info("surface identity store initialized", "link_ttl", linkTTL)
	return &Store{pool: pool, now: func() time.Time { return time.Now().UTC() }, linkTTL: linkTTL}, nil
}

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

// principalPattern: v1 links only GitHub-verified humans, the form every
// initial consumer (human-input actor_refs, work-item owners) keys on.
var principalPattern = regexp.MustCompile(`^github:[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)

// externalIDPattern bounds a surface-native id per surface. A Telegram user
// id is a positive integer; a portal subject is an opaque token.
var externalIDPattern = map[string]*regexp.Regexp{
	SurfaceTelegram: regexp.MustCompile(`^[1-9][0-9]{0,19}$`),
	SurfacePortal:   regexp.MustCompile(`^[A-Za-z0-9._:@|-]{1,256}$`),
}

// ValidExternalID reports whether id is a well-formed native id for surface.
func ValidExternalID(surface, id string) bool {
	p, ok := externalIDPattern[surface]
	return ok && p.MatchString(id)
}

func hashCode(code string) string {
	sum := sha256.Sum256([]byte(normalizeCode(code)))
	return hex.EncodeToString(sum[:])
}

// normalizeCode tolerates what a human does when retyping a code: case and
// the grouping dashes. It never adds entropy back; it only removes noise.
func normalizeCode(code string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
}

var codeEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func newCode() (string, error) {
	var b [20]byte // 160 bits
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	raw := codeEncoding.EncodeToString(b[:]) // 32 chars
	groups := make([]string, 0, 8)
	for i := 0; i < len(raw); i += 4 {
		groups = append(groups, raw[i:i+4])
	}
	return strings.Join(groups, "-"), nil
}

func newID(prefix string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b[:]), nil
}

// CreateChallenge mints a one-time challenge for principal on surface.
func (s *Store) CreateChallenge(ctx context.Context, principal, surface string) (*Challenge, error) {
	if !principalPattern.MatchString(principal) {
		return nil, fmt.Errorf("%w: principal %q cannot hold a surface link", ErrInvalid, principal)
	}
	if !IsSurface(surface) {
		return nil, fmt.Errorf("%w: unknown surface %q", ErrInvalid, surface)
	}
	code, err := newCode()
	if err != nil {
		return nil, fmt.Errorf("surfaceid: random: %w", err)
	}
	id, err := newID("sic_")
	if err != nil {
		return nil, fmt.Errorf("surfaceid: random: %w", err)
	}
	now := s.now()
	c := &Challenge{ID: id, Code: code, Surface: surface, Principal: principal, ExpiresAt: now.Add(ChallengeTTL)}
	err = s.withTx(ctx, "surfaceid-challenge:"+principal, func(tx pgx.Tx) error {
		// Housekeeping: nothing past its expiry by a day is worth keeping.
		if _, err := tx.Exec(ctx, `DELETE FROM surface_identity_challenges WHERE expires_at < $1`, now.Add(-24*time.Hour)); err != nil {
			return err
		}
		var open int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM surface_identity_challenges
			WHERE principal=$1 AND consumed_at IS NULL AND expires_at > $2`, principal, now).Scan(&open); err != nil {
			return err
		}
		if open >= MaxOpenChallenges {
			return ErrTooManyChallenges
		}
		_, err := tx.Exec(ctx, `INSERT INTO surface_identity_challenges
			(id, code_hash, principal, surface, created_at, expires_at) VALUES ($1,$2,$3,$4,$5,$6)`,
			c.ID, hashCode(code), principal, surface, now, c.ExpiresAt)
		return err
	})
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Redeem consumes a challenge on behalf of the surface that observed the
// code, binding externalID to the principal that asked for it.
//
// Every redemption that finds the challenge consumes it, including a refused
// one: a code that reached the wrong surface, or arrived late, has been
// exposed and must not be tried again.
func (s *Store) Redeem(ctx context.Context, surface, code, externalID string) (*Link, error) {
	if !IsSurface(surface) {
		return nil, fmt.Errorf("%w: unknown surface %q", ErrInvalid, surface)
	}
	if !ValidExternalID(surface, externalID) {
		return nil, fmt.Errorf("%w: external_id is not a %s identity", ErrInvalid, surface)
	}
	if normalizeCode(code) == "" {
		return nil, &ChallengeError{Reason: ReasonUnknown}
	}
	var (
		link    *Link
		refusal error
	)
	now := s.now()
	err := s.withTx(ctx, "surfaceid-link:"+surface+":"+externalID, func(tx pgx.Tx) error {
		var (
			id, principal, chSurface string
			expires                  time.Time
			consumed                 *time.Time
		)
		err := tx.QueryRow(ctx, `SELECT id, principal, surface, expires_at, consumed_at
			FROM surface_identity_challenges WHERE code_hash=$1 FOR UPDATE`, hashCode(code)).
			Scan(&id, &principal, &chSurface, &expires, &consumed)
		if errors.Is(err, pgx.ErrNoRows) {
			refusal = &ChallengeError{Reason: ReasonUnknown}
			return nil
		}
		if err != nil {
			return err
		}
		consume := func(outcome string) error {
			_, err := tx.Exec(ctx, `UPDATE surface_identity_challenges SET consumed_at=$2, outcome=$3 WHERE id=$1`, id, now, outcome)
			return err
		}
		switch {
		case consumed != nil:
			refusal = &ChallengeError{Reason: ReasonUsed}
			return nil
		case chSurface != surface:
			refusal = &ChallengeError{Reason: ReasonWrongSource}
			return consume(ReasonWrongSource)
		case !now.Before(expires):
			refusal = &ChallengeError{Reason: ReasonExpired}
			return consume(ReasonExpired)
		}
		// FOR UPDATE: a Revoke committing meanwhile is waited for, so this
		// never reports (or audits) a link that is already revoked.
		existing, err := liveLink(ctx, tx, surface, externalID, true)
		if err != nil && !errors.Is(err, ErrLinkNotFound) {
			return err
		}
		if existing != nil && s.expired(existing, now) {
			// An expired link no longer answers; retire it so a fresh one
			// can take its place.
			if _, err := tx.Exec(ctx, `UPDATE surface_identity_links SET revoked_at=$2, revoked_by='expired' WHERE id=$1`, existing.ID, now); err != nil {
				return err
			}
			existing = nil
		}
		if existing != nil {
			if existing.Principal != principal {
				refusal = ErrLinkConflict
				return consume(ReasonConflict)
			}
			link = existing
			return consume(ReasonLinked)
		}
		linkID, err := newID("sil_")
		if err != nil {
			return err
		}
		l := &Link{ID: linkID, Surface: surface, ExternalID: externalID, Principal: principal, CreatedAt: now}
		if s.linkTTL > 0 {
			exp := now.Add(s.linkTTL)
			l.ExpiresAt = &exp
		}
		if _, err := tx.Exec(ctx, `INSERT INTO surface_identity_links
			(id, surface, external_id, principal, challenge_id, created_at, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			l.ID, l.Surface, l.ExternalID, l.Principal, id, l.CreatedAt, l.ExpiresAt); err != nil {
			return err
		}
		link = l
		return consume(ReasonLinked)
	})
	if err != nil {
		return nil, err
	}
	if refusal != nil {
		return nil, refusal
	}
	return link, nil
}

const linkColumns = `id, surface, external_id, principal, created_at, expires_at, revoked_at, revoked_by`

func scanLink(row pgx.Row) (*Link, error) {
	var l Link
	if err := row.Scan(&l.ID, &l.Surface, &l.ExternalID, &l.Principal, &l.CreatedAt, &l.ExpiresAt, &l.RevokedAt, &l.RevokedBy); err != nil {
		return nil, err
	}
	l.CreatedAt = l.CreatedAt.UTC()
	for _, t := range []**time.Time{&l.ExpiresAt, &l.RevokedAt} {
		if *t != nil {
			u := (*t).UTC()
			*t = &u
		}
	}
	return &l, nil
}

func liveLink(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, surface, externalID string, forUpdate bool) (*Link, error) {
	query := `SELECT ` + linkColumns + ` FROM surface_identity_links
		WHERE surface=$1 AND external_id=$2 AND revoked_at IS NULL`
	if forUpdate {
		query += ` FOR UPDATE`
	}
	l, err := scanLink(q.QueryRow(ctx, query, surface, externalID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrLinkNotFound
	}
	return l, err
}

func (s *Store) expired(l *Link, now time.Time) bool {
	return l.ExpiresAt != nil && !now.Before(*l.ExpiresAt)
}

// Resolve returns the live link for a surface identity. It fails closed:
// no link, a revoked one or an expired one is an error, never a default.
func (s *Store) Resolve(ctx context.Context, surface, externalID string) (*Link, error) {
	if !IsSurface(surface) || !ValidExternalID(surface, externalID) {
		return nil, ErrLinkNotFound
	}
	l, err := liveLink(ctx, s.pool, surface, externalID, false)
	if errors.Is(err, ErrLinkNotFound) {
		var revoked bool
		if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM surface_identity_links
			WHERE surface=$1 AND external_id=$2)`, surface, externalID).Scan(&revoked); err != nil {
			return nil, err
		}
		if revoked {
			return nil, ErrLinkRevoked
		}
		return nil, ErrLinkNotFound
	}
	if err != nil {
		return nil, err
	}
	if s.expired(l, s.now()) {
		return nil, ErrLinkExpired
	}
	return l, nil
}

// Links lists a principal's links, live and revoked, newest first.
func (s *Store) Links(ctx context.Context, principal string) ([]Link, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+linkColumns+` FROM surface_identity_links
		WHERE principal=$1 ORDER BY created_at DESC, id`, principal)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Link{}
	for rows.Next() {
		l, err := scanLink(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *l)
	}
	return out, rows.Err()
}

// Revoke ends a link. Only its principal may, or an admin (asAdmin). A link
// that is already revoked stays as it was and is returned unchanged.
func (s *Store) Revoke(ctx context.Context, id, by string, asAdmin bool) (*Link, error) {
	var out *Link
	err := s.withTx(ctx, "surfaceid-revoke:"+id, func(tx pgx.Tx) error {
		l, err := scanLink(tx.QueryRow(ctx, `SELECT `+linkColumns+` FROM surface_identity_links WHERE id=$1 FOR UPDATE`, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrLinkNotFound
		}
		if err != nil {
			return err
		}
		if l.Principal != by && !asAdmin {
			// Someone else's link answers as if it did not exist.
			return ErrLinkNotFound
		}
		if l.RevokedAt == nil {
			now := s.now()
			if _, err := tx.Exec(ctx, `UPDATE surface_identity_links SET revoked_at=$2, revoked_by=$3 WHERE id=$1`, id, now, by); err != nil {
				return err
			}
			l.RevokedAt, l.RevokedBy = &now, by
		}
		out = l
		return nil
	})
	return out, err
}

func (s *Store) withTx(ctx context.Context, lockKey string, fn func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("surfaceid: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once Commit has succeeded
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, lockKey); err != nil {
		return fmt.Errorf("surfaceid: acquire lock: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("surfaceid: commit: %w", err)
	}
	return nil
}
