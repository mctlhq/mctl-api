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

package principals

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// Explicit identity linking (mctl-api#435). An identity joins an existing
// principal only through LinkIdentity, after the caller proved both
// identities in one session (internal/api/handlers_identity_link.go). It
// never happens by matching a username or an e-mail (#373).

// Link outcomes.
const (
	LinkLinked        = "linked"
	LinkAlreadyLinked = "already_linked"
)

var (
	// ErrIdentityOwnedElsewhere: the identity already belongs to another
	// principal. Self-service never moves it (owner decision A on #435); an
	// admin merges the two principals instead (MergePrincipals).
	ErrIdentityOwnedElsewhere = errors.New("identity belongs to another principal")
	// ErrIdentityRevoked: the identity was revoked on this principal.
	// Revoking was a decision; linking does not undo it.
	ErrIdentityRevoked = errors.New("identity was revoked")
	// ErrPrincipalAlreadyLinked: the principal already holds a different
	// live identity of the same provider and issuer.
	ErrPrincipalAlreadyLinked = errors.New("principal already holds an identity of this provider")
	// ErrLastIdentity: unlinking would leave the principal with no live
	// identity, i.e. nobody could ever act as it again.
	ErrLastIdentity = errors.New("cannot unlink the last live identity of a principal")
	// ErrMergeConflict: both principals hold a live identity of the same
	// provider and issuer, so merging would give one principal two.
	ErrMergeConflict = errors.New("both principals hold an identity of the same provider")
)

// OwnedElsewhereError names the principal that holds the identity.
type OwnedElsewhereError struct{ PrincipalID string }

func (e *OwnedElsewhereError) Error() string {
	return fmt.Sprintf("%s (%s)", ErrIdentityOwnedElsewhere, e.PrincipalID)
}

func (e *OwnedElsewhereError) Unwrap() error { return ErrIdentityOwnedElsewhere }

func principalLockKey(id string) string { return "principals:principal|" + id }

// lockPrincipalTx takes the per-principal advisory lock inside tx.
func lockPrincipalTx(ctx context.Context, tx pgx.Tx, id string) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, principalLockKey(id)); err != nil {
		return fmt.Errorf("principals: acquire principal lock: %w", err)
	}
	return nil
}

func getPrincipalTx(ctx context.Context, tx pgx.Tx, id string) (*Principal, error) {
	return scanPrincipal(tx.QueryRow(ctx, `SELECT `+principalColumns+` FROM principals p WHERE p.id=$1`, id))
}

// LinkIdentity attaches id to principalID. It returns LinkLinked or
// LinkAlreadyLinked, or one of the errors above; on
// ErrIdentityOwnedElsewhere the error is an *OwnedElsewhereError.
func (s *Store) LinkIdentity(ctx context.Context, principalID string, id auth.Identity) (string, error) {
	if err := validIdentity(id); err != nil {
		return "", err
	}
	if id.Kind != auth.KindHuman {
		return "", fmt.Errorf("%w: only human identities are linked", ErrInvalid)
	}
	var outcome string
	err := s.withTx(ctx, lockKey(id), func(tx pgx.Tx) error {
		if err := lockPrincipalTx(ctx, tx, principalID); err != nil {
			return err
		}
		p, err := getPrincipalTx(ctx, tx, principalID)
		if err != nil {
			return err
		}
		if p.Kind != auth.KindHuman {
			return fmt.Errorf("%w: principal %s is not human", ErrInvalid, p.ID)
		}
		if p.Status != StatusActive {
			return auth.ErrPrincipalDisabled
		}

		var owner string
		var revoked *time.Time
		err = tx.QueryRow(ctx, `SELECT principal_id, revoked_at FROM external_identities
			WHERE provider=$1 AND issuer=$2 AND subject=$3`, id.Provider, id.Issuer, id.Subject).Scan(&owner, &revoked)
		switch {
		case err == nil && owner != principalID:
			return &OwnedElsewhereError{PrincipalID: owner}
		case err == nil && revoked != nil:
			return ErrIdentityRevoked
		case err == nil:
			if _, err := tx.Exec(ctx, `UPDATE external_identities SET verified_at=$4
				WHERE provider=$1 AND issuer=$2 AND subject=$3`, id.Provider, id.Issuer, id.Subject, s.now()); err != nil {
				return err
			}
			outcome = LinkAlreadyLinked
			return nil
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}

		var other int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM external_identities
			WHERE principal_id=$1 AND provider=$2 AND issuer=$3 AND revoked_at IS NULL`,
			principalID, id.Provider, id.Issuer).Scan(&other); err != nil {
			return err
		}
		if other > 0 {
			return ErrPrincipalAlreadyLinked
		}
		if err := insertIdentity(ctx, tx, principalID, id, s.now()); err != nil {
			return err
		}
		outcome = LinkLinked
		return nil
	})
	if err != nil {
		return "", err
	}
	return outcome, nil
}

// UnlinkIdentity revokes one of principalID's identities. Revoking an
// already revoked identity is a no-op. The identity stays recorded (and
// refused at authentication once the resolver re-reads it: the caller drops
// principalID from Resolver's cache, see Resolver.Forget); only an operator
// restores it.
func (s *Store) UnlinkIdentity(ctx context.Context, principalID, identityID string) (*ExternalIdentity, error) {
	var out ExternalIdentity
	err := s.withTx(ctx, principalLockKey(principalID), func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT id, principal_id, provider, issuer, subject, display, verified_at, revoked_at
			FROM external_identities WHERE id=$1 AND principal_id=$2`, identityID, principalID).
			Scan(&out.ID, &out.PrincipalID, &out.Provider, &out.Issuer, &out.Subject, &out.Display, &out.VerifiedAt, &out.RevokedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if out.RevokedAt != nil {
			return nil
		}
		var others int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM external_identities
			WHERE principal_id=$1 AND id<>$2 AND revoked_at IS NULL`, principalID, identityID).Scan(&others); err != nil {
			return err
		}
		if others == 0 {
			return ErrLastIdentity
		}
		now := s.now()
		if _, err := tx.Exec(ctx, `UPDATE external_identities SET revoked_at=$2 WHERE id=$1`, identityID, now); err != nil {
			return err
		}
		out.RevokedAt = &now
		return nil
	})
	if err != nil {
		return nil, err
	}
	out.VerifiedAt = out.VerifiedAt.UTC()
	return &out, nil
}

// MergePrincipals moves every live identity of from onto into and disables
// from (never deletes it: audit rows reference it). Revoked identities stay
// on from, where they were revoked: into never inherits an identity it could
// not use, and moved counts only identities that now sign in as into. It is
// the admin operation behind a refused self-service link (owner decision A
// on #435) and is not reachable from self-service. Both must be human, into
// must be active, and they must not both hold a live identity of the same
// provider and issuer.
func (s *Store) MergePrincipals(ctx context.Context, from, into string) (moved int, err error) {
	if from == "" || into == "" || from == into {
		return 0, fmt.Errorf("%w: merge needs two different principals", ErrInvalid)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("principals: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Both principal locks, in a fixed order, so two merges of the same pair
	// in opposite directions cannot deadlock.
	keys := []string{from, into}
	sort.Strings(keys)
	for _, k := range keys {
		if err := lockPrincipalTx(ctx, tx, k); err != nil {
			return 0, err
		}
	}
	src, err := getPrincipalTx(ctx, tx, from)
	if err != nil {
		return 0, err
	}
	dst, err := getPrincipalTx(ctx, tx, into)
	if err != nil {
		return 0, err
	}
	if src.Kind != auth.KindHuman || dst.Kind != auth.KindHuman {
		return 0, fmt.Errorf("%w: only human principals are merged", ErrInvalid)
	}
	if dst.Status != StatusActive {
		return 0, auth.ErrPrincipalDisabled
	}
	var conflicts int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM external_identities a
		JOIN external_identities b ON a.provider=b.provider AND a.issuer=b.issuer
		WHERE a.principal_id=$1 AND b.principal_id=$2 AND a.revoked_at IS NULL AND b.revoked_at IS NULL`,
		from, into).Scan(&conflicts); err != nil {
		return 0, err
	}
	if conflicts > 0 {
		return 0, ErrMergeConflict
	}
	tag, err := tx.Exec(ctx, `UPDATE external_identities SET principal_id=$2 WHERE principal_id=$1 AND revoked_at IS NULL`, from, into)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `UPDATE principals SET status=$2 WHERE id=$1`, from, StatusDisabled); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("principals: commit: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
