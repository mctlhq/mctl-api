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
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// Sign-in through a linked identity (mctl-api#467). The MCP OAuth server
// signs a ZITADEL user in as the GitHub login of the principal that ZITADEL
// identity was explicitly linked to (#435), so the tokens it mints, and the
// groups and admin decision behind them, are the ones a GitHub sign-in of
// the same person produces.

var (
	// ErrNoGitHubIdentity: the identity's principal holds no live GitHub
	// identity, e.g. a ZITADEL user that signed in with a bearer token before
	// linking and so got a principal of its own.
	ErrNoGitHubIdentity = errors.New("principal holds no live GitHub identity")
	// ErrGitHubLoginUnknown: the principal's GitHub identity has no current
	// login (another account took the login since, claimGitHubDisplay), so
	// there is nothing to sign in as until GitHub proves one again.
	ErrGitHubLoginUnknown = errors.New("the principal's GitHub login is not known")
	// ErrAmbiguousGitHubIdentity: more than one live GitHub identity. Linking
	// and merging never produce this; it is refused rather than guessed.
	ErrAmbiguousGitHubIdentity = errors.New("principal holds more than one live GitHub identity")
)

// LinkedGitHub returns the principal a live identity belongs to and that
// principal's live GitHub identity. It only reads: an identity it does not
// know is ErrNotFound, never provisioned.
//
// Refusals: a revoked identity is auth.ErrIdentityRefused, a disabled
// principal auth.ErrPrincipalDisabled, and a principal without exactly one
// live GitHub identity with a login one of the errors above. Any other error
// is a failed read, which a caller must not treat as "not linked".
func (s *Store) LinkedGitHub(ctx context.Context, id auth.Identity) (*Principal, *ExternalIdentity, error) {
	if err := validIdentity(id); err != nil {
		return nil, nil, err
	}
	if id.Provider == auth.ProviderGitHub {
		return nil, nil, fmt.Errorf("%w: sign-in through a linked identity starts from a non-GitHub identity", ErrInvalid)
	}
	// One statement, so the identity, its principal and the principal's
	// GitHub identities come from one snapshot: a merge committing between
	// two reads could otherwise show the principal with its GitHub identity
	// already moved away.
	rows, err := s.pool.Query(ctx, `SELECT `+principalColumns+`, x.revoked_at,
			g.id, g.subject, g.display, g.verified_at
		FROM external_identities x
		JOIN principals p ON p.id = x.principal_id
		LEFT JOIN external_identities g
			ON g.principal_id = p.id AND g.provider = 'github' AND g.revoked_at IS NULL
		WHERE x.provider=$1 AND x.issuer=$2 AND x.subject=$3
		ORDER BY g.verified_at, g.id`, id.Provider, id.Issuer, id.Subject)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var (
		p       *Principal
		revoked *time.Time
		gh      []ExternalIdentity
	)
	for rows.Next() {
		var (
			cur                     Principal
			gID, gSubject, gDisplay *string
			gVerified               *time.Time
		)
		if err := rows.Scan(&cur.ID, &cur.Kind, &cur.DisplayName, &cur.Status, &cur.CreatedAt, &revoked,
			&gID, &gSubject, &gDisplay, &gVerified); err != nil {
			return nil, nil, err
		}
		if p == nil {
			cur.CreatedAt = cur.CreatedAt.UTC()
			p = &cur
		}
		if gID != nil {
			gh = append(gh, ExternalIdentity{
				ID: *gID, PrincipalID: cur.ID, Provider: auth.ProviderGitHub,
				Subject: *gSubject, Display: *gDisplay, VerifiedAt: gVerified.UTC(),
			})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	switch {
	case p == nil:
		return nil, nil, ErrNotFound
	case revoked != nil:
		return nil, nil, fmt.Errorf("%w: external identity %s was revoked", auth.ErrIdentityRefused, id.Provider)
	case p.Status != StatusActive:
		return nil, nil, auth.ErrPrincipalDisabled
	case len(gh) == 0:
		return p, nil, ErrNoGitHubIdentity
	case len(gh) > 1:
		return p, nil, ErrAmbiguousGitHubIdentity
	case gh[0].Display == "":
		return p, nil, ErrGitHubLoginUnknown
	}
	return p, &gh[0], nil
}
