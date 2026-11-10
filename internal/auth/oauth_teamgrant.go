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

package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/auth/refreshstore"
	"github.com/mctlhq/mctl-api/internal/auth/teamgrant"
)

// TeamEligibility is the live answer to "which teams may this principal pick
// for the Glovo pilot": principal-mode membership of the tenant, intersected
// with the per-principal pilot allowlist, minus the non-selectable tenants.
// It is defined here so this package imports nothing from internal/glovo; the
// implementation lives in internal/glovo/scope and main wires it. An error
// is "could not read", never "not eligible".
type TeamEligibility interface {
	// Eligible lists the teams principalID may select.
	Eligible(ctx context.Context, principalID string) ([]string, error)
	// Has reports whether principalID may act for tenant right now.
	Has(ctx context.Context, principalID, tenant string) (bool, error)
}

// ErrTeamGrantInvalid is returned for a refresh whose team grant is unknown,
// pending, revoked, expired or mismatched, or whose principal lost the team.
// It reads as an invalid grant.
var ErrTeamGrantInvalid = errors.New("invalid or expired refresh token")

// GlovoReady reports whether the Glovo resource may be admitted: the kill
// switch is on and every readiness dependency is present. GLOVO_MCP_RESOURCE
// alone never opens it. The refresh store and the grant store must be the
// transactional Postgres pair, so activation and revocation are atomic.
func (s *OAuthServer) GlovoReady() bool {
	if s == nil || !s.GlovoEnabled || s.GlovoResource == "" || !s.PrincipalMode || s.TeamEligibility == nil {
		return false
	}
	if s.TeamGrants == nil {
		return false
	}
	if _, ok := s.TeamGrants.(teamgrant.Transactional); !ok {
		return false
	}
	_, ok := s.RefreshStore.(refreshstore.BoundStore)
	return ok
}

// isGlovoFlow reports whether a stored flow resource is the Glovo resource.
func (s *OAuthServer) isGlovoFlow(resource string) bool {
	return s != nil && s.GlovoResource != "" && resource == s.GlovoResource
}

// IsGlovoFlow is isGlovoFlow for the API package.
func (s *OAuthServer) IsGlovoFlow(resource string) bool { return s.isGlovoFlow(resource) }

// TeamGrantLifetime is how long a team grant lives: the refresh token TTL,
// with no sliding extension.
func (s *OAuthServer) TeamGrantLifetime() time.Duration {
	if s.RefreshTokenTTL == 0 {
		return 30 * 24 * time.Hour
	}
	return s.RefreshTokenTTL
}

// CreateTeamGrant records the human's choice as a pending grant, superseding
// any earlier grant of the same (principal, client, resource). It is inert
// until the code exchange activates it.
func (s *OAuthServer) CreateTeamGrant(ctx context.Context, principalID, clientID, tenant string) (teamgrant.Grant, error) {
	if !s.GlovoReady() {
		return teamgrant.Grant{}, ErrGlovoNotReady
	}
	g, err := s.TeamGrants.Create(ctx, teamgrant.Grant{
		PrincipalID: principalID, Tenant: tenant, Resource: s.GlovoResource, ClientID: clientID,
		ExpiresAt: time.Now().Add(s.TeamGrantLifetime()),
	})
	if err != nil {
		slog.Error("oauth: team grant create failed", "error", err)
		return teamgrant.Grant{}, fmt.Errorf("create team grant: %w", ErrServerError)
	}
	return g, nil
}

// EligibleTeams is TeamEligibility.Eligible with the not-ready and error
// handling the consent step needs.
func (s *OAuthServer) EligibleTeams(ctx context.Context, principalID string) ([]string, error) {
	if !s.GlovoReady() {
		return nil, ErrGlovoNotReady
	}
	teams, err := s.TeamEligibility.Eligible(ctx, principalID)
	if err != nil {
		slog.Error("oauth: team eligibility read failed", "error", err)
		return nil, fmt.Errorf("read team eligibility: %w", ErrServerError)
	}
	return teams, nil
}

// exchangeGlovoCode is the code exchange of a Glovo flow. The refresh token
// is inserted and the team grant activated in one transaction; the access
// token is signed only after it commits.
func (s *OAuthServer) exchangeGlovoCode(ctx context.Context, entry authCodeEntry, clientID, bound string) (string, string, error) {
	if !s.GlovoReady() {
		return "", "", ErrGlovoNotReady
	}
	if entry.TeamGrantID == "" || entry.SelectedTenant == "" || entry.PrincipalID == "" {
		return "", "", errors.New("invalid or expired authorization code")
	}
	if err := s.checkMintPrincipal(entry.PrincipalID); err != nil {
		return "", "", err
	}
	store := s.RefreshStore.(refreshstore.BoundStore)
	token, expiresAt, err := s.newRefreshTokenValue()
	if err != nil {
		return "", "", err
	}
	sess := refreshstore.Session{Login: entry.Login, PrincipalID: entry.PrincipalID, Groups: entry.Groups,
		AuthMethod: bound, Resource: entry.Resource, TeamGrantID: entry.TeamGrantID}
	err = store.InsertBound(ctx, token, clientID, sess, expiresAt,
		func(ctx context.Context, tx pgx.Tx, familyID uuid.UUID) error {
			return teamgrant.ActivateTx(ctx, tx, entry.TeamGrantID, entry.PrincipalID, clientID, entry.Resource, familyID)
		})
	if errors.Is(err, teamgrant.ErrGrantInvalid) {
		return "", "", errors.New("invalid or expired authorization code")
	}
	if err != nil {
		slog.Error("oauth: glovo code exchange store failed", "error", err)
		return "", "", fmt.Errorf("bind team grant: %w", ErrServerError)
	}
	accessToken, err := s.issueJWTWithGrant(entry.Login, entry.PrincipalID, entry.Groups, s.GlovoResource, clientID, entry.TeamGrantID, entry.SelectedTenant)
	if err != nil {
		// Committed but never delivered: end the session.
		if rerr := s.RefreshStore.RevokeFamily(token, clientID, "mint_failed"); rerr != nil {
			slog.Error("oauth: revoke after failed glovo mint failed", "error", rerr)
		}
		return "", "", err
	}
	s.touchClient(clientID)
	return accessToken, token, nil
}

// glovoRefreshAccept is the grant part of the refresh accept callback. It
// only reads, so a refusal spends nothing; revocation, where one follows, is
// a separate write after the rotation returns. grant receives the checked
// grant. tx is nil when the store cannot run it transactionally, which
// refuses the session: a Glovo session never rotates outside a transaction.
func (s *OAuthServer) glovoRefreshAccept(ctx context.Context, tx pgx.Tx, sess refreshstore.Session, clientID string, grant *teamgrant.Grant, revoke *bool) error {
	if sess.TeamGrantID == "" && !s.isGlovoFlow(sess.Resource) {
		return nil
	}
	if !s.GlovoReady() {
		return ErrGlovoNotReady
	}
	if sess.TeamGrantID == "" || tx == nil || sess.PrincipalID == "" {
		*revoke = true
		return ErrTeamGrantInvalid
	}
	g, err := teamgrant.CheckTx(ctx, tx, sess.TeamGrantID, sess.PrincipalID, clientID, sess.Resource)
	if errors.Is(err, teamgrant.ErrGrantInvalid) {
		*revoke = true
		return ErrTeamGrantInvalid
	}
	if err != nil {
		slog.Error("oauth: team grant check failed on refresh", "error", err)
		return fmt.Errorf("check team grant: %w", ErrServerError)
	}
	ok, err := s.TeamEligibility.Has(ctx, sess.PrincipalID, g.Tenant)
	if err != nil {
		slog.Error("oauth: team eligibility read failed on refresh", "error", err)
		return fmt.Errorf("read team eligibility: %w", ErrServerError)
	}
	if !ok {
		*revoke = true
		return ErrTeamGrantInvalid
	}
	*grant = g
	return nil
}
