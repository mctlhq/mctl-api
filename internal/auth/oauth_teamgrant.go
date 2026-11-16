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

// GlovoConsentSource is the glovo:c2 consent a personal grant stands on
// (glovoconsent.ConsentGrants). HeldSince is true only while the principal
// holds an active consent recorded at or before at; an error means it could
// not be read, which is never a grant.
type GlovoConsentSource interface {
	HeldSince(ctx context.Context, principalID string, at time.Time) (bool, error)
}

// grantKindPersonal is the tgk claim of a token minted under a personal grant.
const grantKindPersonal = teamgrant.KindPersonal

// ErrPersonalGrantRefused is the definite "no" for a personal grant: the
// principal is not an active human, or holds no consent that covers it.
// Every other error from PersonalGrantAllowed means it could not be checked.
var ErrPersonalGrantRefused = errors.New("personal glovo access is not available for this account")

// PersonalGrantsEnabled reports whether a personal grant can be offered at
// all: the Glovo resource is ready and the consent source is configured.
func (s *OAuthServer) PersonalGrantsEnabled() bool {
	return s != nil && s.GlovoConsent != nil && s.GlovoReady()
}

// PersonalGrantAllowed decides whether principalID may hold a personal grant
// created at at: an active human principal (never an agent or a service)
// with a glovo:c2 consent recorded no later than at. nil is yes;
// ErrPersonalGrantRefused is a definite no; any other error is a failed
// read, which the caller must refuse, never grant.
func (s *OAuthServer) PersonalGrantAllowed(ctx context.Context, principalID string, at time.Time) error {
	if !s.PersonalGrantsEnabled() {
		return ErrGlovoNotReady
	}
	if principalID == "" || !ValidPrincipalID(principalID) {
		return ErrPersonalGrantRefused
	}
	human, ok := s.TokenPrincipalChecker.(HumanPrincipalChecker)
	if !ok {
		// Without a kind check an agent or service could pass: refuse.
		return fmt.Errorf("personal grant: no human principal checker: %w", ErrServerError)
	}
	switch err := human.CheckHumanPrincipal(ctx, principalID); {
	case errors.Is(err, ErrIdentityRefused), errors.Is(err, ErrPrincipalDisabled):
		return ErrPersonalGrantRefused
	case err != nil:
		slog.Error("oauth: principal kind read failed for a personal grant", "error", err)
		return fmt.Errorf("check principal kind: %w", ErrServerError)
	}
	held, err := s.GlovoConsent.HeldSince(ctx, principalID, at)
	if err != nil {
		slog.Error("oauth: glovo consent read failed for a personal grant", "error", err)
		return fmt.Errorf("read glovo consent: %w", ErrServerError)
	}
	if !held {
		return ErrPersonalGrantRefused
	}
	return nil
}

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

// CreatePersonalGrant records a pending personal grant: no team, scoped to
// the principal alone. It supersedes any earlier grant of the same
// (principal, client, resource), team or personal, and is inert until the
// code exchange activates it. The caller has checked PersonalGrantAllowed.
func (s *OAuthServer) CreatePersonalGrant(ctx context.Context, principalID, clientID string) (teamgrant.Grant, error) {
	if !s.PersonalGrantsEnabled() {
		return teamgrant.Grant{}, ErrGlovoNotReady
	}
	g, err := s.TeamGrants.Create(ctx, teamgrant.Grant{
		PrincipalID: principalID, Kind: teamgrant.KindPersonal, Resource: s.GlovoResource, ClientID: clientID,
		ExpiresAt: time.Now().Add(s.TeamGrantLifetime()),
	})
	if err != nil {
		slog.Error("oauth: personal grant create failed", "error", err)
		return teamgrant.Grant{}, fmt.Errorf("create personal grant: %w", ErrServerError)
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
	kind := teamgrant.KindTeam
	if entry.PersonalGrant {
		kind = teamgrant.KindPersonal
		if entry.TeamGrantID == "" || entry.SelectedTenant != "" || entry.PrincipalID == "" {
			return "", "", errors.New("invalid or expired authorization code")
		}
		// The consent and the principal's kind are read again: a consent
		// withdrawn since the consent page mints nothing.
		switch err := s.PersonalGrantAllowed(ctx, entry.PrincipalID, time.Now()); {
		case errors.Is(err, ErrPersonalGrantRefused):
			return "", "", errors.New("invalid or expired authorization code")
		case errors.Is(err, ErrGlovoNotReady):
			return "", "", err
		case err != nil:
			return "", "", err
		}
	} else if entry.TeamGrantID == "" || entry.SelectedTenant == "" || entry.PrincipalID == "" {
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
			return teamgrant.ActivateTx(ctx, tx, entry.TeamGrantID, entry.PrincipalID, clientID, entry.Resource, kind, familyID)
		})
	if errors.Is(err, teamgrant.ErrGrantInvalid) {
		return "", "", errors.New("invalid or expired authorization code")
	}
	if err != nil {
		slog.Error("oauth: glovo code exchange store failed", "error", err)
		return "", "", fmt.Errorf("bind team grant: %w", ErrServerError)
	}
	accessToken, err := s.issueJWTWithGrant(entry.Login, entry.PrincipalID, entry.Groups, s.GlovoResource, clientID, entry.TeamGrantID, entry.SelectedTenant, entry.PersonalGrant)
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
	if g.IsPersonal() {
		// A personal grant lives on the consent it was created under and the
		// principal staying an active human; there is no team to re-check.
		// With the consent source switched off it is simply lost.
		if s.GlovoConsent == nil {
			*revoke = true
			return ErrTeamGrantInvalid
		}
		switch err := s.PersonalGrantAllowed(ctx, sess.PrincipalID, g.CreatedAt); {
		case errors.Is(err, ErrPersonalGrantRefused):
			*revoke = true
			return ErrTeamGrantInvalid
		case err != nil:
			return fmt.Errorf("check personal grant: %w", ErrServerError)
		}
		*grant = g
		return nil
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
