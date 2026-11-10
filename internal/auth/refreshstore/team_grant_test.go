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

package refreshstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// These tests need TEST_DB_URL (see newTestStore). They write grant rows
// directly: the grant store package depends on this one, not the reverse.

const (
	tgPrincipal = "prn_01JBBBBBBBBBBBBBBBBBBBBBBB"
	tgResource  = "https://glovo.mctl.ai/mcp"
)

func insertPendingGrant(t *testing.T, s *PostgresStore, id string, expires time.Duration) {
	t.Helper()
	if _, err := s.pool.Exec(context.Background(),
		`INSERT INTO oauth_team_grants (grant_id, principal_id, tenant, resource, client_id, state, created_at, expires_at)
		 VALUES ($1, $2, 'alpha', $3, 'client-1', 'pending', now(), now() + $4 * interval '1 second')`,
		id, tgPrincipal, tgResource, expires.Seconds()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.pool.Exec(context.Background(), `DELETE FROM oauth_team_grants WHERE grant_id = $1`, id)
	})
}

func grantState(t *testing.T, s *PostgresStore, id string) string {
	t.Helper()
	var st string
	if err := s.pool.QueryRow(context.Background(), `SELECT state FROM oauth_team_grants WHERE grant_id = $1`, id).Scan(&st); err != nil {
		t.Fatal(err)
	}
	return st
}

func activate(id string) func(context.Context, pgx.Tx, uuid.UUID) error {
	return func(ctx context.Context, tx pgx.Tx, fam uuid.UUID) error {
		tag, err := tx.Exec(ctx, `UPDATE oauth_team_grants SET state = 'active', refresh_family_id = $2 WHERE grant_id = $1 AND state = 'pending' AND expires_at > now()`, id, fam)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errors.New("not activated")
		}
		return nil
	}
}

func TestInsertBoundIsAllOrNothing(t *testing.T) {
	s := newTestStore(t)
	exp := time.Now().Add(time.Hour)
	sess := Session{PrincipalID: tgPrincipal, Resource: tgResource, TeamGrantID: "tgr_bound1"}

	// Expired grant: activation updates zero rows, nothing commits.
	insertPendingGrant(t, s, "tgr_bound1", -time.Minute)
	if err := s.InsertBound(context.Background(), uniqueTok(t, "a"), "client-1", sess, exp, activate("tgr_bound1")); err == nil {
		t.Fatal("expired grant activated")
	}
	if _, err := s.Rotate(uniqueTok(t, "a"), uniqueTok(t, "b"), "client-1", exp); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("a refresh row was committed: %v", err)
	}

	// Live grant: both commit, the id survives rotation.
	insertPendingGrant(t, s, "tgr_bound2", time.Hour)
	sess.TeamGrantID = "tgr_bound2"
	if err := s.InsertBound(context.Background(), uniqueTok(t, "c"), "client-1", sess, exp, activate("tgr_bound2")); err != nil {
		t.Fatal(err)
	}
	if grantState(t, s, "tgr_bound2") != "active" {
		t.Fatal("grant not active")
	}
	got, err := s.Rotate(uniqueTok(t, "c"), uniqueTok(t, "d"), "client-1", exp)
	if err != nil || got.TeamGrantID != "tgr_bound2" {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestRotateIfTxRefusalWritesNothing(t *testing.T) {
	s := newTestStore(t)
	exp := time.Now().Add(time.Hour)
	insertPendingGrant(t, s, "tgr_tx1", time.Hour)
	sess := Session{PrincipalID: tgPrincipal, Resource: tgResource, TeamGrantID: "tgr_tx1"}
	if err := s.InsertBound(context.Background(), uniqueTok(t, "a"), "client-1", sess, exp, activate("tgr_tx1")); err != nil {
		t.Fatal(err)
	}
	refusal := errors.New("refused")
	_, err := s.RotateIfTx(uniqueTok(t, "a"), uniqueTok(t, "b"), "client-1", exp, func(_ context.Context, _ pgx.Tx, _ Session) error { return refusal })
	if !errors.Is(err, refusal) {
		t.Fatalf("%v", err)
	}
	// Not spent: the same token still rotates.
	if _, err := s.RotateIfTx(uniqueTok(t, "a"), uniqueTok(t, "b"), "client-1", exp, nil); err != nil {
		t.Fatalf("token spent by a refusal: %v", err)
	}
}

func TestRevokeFamilyRevokesGrantAtomically(t *testing.T) {
	s := newTestStore(t)
	exp := time.Now().Add(time.Hour)
	insertPendingGrant(t, s, "tgr_rev1", time.Hour)
	sess := Session{PrincipalID: tgPrincipal, Resource: tgResource, TeamGrantID: "tgr_rev1"}
	if err := s.InsertBound(context.Background(), uniqueTok(t, "a"), "client-1", sess, exp, activate("tgr_rev1")); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeFamily(uniqueTok(t, "a"), "client-1", "explicit_revoke"); err != nil {
		t.Fatal(err)
	}
	if grantState(t, s, "tgr_rev1") != "revoked" {
		t.Fatal("grant outlived its family")
	}
}

func TestReuseDetectionRevokesGrant(t *testing.T) {
	s := newTestStore(t)
	withShortGraceWindow(t, time.Nanosecond)
	exp := time.Now().Add(time.Hour)
	insertPendingGrant(t, s, "tgr_reuse1", time.Hour)
	sess := Session{PrincipalID: tgPrincipal, Resource: tgResource, TeamGrantID: "tgr_reuse1"}
	if err := s.InsertBound(context.Background(), uniqueTok(t, "a"), "client-1", sess, exp, activate("tgr_reuse1")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rotate(uniqueTok(t, "a"), uniqueTok(t, "b"), "client-1", exp); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, err := s.Rotate(uniqueTok(t, "a"), uniqueTok(t, "c"), "client-1", exp); !errors.Is(err, ErrReuseDetected) {
		t.Fatalf("%v", err)
	}
	if grantState(t, s, "tgr_reuse1") != "revoked" {
		t.Fatal("a replayed token left its grant active")
	}
}

func TestRevokePrincipalRevokesGrant(t *testing.T) {
	s := newTestStore(t)
	exp := time.Now().Add(time.Hour)
	insertPendingGrant(t, s, "tgr_prn1", time.Hour)
	sess := Session{PrincipalID: tgPrincipal, Resource: tgResource, TeamGrantID: "tgr_prn1"}
	if err := s.InsertBound(context.Background(), uniqueTok(t, "a"), "client-1", sess, exp, activate("tgr_prn1")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokePrincipal(tgPrincipal, "unlink"); err != nil {
		t.Fatal(err)
	}
	if grantState(t, s, "tgr_prn1") != "revoked" {
		t.Fatal("grant outlived the principal's sessions")
	}
}
