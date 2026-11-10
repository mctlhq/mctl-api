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

package teamgrant_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/mctlhq/mctl-api/internal/auth/refreshstore"
	"github.com/mctlhq/mctl-api/internal/auth/teamgrant"
)

// TestPostgresStoreEndToEnd exercises the real SQL (DDL idempotence,
// supersede, Check, ActivateTx atomicity, family and principal revocation).
// It needs TEST_DB_URL, like the refreshstore tests.
func TestPostgresStoreEndToEnd(t *testing.T) {
	if os.Getenv("TEST_DB_URL") == "" {
		t.Skip("TEST_DB_URL not set; skipping Postgres tests")
	}
	ctx := context.Background()
	rs, err := refreshstore.NewPostgresStore(ctx, os.Getenv("TEST_DB_URL"))
	if err != nil {
		t.Fatal(err)
	}
	// idempotent DDL: second init
	if _, err := refreshstore.NewPostgresStore(ctx, os.Getenv("TEST_DB_URL")); err != nil {
		t.Fatal("second init", err)
	}
	gs, _ := teamgrant.NewPostgresStore(rs.Pool())
	sfx := uuid.NewString()
	prn, cl, res := "prn_it_"+sfx, "c1", "https://glovo.mctl.ai/mcp"
	t.Cleanup(func() {
		_, _ = rs.Pool().Exec(context.Background(), `DELETE FROM oauth_team_grants WHERE principal_id = $1`, prn)
	})
	g1, err := gs.Create(ctx, teamgrant.Grant{PrincipalID: prn, Tenant: "alpha", ClientID: cl, Resource: res, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gs.Check(ctx, g1.ID, prn, cl, res); !errors.Is(err, teamgrant.ErrGrantInvalid) {
		t.Fatal("pending passed", err)
	}
	sess := refreshstore.Session{PrincipalID: prn, Resource: res, TeamGrantID: g1.ID}
	err = rs.InsertBound(ctx, "rawtok-"+sfx+"-1", cl, sess, time.Now().Add(time.Hour), func(ctx context.Context, tx pgx.Tx, f uuid.UUID) error {
		return teamgrant.ActivateTx(ctx, tx, g1.ID, prn, cl, res, f)
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := gs.Check(ctx, g1.ID, prn, cl, res)
	if err != nil || got.Tenant != "alpha" || got.RefreshFamilyID == "" {
		t.Fatal(got, err)
	}
	// wrong principal / client / resource
	for _, c := range [][3]string{{"prn_other", cl, res}, {prn, "c2", res}, {prn, cl, "x"}} {
		if _, err := gs.Check(ctx, g1.ID, c[0], c[1], c[2]); !errors.Is(err, teamgrant.ErrGrantInvalid) {
			t.Fatal("mismatch passed", c)
		}
	}
	// supersede
	g2, err := gs.Create(ctx, teamgrant.Grant{PrincipalID: prn, Tenant: "beta", ClientID: cl, Resource: res, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gs.Check(ctx, g1.ID, prn, cl, res); !errors.Is(err, teamgrant.ErrGrantInvalid) {
		t.Fatal("superseded passed")
	}
	// double activation refused
	err = rs.InsertBound(ctx, "rawtok-"+sfx+"-2", cl, refreshstore.Session{PrincipalID: prn, Resource: res, TeamGrantID: g2.ID}, time.Now().Add(time.Hour), func(ctx context.Context, tx pgx.Tx, f uuid.UUID) error {
		return teamgrant.ActivateTx(ctx, tx, g2.ID, prn, "wrongclient", res, f)
	})
	if !errors.Is(err, teamgrant.ErrGrantInvalid) {
		t.Fatal("activate wrong client", err)
	}
	if _, e := rs.Rotate("rawtok-"+sfx+"-2", "rawtok-"+sfx+"-3", cl, time.Now().Add(time.Hour)); !errors.Is(e, refreshstore.ErrInvalidToken) {
		t.Fatal("row committed")
	}
	err = rs.InsertBound(ctx, "rawtok-"+sfx+"-4", cl, refreshstore.Session{PrincipalID: prn, Resource: res, TeamGrantID: g2.ID}, time.Now().Add(time.Hour), func(ctx context.Context, tx pgx.Tx, f uuid.UUID) error {
		return teamgrant.ActivateTx(ctx, tx, g2.ID, prn, cl, res, f)
	})
	if err != nil {
		t.Fatal(err)
	}
	// reuse -> revoke grant
	if _, err := rs.RotateIfTx("rawtok-"+sfx+"-4", "rawtok-"+sfx+"-5", cl, time.Now().Add(time.Hour), func(ctx context.Context, tx pgx.Tx, s refreshstore.Session) error {
		_, err := teamgrant.CheckTx(ctx, tx, s.TeamGrantID, s.PrincipalID, cl, res)
		return err
	}); err != nil {
		t.Fatal("rotate", err)
	}
	// revoke family -> grant revoked
	if err := rs.RevokeFamily("rawtok-"+sfx+"-5", cl, "explicit_revoke"); err != nil {
		t.Fatal(err)
	}
	if _, err := gs.Check(ctx, g2.ID, prn, cl, res); !errors.Is(err, teamgrant.ErrGrantInvalid) {
		t.Fatal("grant live after family revoke")
	}
	// principal revoke
	g3, _ := gs.Create(ctx, teamgrant.Grant{PrincipalID: prn, Tenant: "alpha", ClientID: cl, Resource: res, ExpiresAt: time.Now().Add(time.Hour)})
	if _, err := rs.RevokePrincipal(prn, "unlink"); err != nil {
		t.Fatal(err)
	}
	var st string
	if err := rs.Pool().QueryRow(ctx, `SELECT state FROM oauth_team_grants WHERE grant_id=$1`, g3.ID).Scan(&st); err != nil {
		t.Fatal(err)
	}
	if st != "revoked" {
		t.Fatal("pending grant not revoked by principal", st)
	}
}
