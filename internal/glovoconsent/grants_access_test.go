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

package glovoconsent

import (
	"context"
	"errors"
	"testing"
	"time"
)

// accessFault wraps a real access source and fails or lies on demand.
type accessFault struct {
	AccessSource
	err    error
	status AccessStatus
}

func (a accessFault) AccessState(ctx context.Context, pid string) (AccessStatus, error) {
	if a.err != nil {
		return "", a.err
	}
	if a.status != "" {
		return a.status, nil
	}
	return a.AccessSource.AccessState(ctx, pid)
}

// HasGrant and HeldSince over consent x access x flag, against Postgres.
// Flag off ignores access entirely; flag on needs consent AND approved
// access; a read error or an unknown status is an error, never a grant.
func TestConsentGrantsAccessGateTable(t *testing.T) {
	ctx := context.Background()
	type consentCase struct {
		name  string
		setup func(t *testing.T, s *PostgresStore)
		ok    bool // the consent condition holds
	}
	consents := []consentCase{
		{"absent", func(*testing.T, *PostgresStore) {}, false},
		{"active", func(t *testing.T, s *PostgresStore) {
			if _, _, err := s.Record(ctx, pidA, "github:a", testCap); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"revoked", func(t *testing.T, s *PostgresStore) {
			if _, _, err := s.Record(ctx, pidA, "github:a", testCap); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Revoke(ctx, pidA, "github:a"); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"wrong version", func(t *testing.T, s *PostgresStore) {
			if _, _, err := s.Record(ctx, pidA, "github:a", testCap); err != nil {
				t.Fatal(err)
			}
			if _, err := s.pool.Exec(ctx, `UPDATE glovo_link_consents SET consent_version = 'c2-link-v0' WHERE principal_id = $1 AND revoked_at IS NULL`, pidA); err != nil {
				t.Fatal(err)
			}
		}, false},
	}
	type accessCase struct {
		name     string
		setup    func(t *testing.T, s *PostgresStore, clock *time.Time)
		fault    *accessFault
		approved bool
		wantErr  bool
	}
	request := func(t *testing.T, s *PostgresStore) {
		if _, _, err := s.RequestAccess(ctx, pidA); err != nil {
			t.Fatal(err)
		}
	}
	approve := func(t *testing.T, s *PostgresStore) {
		request(t, s)
		if _, err := s.ApproveAccess(ctx, pidA, "owner", "ok", testCap); err != nil {
			t.Fatal(err)
		}
	}
	accesses := []accessCase{
		{name: "none", setup: func(*testing.T, *PostgresStore, *time.Time) {}},
		{name: "pending", setup: func(t *testing.T, s *PostgresStore, _ *time.Time) { request(t, s) }},
		{name: "approved", setup: func(t *testing.T, s *PostgresStore, _ *time.Time) { approve(t, s) }, approved: true},
		{name: "rejected", setup: func(t *testing.T, s *PostgresStore, _ *time.Time) {
			request(t, s)
			if _, err := s.RejectAccess(ctx, pidA, "owner", "no"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "revoked", setup: func(t *testing.T, s *PostgresStore, _ *time.Time) {
			approve(t, s)
			if _, err := s.RevokeAccess(ctx, pidA, "owner", "gone"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "lapsed", setup: func(t *testing.T, s *PostgresStore, clock *time.Time) {
			request(t, s)
			*clock = clock.Add(AccessRequestTTL + time.Hour)
		}},
		{name: "error", setup: func(t *testing.T, s *PostgresStore, _ *time.Time) { approve(t, s) },
			fault: &accessFault{err: errors.New("db down")}, wantErr: true},
		{name: "unknown status", setup: func(t *testing.T, s *PostgresStore, _ *time.Time) { approve(t, s) },
			fault: &accessFault{status: "frobnicated"}, wantErr: true},
	}
	for _, c := range consents {
		for _, a := range accesses {
			for _, flagOn := range []bool{false, true} {
				name := c.name + "/" + a.name + "/flag-off"
				if flagOn {
					name = c.name + "/" + a.name + "/flag-on"
				}
				t.Run(name, func(t *testing.T) {
					s, clock := newAccessStore(t, flagOn)
					c.setup(t, s)
					a.setup(t, s, clock)
					g := ConsentGrants{Store: s}
					if flagOn {
						g.Access = s
						if a.fault != nil {
							f := *a.fault
							f.AccessSource = s
							g.Access = f
						}
					}
					at := time.Now().AddDate(10, 0, 0)
					wantGrant := c.ok && (!flagOn || a.approved)
					// An access error only surfaces once the consent
					// condition holds; a consent that fails is a plain no.
					wantErr := flagOn && c.ok && a.wantErr
					if wantErr {
						wantGrant = false
					}
					has, err := g.HasGrant(ctx, pidA, GrantC2)
					if has != wantGrant || (err != nil) != wantErr {
						t.Errorf("HasGrant = %v %v, want %v err=%v", has, err, wantGrant, wantErr)
					}
					held, err := g.HeldSince(ctx, pidA, at)
					if held != wantGrant || (err != nil) != wantErr {
						t.Errorf("HeldSince = %v %v, want %v err=%v", held, err, wantGrant, wantErr)
					}
				})
			}
		}
	}
}

// A personal grant created while access was approved stops working when the
// access is revoked, at the next check, and never before. A grant older than
// the consent is refused whatever the access says.
func TestHeldSinceFollowsAccessRevocation(t *testing.T) {
	ctx := context.Background()
	s, _ := newAccessStore(t, true)
	rec, _, err := s.Record(ctx, pidA, "github:a", testCap)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RequestAccess(ctx, pidA); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveAccess(ctx, pidA, "owner", "ok", testCap); err != nil {
		t.Fatal(err)
	}
	g := ConsentGrants{Store: s, Access: s}
	grantAt := rec.RecordedAt.Add(time.Second)
	if ok, err := g.HeldSince(ctx, pidA, grantAt); !ok || err != nil {
		t.Fatalf("approved = %v %v, want held", ok, err)
	}
	if ok, err := g.HeldSince(ctx, pidA, rec.RecordedAt.Add(-time.Hour)); ok || err != nil {
		t.Fatalf("grant older than the consent = %v %v, want not held", ok, err)
	}
	if _, err := s.RevokeAccess(ctx, pidA, "owner", "gone"); err != nil {
		t.Fatal(err)
	}
	if ok, err := g.HeldSince(ctx, pidA, grantAt); ok || err != nil {
		t.Fatalf("after RevokeAccess = %v %v, want not held", ok, err)
	}
	// Re-approval is an explicit owner decision: the same grant, bound to
	// the same unchanged consent, works again; a withdrawn and re-recorded
	// consent still does not revive it.
	if _, _, err := s.RequestAccess(ctx, pidA); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveAccess(ctx, pidA, "owner", "again", testCap); err != nil {
		t.Fatal(err)
	}
	if ok, err := g.HeldSince(ctx, pidA, grantAt); !ok || err != nil {
		t.Fatalf("after re-approval = %v %v, want held", ok, err)
	}
	if _, err := s.Revoke(ctx, pidA, "github:a"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Record(ctx, pidA, "github:a", testCap); err != nil {
		t.Fatal(err)
	}
	if ok, err := g.HeldSince(ctx, pidA, grantAt); ok || err != nil {
		t.Fatalf("grant older than a re-recorded consent = %v %v, want not held", ok, err)
	}
}

// Existing consent holders keep the grant across the flag flip because the
// backfill approves them; a consent recorded after the flip with no access
// row does not get it.
func TestBackfilledConsentHolderKeepsGrantNewOneDoesNot(t *testing.T) {
	ctx := context.Background()
	s, _ := newAccessStore(t, false)
	if _, _, err := s.Record(ctx, pidA, "github:a", testCap); err != nil {
		t.Fatal(err)
	}
	// Before the flip: the grant is the consent alone.
	if ok, err := (ConsentGrants{Store: s}).HasGrant(ctx, pidA, GrantC2); !ok || err != nil {
		t.Fatalf("pre-flip = %v %v", ok, err)
	}
	// The flip: the access gate is on and the backfill runs.
	s.accessRequired = true
	if _, err := s.pool.Exec(ctx, `DELETE FROM glovo_access_meta`); err != nil {
		t.Fatal(err)
	}
	if err := s.backfillAccess(ctx); err != nil {
		t.Fatal(err)
	}
	g := ConsentGrants{Store: s, Access: s}
	if ok, err := g.HasGrant(ctx, pidA, GrantC2); !ok || err != nil {
		t.Fatalf("pre-existing holder after the backfill = %v %v, want the grant", ok, err)
	}
	if ok, err := g.HeldSince(ctx, pidA, time.Now()); !ok || err != nil {
		t.Fatalf("pre-existing holder HeldSince = %v %v, want held", ok, err)
	}
	if _, _, err := s.Record(ctx, pidB, "github:b", testCap); err != nil {
		t.Fatal(err)
	}
	if ok, err := g.HasGrant(ctx, pidB, GrantC2); ok || err != nil {
		t.Fatalf("consent after the flip, no access = %v %v, want no grant", ok, err)
	}
	if ok, err := g.HeldSince(ctx, pidB, time.Now().Add(time.Hour)); ok || err != nil {
		t.Fatalf("consent after the flip, HeldSince = %v %v, want not held", ok, err)
	}
}
