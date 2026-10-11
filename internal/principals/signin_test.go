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
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
)

func linkedAlice(t *testing.T, s *Store) *Principal {
	t.Helper()
	ctx := context.Background()
	p, err := s.Provision(ctx, github(1, "alice"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.LinkIdentity(ctx, p.ID, zitadel("z1", "alice")); err != nil {
		t.Fatal(err)
	}
	return p
}

func countRows(t *testing.T, s *Store) (principals, identities int) {
	t.Helper()
	ctx := context.Background()
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM principals`).Scan(&principals); err != nil {
		t.Fatal(err)
	}
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM external_identities`).Scan(&identities); err != nil {
		t.Fatal(err)
	}
	return principals, identities
}

func TestLinkedGitHubReturnsTheLinkedPrincipalsLogin(t *testing.T) {
	s := newStoreForTest(t)
	p := linkedAlice(t, s)
	got, gh, err := s.LinkedGitHub(context.Background(), zitadel("z1", ""))
	if err != nil || got.ID != p.ID || gh == nil || gh.Display != "alice" || gh.Subject != "1" || gh.Provider != auth.ProviderGitHub {
		t.Fatalf("LinkedGitHub = %+v, %+v, %v; want %s as alice (1)", got, gh, err, p.ID)
	}
}

// Read-only: an identity nobody has seen is ErrNotFound and writes nothing.
func TestLinkedGitHubNeverProvisions(t *testing.T) {
	s := newStoreForTest(t)
	linkedAlice(t, s)
	beforeP, beforeX := countRows(t, s)
	if _, _, err := s.LinkedGitHub(context.Background(), zitadel("z-unknown", "bob")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if p, x := countRows(t, s); p != beforeP || x != beforeX {
		t.Fatalf("rows %d/%d -> %d/%d: LinkedGitHub wrote", beforeP, beforeX, p, x)
	}
}

// A ZITADEL user that got a principal of its own (a bearer token before
// linking) is not linked, and the caller learns which principal it is.
func TestLinkedGitHubOfAnOwnPrincipal(t *testing.T) {
	s := newStoreForTest(t)
	linkedAlice(t, s)
	own, err := s.Provision(context.Background(), zitadel("z2", "bob"))
	if err != nil {
		t.Fatal(err)
	}
	p, gh, err := s.LinkedGitHub(context.Background(), zitadel("z2", ""))
	if !errors.Is(err, ErrNoGitHubIdentity) || p == nil || p.ID != own.ID || gh != nil {
		t.Fatalf("LinkedGitHub = %+v, %+v, %v; want ErrNoGitHubIdentity naming %s", p, gh, err, own.ID)
	}
}

func TestLinkedGitHubRefusals(t *testing.T) {
	ctx := context.Background()
	t.Run("revoked identity", func(t *testing.T) {
		s := newStoreForTest(t)
		p := linkedAlice(t, s)
		ids, _ := s.Identities(ctx, p.ID)
		for _, x := range ids {
			if x.Provider == "zitadel" {
				if _, err := s.UnlinkIdentity(ctx, p.ID, x.ID); err != nil {
					t.Fatal(err)
				}
			}
		}
		if _, _, err := s.LinkedGitHub(ctx, zitadel("z1", "")); !errors.Is(err, auth.ErrIdentityRefused) {
			t.Fatalf("err = %v, want ErrIdentityRefused", err)
		}
	})
	t.Run("disabled principal", func(t *testing.T) {
		s := newStoreForTest(t)
		p := linkedAlice(t, s)
		if err := s.SetStatus(ctx, p.ID, StatusDisabled); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.LinkedGitHub(ctx, zitadel("z1", "")); !errors.Is(err, auth.ErrPrincipalDisabled) {
			t.Fatalf("err = %v, want ErrPrincipalDisabled", err)
		}
	})
	t.Run("revoked GitHub identity", func(t *testing.T) {
		s := newStoreForTest(t)
		p := linkedAlice(t, s)
		ids, _ := s.Identities(ctx, p.ID)
		for _, x := range ids {
			if x.Provider == auth.ProviderGitHub {
				if _, err := s.UnlinkIdentity(ctx, p.ID, x.ID); err != nil {
					t.Fatal(err)
				}
			}
		}
		if _, _, err := s.LinkedGitHub(ctx, zitadel("z1", "")); !errors.Is(err, ErrNoGitHubIdentity) {
			t.Fatalf("err = %v, want ErrNoGitHubIdentity", err)
		}
	})
	t.Run("login taken by another account", func(t *testing.T) {
		s := newStoreForTest(t)
		linkedAlice(t, s)
		// GitHub now reports "alice" for id 2: id 1's row loses the login.
		if _, err := s.Provision(ctx, github(2, "alice")); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.LinkedGitHub(ctx, zitadel("z1", "")); !errors.Is(err, ErrGitHubLoginUnknown) {
			t.Fatalf("err = %v, want ErrGitHubLoginUnknown", err)
		}
	})
	t.Run("two GitHub identities", func(t *testing.T) {
		s := newStoreForTest(t)
		p := linkedAlice(t, s)
		// Linking and merging never produce this; write it directly.
		if _, err := s.pool.Exec(ctx, `INSERT INTO external_identities
			(id, principal_id, provider, issuer, subject, display, verified_at) VALUES ('xid_extra',$1,'github','','3','carol',$2)`,
			p.ID, time.Now()); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.LinkedGitHub(ctx, zitadel("z1", "")); !errors.Is(err, ErrAmbiguousGitHubIdentity) {
			t.Fatalf("err = %v, want ErrAmbiguousGitHubIdentity", err)
		}
	})
	t.Run("GitHub identity as input", func(t *testing.T) {
		s := newStoreForTest(t)
		linkedAlice(t, s)
		if _, _, err := s.LinkedGitHub(ctx, github(1, "alice")); !errors.Is(err, ErrInvalid) {
			t.Fatalf("err = %v, want ErrInvalid", err)
		}
	})
}

// A failed read is an error of its own, never ErrNotFound.
func TestLinkedGitHubFailedReadIsNotNotFound(t *testing.T) {
	s := newStoreForTest(t)
	linkedAlice(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := s.LinkedGitHub(ctx, zitadel("z1", ""))
	if err == nil || errors.Is(err, ErrNotFound) || errors.Is(err, ErrNoGitHubIdentity) {
		t.Fatalf("err = %v, want a read failure", err)
	}
}
