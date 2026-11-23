// Copyright 2026 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/glovoconsent"
)

// memConsent is a consent Store holding one active consent recorded at since.
type memConsent struct {
	rec glovoconsent.Record
}

func (m memConsent) Record(context.Context, string, string, int) (glovoconsent.Record, bool, error) {
	return m.rec, false, nil
}
func (m memConsent) Revoke(context.Context, string, string) (glovoconsent.Record, error) {
	return m.rec, nil
}
func (m memConsent) Active(context.Context, string) (glovoconsent.Record, error) {
	return m.rec, nil
}

// memAccess is an access source whose state and failure the test sets.
type memAccess struct {
	mu     sync.Mutex
	status glovoconsent.AccessStatus
	err    error
}

func (a *memAccess) AccessState(context.Context, string) (glovoconsent.AccessStatus, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.status, a.err
}

func (a *memAccess) set(s glovoconsent.AccessStatus, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.status, a.err = s, err
}

// gatedEnv is a personal env whose consent source is the real
// glovoconsent.ConsentGrants over an in-memory consent and access. With
// gated false the access source is nil (GLOVO_ACCESS_REQUIRED off).
func gatedEnv(t *testing.T, gated bool, status glovoconsent.AccessStatus) (*personalEnv, *memAccess) {
	t.Helper()
	e := newPersonalEnv(t)
	acc := &memAccess{status: status}
	src := glovoconsent.ConsentGrants{Store: memConsent{rec: glovoconsent.Record{
		ID: "gcn_1", PrincipalID: tgPRN, Version: glovoconsent.Version, RecordedAt: time.Now().Add(-time.Minute),
	}}}
	if gated {
		src.Access = acc
	}
	e.o.GlovoConsent = src
	return e, acc
}

// The personal-grant path end to end with the access gate on: refused
// without approval, allowed with it, refused again after the access is
// revoked (code exchange and refresh), and a failed access read is a server
// error, never a grant. With the gate off access is ignored.
func TestPersonalGrantRequiresApprovedAccess(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	for _, st := range []glovoconsent.AccessStatus{glovoconsent.AccessNone, glovoconsent.AccessPending,
		glovoconsent.AccessRejected, glovoconsent.AccessRevoked} {
		e, _ := gatedEnv(t, true, st)
		if err := e.o.PersonalGrantAllowed(ctx, tgPRN, now); !errors.Is(err, ErrPersonalGrantRefused) {
			t.Errorf("gate on, access %s: %v, want refused", st, err)
		}
		off, _ := gatedEnv(t, false, st)
		if err := off.o.PersonalGrantAllowed(ctx, tgPRN, now); err != nil {
			t.Errorf("gate off, access %s: %v, want allowed", st, err)
		}
	}
	e, acc := gatedEnv(t, true, glovoconsent.AccessApproved)
	if err := e.o.PersonalGrantAllowed(ctx, tgPRN, now); err != nil {
		t.Fatalf("approved: %v", err)
	}
	acc.set("", errors.New("db down"))
	if err := e.o.PersonalGrantAllowed(ctx, tgPRN, now); !errors.Is(err, ErrServerError) || errors.Is(err, ErrPersonalGrantRefused) {
		t.Fatalf("access read error: %v, want a server error", err)
	}

	// Code exchange: approval revoked between the consent page and the
	// exchange mints nothing; an outage is a server error and mints nothing.
	for name, tc := range map[string]struct {
		status  glovoconsent.AccessStatus
		err     error
		wantErr error
	}{
		"revoked":      {glovoconsent.AccessRevoked, nil, nil},
		"access error": {"", errors.New("db down"), ErrServerError},
	} {
		t.Run("exchange "+name, func(t *testing.T) {
			e, acc := gatedEnv(t, true, glovoconsent.AccessApproved)
			code, g := e.personalCode(t)
			acc.set(tc.status, tc.err)
			access, refresh, err := e.exchange(code)
			if err == nil || access != "" || refresh != "" {
				t.Fatalf("exchange succeeded: %v", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("err %v, want %v", err, tc.wantErr)
			}
			if e.store.Live() != 0 {
				t.Fatal("a refresh token was committed")
			}
			if _, err := e.grants.Check(ctx, g.ID, tgPRN, tgClient, e.o.GlovoResource); err == nil {
				t.Fatal("grant activated")
			}
		})
	}

	// Refresh: approved rotates; revoked revokes family and grant; an outage
	// refuses without revoking anything.
	refresh := func(e *personalEnv, tok string) error {
		_, _, err := e.o.RefreshAccessTokenForResource(ctx, tok, tgClient, ClientAssertion{}, nil)
		return err
	}
	setup := func(t *testing.T) (*personalEnv, *memAccess, string) {
		e, acc := gatedEnv(t, true, glovoconsent.AccessApproved)
		code, _ := e.personalCode(t)
		_, tok, err := e.exchange(code)
		if err != nil {
			t.Fatal(err)
		}
		return e, acc, tok
	}
	t.Run("refresh approved", func(t *testing.T) {
		e, _, tok := setup(t)
		if err := refresh(e, tok); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("refresh after RevokeAccess", func(t *testing.T) {
		e, acc, tok := setup(t)
		acc.set(glovoconsent.AccessRevoked, nil)
		if err := refresh(e, tok); err == nil {
			t.Fatal("refreshed after the access was revoked")
		}
		if e.store.Live() != 0 {
			t.Fatal("family left live")
		}
	})
	t.Run("refresh access error", func(t *testing.T) {
		e, acc, tok := setup(t)
		acc.set("", errors.New("db down"))
		if err := refresh(e, tok); !errors.Is(err, ErrServerError) {
			t.Fatalf("access error: %v", err)
		}
		if e.store.Live() != 1 {
			t.Fatal("an outage revoked the session")
		}
	})
}
