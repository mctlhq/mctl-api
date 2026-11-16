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
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth/teamgrant"
)

// fakeConsent is a GlovoConsentSource: the principal holds the consent
// recorded at since while held is true.
type fakeConsent struct {
	mu    sync.Mutex
	held  map[string]time.Time
	err   error
	calls int
}

func (f *fakeConsent) HeldSince(_ context.Context, prn string, at time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return false, f.err
	}
	since, ok := f.held[prn]
	return ok && !since.After(at), nil
}

func (f *fakeConsent) set(prn string, since time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.held[prn] = since
}

func (f *fakeConsent) revoke(prn string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.held, prn)
}

// fakeKinds is a TokenPrincipalChecker that also checks a principal's kind.
type fakeKinds struct {
	agents map[string]bool
	err    error
}

func (f *fakeKinds) CheckPrincipal(context.Context, string) error { return f.err }

func (f *fakeKinds) CheckHumanPrincipal(_ context.Context, prn string) error {
	if f.err != nil {
		return f.err
	}
	if f.agents[prn] {
		return ErrIdentityRefused
	}
	return nil
}

type personalEnv struct {
	*glovoEnv
	consent *fakeConsent
	kinds   *fakeKinds
}

// newPersonalEnv is a Glovo env whose principal has no team and holds the
// glovo:c2 consent, recorded a minute ago.
func newPersonalEnv(t *testing.T) *personalEnv {
	t.Helper()
	e := newGlovoEnv(t)
	e.elig.teams = map[string][]string{}
	c := &fakeConsent{held: map[string]time.Time{tgPRN: time.Now().Add(-time.Minute)}}
	k := &fakeKinds{agents: map[string]bool{}}
	e.o.GlovoConsent, e.o.TokenPrincipalChecker = c, k
	return &personalEnv{glovoEnv: e, consent: c, kinds: k}
}

func (e *personalEnv) personalCode(t *testing.T) (string, teamgrant.Grant) {
	t.Helper()
	g, err := e.o.CreatePersonalGrant(context.Background(), tgPRN, tgClient)
	if err != nil {
		t.Fatal(err)
	}
	code, err := e.o.IssueCodeForPersonalGrant(context.Background(), "", tgPRN, tgClient, tgRedir, challenge(), nil, "", e.o.GlovoResource, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	return code, g
}

func TestPersonalGrantAllowed(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	e := newPersonalEnv(t)
	if err := e.o.PersonalGrantAllowed(ctx, tgPRN, now); err != nil {
		t.Fatalf("human with consent: %v", err)
	}
	for name, tc := range map[string]struct {
		mutate  func(*personalEnv)
		refused bool // a definite no; otherwise a failed read
	}{
		"no consent":            {func(e *personalEnv) { e.consent.revoke(tgPRN) }, true},
		"consent after grant":   {func(e *personalEnv) { e.consent.set(tgPRN, now.Add(time.Second)) }, true},
		"agent principal":       {func(e *personalEnv) { e.kinds.agents[tgPRN] = true }, true},
		"disabled principal":    {func(e *personalEnv) { e.kinds.err = ErrPrincipalDisabled }, true},
		"consent store error":   {func(e *personalEnv) { e.consent.err = errors.New("db down") }, false},
		"principal store error": {func(e *personalEnv) { e.kinds.err = errors.New("db down") }, false},
		"no kind checker":       {func(e *personalEnv) { e.o.TokenPrincipalChecker = nil }, false},
	} {
		t.Run(name, func(t *testing.T) {
			e := newPersonalEnv(t)
			tc.mutate(e)
			err := e.o.PersonalGrantAllowed(ctx, tgPRN, now)
			if err == nil {
				t.Fatal("allowed")
			}
			if got := errors.Is(err, ErrPersonalGrantRefused); got != tc.refused {
				t.Fatalf("refused=%v, want %v (%v)", got, tc.refused, err)
			}
		})
	}
	off := newPersonalEnv(t)
	off.o.GlovoConsent = nil
	if off.o.PersonalGrantsEnabled() {
		t.Fatal("personal grants enabled without a consent source")
	}
	if err := off.o.PersonalGrantAllowed(ctx, tgPRN, now); !errors.Is(err, ErrGlovoNotReady) {
		t.Fatalf("consent source off: %v", err)
	}
	if _, err := off.o.CreatePersonalGrant(ctx, tgPRN, tgClient); !errors.Is(err, ErrGlovoNotReady) {
		t.Fatalf("personal grant created with the consent source off: %v", err)
	}
}

func TestPersonalCodeShape(t *testing.T) {
	ctx := context.Background()
	e := newPersonalEnv(t)
	if _, err := e.o.IssueCodeForPersonalGrant(ctx, "", tgPRN, tgClient, tgRedir, "c", nil, "", e.o.GlovoResource, ""); err == nil {
		t.Fatal("personal code without a grant")
	}
	if _, err := e.o.IssueCodeForPersonalGrant(ctx, "", tgPRN, tgClient, tgRedir, "c", nil, "", "", "tgr_x"); err == nil {
		t.Fatal("personal grant on a non-glovo code")
	}
	if _, err := e.o.issueCodeForGrant(ctx, "", tgPRN, tgClient, tgRedir, "c", nil, "", e.o.GlovoResource, "tgr_x", "alpha", true); err == nil {
		t.Fatal("personal code naming a team")
	}
	e.o.GlovoConsent = nil
	if _, err := e.o.IssueCodeForPersonalGrant(ctx, "", tgPRN, tgClient, tgRedir, "c", nil, "", e.o.GlovoResource, "tgr_x"); err == nil {
		t.Fatal("personal code with the consent source off")
	}
}

// The exchange of a personal code activates the personal grant and signs tgr
// with tgk=personal and no stn: the token is never a team token.
func TestPersonalExchangeSignsPersonalClaims(t *testing.T) {
	e := newPersonalEnv(t)
	code, g := e.personalCode(t)
	access, refresh, err := e.exchange(code)
	if err != nil {
		t.Fatal(err)
	}
	u, err := e.o.ValidateJWT(access)
	if err != nil {
		t.Fatal(err)
	}
	if id, ok := u.PersonalGrant(); !ok || id != g.ID {
		t.Fatalf("personal claims: %q %v", id, ok)
	}
	if _, _, ok := u.TeamGrant(); ok {
		t.Fatal("a personal token reads as a team token")
	}
	got, err := e.grants.Check(context.Background(), g.ID, tgPRN, tgClient, e.o.GlovoResource)
	if err != nil || !got.IsPersonal() {
		t.Fatalf("activated grant: %+v %v", got, err)
	}
	if s, _ := e.store.Session(refresh); s.TeamGrantID != g.ID {
		t.Fatalf("session grant %q", s.TeamGrantID)
	}
}

func TestPersonalExchangeRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		prep    func(*personalEnv)
		wantErr error
	}{
		"consent withdrawn since consent": {func(e *personalEnv) { e.consent.revoke(tgPRN) }, nil},
		"consent store error":             {func(e *personalEnv) { e.consent.err = errors.New("db down") }, ErrServerError},
		"principal became an agent":       {func(e *personalEnv) { e.kinds.agents[tgPRN] = true }, nil},
		"consent source switched off":     {func(e *personalEnv) { e.o.GlovoConsent = nil }, ErrGlovoNotReady},
	} {
		t.Run(name, func(t *testing.T) {
			e := newPersonalEnv(t)
			code, g := e.personalCode(t)
			tc.prep(e)
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
			if _, err := e.grants.Check(context.Background(), g.ID, tgPRN, tgClient, e.o.GlovoResource); err == nil {
				t.Fatal("grant activated")
			}
		})
	}
	// A personal grant id carried by a team code is never activated.
	e := newPersonalEnv(t)
	g, err := e.o.CreatePersonalGrant(context.Background(), tgPRN, tgClient)
	if err != nil {
		t.Fatal(err)
	}
	code, err := e.o.IssueCodeForTeamGrant(context.Background(), "", tgPRN, tgClient, tgRedir, challenge(), nil, "", e.o.GlovoResource, g.ID, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.exchange(code); err == nil || e.store.Live() != 0 {
		t.Fatalf("team code over a personal grant exchanged: %v", err)
	}
}

// Revocation runs on the issued tokens: once the consent is withdrawn, the
// refresh token issued under the personal grant is refused and its family
// and grant are revoked; a store error refuses without revoking anything.
func TestPersonalRefresh(t *testing.T) {
	setup := func(t *testing.T) (*personalEnv, string, teamgrant.Grant) {
		e := newPersonalEnv(t)
		code, g := e.personalCode(t)
		_, refresh, err := e.exchange(code)
		if err != nil {
			t.Fatal(err)
		}
		return e, refresh, g
	}
	refresh := func(e *personalEnv, tok string) (string, string, error) {
		return e.o.RefreshAccessTokenForResource(context.Background(), tok, tgClient, ClientAssertion{}, nil)
	}
	grantLive := func(e *personalEnv, g teamgrant.Grant) bool {
		_, err := e.grants.Check(context.Background(), g.ID, tgPRN, tgClient, e.o.GlovoResource)
		return err == nil
	}

	t.Run("consent held rotates and keeps the personal grant", func(t *testing.T) {
		e, tok, g := setup(t)
		access, next, err := refresh(e, tok)
		if err != nil || next == "" {
			t.Fatal(err)
		}
		u, err := e.o.ValidateJWT(access)
		if err != nil {
			t.Fatal(err)
		}
		if id, ok := u.PersonalGrant(); !ok || id != g.ID {
			t.Fatalf("%q %v", id, ok)
		}
		if _, _, ok := u.TeamGrant(); ok {
			t.Fatal("refreshed personal token reads as a team token")
		}
	})
	t.Run("consent withdrawn revokes family and grant", func(t *testing.T) {
		e, tok, g := setup(t)
		e.consent.revoke(tgPRN)
		if _, _, err := refresh(e, tok); err == nil {
			t.Fatal("refreshed without consent")
		}
		if e.store.Live() != 0 || grantLive(e, g) {
			t.Fatalf("live tokens %d, grant live %v", e.store.Live(), grantLive(e, g))
		}
	})
	t.Run("consenting again does not revive the grant", func(t *testing.T) {
		e, tok, g := setup(t)
		e.consent.set(tgPRN, time.Now().Add(time.Second))
		if _, _, err := refresh(e, tok); err == nil {
			t.Fatal("a later consent revived the grant")
		}
		if e.store.Live() != 0 || grantLive(e, g) {
			t.Fatal("family or grant left live")
		}
	})
	t.Run("principal became an agent", func(t *testing.T) {
		e, tok, _ := setup(t)
		e.kinds.agents[tgPRN] = true
		if _, _, err := refresh(e, tok); err == nil {
			t.Fatal("refreshed for an agent")
		}
		if e.store.Live() != 0 {
			t.Fatal("family left live")
		}
	})
	t.Run("consent store error refuses and revokes nothing", func(t *testing.T) {
		e, tok, g := setup(t)
		e.consent.err = errors.New("db down")
		if _, _, err := refresh(e, tok); !errors.Is(err, ErrServerError) {
			t.Fatalf("store error: %v", err)
		}
		if e.store.Live() != 1 || !grantLive(e, g) {
			t.Fatal("an outage revoked the session")
		}
	})
	t.Run("consent source switched off revokes", func(t *testing.T) {
		e, tok, g := setup(t)
		e.o.GlovoConsent = nil
		if _, _, err := refresh(e, tok); err == nil {
			t.Fatal("refreshed with the consent source off")
		}
		if e.store.Live() != 0 || grantLive(e, g) {
			t.Fatal("family or grant left live")
		}
	})
}

// tgk is read and minted only on the Glovo audience, and a personal claim
// with a team is no grant at all.
func TestPersonalClaimsOnlyOnGlovoAudience(t *testing.T) {
	e := newPersonalEnv(t)
	o := e.o
	forge := func(aud audience, stn string) *User {
		tok, err := signJWT(jwtPayload{Issuer: o.BaseURL, Subject: "alice", PID: tgPRN, Audience: aud,
			TeamGrant: "tgr_forged", SelectedTenant: stn, GrantKind: grantKindPersonal, ExpiresAt: time.Now().Add(time.Hour).Unix()}, o.JWTSecret)
		if err != nil {
			t.Fatal(err)
		}
		u, err := o.ValidateJWT(tok)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	apiTok, err := signJWT(jwtPayload{Issuer: o.BaseURL, Subject: "alice", PID: tgPRN, Audience: audience{o.BaseURL},
		TeamGrant: "tgr_forged", GrantKind: grantKindPersonal, ExpiresAt: time.Now().Add(time.Hour).Unix()}, o.JWTSecret)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := o.verifyAccessToken(apiTok); err != nil || p.GrantKind != "" || p.TeamGrant != "" {
		t.Fatalf("tgk kept on an API token: %+v %v", p, err)
	}
	if _, ok := forge(audience{o.BaseURL}, "").PersonalGrant(); ok {
		t.Fatal("tgk honoured on an API token")
	}
	if id, ok := forge(audience{GlovoResourceIntended}, "").PersonalGrant(); !ok || id != "tgr_forged" {
		t.Fatal("tgk not read on the glovo audience")
	}
	if _, ok := forge(audience{GlovoResourceIntended}, "alpha").PersonalGrant(); ok {
		t.Fatal("a personal claim naming a team is a personal grant")
	}
	for _, aud := range []string{o.BaseURL, testSupportRes} {
		tok, err := o.issueJWTWithGrant("alice", tgPRN, nil, aud, tgClient, "tgr_x", "", true)
		if err != nil {
			t.Fatal(err)
		}
		p, err := o.verifyAccessToken(tok)
		if err != nil || p.GrantKind != "" || p.TeamGrant != "" {
			t.Fatalf("personal claims minted for %s: %v", aud, err)
		}
	}
	if _, err := o.issueJWTWithGrant("alice", tgPRN, nil, GlovoResourceIntended, tgClient, "tgr_x", "alpha", true); err == nil {
		t.Fatal("minted a personal token naming a team")
	}
}
