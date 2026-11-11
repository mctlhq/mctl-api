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
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth/refreshstore"
	"github.com/mctlhq/mctl-api/internal/auth/refreshstore/refreshstoretest"
	"github.com/mctlhq/mctl-api/internal/auth/teamgrant"
)

const (
	tgPRN    = "prn_01JBBBBBBBBBBBBBBBBBBBBBBB"
	tgClient = "client-1"
	tgRedir  = "https://app.example.com/cb"
	tgVerif  = "verifier-verifier-verifier-verifier-1234"
)

// fakeElig is a TeamEligibility over a fixed map.
type fakeElig struct {
	teams map[string][]string // principal -> tenants
	err   error
}

func (f *fakeElig) Eligible(_ context.Context, prn string) ([]string, error) {
	return f.teams[prn], f.err
}

func (f *fakeElig) Has(_ context.Context, prn, tenant string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	for _, t := range f.teams[prn] {
		if t == tenant {
			return true, nil
		}
	}
	return false, nil
}

type glovoEnv struct {
	o      *OAuthServer
	store  *refreshstoretest.Bound
	grants *refreshstoretest.TxGrants
	elig   *fakeElig
}

func newGlovoEnv(t *testing.T) *glovoEnv {
	t.Helper()
	o := newResourceServer(t)
	o.GlovoResource = GlovoResourceIntended
	o.PrincipalMode = true
	g := refreshstoretest.NewTxGrants()
	st := refreshstoretest.NewBound(g)
	el := &fakeElig{teams: map[string][]string{tgPRN: {"alpha", "beta"}}}
	o.RefreshStore, o.TeamGrants, o.TeamEligibility, o.GlovoEnabled = st, g, el, true
	return &glovoEnv{o: o, store: st, grants: g, elig: el}
}

func challenge() string {
	h := sha256.Sum256([]byte(tgVerif))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// codeFor creates a grant for tenant and a code bound to it.
func (e *glovoEnv) codeFor(t *testing.T, tenant string) (code string, g teamgrant.Grant) {
	t.Helper()
	g, err := e.o.CreateTeamGrant(context.Background(), tgPRN, tgClient, tenant)
	if err != nil {
		t.Fatal(err)
	}
	code, err = e.o.IssueCodeForTeamGrant(context.Background(), "", tgPRN, tgClient, tgRedir, challenge(), nil, "", e.o.GlovoResource, g.ID, g.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	return code, g
}

func (e *glovoEnv) exchange(code string) (string, string, error) {
	return e.o.ExchangeCodeForResource(context.Background(), code, tgVerif, tgClient, tgRedir, ClientAssertion{}, []string{GlovoResourceIntended})
}

func TestGlovoAdmissionNeedsSwitchAndEveryDependency(t *testing.T) {
	notReady := func(o *OAuthServer) bool {
		_, err := o.ResolveResource([]string{GlovoResourceIntended})
		return errors.Is(err, ErrGlovoNotReady)
	}
	e := newGlovoEnv(t)
	if notReady(e.o) {
		t.Fatal("all dependencies present: want admitted")
	}
	for name, mutate := range map[string]func(*OAuthServer){
		"switch off":        func(o *OAuthServer) { o.GlovoEnabled = false },
		"no principal mode": func(o *OAuthServer) { o.PrincipalMode = false },
		"no eligibility":    func(o *OAuthServer) { o.TeamEligibility = nil },
		"no grant store":    func(o *OAuthServer) { o.TeamGrants = nil },
		"memory grants":     func(o *OAuthServer) { o.TeamGrants = teamgrant.NewMemoryStore() },
		"no refresh store":  func(o *OAuthServer) { o.RefreshStore = nil },
		"unbound refresh store": func(o *OAuthServer) {
			o.RefreshStore = struct{ refreshstore.Store }{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newGlovoEnv(t)
			mutate(e.o)
			if !notReady(e.o) {
				t.Fatal("admitted")
			}
			if _, err := e.o.IssueCodeForTeamGrant(context.Background(), "", tgPRN, tgClient, tgRedir, "c", nil, "", GlovoResourceIntended, "tgr_x", "alpha"); !errors.Is(err, ErrGlovoNotReady) {
				t.Fatalf("code issued: %v", err)
			}
		})
	}
	// The resource alone never opens it.
	e = newGlovoEnv(t)
	e.o.GlovoEnabled = false
	if !notReady(e.o) {
		t.Fatal("GLOVO_MCP_RESOURCE alone admitted")
	}
}

func TestGlovoCodeNeedsGrant(t *testing.T) {
	e := newGlovoEnv(t)
	if _, err := e.o.IssueCodeForTeamGrant(context.Background(), "", tgPRN, tgClient, tgRedir, "c", nil, "", e.o.GlovoResource, "", ""); err == nil {
		t.Fatal("glovo code without a grant issued")
	}
	if _, err := e.o.IssueCodeForTeamGrant(context.Background(), "", tgPRN, tgClient, tgRedir, "c", nil, "", "", "tgr_x", "alpha"); err == nil {
		t.Fatal("grant on a non-glovo code accepted")
	}
	if _, err := e.o.IssueRefreshToken("", tgPRN, nil, tgClient); err != nil {
		t.Fatal(err)
	}
}

func TestGlovoExchangeActivatesOnceAndSignsClaims(t *testing.T) {
	e := newGlovoEnv(t)
	code, g := e.codeFor(t, "alpha")
	if _, err := e.grants.Check(context.Background(), g.ID, tgPRN, tgClient, e.o.GlovoResource); !errors.Is(err, teamgrant.ErrGrantInvalid) {
		t.Fatalf("a pending grant passed Check: %v", err)
	}
	access, refresh, err := e.exchange(code)
	if err != nil {
		t.Fatal(err)
	}
	u, err := e.o.ValidateJWT(access)
	if err != nil {
		t.Fatal(err)
	}
	id, tenant, ok := u.TeamGrant()
	if !u.IsGlovoAudience() || !ok || id != g.ID || tenant != "alpha" {
		t.Fatalf("claims: %v %q %q %v", u.IsGlovoAudience(), id, tenant, ok)
	}
	if _, err := e.grants.Check(context.Background(), g.ID, tgPRN, tgClient, e.o.GlovoResource); err != nil {
		t.Fatalf("activated grant: %v", err)
	}
	if s, _ := e.store.Session(refresh); s.TeamGrantID != g.ID {
		t.Fatalf("session grant %q", s.TeamGrantID)
	}
	// T14: the same code twice yields tokens once.
	if _, _, err := e.exchange(code); err == nil {
		t.Fatal("code redeemed twice")
	}
	if e.store.Live() != 1 {
		t.Fatalf("live tokens %d", e.store.Live())
	}
}

func TestGlovoExchangeRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		prep func(e *glovoEnv, g teamgrant.Grant)
	}{
		"superseded by a newer selection": {func(e *glovoEnv, _ teamgrant.Grant) {
			if _, err := e.o.CreateTeamGrant(context.Background(), tgPRN, tgClient, "beta"); err != nil {
				panic(err)
			}
		}},
		"expired": {func(e *glovoEnv, _ teamgrant.Grant) {
			e.grants.SetClock(func() time.Time { return time.Now().Add(365 * 24 * time.Hour) })
		}},
		"revoked": {func(e *glovoEnv, g teamgrant.Grant) { _ = e.grants.Revoke(context.Background(), g.ID, "test") }},
		"fault before commit": {func(e *glovoEnv, _ teamgrant.Grant) {
			e.store.FailBind = errors.New("boom")
		}},
	} {
		t.Run(name, func(t *testing.T) {
			e := newGlovoEnv(t)
			code, g := e.codeFor(t, "alpha")
			tc.prep(e, g)
			access, refresh, err := e.exchange(code)
			if err == nil || access != "" || refresh != "" {
				t.Fatalf("exchange succeeded: %v", err)
			}
			if e.store.Live() != 0 {
				t.Fatal("a refresh token was committed")
			}
			e.grants.SetClock(time.Now)
			if _, err := e.grants.Check(context.Background(), g.ID, tgPRN, tgClient, e.o.GlovoResource); err == nil {
				t.Fatal("an active grant is left without a live family")
			}
		})
	}
}

func TestGlovoExchangeKillSwitchSpendsNothing(t *testing.T) {
	e := newGlovoEnv(t)
	code, _ := e.codeFor(t, "alpha")
	e.o.GlovoEnabled = false
	if _, _, err := e.exchange(code); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("exchange with switch off: %v", err)
	}
	if e.store.Live() != 0 {
		t.Fatal("token committed")
	}
}

func TestGlovoRefresh(t *testing.T) {
	setup := func(t *testing.T) (*glovoEnv, string, teamgrant.Grant) {
		e := newGlovoEnv(t)
		code, g := e.codeFor(t, "alpha")
		_, refresh, err := e.exchange(code)
		if err != nil {
			t.Fatal(err)
		}
		return e, refresh, g
	}
	refresh := func(e *glovoEnv, tok string, requested ...string) (string, string, error) {
		return e.o.RefreshAccessTokenForResource(context.Background(), tok, tgClient, ClientAssertion{}, requested)
	}

	t.Run("carries the same grant and tenant", func(t *testing.T) {
		e, tok, g := setup(t)
		access, next, err := refresh(e, tok)
		if err != nil {
			t.Fatal(err)
		}
		u, err := e.o.ValidateJWT(access)
		if err != nil {
			t.Fatal(err)
		}
		if id, tenant, _ := u.TeamGrant(); id != g.ID || tenant != "alpha" {
			t.Fatalf("%q %q", id, tenant)
		}
		if s, _ := e.store.Session(next); s.TeamGrantID != g.ID {
			t.Fatal("grant not carried")
		}
	})
	t.Run("lost membership revokes grant then family, nothing minted", func(t *testing.T) {
		e, tok, g := setup(t)
		e.elig.teams[tgPRN] = []string{"beta"}
		access, next, err := refresh(e, tok)
		if !errors.Is(err, ErrTeamGrantInvalid) || access != "" || next != "" {
			t.Fatalf("%v", err)
		}
		if _, err := e.grants.Check(context.Background(), g.ID, tgPRN, tgClient, e.o.GlovoResource); err == nil {
			t.Fatal("grant still active")
		}
		if e.store.Live() != 0 {
			t.Fatal("family still live")
		}
		if ev := e.store.Events; len(ev) != 2 || ev[0] != "revoke-grant" || ev[1] != "revoke-family" {
			t.Fatalf("order %v", ev)
		}
	})
	t.Run("revoked grant ends the family", func(t *testing.T) {
		e, tok, g := setup(t)
		_ = e.grants.Revoke(context.Background(), g.ID, "test")
		if _, _, err := refresh(e, tok); !errors.Is(err, ErrTeamGrantInvalid) {
			t.Fatalf("%v", err)
		}
		if e.store.Live() != 0 {
			t.Fatal("family still live")
		}
	})
	t.Run("a store failure spends nothing and revokes nothing", func(t *testing.T) {
		e, tok, g := setup(t)
		e.elig.err = errors.New("membership unreadable")
		if _, _, err := refresh(e, tok); !errors.Is(err, ErrServerError) {
			t.Fatalf("%v", err)
		}
		e.elig.err = nil
		if e.store.Live() != 1 || len(e.store.Events) != 0 {
			t.Fatal("token spent or revoked")
		}
		e.grants.Err = errors.New("down")
		if _, _, err := refresh(e, tok); !errors.Is(err, ErrServerError) {
			t.Fatalf("grant store down: %v", err)
		}
		e.grants.Err = nil
		if _, err := e.grants.Check(context.Background(), g.ID, tgPRN, tgClient, e.o.GlovoResource); err != nil {
			t.Fatal("grant revoked by an outage")
		}
		if _, _, err := refresh(e, tok); err != nil {
			t.Fatalf("token spent by an outage: %v", err)
		}
	})
	t.Run("kill switch refuses without spending", func(t *testing.T) {
		e, tok, _ := setup(t)
		e.o.GlovoEnabled = false
		if _, _, err := refresh(e, tok); !errors.Is(err, ErrInvalidTarget) {
			t.Fatalf("%v", err)
		}
		if e.store.Live() != 1 {
			t.Fatal("token spent")
		}
	})
	t.Run("a glovo session with no grant is refused", func(t *testing.T) {
		e := newGlovoEnv(t)
		if err := e.store.Insert("legacy", tgClient, refreshstore.Session{PrincipalID: tgPRN, Resource: e.o.GlovoResource}, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := refresh(e, "legacy"); !errors.Is(err, ErrTeamGrantInvalid) {
			t.Fatalf("%v", err)
		}
	})
}

func TestGlovoRevocationOrderAndFailure(t *testing.T) {
	e := newGlovoEnv(t)
	code, g := e.codeFor(t, "alpha")
	_, tok, err := e.exchange(code)
	if err != nil {
		t.Fatal(err)
	}
	e.store.FailRevoke = errors.New("db down")
	if err := e.o.RevokeRefreshToken(tok, tgClient); !errors.Is(err, ErrServerError) {
		t.Fatalf("a failed revoke reported success: %v", err)
	}
	if e.store.Live() != 1 {
		t.Fatal("revoked despite failure")
	}
	e.store.FailRevoke = nil
	if err := e.o.RevokeRefreshToken(tok, tgClient); err != nil {
		t.Fatal(err)
	}
	if ev := e.store.Events; len(ev) != 2 || ev[0] != "revoke-grant" {
		t.Fatalf("order %v", ev)
	}
	if _, err := e.grants.Check(context.Background(), g.ID, tgPRN, tgClient, e.o.GlovoResource); err == nil {
		t.Fatal("grant survived revoke")
	}

	code, g = e.codeFor(t, "beta")
	if _, _, err := e.exchange(code); err != nil {
		t.Fatal(err)
	}
	e.store.Events = nil
	if n, err := e.o.RevokePrincipalSessions(tgPRN, "unlink"); err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
	if ev := e.store.Events; len(ev) != 2 || ev[0] != "revoke-grant" {
		t.Fatalf("order %v", ev)
	}
	if _, err := e.grants.Check(context.Background(), g.ID, tgPRN, tgClient, e.o.GlovoResource); err == nil {
		t.Fatal("grant survived principal revoke")
	}
}

func TestTeamClaimsOnlyOnGlovoAudience(t *testing.T) {
	e := newGlovoEnv(t)
	o := e.o
	forge := func(aud audience) *User {
		tok, err := signJWT(jwtPayload{Issuer: o.BaseURL, Subject: "alice", PID: tgPRN, Audience: aud,
			TeamGrant: "tgr_forged", SelectedTenant: "alpha", ExpiresAt: time.Now().Add(time.Hour).Unix()}, o.JWTSecret)
		if err != nil {
			t.Fatal(err)
		}
		u, err := o.ValidateJWT(tok)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	if _, _, ok := forge(audience{o.BaseURL}).TeamGrant(); ok {
		t.Fatal("tgr/stn honoured on an API token")
	}
	if _, _, ok := forge(audience{testSupportRes}).TeamGrant(); ok {
		t.Fatal("tgr/stn honoured on a support token")
	}
	if id, tn, ok := forge(audience{GlovoResourceIntended}).TeamGrant(); !ok || id != "tgr_forged" || tn != "alpha" {
		t.Fatal("claims not read on the glovo audience")
	}
	// Minting never signs them for another audience.
	for _, aud := range []string{o.BaseURL, testSupportRes} {
		tok, err := o.issueJWTWithGrant("alice", tgPRN, nil, aud, tgClient, "tgr_x", "alpha")
		if err != nil {
			t.Fatal(err)
		}
		p, err := o.verifyAccessToken(tok)
		if err != nil || p.TeamGrant != "" || p.SelectedTenant != "" {
			t.Fatalf("claims minted for %s: %v", aud, err)
		}
	}
	// A Glovo token without both claims has no grant.
	if _, _, ok := (&User{glovoAudience: true, teamGrantID: "tgr_x"}).TeamGrant(); ok {
		t.Fatal("grant without a tenant")
	}
}
