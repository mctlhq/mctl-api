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

package teamgrant

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	prn = "prn_01JBBBBBBBBBBBBBBBBBBBBBBB"
	cl  = "client-1"
	res = "https://glovo.mctl.ai/mcp"
)

func newGrant(t *testing.T, m *MemoryStore, tenant string) Grant {
	t.Helper()
	g, err := m.Create(context.Background(), Grant{PrincipalID: prn, Tenant: tenant, ClientID: cl, Resource: res, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(g.ID, IDPrefix) || g.State != StatePending {
		t.Fatalf("%+v", g)
	}
	return g
}

func TestPendingNeverChecks(t *testing.T) {
	m := NewMemoryStore()
	g := newGrant(t, m, "alpha")
	if _, err := m.Check(context.Background(), g.ID, prn, cl, res); !errors.Is(err, ErrGrantInvalid) {
		t.Fatalf("pending grant passed Check: %v", err)
	}
	if err := m.Activate(g.ID, prn, cl, res, "fam"); err != nil {
		t.Fatal(err)
	}
	got, err := m.Check(context.Background(), g.ID, prn, cl, res)
	if err != nil || got.Tenant != "alpha" || got.RefreshFamilyID != "fam" {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestSupersedeOnCreate(t *testing.T) {
	m := NewMemoryStore()
	a := newGrant(t, m, "alpha")
	_ = m.Activate(a.ID, prn, cl, res, "fam")
	b := newGrant(t, m, "beta")
	if _, err := m.Check(context.Background(), a.ID, prn, cl, res); !errors.Is(err, ErrGrantInvalid) {
		t.Fatalf("superseded grant still valid: %v", err)
	}
	if err := m.Activate(b.ID, prn, cl, res, "fam2"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Check(context.Background(), b.ID, prn, cl, res); err != nil {
		t.Fatal(err)
	}
}

func TestMismatchExpiryAndRevoke(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryStore()
	g := newGrant(t, m, "alpha")
	_ = m.Activate(g.ID, prn, cl, res, "fam")
	for name, args := range map[string][4]string{
		"principal": {g.ID, "prn_01JCCCCCCCCCCCCCCCCCCCCCCC", cl, res},
		"client":    {g.ID, prn, "other", res},
		"resource":  {g.ID, prn, cl, "https://x.example"},
		"unknown":   {"tgr_nope", prn, cl, res},
	} {
		if _, err := m.Check(ctx, args[0], args[1], args[2], args[3]); !errors.Is(err, ErrGrantInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	m.SetClock(func() time.Time { return time.Now().Add(2 * time.Hour) })
	if _, err := m.Check(ctx, g.ID, prn, cl, res); !errors.Is(err, ErrGrantInvalid) {
		t.Fatalf("expired: %v", err)
	}
	m.SetClock(time.Now)
	if err := m.RevokeByFamily(ctx, "fam", "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Check(ctx, g.ID, prn, cl, res); !errors.Is(err, ErrGrantInvalid) {
		t.Fatalf("revoked by family: %v", err)
	}
	h := newGrant(t, m, "beta")
	_ = m.Activate(h.ID, prn, cl, res, "fam3")
	if err := m.RevokeByPrincipal(ctx, prn, "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Check(ctx, h.ID, prn, cl, res); !errors.Is(err, ErrGrantInvalid) {
		t.Fatalf("revoked by principal: %v", err)
	}
}

func TestOutageIsNotInvalid(t *testing.T) {
	m := NewMemoryStore()
	m.Err = errors.New("down")
	_, err := m.Check(context.Background(), "tgr_x", prn, cl, res)
	if err == nil || errors.Is(err, ErrGrantInvalid) {
		t.Fatalf("an outage must not read as an invalid grant: %v", err)
	}
}

func TestCreateValidates(t *testing.T) {
	m := NewMemoryStore()
	for _, g := range []Grant{
		{Tenant: "a", Resource: res, ExpiresAt: time.Now()},
		{PrincipalID: prn, Resource: res, ExpiresAt: time.Now()},
		{PrincipalID: prn, Tenant: "a", ExpiresAt: time.Now()},
		{PrincipalID: prn, Tenant: "a", Resource: res},
	} {
		if _, err := m.Create(context.Background(), g); err == nil {
			t.Errorf("accepted %+v", g)
		}
	}
}
