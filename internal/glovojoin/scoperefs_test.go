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

package glovojoin

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/glovo"
)

func scopeSubject(exp time.Time) Subject {
	return Subject{PrincipalID: subjPrincipal, Tenant: "acme", GrantID: "tgr_1", FamilyID: "fam_1",
		InstallID: "gin_abc", InstallRevision: 3, ExpiresAt: exp}
}

func TestScopeRefsIssueAndValidate(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	now := time.Now()
	s := &ScopeRefs{DB: e.rp, Now: func() time.Time { return now }}
	sub := scopeSubject(now.Add(time.Hour))
	ref, exp, err := s.Issue(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	if !scopeRefRE.MatchString(ref) || len(ref) != 36 {
		t.Fatalf("ref shape %q", ref)
	}
	if d := exp.Sub(now); d <= 0 || d > ScopeRefTTL {
		t.Fatalf("ttl %s", d)
	}
	if r := s.Validate(ctx, ref, sub); r != nil {
		t.Fatalf("a fresh ref was refused: %v", r)
	}
	// Only the hash is stored: the plaintext is nowhere in the table.
	var n int
	if err := e.rp.QueryRow(ctx, `SELECT count(*) FROM glovo.join_scope_refs WHERE ref_hash = $1 OR principal_id = $1 OR tenant = $1`, ref).Scan(&n); err != nil || n != 0 {
		t.Fatalf("plaintext ref reachable in the table: %d, %v", n, err)
	}
	var hash string
	if err := e.rp.QueryRow(ctx, `SELECT ref_hash FROM glovo.join_scope_refs`).Scan(&hash); err != nil || hash != refHash(ref) || strings.Contains(hash, ref) {
		t.Fatalf("stored hash %q, %v", hash, err)
	}
	// Two refs for one subject are distinct (192 bits from crypto/rand).
	ref2, _, err := s.Issue(ctx, sub)
	if err != nil || ref2 == ref {
		t.Fatalf("second ref %q, %v", ref2, err)
	}
}

func TestScopeRefTTLIsMinOfFiveMinutesAndTokenExp(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	now := time.Now()
	s := &ScopeRefs{DB: e.rp, Now: func() time.Time { return now }}
	_, exp, err := s.Issue(ctx, scopeSubject(now.Add(90*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	if d := exp.Sub(now); d < 89*time.Second || d > 90*time.Second {
		t.Fatalf("a short token gave ttl %s, want about 90s", d)
	}
	_, exp, err = s.Issue(ctx, scopeSubject(now.Add(24*time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if d := exp.Sub(now); d < 299*time.Second || d > 300*time.Second {
		t.Fatalf("a long token gave ttl %s, want 5m", d)
	}
	if _, _, err := s.Issue(ctx, scopeSubject(now.Add(-time.Second))); err == nil {
		t.Fatal("a ref was issued against an expired token")
	}
}

func TestScopeRefValidationRefusals(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	now := time.Now()
	clock := now
	s := &ScopeRefs{DB: e.rp, Now: func() time.Time { return clock }}
	sub := scopeSubject(now.Add(time.Hour))
	ref, _, err := s.Issue(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	wrong := func(mut func(*Subject)) Subject { c := sub; mut(&c); return c }
	for name, c := range map[string]struct {
		ref  string
		sub  Subject
		code glovo.Code
		why  string
	}{
		"other principal": {ref, wrong(func(s *Subject) { s.PrincipalID = "prn_ffffffffffffffff" }), glovo.CodeNotAuthorized, "scope_ref_invalid"},
		"other tenant":    {ref, wrong(func(s *Subject) { s.Tenant = "other" }), glovo.CodeNotAuthorized, "scope_ref_invalid"},
		"other family":    {ref, wrong(func(s *Subject) { s.FamilyID = "fam_2" }), glovo.CodeNotAuthorized, "scope_ref_invalid"},
		"other install":   {ref, wrong(func(s *Subject) { s.InstallID = "gin_other" }), glovo.CodeNotAuthorized, "scope_ref_invalid"},
		"stale revision":  {ref, wrong(func(s *Subject) { s.InstallRevision = 4 }), glovo.CodeStaleInstall, "scope_ref_stale"},
		"unknown":         {"gsc_" + strings.Repeat("A", 32), sub, glovo.CodeNotAuthorized, "scope_ref_invalid"},
		"malformed":       {"gsc_short", sub, glovo.CodeNotAuthorized, "scope_ref_invalid"},
		"empty":           {"", sub, glovo.CodeNotAuthorized, "scope_ref_invalid"},
		"wrong prefix":    {"xxx_" + ref[4:], sub, glovo.CodeNotAuthorized, "scope_ref_invalid"},
	} {
		r := s.Validate(ctx, c.ref, c.sub)
		if r == nil || r.Err.Code != c.code || r.Reason != c.why || r.Unauthenticated {
			t.Errorf("%s: %+v, want %s %s", name, r, c.code, c.why)
		}
	}
	// Expiry is refused on read, with no sweep needed.
	clock = now.Add(ScopeRefTTL + time.Second)
	if r := s.Validate(ctx, ref, sub); r == nil || r.Err.Code != glovo.CodeNotAuthorized || r.Reason != "scope_ref_invalid" {
		t.Fatalf("an expired ref = %+v", r)
	}
}

// A failed read is unavailable, never "unknown ref".
func TestScopeRefFailedReadIsUnavailable(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	now := time.Now()
	s := &ScopeRefs{DB: e.rp, Now: func() time.Time { return now }}
	sub := scopeSubject(now.Add(time.Hour))
	ref, _, err := s.Issue(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, e.mp, `DROP TABLE glovo.join_scope_refs`)
	if r := s.Validate(ctx, ref, sub); r == nil || r.Err.Code != glovo.CodeUnavailable {
		t.Fatalf("a missing table = %+v", r)
	}
	if _, _, err := s.Issue(ctx, sub); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("issue on a missing table = %v", err)
	}
}

func TestScopeRefSweepIsBounded(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	now := time.Now()
	clock := now
	s := &ScopeRefs{DB: e.rp, Now: func() time.Time { return clock }}
	for i := 0; i < 5; i++ {
		if _, _, err := s.Issue(ctx, scopeSubject(now.Add(time.Hour))); err != nil {
			t.Fatal(err)
		}
	}
	clock = now.Add(ScopeRefTTL + time.Minute)
	if n, err := s.Sweep(ctx, 3); err != nil || n != 3 {
		t.Fatalf("first sweep = %d, %v", n, err)
	}
	if n, err := s.Sweep(ctx, 3); err != nil || n != 2 {
		t.Fatalf("second sweep = %d, %v", n, err)
	}
}
