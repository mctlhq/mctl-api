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

package contract

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// must unwraps a (value, error) pair; a test setup error is a bug, so it panics.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func schedKey(au string, at time.Time) string {
	return must(OccurrenceKey(au, "at", must(ScheduledSource(at))))
}

func eventKey(au, kind, prod, typ, id string) string {
	return must(OccurrenceKey(au, kind, must(EventSource(prod, typ, id))))
}

func TestOccurrenceKeys(t *testing.T) {
	at := time.Date(2026, 12, 1, 10, 0, 0, 0, time.UTC)
	a := schedKey("au_1", at)
	if a != schedKey("au_1", at.In(time.FixedZone("x", 3600))) {
		t.Fatal("key must be zone independent")
	}
	if !strings.HasPrefix(a, "occ_") || len(a) != 36 {
		t.Fatalf("bad key %q", a)
	}
	b := schedKey("au_1", at.Add(time.Minute))
	if a == b || ExternalKey("au_1", a) == ExternalKey("au_1", b) || FireIdempotencyKey(a) == FireIdempotencyKey(b) {
		t.Fatal("overlapping occurrences must differ")
	}
	if ExternalKey("au_1", a) != "automation:au_1:"+a || FireIdempotencyKey(a) != "automation-fire:"+a {
		t.Fatal("derivation unstable")
	}
}

// T2: the key depends only on (producer, type, stable id), never a delivery id.
func TestEventKeyIgnoresDelivery(t *testing.T) {
	if eventKey("au_1", "event", "github", "check_run", "evt-9") != eventKey("au_1", "event", "github", "check_run", "evt-9") {
		t.Fatal("same stable producer event id must give one key")
	}
}

// T3.
func TestOccurrenceDisambiguation(t *testing.T) {
	base := eventKey("au_1", "event", "github", "check_run", "x")
	if base == eventKey("au_1", "event", "gitlab", "check_run", "x") ||
		base == eventKey("au_1", "event", "github", "workflow_run", "x") {
		t.Fatal("producer and type must separate keys")
	}
	if eventKey("au_1", "event", "a|b", "c", "x") == eventKey("au_1", "event", "a", "b|c", "x") {
		t.Fatal("length prefix must prevent collisions")
	}
	ev := must(EventSource("x", "x", "x"))
	man := must(ManualSource("x", "x", "x"))
	if must(OccurrenceKey("au_1", "event", ev)) == must(OccurrenceKey("au_1", "event", man)) {
		t.Fatal("event and manual sources must differ")
	}
	for i, f := range []func() error{
		func() error { _, e := EventSource("", "t", "i"); return e },
		func() error { _, e := EventSource("p", "", "i"); return e },
		func() error { _, e := EventSource("p", "t", ""); return e },
		func() error { _, e := ManualSource("p", "", "k"); return e },
		func() error { _, e := ScheduledSource(time.Time{}); return e },
		func() error { _, e := OccurrenceKey("", "at", ev); return e },
		func() error { _, e := OccurrenceKey("au_1", "at", OccurrenceSource{}); return e },
	} {
		if CodeOf(f()) != CodeInvalid {
			t.Fatalf("case %d: empty part must be automation_invalid", i)
		}
	}
}

func claimReq(tenant, au, key, hash string, ver int) ClaimRequest {
	return ClaimRequest{ClaimKey: ClaimKey{tenant, au, key}, RequestHash: hash, AdmittedVersion: ver}
}

type minter struct{ n atomic.Int32 }

func (m *minter) mint() (string, error) { m.n.Add(1); return "wi_1", nil }

// T1.
func TestReplayAcrossDefinitionVersion(t *testing.T) {
	var s ClaimStore
	var m minter
	key := schedKey("au_1", time.Date(2026, 12, 1, 10, 0, 0, 0, time.UTC))
	r1 := must(s.Claim(claimReq("t", "au_1", key, "h", 1), m.mint))
	r2 := must(s.Claim(claimReq("t", "au_1", key, "h", 2), m.mint))
	if r1.Replayed || !r2.Replayed || r2.WorkItemID != "wi_1" || r2.AdmittedVersion != 1 || m.n.Load() != 1 {
		t.Fatalf("r1=%+v r2=%+v mints=%d", r1, r2, m.n.Load())
	}
}

// T4.
func TestTombstoneReplay(t *testing.T) {
	var s ClaimStore
	var m minter
	k := ClaimKey{"t", "au_1", "occ_1"}
	now := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	must(s.Claim(claimReq("t", "au_1", "occ_1", "h", 1), m.mint))
	s.Close(k, now)
	s.Cleanup(now.Add(time.Hour), DefaultTombstoneHorizon)
	if st, _ := s.Status(k); st != ClaimTombstoned {
		t.Fatalf("status = %s", st)
	}
	r := must(s.Claim(claimReq("t", "au_1", "occ_1", "h", 1), m.mint))
	if !r.Replayed || m.n.Load() != 1 {
		t.Fatalf("replay inside horizon: %+v mints=%d", r, m.n.Load())
	}
	// Past the horizon the tombstone is dropped and the replay is a new occurrence.
	s.Cleanup(now.Add(DefaultTombstoneHorizon+time.Hour), DefaultTombstoneHorizon)
	if _, ok := s.Status(k); ok {
		t.Fatal("tombstone must be dropped after the horizon")
	}
	r = must(s.Claim(claimReq("t", "au_1", "occ_1", "h", 1), m.mint))
	if r.Replayed || m.n.Load() != 2 {
		t.Fatalf("replay after horizon: %+v mints=%d", r, m.n.Load())
	}
}

// T5.
func TestCrashReconcile(t *testing.T) {
	k := ClaimKey{"t", "au_1", "occ_1"}
	crash := func() *ClaimStore {
		s := &ClaimStore{}
		_, err := s.Claim(claimReq("t", "au_1", "occ_1", "h", 1), func() (string, error) { return "", errors.New("crash") })
		if CodeOf(err) != CodeAuthorityUnavailable {
			t.Fatalf("crash claim: %v", err)
		}
		return s
	}
	var m minter
	s := crash()
	if err := s.Reconcile(k, func() (string, bool, error) { return "wi_9", true, nil }); err != nil {
		t.Fatal(err)
	}
	if r := must(s.Claim(claimReq("t", "au_1", "occ_1", "h", 1), m.mint)); !r.Replayed || r.WorkItemID != "wi_9" {
		t.Fatalf("found: %+v", r)
	}
	s = crash()
	if err := s.Reconcile(k, func() (string, bool, error) { return "", false, nil }); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.Status(k); st != ClaimFailed {
		t.Fatalf("not found: status %s", st)
	}
	s = crash()
	if CodeOf(s.Reconcile(k, func() (string, bool, error) { return "", false, errors.New("down") })) != CodeAuthorityUnavailable {
		t.Fatal("lookup error must be unavailable")
	}
	if st, _ := s.Status(k); st != ClaimClaimed {
		t.Fatalf("lookup error: status %s", st)
	}
	if m.n.Load() != 0 {
		t.Fatal("reconciliation must never mint")
	}
}

// T6.
func TestClaimConflict(t *testing.T) {
	var s ClaimStore
	var m minter
	must(s.Claim(claimReq("t", "au_1", "occ_1", "h", 1), m.mint))
	for name, req := range map[string]ClaimRequest{
		"hash": claimReq("t", "au_1", "occ_1", "other", 1),
	} {
		if CodeOf(errOnly(s.Claim(req, m.mint))) != CodeOccurrenceConflict {
			t.Errorf("%s: not a conflict", name)
		}
	}
	// A different tenant or au_ is a different claim key, never a replay.
	if r := must(s.Claim(claimReq("t2", "au_1", "occ_1", "h", 1), m.mint)); r.Replayed {
		t.Fatal("different tenant must not replay")
	}
	if CodeOccurrenceConflict.HTTPStatus() != 409 {
		t.Fatal("conflict must be 409")
	}
	if m.n.Load() != 2 {
		t.Fatalf("mints = %d", m.n.Load())
	}
}

func errOnly[T any](_ T, err error) error { return err }

func TestClaimUnavailableMintsNothing(t *testing.T) {
	var s ClaimStore
	var m minter
	req := claimReq("t", "au_1", "occ_1", "h", 1)
	req.Unavailable = true
	if CodeOf(errOnly(s.Claim(req, m.mint))) != CodeAuthorityUnavailable || m.n.Load() != 0 {
		t.Fatal("unavailable source must fail closed")
	}
}

// T7 (run under -race).
func TestClaimRace(t *testing.T) {
	var s ClaimStore
	var m minter
	var replayed atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := s.Claim(claimReq("t", "au_1", "occ_1", "h", 1), m.mint)
			if err != nil {
				t.Error(err)
			}
			if r.Replayed {
				replayed.Add(1)
			}
		}()
	}
	wg.Wait()
	if m.n.Load() != 1 || replayed.Load() != 31 {
		t.Fatalf("mints=%d replayed=%d", m.n.Load(), replayed.Load())
	}
}

// T8.
func TestManualRun(t *testing.T) {
	var m ManualRequests
	body := []byte(`{"idempotency_key":"k1"}`)
	r1 := must(m.Submit("p", "t", "au_1", body))
	r2 := must(m.Submit("p", "t", "au_1", body))
	if r1.Replayed || !r2.Replayed || r1.OccurrenceKey != r2.OccurrenceKey {
		t.Fatalf("%+v %+v", r1, r2)
	}
	other := []byte(`{"idempotency_key":"k1","schema_version":"automation/v1"}`)
	if CodeOf(errOnly(m.Submit("p", "t", "au_1", other))) != CodeIdempotencyKeyReused {
		t.Fatal("different body must be key reuse")
	}
	for _, c := range [][3]string{{"p2", "t", "au_1"}, {"p", "t2", "au_1"}, {"p", "t", "au_2"}} {
		r := must(m.Submit(c[0], c[1], c[2], body))
		if r.Replayed || r.OccurrenceKey == r1.OccurrenceKey {
			t.Fatalf("%v collides with the first occurrence", c)
		}
	}
	if CodeOf(ExecuteManual(r1)) != CodeTriggerUnsupported {
		t.Fatal("manual execution must be unsupported")
	}
	if CodeOf(errOnly(m.Submit("p", "t", "au_1", []byte(`{"idempotency_key":"k","occurrence_key":"occ_x"}`)))) != CodeServerOwnedField {
		t.Fatal("spoofed occurrence_key")
	}
}

// T9.
func TestCheckSupportFire(t *testing.T) {
	now := time.Date(2026, 12, 1, 10, 0, 0, 0, time.UTC)
	ok := SupportFireInputs{ConsentLive: true, ConsentVerified: true, TokenMintedForFire: true,
		TokenTTL: time.Hour, TokenExpiresAt: now.Add(time.Hour), Now: now}
	if err := CheckSupportFire(ok); err != nil {
		t.Fatal(err)
	}
	muts := map[string]func(*SupportFireInputs){
		"expired":          func(i *SupportFireInputs) { i.TokenExpiresAt = now },
		"ttl over 1h":      func(i *SupportFireInputs) { i.TokenTTL = time.Hour + time.Second },
		"self minted":      func(i *SupportFireInputs) { i.TokenSelfMinted = true },
		"not for fire":     func(i *SupportFireInputs) { i.TokenMintedForFire = false },
		"consent not live": func(i *SupportFireInputs) { i.ConsentLive = false },
		"not verified":     func(i *SupportFireInputs) { i.ConsentVerified = false },
		"auth_ref":         func(i *SupportFireInputs) { i.AuthRef = "r" },
	}
	for n, m := range muts {
		in := ok
		m(&in)
		if CodeOf(CheckSupportFire(in)) != CodeSupportConstraint {
			t.Errorf("%s not refused", n)
		}
	}
	// A 24h definition TTL passes the definition check and still needs a 1h token.
	def := SupportInputs{OwnerAuthorized: true, TenantBound: true, Scope: ScopeSupport, TTL: SupportMaxTTL, MaxFires: 1}
	if err := CheckSupport(def); err != nil {
		t.Fatal(err)
	}
	if SupportTokenMaxTTL != time.Hour {
		t.Fatal("support token max ttl must stay 1h")
	}
}

// T10.
func TestSupportRegisteredNotEnabled(t *testing.T) {
	if _, ok := LookupTemplate("support.diagnostic-followup.v1"); !ok {
		t.Fatal("support template must stay registered")
	}
	if TemplateEnabled("support.diagnostic-followup.v1", "at") || !TemplateEnabled("reminder.v1", "at") {
		t.Fatal("enabled allowlist wrong")
	}
}

// T12.
func TestAntiOracle(t *testing.T) {
	for mask := 0; mask < 8; mask++ {
		in := liveInputs()
		in.Link = LinkUnlinked
		in.TargetExists, in.OwnerMatches, in.TenantAccessible = mask&1 != 0, mask&2 != 0, mask&4 != 0
		if d := Decide(CheckpointFire, in); d.Code != CodeIdentityUnlinked {
			t.Errorf("mask %d: %+v", mask, d)
		}
	}
	var bodies [][]byte
	for _, mut := range []func(*Inputs){
		func(i *Inputs) { i.TargetExists = false },
		func(i *Inputs) { i.OwnerMatches = false },
		func(i *Inputs) { i.TenantAccessible = false },
	} {
		in := liveInputs()
		mut(&in)
		d := Decide(CheckpointFire, in)
		if d.Code != CodeNotFound || d.Code.HTTPStatus() != 404 {
			t.Fatalf("%+v", d)
		}
		bodies = append(bodies, ErrorBody(d.Code))
	}
	if !bytes.Equal(bodies[0], bodies[1]) || !bytes.Equal(bodies[1], bodies[2]) {
		t.Fatal("404 bodies must be byte-identical")
	}
}

// T13.
func TestToolchainTimeAndLoopVars(t *testing.T) {
	for _, in := range []string{"2026-12-01T10:00:00.5Z", "2026-12-01T10:00:00.123456789+02:00", "2026-12-01T10:00:00.1234567891Z"} {
		if _, err := time.Parse(time.RFC3339, in); err != nil {
			t.Errorf("%s: %v", in, err)
		}
	}
	var fs []func() int
	for i := range 3 {
		fs = append(fs, func() int { return i })
	}
	for i, f := range fs {
		if f() != i {
			t.Fatalf("loop variable shared across iterations: %d != %d", f(), i)
		}
	}
}

// T14.
func TestGMTFamilyZones(t *testing.T) {
	for _, z := range []string{"Etc/GMT+5", "Etc/GMT-14", "Etc/GMT0", "GMT0", "GMT+0", "Etc/GMT+2"} {
		if c := CodeOf(errOf(ResolveAt("2026-12-01T09:00:00", z, "reject", "reject"))); c != CodeInvalid {
			t.Errorf("zone %q = %q", z, c)
		}
	}
	for _, z := range []string{"UTC", "Etc/UTC", "GMT", "Etc/GMT", "America/New_York"} {
		if _, err := ResolveAt("2026-12-01T09:00:00", z, "reject", "reject"); err != nil {
			t.Errorf("zone %q: %v", z, err)
		}
	}
}
