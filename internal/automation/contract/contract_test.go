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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFixtures(t *testing.T) {
	raw, err := os.ReadFile("testdata/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var man []struct{ File, Kind, Code, Template string }
	if err := json.Unmarshal(raw, &man); err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, m := range man {
		listed[m.File] = true
		t.Run(m.File, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join("testdata", m.File))
			if err != nil {
				t.Fatal(err)
			}
			var verr error
			switch m.Kind {
			case "create":
				verr = ValidateCreate(body)
			case "patch":
				tmplID := m.Template
				if tmplID == "" {
					tmplID = "reminder.v1"
				}
				tmpl, ok := LookupTemplate(tmplID)
				if !ok {
					t.Fatalf("unknown template %q", tmplID)
				}
				verr = ValidatePatch(body, tmpl)
			case "definition":
				verr = ValidateDefinition(body)
			case "run":
				verr = ValidateRun(body)
			default:
				t.Fatalf("unknown kind %q", m.Kind)
			}
			if got := CodeOf(verr); got != Code(m.Code) {
				t.Fatalf("code = %q (err %v), want %q", got, verr, m.Code)
			}
			if m.Code == "" && verr != nil {
				t.Fatalf("valid fixture failed: %v", verr)
			}
		})
	}
	for _, dir := range []string{"valid", "invalid"} {
		files, err := filepath.Glob("testdata/" + dir + "/*.json")
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if !listed[strings.TrimPrefix(filepath.ToSlash(f), "testdata/")] {
				t.Errorf("fixture %s missing from manifest", f)
			}
		}
	}
}

func TestReminderTextLimit(t *testing.T) {
	mk := func(n int) []byte {
		return []byte(`{"idempotency_key":"k","template_id":"reminder.v1","params":{"text":"` + strings.Repeat("a", n) + `"},"trigger":{"kind":"at","instant":"2026-12-01T10:00:00Z"}}`)
	}
	if err := ValidateCreate(mk(2048)); err != nil {
		t.Fatalf("2048 bytes: %v", err)
	}
	if got := CodeOf(ValidateCreate(mk(2049))); got != CodeInvalid {
		t.Fatalf("2049 bytes: %q", got)
	}
}

func TestErrorVocabularyMatchesSchema(t *testing.T) {
	for _, c := range Codes() {
		body := ErrorBody(c)
		s, err := schema("automation-error.schema.json")
		if err != nil {
			t.Fatal(err)
		}
		var v any
		_ = json.Unmarshal(body, &v)
		if err := s.Validate(v); err != nil {
			t.Errorf("%s not in schema enum: %v", c, err)
		}
		if c.HTTPStatus() == 0 {
			t.Errorf("%s has no status", c)
		}
	}
	if len(Codes()) != 18 {
		t.Fatalf("vocabulary size = %d", len(Codes()))
	}
}

func TestResolveAtDST(t *testing.T) {
	got, err := ResolveAt("2026-03-08T02:30:00", "America/New_York", "shift_forward", "reject")
	if err != nil {
		t.Fatal(err)
	}
	ny, _ := time.LoadLocation("America/New_York")
	if w := got.In(ny).Format("15:04 MST"); w != "03:30 EDT" {
		t.Fatalf("gap shift = %s", w)
	}
	if c := CodeOf(errOf(ResolveAt("2026-03-08T02:30:00", "America/New_York", "reject", "reject"))); c != CodeTimeAmbiguous {
		t.Fatalf("gap reject = %q", c)
	}
	e, _ := ResolveAt("2026-10-25T02:30:00", "Europe/Berlin", "reject", "earlier")
	l, _ := ResolveAt("2026-10-25T02:30:00", "Europe/Berlin", "reject", "later")
	if !e.Before(l) || l.Sub(e) != time.Hour {
		t.Fatalf("fold earlier=%s later=%s", e, l)
	}
	if c := CodeOf(errOf(ResolveAt("2026-10-25T02:30:00", "Europe/Berlin", "reject", "reject"))); c != CodeTimeAmbiguous {
		t.Fatalf("fold reject = %q", c)
	}
	for _, z := range []string{"Mars/Base", "+02:00", "UTC+2", "", "Local"} {
		if c := CodeOf(errOf(ResolveAt("2026-12-01T09:00:00", z, "reject", "reject"))); c != CodeInvalid {
			t.Errorf("zone %q = %q", z, c)
		}
	}
	if _, err := ResolveAt("2026-12-01T09:00:00", "Europe/Berlin", "reject", "reject"); err != nil {
		t.Fatalf("plain time: %v", err)
	}
}

func errOf(_ time.Time, err error) error { return err }

func TestOccurrenceKeys(t *testing.T) {
	at := time.Date(2026, 12, 1, 10, 0, 0, 0, time.UTC)
	a := OccurrenceKeyAt("au_1", 1, "at", at)
	if a != OccurrenceKeyAt("au_1", 1, "at", at.In(time.FixedZone("x", 3600))) {
		t.Fatal("key must be zone independent")
	}
	if !strings.HasPrefix(a, "occ_") || len(a) != 36 {
		t.Fatalf("bad key %q", a)
	}
	b := OccurrenceKeyAt("au_1", 1, "at", at.Add(time.Minute))
	if a == b || ExternalKey("au_1", a) == ExternalKey("au_1", b) || FireIdempotencyKey(a) == FireIdempotencyKey(b) {
		t.Fatal("overlapping occurrences must differ")
	}
	if FireIdempotencyKey(a) != FireIdempotencyKey(OccurrenceKeyAt("au_1", 1, "at", at)) || ExternalKey("au_1", a) != "automation:au_1:"+a {
		t.Fatal("derivation unstable")
	}
	var s OccurrenceSet
	if err := s.Claim(a); err != nil {
		t.Fatal(err)
	}
	if CodeOf(s.Claim(a)) != CodeOccurrenceDuplicate {
		t.Fatal("second delivery must be a replay")
	}
}

func liveInputs() Inputs {
	return Inputs{
		Link: LinkLive, Install: InstallLive, SurfaceMatches: true, TenantMember: true,
		TargetExists: true, TenantAccessible: true, OwnerMatches: true,
		PinnedPolicyVersion: "p1", LivePolicyVersion: "p1",
		BudgetNeeded: 1, HeadroomPerRun: 5, HeadroomPerDay: 5, HeadroomPerTenant: 5,
		ThisExecutionID: "we_1",
	}
}

func TestDecide(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Inputs)
		cp   Checkpoint
		want Code
	}{
		{"allowed", func(*Inputs) {}, CheckpointFire, ""},
		{"zero value denied", func(i *Inputs) { *i = Inputs{} }, CheckpointFire, CodeIdentityUnlinked},
		{"unknown link", func(i *Inputs) { i.Link = LinkUnknown }, CheckpointCreateUpdate, CodeIdentityUnlinked},
		{"unlinked", func(i *Inputs) { i.Link = LinkUnlinked }, CheckpointFire, CodeIdentityUnlinked},
		{"expired", func(i *Inputs) { i.Link = LinkExpired }, CheckpointSideEffect, CodeIdentityUnlinked},
		{"revoked", func(i *Inputs) { i.Link = LinkRevoked }, CheckpointSideEffect, CodeIdentityUnlinked},
		{"revoked install", func(i *Inputs) { i.Install = InstallRevoked }, CheckpointFire, CodeIdentityUnlinked},
		{"surface mismatch", func(i *Inputs) { i.SurfaceMatches = false }, CheckpointFire, CodeIdentityUnlinked},
		{"not a tenant member", func(i *Inputs) { i.TenantMember = false }, CheckpointFire, CodeIdentityUnlinked},
		{"cross owner", func(i *Inputs) { i.OwnerMatches = false }, CheckpointCreateUpdate, CodeNotFound},
		{"cross tenant", func(i *Inputs) { i.TenantAccessible = false }, CheckpointCreateUpdate, CodeNotFound},
		{"missing", func(i *Inputs) { i.TargetExists = false }, CheckpointCreateUpdate, CodeNotFound},
		{"owner change", func(i *Inputs) { i.ChangesOwner = true }, CheckpointCreateUpdate, CodeNotFound},
		{"policy drift", func(i *Inputs) { i.LivePolicyVersion = "p2" }, CheckpointFire, CodePolicyDrift},
		{"per run budget", func(i *Inputs) { i.HeadroomPerRun = 0 }, CheckpointFire, CodeBudgetExhausted},
		{"per day budget", func(i *Inputs) { i.HeadroomPerDay = 0 }, CheckpointFire, CodeBudgetExhausted},
		{"per tenant budget", func(i *Inputs) { i.HeadroomPerTenant = 0 }, CheckpointFire, CodeBudgetExhausted},
		{"budget unavailable", func(i *Inputs) { i.Unavailable = []Source{SourceBudget} }, CheckpointFire, CodeAuthorityUnavailable},
		{"identity unavailable beats unlinked", func(i *Inputs) { i.Link = LinkRevoked; i.Unavailable = []Source{SourceIdentity} }, CheckpointFire, CodeAuthorityUnavailable},
		{"foreign aar", func(i *Inputs) { i.Approval = &ApprovalBinding{ExecutionID: "we_other"} }, CheckpointSideEffect, CodeApprovalNotReusable},
		{"schedule as approval", func(i *Inputs) { i.ScheduleAsApproval = true; i.ApprovalRequired = true }, CheckpointSideEffect, CodeApprovalNotReusable},
		{"approval missing", func(i *Inputs) { i.ApprovalRequired = true }, CheckpointSideEffect, CodeApprovalRequired},
		{"approval bound to this run", func(i *Inputs) { i.ApprovalRequired = true; i.Approval = &ApprovalBinding{ExecutionID: "we_1"} }, CheckpointSideEffect, ""},
		{"install zero value", func(i *Inputs) { i.Install = 0 }, CheckpointFire, CodeIdentityUnlinked},
		{"install not required", func(i *Inputs) { i.Install = InstallNotRequired }, CheckpointFire, ""},
		{"approval empty execution id", func(i *Inputs) { i.Approval = &ApprovalBinding{} }, CheckpointSideEffect, CodeApprovalNotReusable},
		{"approval with empty this execution", func(i *Inputs) {
			i.ThisExecutionID = ""
			i.Approval = &ApprovalBinding{ExecutionID: "we_1"}
		}, CheckpointSideEffect, CodeApprovalNotReusable},
		{"approval both empty", func(i *Inputs) {
			i.ThisExecutionID = ""
			i.Approval = &ApprovalBinding{}
		}, CheckpointSideEffect, CodeApprovalNotReusable},
		{"invalid checkpoint beats unavailable", func(i *Inputs) { i.Unavailable = []Source{SourceBudget} }, Checkpoint(9), CodeInvalid},
		{"invalid checkpoint", func(*Inputs) {}, Checkpoint(0), CodeInvalid},
	}
	for _, c := range cases {
		in := liveInputs()
		c.mut(&in)
		d := Decide(c.cp, in)
		if d.Code != c.want || d.Allowed != (c.want == "") {
			t.Errorf("%s: got %+v, want code %q", c.name, d, c.want)
		}
	}
}

func TestNotFoundBodiesIdentical(t *testing.T) {
	want := []byte(`{"error":{"code":"automation_not_found","message":"automation_not_found"}}`)
	if !bytes.Equal(ErrorBody(CodeNotFound), want) {
		t.Fatalf("not_found body = %s", ErrorBody(CodeNotFound))
	}
	if CodeNotFound.HTTPStatus() != 404 {
		t.Fatalf("not_found status = %d", CodeNotFound.HTTPStatus())
	}
}

func TestCheckSupport(t *testing.T) {
	ok := SupportInputs{OwnerAuthorized: true, TenantBound: true, Scope: ScopeSupport, TTL: time.Hour, MaxFires: 3, Capabilities: []string{"read.logs"}}
	if err := CheckSupport(ok); err != nil {
		t.Fatal(err)
	}
	muts := map[string]func(*SupportInputs){
		"no owner":    func(i *SupportInputs) { i.OwnerAuthorized = false },
		"no tenant":   func(i *SupportInputs) { i.TenantBound = false },
		"wrong scope": func(i *SupportInputs) { i.Scope = ScopeNone },
		"ttl":         func(i *SupportInputs) { i.TTL = 25 * time.Hour },
		"fires":       func(i *SupportInputs) { i.MaxFires = 4 },
		"write":       func(i *SupportInputs) { i.Capabilities = []string{"write.x"} },
		"delegate":    func(i *SupportInputs) { i.DelegatedActor = "a" },
		"impersonate": func(i *SupportInputs) { i.ImpersonatedOwner = "o" },
		"auth ref":    func(i *SupportInputs) { i.AuthRef = "r" },
	}
	for n, m := range muts {
		in := ok
		m(&in)
		if CodeOf(CheckSupport(in)) != CodeSupportConstraint {
			t.Errorf("%s not rejected", n)
		}
	}
	in := ok
	in.AuthRef, in.AuthRefLive = "r", true
	if err := CheckSupport(in); err != nil {
		t.Errorf("live auth_ref: %v", err)
	}
}

// A ttl_seconds whose conversion to a Duration overflows int64 must not wrap
// into the allowed (0, 24h] window: 18446744074 s wrapped to ~0.29s and
// -18446744073 s to ~0.71s, both accepted.
func TestSupportTTLOverflowIsRefused(t *testing.T) {
	base := SupportInputs{OwnerAuthorized: true, TenantBound: true, Scope: ScopeSupport, MaxFires: 1}
	for _, lit := range []string{"18446744074", "-18446744073", "9223372036854775807", "86401", "0", "-1", "1e3", "3600.5"} {
		in := supportInputsFromBody(map[string]any{"ttl_seconds": json.Number(lit)}, Template{Scope: ScopeSupport})
		in.OwnerAuthorized, in.TenantBound, in.MaxFires = base.OwnerAuthorized, base.TenantBound, base.MaxFires
		if CodeOf(CheckSupport(in)) != CodeSupportConstraint {
			t.Errorf("ttl_seconds %s: accepted as TTL %v", lit, in.TTL)
		}
	}
	for lit, want := range map[string]time.Duration{"1": time.Second, "86400": SupportMaxTTL} {
		in := supportInputsFromBody(map[string]any{"ttl_seconds": json.Number(lit)}, Template{Scope: ScopeSupport})
		in.OwnerAuthorized, in.TenantBound, in.MaxFires = base.OwnerAuthorized, base.TenantBound, base.MaxFires
		if in.TTL != want || CheckSupport(in) != nil {
			t.Errorf("ttl_seconds %s: TTL %v, err %v; want %v accepted", lit, in.TTL, CheckSupport(in), want)
		}
	}
}

func TestParallelValidation(t *testing.T) {
	bodies := [][]byte{
		[]byte(`{"idempotency_key":"k","template_id":"reminder.v1","params":{"text":"hi"},"trigger":{"kind":"at","instant":"2026-12-01T10:00:00Z"}}`),
		[]byte(`{"idempotency_key":"k","template_id":"reminder.v1","params":{"text":"hi","x":1},"trigger":{"kind":"at","instant":"2026-12-01T10:00:00Z"}}`),
		[]byte(`{"idempotency_key":"k","template_id":"support.diagnostic-followup.v1","params":{"question_ref":"q"},"trigger":{"kind":"at","instant":"2026-12-01T10:00:00Z"},"ttl_seconds":60,"max_fires":1}`),
	}
	want := []Code{"", CodeUnknownField, CodeTriggerUnsupported}
	var wg sync.WaitGroup
	for n := 0; n < 16; n++ {
		for i := range bodies {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if got := CodeOf(ValidateCreate(bodies[i])); got != want[i] {
					t.Errorf("body %d: code %q, want %q", i, got, want[i])
				}
			}()
		}
	}
	wg.Wait()
}
