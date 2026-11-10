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
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/glovo"
)

// approvalTTLOnPrepare runs one prepare on the real stack and returns the
// stored approval's life as the database clock measured it, bounded by the
// wall clock around the call.
func approvalTTLOnPrepare(t *testing.T, want time.Duration) {
	t.Helper()
	s := newStack(t)
	s.activate("k-ttl")
	p := s.preview(stackBasket)
	before := time.Now().UTC()
	res, rf := s.prepare.Prepare(context.Background(), s.req(p, "key-ttl"))
	after := time.Now().UTC()
	if rf != nil {
		t.Fatal(rf)
	}
	slack := 2 * time.Second
	if lo, hi := before.Add(want).Add(-slack), after.Add(want).Add(slack); res.ExpiresAt.Before(lo) || res.ExpiresAt.After(hi) {
		t.Fatalf("expires_at %s is not now + %s (%s .. %s)", res.ExpiresAt, want, lo, hi)
	}
	var stored time.Time
	if err := s.mp.QueryRow(context.Background(), `SELECT expires_at FROM public.action_approval_requests WHERE id = $1`, res.ConsentRequestID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !stored.Equal(res.ExpiresAt) {
		t.Fatalf("stored expiry %s, returned %s", stored, res.ExpiresAt)
	}
	// A replay renders the same stored expiry.
	again, rf := s.prepare.Prepare(context.Background(), s.req(p, "key-ttl"))
	if rf != nil || !again.Replayed || !again.ExpiresAt.Equal(res.ExpiresAt) {
		t.Fatalf("replay %+v, %v", again, rf)
	}
}

// T13 (build half): a prepare writes an approval that lives 15 minutes (owner
// decision 10.11, 900 s). The literal is on purpose: a test that reads the
// constant back cannot catch a prepare that ignores it.
func TestPrepareApprovalExpiresAfterTheDecidedTTL(t *testing.T) {
	approvalTTLOnPrepare(t, 900*time.Second)
}

// P2-a: the live connection is checked against the subject's CURRENT install
// revision and install, not only against the preview.
func TestPrepareRefusesASubjectOfAStaleInstall(t *testing.T) {
	for _, c := range []struct {
		name string
		mut  func(*PrepareRequest)
	}{
		{"older revision", func(r *PrepareRequest) { r.InstallRevision-- }},
		{"newer revision", func(r *PrepareRequest) { r.InstallRevision++ }},
		{"other install", func(r *PrepareRequest) { r.InstallID = "gin_00000000000000000000" }},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newStack(t)
			s.activate("k-subj-" + c.name)
			p := s.preview(stackBasket)
			r := s.req(p, "key-subj")
			c.mut(&r)
			if r.InstallRevision < 1 {
				r.InstallRevision = 1
				r.InstallID += "x"
			}
			_, rf := s.prepare.Prepare(context.Background(), r)
			wantCode(t, rf, glovo.CodeStaleInstall, "subject_install_stale")
			if w := s.writes(); w != [6]int{0, 0, 0, 0, 0, 0} {
				t.Fatalf("wrote for a stale subject: %v", w)
			}
			// The same preview is still usable with the current install.
			if _, rf := s.prepare.Prepare(context.Background(), s.req(p, "key-subj-ok")); rf != nil {
				t.Fatalf("the preview was spent by a refused prepare: %v", rf)
			}
		})
	}
}

// P13/P19: a preview read on an older connection, or under an install the
// connection no longer has, is refused even when the subject is current.
func TestPrepareRefusesAPreviewOfAnotherConnectionOrInstall(t *testing.T) {
	for _, c := range []struct{ name, set string }{
		{"older connection", `connection_id = 'gcn_00000000000000000000'`},
		{"reinstalled app", `install_id = 'gin_00000000000000000001'`},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newStack(t)
			s.activate("k-pv-" + c.name)
			p := s.preview(stackBasket)
			if _, err := s.mp.Exec(context.Background(), `UPDATE glovo.join_previews SET `+c.set+` WHERE id = $1`, p.ID); err != nil {
				t.Fatal(err)
			}
			_, rf := s.prepare.Prepare(context.Background(), s.req(p, "key-pv"))
			wantCode(t, rf, glovo.CodeStaleInstall, "preview_connection_changed")
			if w := s.writes(); w != [6]int{0, 0, 0, 0, 0, 0} {
				t.Fatalf("wrote on a stale preview: %v", w)
			}
		})
	}
}

// P18: the stored basket must still hash to the stored fingerprint under the
// canonical form. The table CHECK pins the fingerprint to the raw bytes, so a
// raw basket that is not canonical (valid JSON, other spacing) passes the
// CHECK and is caught only by the recheck.
func TestPrepareRechecksTheBasketFingerprint(t *testing.T) {
	s := newStack(t)
	s.activate("k-fp")
	p := s.preview(stackBasket)
	raw := append([]byte(" "), p.Approval...)
	if _, err := s.mp.Exec(context.Background(), `UPDATE glovo.join_previews SET approval_basket = $2, fingerprint = 'sha256:' || encode(sha256($2), 'hex') WHERE id = $1`, p.ID, raw); err != nil {
		t.Fatal(err)
	}
	_, rf := s.prepare.Prepare(context.Background(), s.req(p, "key-fp"))
	wantCode(t, rf, glovo.CodeFingerprintChanged, "preview_fingerprint")
	if w := s.writes(); w != [6]int{0, 0, 0, 0, 0, 0} {
		t.Fatalf("wrote for a changed basket: %v", w)
	}
}
