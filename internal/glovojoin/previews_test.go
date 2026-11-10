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

func samplePreview(t *testing.T, now time.Time, approval []byte) Preview {
	t.Helper()
	id, err := NewPreviewID()
	if err != nil {
		t.Fatal(err)
	}
	p := Preview{ID: id, Tenant: "acme", PrincipalID: subjPrincipal, ConnectionID: "gcn_x", InstallID: "gin_abc", InstallRevision: 3,
		PayloadHash: PayloadHash([]byte("{}")), CreatedAt: now, ExpiresAt: now.Add(PreviewTTL)}
	if approval != nil {
		p.Approval = approval
		p.Fingerprint = digestOf(approval)
	}
	return p
}

func TestPreviewStoreLifecycle(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	p := samplePreview(t, now, []byte(`{"v":"x"}`))
	if err := InsertPreview(ctx, e.rp, p); err != nil {
		t.Fatal(err)
	}
	got, ref := LoadPreview(ctx, e.rp, p.ID, "acme", subjPrincipal, now)
	if ref != nil || got.Fingerprint != p.Fingerprint || string(got.Approval) != `{"v":"x"}` || got.ConsumedOrderRef != "" || got.InstallRevision != 3 {
		t.Fatalf("load = %+v, %v", got, ref)
	}
	// Foreign tenant, foreign principal, unknown id and expired are all the
	// same 404 not_found.
	for name, c := range map[string]struct {
		id, tenant, prn, why string
		at                   time.Time
	}{
		"foreign tenant":    {p.ID, "other", subjPrincipal, "preview_not_found", now},
		"foreign principal": {p.ID, "acme", "prn_ffffffffffffffff", "preview_not_found", now},
		"unknown":           {"gpv_" + p.ID[4:] + "x", "acme", subjPrincipal, "preview_not_found", now},
		"expired":           {p.ID, "acme", subjPrincipal, "preview_expired", now.Add(PreviewTTL)},
	} {
		if _, r := LoadPreview(ctx, e.rp, c.id, c.tenant, c.prn, c.at); r == nil || r.Err.Code != glovo.CodeNotFound || r.Reason != c.why {
			t.Errorf("%s: %+v", name, r)
		}
	}
	// Empty preview: NULL basket, empty fingerprint.
	ep := samplePreview(t, now, nil)
	if err := InsertPreview(ctx, e.rp, ep); err != nil {
		t.Fatal(err)
	}
	if got, r := LoadPreview(ctx, e.rp, ep.ID, "acme", subjPrincipal, now); r != nil || got.Approval != nil || got.Fingerprint != "" {
		t.Fatalf("empty preview = %+v, %v", got, r)
	}
	// A preview that outlives 15 minutes is refused by the table.
	long := samplePreview(t, now, nil)
	long.ExpiresAt = now.Add(16 * time.Minute)
	if err := InsertPreview(ctx, e.rp, long); err == nil {
		t.Fatal("a 16 minute preview was stored")
	}
}

func TestPreviewClaimIsSingleUseAndScoped(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	p := samplePreview(t, now, []byte(`{"v":"x"}`))
	if err := InsertPreview(ctx, e.rp, p); err != nil {
		t.Fatal(err)
	}
	if ok, err := ClaimPreview(ctx, e.rp, p.ID, "other", subjPrincipal, orderRefA); err != nil || ok {
		t.Fatalf("a foreign tenant claimed: %v, %v", ok, err)
	}
	if ok, err := ClaimPreview(ctx, e.rp, p.ID, "acme", "prn_ffffffffffffffff", orderRefA); err != nil || ok {
		t.Fatalf("a foreign principal claimed: %v, %v", ok, err)
	}
	if ok, err := ClaimPreview(ctx, e.rp, p.ID, "acme", subjPrincipal, orderRefA); err != nil || !ok {
		t.Fatalf("first claim: %v, %v", ok, err)
	}
	if ok, err := ClaimPreview(ctx, e.rp, p.ID, "acme", subjPrincipal, orderRefB); err != nil || ok {
		t.Fatalf("second claim won: %v, %v", ok, err)
	}
	got, _ := LoadPreview(ctx, e.rp, p.ID, "acme", subjPrincipal, now)
	if got.ConsumedOrderRef != orderRefA {
		t.Fatalf("consumed by %q", got.ConsumedOrderRef)
	}
	// The same order ref cannot consume a second preview (partial unique index).
	q := samplePreview(t, now, []byte(`{"v":"y"}`))
	if err := InsertPreview(ctx, e.rp, q); err != nil {
		t.Fatal(err)
	}
	if ok, err := ClaimPreview(ctx, e.rp, q.ID, "acme", subjPrincipal, orderRefA); err == nil && ok {
		t.Fatal("one order ref consumed two previews")
	}
	// A rolled-back claim leaves the preview usable.
	r := samplePreview(t, now, []byte(`{"v":"z"}`))
	if err := InsertPreview(ctx, e.rp, r); err != nil {
		t.Fatal(err)
	}
	tx, err := e.rp.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := ClaimPreview(ctx, tx, r.ID, "acme", subjPrincipal, orderRefB); err != nil || !ok {
		t.Fatal(ok, err)
	}
	_ = tx.Rollback(ctx)
	if got, _ := LoadPreview(ctx, e.rp, r.ID, "acme", subjPrincipal, now); got == nil || got.ConsumedOrderRef != "" {
		t.Fatalf("a rolled-back claim stuck: %+v", got)
	}
}

// TestReissuedRefLivesAgainAfterItsTTL: a pho_ or cursor ref the history read
// returns again after it expired must be accepted again, and the re-issue must
// neither extend a live row, nor touch another owner's row.
func TestReissuedRefLivesAgainAfterItsTTL(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	t0 := time.Now().UTC().Truncate(time.Second)
	ref := "pho_00000000000000000009"
	rec := func(tenant, prn, conn string, at time.Time) {
		t.Helper()
		if err := RecordIssuedRefs(ctx, e.rp, tenant, prn, conn, []string{ref}, "curR", at); err != nil {
			t.Fatal(err)
		}
	}
	issued := func(tenant, prn, conn, kind, r string, at time.Time) bool {
		t.Helper()
		ok, err := RefIssued(ctx, e.rp, tenant, prn, conn, kind, r, at)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	rec("acme", subjPrincipal, "gcn_x", t0)
	rec("other", subjPrincipal, "gcn_x", t0) // another tenant, same ref
	later := t0.Add(ReadRefTTL + time.Minute)
	if issued("acme", subjPrincipal, "gcn_x", RefKindPho, ref, later) {
		t.Fatal("a ref was accepted after its TTL")
	}
	// A live row is not extended by a re-issue half way through its life.
	half := t0.Add(ReadRefTTL / 2)
	rec("acme", subjPrincipal, "gcn_x", half)
	if issued("acme", subjPrincipal, "gcn_x", RefKindPho, ref, later) {
		t.Fatal("re-issue extended a live ref")
	}
	// After the TTL the re-issue brings both kinds back, for that owner only.
	rec("acme", subjPrincipal, "gcn_x", later)
	for _, k := range []struct{ kind, ref string }{{RefKindPho, ref}, {RefKindCursor, "curR"}} {
		if !issued("acme", subjPrincipal, "gcn_x", k.kind, k.ref, later.Add(time.Minute)) {
			t.Errorf("a re-issued %s ref was refused after a TTL", k.kind)
		}
	}
	if issued("other", subjPrincipal, "gcn_x", RefKindPho, ref, later.Add(time.Minute)) {
		t.Error("re-issue to one tenant revived the ref of another")
	}
	if issued("acme", subjPrincipal, "gcn_y", RefKindPho, ref, later.Add(time.Minute)) {
		t.Error("re-issue revived the ref on another connection")
	}
	if issued("acme", "prn_ffffffffffffffff", "gcn_x", RefKindPho, ref, later.Add(time.Minute)) {
		t.Error("re-issue revived the ref of another principal")
	}
}

func TestReadRefsAreIssuedOnlyToTheirOwner(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	now := time.Now().UTC()
	pho := []string{"pho_00000000000000000000", "pho_00000000000000000001"}
	if err := RecordIssuedRefs(ctx, e.rp, "acme", subjPrincipal, "gcn_x", pho, "cur1", now); err != nil {
		t.Fatal(err)
	}
	// Recording twice is idempotent.
	if err := RecordIssuedRefs(ctx, e.rp, "acme", subjPrincipal, "gcn_x", pho, "cur1", now); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		tenant, prn, conn, kind, ref string
		at                           time.Time
		want                         bool
	}{
		{"acme", subjPrincipal, "gcn_x", RefKindPho, pho[0], now, true},
		{"acme", subjPrincipal, "gcn_x", RefKindCursor, "cur1", now, true},
		{"acme", subjPrincipal, "gcn_x", RefKindPho, "cur1", now, false},
		{"acme", subjPrincipal, "gcn_x", RefKindCursor, pho[0], now, false},
		{"other", subjPrincipal, "gcn_x", RefKindPho, pho[0], now, false},
		{"acme", "prn_ffffffffffffffff", "gcn_x", RefKindPho, pho[0], now, false},
		{"acme", subjPrincipal, "gcn_y", RefKindPho, pho[0], now, false},
		{"acme", subjPrincipal, "gcn_x", RefKindPho, "pho_never", now, false},
		{"acme", subjPrincipal, "gcn_x", RefKindPho, pho[0], now.Add(ReadRefTTL), false},
	} {
		got, err := RefIssued(ctx, e.rp, c.tenant, c.prn, c.conn, c.kind, c.ref, c.at)
		if err != nil || got != c.want {
			t.Errorf("%+v: %v, %v", c, got, err)
		}
	}
	if n, err := SweepReadRefs(ctx, e.rp, now.Add(2*ReadRefTTL), 2); err != nil || n != 2 {
		t.Fatalf("sweep = %d, %v", n, err)
	}
	// A failed read is an error, never "not issued".
	mustExec(t, e.mp, `DROP TABLE glovo.join_read_refs`)
	if got, err := RefIssued(ctx, e.rp, "acme", subjPrincipal, "gcn_x", RefKindPho, pho[0], now); err == nil || got {
		t.Fatalf("a failed read = %v, %v", got, err)
	}
}
