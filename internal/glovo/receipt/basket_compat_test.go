package receipt

import (
	"context"
	"errors"
	"testing"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovobasket"
	"github.com/mctlhq/mctl-api/internal/governance"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Approval schema v2 (the glovo.basket_approval kind, mctl-api#1006) and the
// order pilot's readiness: a database still at v1 is not ready for this
// binary (fail closed, never a pass), the in-place upgrade makes it ready,
// and basket approvals in the shared ledger are not order joints, so they
// neither satisfy nor break the joint-state table Ready reads.
func TestReadyAcrossApprovalSchemaV2WithBasketApprovals(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ok := func(context.Context) error { return nil }
	deps := Deps{GlovoURLExplicit: true, WorkItemsURLExplicit: true, GlovoStoreReady: ok, ProveOneDatabase: ok,
		Glovo: e.rtp, Audit: e.rtp, Policies: governance.Policies, WorkItems: e.store, Bridge: e, Orders: e.ord,
		Conns: e.conns, Members: e.members, WireVersionsEnabled: func() bool { return true }}
	if err := Ready(ctx, deps); err != nil {
		t.Fatalf("v2 Ready: %v", err)
	}

	// A database recorded at v1 is not ready for the v2 binary.
	if _, err := e.mp.Exec(ctx, `UPDATE glovo.approval_schema_version SET version = 1`); err != nil {
		t.Fatal(err)
	}
	var nr *glovo.NotReadyError
	if err := Ready(ctx, deps); !errors.As(err, &nr) || nr.Reason != NotReadySchema {
		t.Fatalf("v1 database: %v, want not_ready %s", err, NotReadySchema)
	}
	// The migration upgrades it in place.
	if err := workitems.ApplyGlovoApprovalSchema(ctx, e.migURL, e.rt, workitems.WithWorkItemsRole(e.wi)); err != nil {
		t.Fatalf("upgrade to v2: %v", err)
	}
	if err := Ready(ctx, deps); err != nil {
		t.Fatalf("after the upgrade: %v", err)
	}

	// Basket approvals in the same ledger.
	before, err := Audit(ctx, e.rtp)
	if err != nil {
		t.Fatal(err)
	}
	if err := glovobasket.ApplySchema(ctx, e.migURL, e.rt); err != nil {
		t.Fatalf("basket schema: %v", err)
	}
	store := &glovobasket.PGStore{Pool: e.rtp}
	o := glovobasket.Owner{Tenant: tenant, PrincipalID: ownerPrn}
	b, _, err := store.Create(ctx, o, "compat", glovobasket.DefaultMaxBaskets)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(ctx, o, b.ID, 1, []glovobasket.Op{{Op: "add", ItemCode: "FAKE-EGGS-12", Quantity: 1}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RequestApproval(ctx, o, b.ID, 2, glovobasket.DefaultApprovalTTL); err != nil {
		t.Fatal(err)
	}
	if err := Ready(ctx, deps); err != nil {
		t.Fatalf("Ready with a basket approval in the ledger: %v", err)
	}
	after, err := Audit(ctx, e.rtp)
	if err != nil {
		t.Fatal(err)
	}
	if after.Checked != before.Checked || len(after.Violations) != 0 {
		t.Fatalf("the joint table read a basket approval: before %+v after %+v", before, after)
	}
}
