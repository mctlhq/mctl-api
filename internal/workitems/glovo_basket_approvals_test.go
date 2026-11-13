package workitems

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/glovo"
)

const testBasket = "gbk_ABCDEFGHIJKLMNOPQRSTUVWXYZ"

func basketInput(rev int64, fp string) GlovoBasketApprovalInput {
	return GlovoBasketApprovalInput{Tenant: testTenant, OwnerPrincipalID: testOwner, BasketID: testBasket,
		Revision: rev, BasketFingerprint: fp, ExpiresIn: time.Hour}
}

func fpOf(c string) string { return "sha256:" + strings.Repeat(c, 64) }

func (g *glovoEnv) createBasketApproval(t *testing.T, in GlovoBasketApprovalInput) *ActionApprovalRequest {
	t.Helper()
	var out *ActionApprovalRequest
	g.tx(t, func(tx pgx.Tx) {
		a, created, err := CreateGlovoBasketApprovalTx(context.Background(), tx, in)
		if err != nil || !created {
			t.Fatalf("CreateGlovoBasketApprovalTx: %v created=%v", err, created)
		}
		out = a
	})
	return out
}

func (g *glovoEnv) decideBasket(t *testing.T, in ActionDecisionInput) (*ActionApprovalRequest, error) {
	t.Helper()
	tx, err := g.rtp.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	a, err := DecideGlovoBasketApprovalTx(context.Background(), tx, in)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(context.Background()); err != nil {
		return nil, err
	}
	return a, nil
}

func ownerApprove(id string) ActionDecisionInput {
	return ActionDecisionInput{ID: id, DecidedBy: "prn:" + testOwner, DecidedByPrincipalID: testOwner,
		Decision: DecisionApprove, AuthorityBasis: GlovoAuthorityBasis, ContextDigest: "sha256:x", AuthzMode: "principal",
		FreshFor: time.Hour}
}

// The whole basket approval: create (idempotent, replay-refused), status,
// the owner decision, and every refusal of the decision.
func TestGlovoBasketApprovalLifecycle(t *testing.T) {
	g := newGlovoEnv(t)
	ctx := context.Background()
	in := basketInput(1, fpOf("a"))
	a := g.createBasketApproval(t, in)
	if a.ActionKind != ActionKindGlovoBasketApproval || a.State != ApprovalPending || a.ExecutionID != testBasket ||
		a.WorkItemID != "" || a.ArtifactHash != in.BasketFingerprint || a.SideEffect != "none" ||
		a.PolicyRuleID != GlovoBasketPolicyRuleID || a.RequestedBy != GlovoBasketRequester {
		t.Fatalf("created row: %+v", a)
	}
	if a.IntentHash != IntentHash(GlovoBasketIntent(in.binding())) {
		t.Fatal("intent hash is not the basket intent")
	}
	// Idempotent on (basket, revision); another fingerprint under it is a replay.
	g.tx(t, func(tx pgx.Tx) {
		again, created, err := CreateGlovoBasketApprovalTx(ctx, tx, in)
		if err != nil || created || again.ID != a.ID {
			t.Fatalf("idempotent create: %v created=%v", err, created)
		}
		other := in
		other.BasketFingerprint = fpOf("b")
		_, _, err = CreateGlovoBasketApprovalTx(ctx, tx, other)
		wantCode(t, err, glovo.CodeApprovalReplayed)
	})
	// Status is owner and tenant scoped, with one not_found for every miss.
	st, err := ReadGlovoBasketApprovalStatus(ctx, g.rtp, testTenant, testOwner, a.ID)
	if err != nil || st.State != GlovoBasketStatePending || st.Revision != 1 || st.BasketFingerprint != in.BasketFingerprint {
		t.Fatalf("status: %+v %v", st, err)
	}
	for _, c := range [][3]string{
		{"other-tenant", testOwner, a.ID},
		{testTenant, "prn_OTHER000000000000000000001", a.ID},
		{testTenant, testOwner, "aar_doesnotexist"},
	} {
		if _, err := ReadGlovoBasketApprovalStatus(ctx, g.rtp, c[0], c[1], c[2]); !errors.Is(err, glovo.ErrNotFound) {
			t.Errorf("status %v: %v, want not_found", c, err)
		}
	}
	// Someone else, or the owner under another basis, cannot approve.
	bad := ownerApprove(a.ID)
	bad.DecidedByPrincipalID = "prn_OTHER000000000000000000001"
	if _, err := g.decideBasket(t, bad); !errors.Is(err, ErrNotGlovoOwner) {
		t.Fatalf("other principal: %v", err)
	}
	bad = ownerApprove(a.ID)
	bad.AuthorityBasis = "platform_admin"
	if _, err := g.decideBasket(t, bad); !errors.Is(err, ErrNotGlovoOwner) {
		t.Fatalf("admin basis: %v", err)
	}
	got, err := g.decideBasket(t, ownerApprove(a.ID))
	if err != nil || got.State != ApprovalApproved || got.FreshUntil == nil {
		t.Fatalf("owner approve: %+v %v", got, err)
	}
	// A replayed decision is already decided, and the stored decision stands.
	if _, err := g.decideBasket(t, ownerApprove(a.ID)); !errors.Is(err, ErrApprovalAlreadyDecided) {
		t.Fatalf("replayed decision: %v", err)
	}
	deny := ownerApprove(a.ID)
	deny.Decision = DecisionDeny
	if _, err := g.decideBasket(t, deny); !errors.Is(err, ErrApprovalAlreadyDecided) {
		t.Fatalf("deny after approve: %v", err)
	}
	st, err = ReadGlovoBasketApprovalStatus(ctx, g.rtp, testTenant, testOwner, a.ID)
	if err != nil || st.State != GlovoBasketStateApproved || st.DecidedAt == nil {
		t.Fatalf("status after approve: %+v %v", st, err)
	}
	// A second revision gets its own approval; denying it is "rejected" and
	// leaves the first one approved.
	b := g.createBasketApproval(t, basketInput(2, fpOf("c")))
	deny = ownerApprove(b.ID)
	deny.Decision, deny.AuthorityBasis, deny.FreshFor = DecisionDeny, "", 0
	if _, err := g.decideBasket(t, deny); err != nil {
		t.Fatalf("owner deny: %v", err)
	}
	if st, err := ReadGlovoBasketApprovalStatus(ctx, g.rtp, testTenant, testOwner, b.ID); err != nil || st.State != GlovoBasketStateRejected {
		t.Fatalf("denied status: %+v %v", st, err)
	}
	if _, _, err := GlovoBasketApprovalForDecision(ctx, g.rtp, "aar_nope", time.Now()); !errors.Is(err, ErrApprovalNotFound) {
		t.Fatalf("pre-read of a missing id: %v", err)
	}
}

// An order-approval method never answers for a basket approval.
func TestGlovoBasketApprovalIsNotAnOrderApproval(t *testing.T) {
	g := newGlovoEnv(t)
	ctx := context.Background()
	a := g.createBasketApproval(t, basketInput(1, fpOf("a")))
	if _, _, err := g.store.GlovoApprovalForDecision(ctx, g.rtp, a.ID); !errors.Is(err, ErrApprovalNotFound) {
		t.Fatalf("order pre-read of a basket approval: %v", err)
	}
	if _, err := g.store.GlovoApprovalStatus(ctx, g.rtp, []string{testTenant}, a.ID); !errors.Is(err, glovo.ErrNotFound) {
		t.Fatalf("order status of a basket approval: %v", err)
	}
	g.tx(t, func(tx pgx.Tx) {
		if _, err := g.store.DecideGlovoApprovalTx(ctx, tx, ActionDecisionInput{ID: a.ID, DecidedBy: "x",
			DecidedByPrincipalID: testOwner, Decision: DecisionApprove, AuthorityBasis: GlovoAuthorityBasis}); !errors.Is(err, ErrApprovalNotFound) {
			t.Fatalf("order decide of a basket approval: %v", err)
		}
	})
	// And the generic spend paths refuse it.
	if _, err := g.store.ConsumeActionApproval(ctx, a.ID, a.IntentHash); !errors.Is(err, ErrApprovalKindNotSpendable) {
		t.Fatalf("generic consume: %v", err)
	}
}

// The database enforces the basket machine on its own: decided rows never
// move, the binding is insert-only, only the owner approves, only the
// runtime role writes, and a row without its binding never commits.
func TestGlovoBasketApprovalDatabaseGuards(t *testing.T) {
	g := newGlovoEnv(t)
	ctx := context.Background()
	a := g.createBasketApproval(t, basketInput(1, fpOf("a")))
	execErr := func(sql string, args ...any) error {
		_, err := g.rtp.Exec(ctx, sql, args...)
		return err
	}
	// A direct approve by someone other than the bound owner.
	if err := execErr(`UPDATE public.action_approval_requests SET state='approved', decided_by_principal_id='prn_X1',
		authority_basis='resource_owner', fresh_until=expires_at WHERE id=$1`, a.ID); err == nil {
		t.Fatal("database accepted an approve by a non-owner")
	}
	if _, err := g.decideBasket(t, ownerApprove(a.ID)); err != nil {
		t.Fatal(err)
	}
	for name, sql := range map[string]string{
		"approved -> reserved": `UPDATE public.action_approval_requests SET state='reserved', reserved_at=now() WHERE id=$1`,
		"approved -> denied":   `UPDATE public.action_approval_requests SET state='denied' WHERE id=$1`,
		"approved -> consumed": `UPDATE public.action_approval_requests SET state='consumed', consumed_at=now() WHERE id=$1`,
		"fingerprint changes":  `UPDATE public.action_approval_requests SET artifact_hash='sha256:` + strings.Repeat("f", 64) + `' WHERE id=$1`,
		"binding update":       `UPDATE glovo.basket_approval_bindings SET revision=7 WHERE approval_id=$1`,
		"binding delete":       `DELETE FROM glovo.basket_approval_bindings WHERE approval_id=$1`,
	} {
		if err := execErr(sql, a.ID); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A basket aar_ without its binding does not commit.
	tx, err := g.rtp.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.action_approval_requests (id, execution_id, action_kind, target, args_digest,
		policy_rule_id, policy_version, artifact_hash, idempotency_key, requested_by, intent_hash, state, expires_at, created_at,
		schema_version, intent_source, policy_decision, policy_reasons)
		VALUES ('aar_nobinding', $1, 'glovo.basket_approval', 't', $2, 'glovo.basket.owner-approval', '1', $2, 'k-nb',
		'service:glovo-basket', 'h', 'pending', now() + interval '1 hour', now(), 'actionapproval/v1', 'basket:x', 'require_approval', '{r}')`,
		testBasket, fpOf("d")); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := tx.Commit(ctx); err == nil {
		t.Fatal("a basket approval without its binding committed")
	}
	// The work-items role writes no Glovo approval of any kind.
	wi := g.wiPool()
	if _, err := wi.Exec(ctx, `INSERT INTO public.action_approval_requests (id, execution_id, action_kind, target, args_digest,
		policy_rule_id, policy_version, idempotency_key, requested_by, intent_hash, state, expires_at, created_at, schema_version)
		VALUES ('aar_wirole', $1, 'glovo.basket_approval', 't', 'd', 'glovo.basket.owner-approval', '1', 'k-wi',
		'service:glovo-basket', 'h', 'pending', now() + interval '1 hour', now(), 'actionapproval/v1')`, testBasket); err == nil {
		t.Fatal("the work-items role wrote a basket approval")
	}
}
