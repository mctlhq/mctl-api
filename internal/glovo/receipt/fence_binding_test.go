package receipt

import (
	"context"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/basket"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// tamper runs statements as the owner role with the user triggers suspended:
// it stages states the guards (rightly) make unreachable for the runtime role.
func (e *env) tamper(stmts ...string) {
	e.t.Helper()
	ctx := context.Background()
	all := []string{`ALTER TABLE public.action_approval_requests DISABLE TRIGGER USER`, `ALTER TABLE glovo.approval_bindings DISABLE TRIGGER USER`}
	all = append(all, stmts...)
	all = append(all, `ALTER TABLE public.action_approval_requests ENABLE TRIGGER USER`, `ALTER TABLE glovo.approval_bindings ENABLE TRIGGER USER`)
	for _, q := range all {
		if _, err := e.mp.Exec(ctx, q); err != nil {
			e.t.Fatalf("%s: %v", q, err)
		}
	}
}

func (e *env) setCommand(cmd, set string) {
	e.t.Helper()
	if _, err := e.mp.Exec(context.Background(), `UPDATE bridge_commands SET `+set+` WHERE command_id=$1`, cmd); err != nil {
		e.t.Fatal(err)
	}
}

// T10: every field the bridge presents, every column of the written command
// and every stored decision field is recomputed against the ledger. Each case
// changes one thing and must be refused; the approval stays reserved.
func TestFenceBindingAndIdentityChecks(t *testing.T) {
	other := "prn_OTHER00000000000000000002"
	type tc struct {
		name string
		do   func(e *env, f fixture, b *bridge.FenceBinding)
		want glovo.Code
	}
	cases := []tc{
		{"presented execution", func(_ *env, _ fixture, b *bridge.FenceBinding) { b.ExecutionID = "we_" + strings.Repeat("0", 20) }, glovo.CodeIntentMismatch},
		{"presented work item", func(_ *env, _ fixture, b *bridge.FenceBinding) { b.WorkItemID = "wi_" + strings.Repeat("0", 20) }, glovo.CodeIntentMismatch},
		{"presented tenant", func(_ *env, _ fixture, b *bridge.FenceBinding) { b.Tenant = "other" }, glovo.CodeIntentMismatch},
		{"presented owner", func(_ *env, _ fixture, b *bridge.FenceBinding) { b.OwnerPrincipalID = other }, glovo.CodeIntentMismatch},
		{"presented connection", func(_ *env, _ fixture, b *bridge.FenceBinding) { b.ConnectionRef = tok("gcn_", 26) }, glovo.CodeIntentMismatch},
		{"presented revision", func(_ *env, _ fixture, b *bridge.FenceBinding) { b.InstallRevision = "9" }, glovo.CodeIntentMismatch},
		{"presented approval", func(_ *env, _ fixture, b *bridge.FenceBinding) { b.ApprovalRef = tok("aar_", 26) }, glovo.CodeIntentMismatch},
		{"presented intent hash", func(_ *env, _ fixture, b *bridge.FenceBinding) { b.IntentHash = "sha256:" + strings.Repeat("0", 64) }, glovo.CodeIntentMismatch},
		{"command provider", func(e *env, f fixture, _ *bridge.FenceBinding) {
			e.setCommand(f.cmd, `provider_ref='someone'`)
			e.caller.ProviderRef = "someone"
		}, glovo.CodeIntentMismatch},
		{"command order", func(e *env, f fixture, _ *bridge.FenceBinding) {
			e.setCommand(f.cmd, `order_ref='`+tok("ordr_", 26)+`'`)
		}, glovo.CodeIntentMismatch},
		{"command connection", func(e *env, f fixture, _ *bridge.FenceBinding) {
			e.setCommand(f.cmd, `connection_ref='`+tok("gcn_", 26)+`'`)
		}, glovo.CodeIntentMismatch},
		{"command revision", func(e *env, f fixture, _ *bridge.FenceBinding) { e.setCommand(f.cmd, `install_revision='9'`) }, glovo.CodeIntentMismatch},
		{"stored binding connection", func(e *env, f fixture, _ *bridge.FenceBinding) {
			e.tamper(`UPDATE glovo.approval_bindings SET connection_ref='` + tok("gcn_", 26) + `' WHERE approval_id='` + f.aar + `'`)
		}, glovo.CodeIntentMismatch},
		{"stored binding execution", func(e *env, f fixture, _ *bridge.FenceBinding) {
			e.tamper(`UPDATE glovo.approval_bindings SET execution_id='we_` + strings.Repeat("1", 20) + `' WHERE approval_id='` + f.aar + `'`)
		}, glovo.CodeIntentMismatch},
		{"stored intent hash", func(e *env, f fixture, _ *bridge.FenceBinding) {
			e.tamper(`UPDATE public.action_approval_requests SET intent_hash='sha256:` + strings.Repeat("2", 64) + `' WHERE id='` + f.aar + `'`)
		}, glovo.CodeIntentMismatch},
		{"decider is not the owner", func(e *env, f fixture, _ *bridge.FenceBinding) {
			e.tamper(`UPDATE public.action_approval_requests SET decided_by_principal_id='` + other + `' WHERE id='` + f.aar + `'`)
		}, glovo.CodeApprovalInvalid},
		{"authority basis is not resource_owner", func(e *env, f fixture, _ *bridge.FenceBinding) {
			e.tamper(`UPDATE public.action_approval_requests SET authority_basis='platform_admin' WHERE id='` + f.aar + `'`)
		}, glovo.CodeApprovalInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			f := e.reserved("")
			b := f.binding(e)
			c.do(e, f, &b)
			_, err := e.run(f, b)
			wantCode(t, err, c.want)
			if got := e.state(f.aar); got != workitems.ApprovalReserved {
				t.Fatalf("state = %s after refusal, want reserved", got)
			}
		})
	}
}

// The ledger's binding fingerprint is compared on its own: here the order and
// the written payload agree with each other, and only the binding differs.
func TestFenceBindingFingerprintOnItsOwn(t *testing.T) {
	e := newEnv(t)
	changed := strings.Replace(basePayload, `pst_0123456789abcdef0123`, `pst_0123456789abcdef0124`, 1)
	_, canon, err := basket.Parse([]byte(changed))
	if err != nil {
		t.Fatal(err)
	}
	f := e.reserved(changed)
	e.ord.order.FinalBasketFingerprint = basket.Fingerprint(canon)
	_, err = e.run(f, f.binding(e))
	wantCode(t, err, glovo.CodeBasketChanged)
}

// PreLock does not fence another kind or a command without its references; the
// answer is permanent (approval_invalid), takes no lock and leaves no entry.
func TestFenceUnfencedCommandsAreRefusedPermanently(t *testing.T) {
	for name, set := range map[string]string{
		"cancel_order_fake": `operation_kind='cancel_order_fake'`,
		"quote":             `operation_kind='quote', approval_ref=''`,
		"empty order_ref":   `order_ref=''`,
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			f := e.reserved("")
			e.setCommand(f.cmd, set)
			_, err := e.run(f, f.binding(e))
			wantCode(t, err, glovo.CodeApprovalInvalid)
			if len(e.log) != 0 {
				t.Fatalf("locks taken for an unfenced command: %v", e.log)
			}
			if e.fence.pending() != 0 {
				t.Fatalf("%d PreLock entries left", e.fence.pending())
			}
			if got := e.state(f.aar); got != workitems.ApprovalReserved {
				t.Fatalf("state = %s, want reserved", got)
			}
		})
	}
}

// Check compares the locked command row with what PreLock read: a row that
// changed in between is refused even when the bridge still presents the old
// values for the fields it carries.
func TestFenceRefusesACommandChangedAfterPreLock(t *testing.T) {
	e := newEnv(t)
	f := e.reserved("")
	ctx := context.Background()
	tx, err := e.rtp.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := e.fence.PreLock(ctx, tx, e.caller, f.cmd); err != nil {
		t.Fatal(err)
	}
	e.setCommand(f.cmd, `order_ref='`+tok("ordr_", 26)+`'`)
	_, err = e.fence.Check(ctx, tx, f.binding(e))
	wantCode(t, err, glovo.CodeIntentMismatch)
}

// Release forgets the PreLock record, so a Check that follows has none.
func TestFenceReleaseForgetsPreLock(t *testing.T) {
	e := newEnv(t)
	f := e.reserved("")
	ctx := context.Background()
	tx, err := e.rtp.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := e.fence.PreLock(ctx, tx, e.caller, f.cmd); err != nil {
		t.Fatal(err)
	}
	if e.fence.pending() != 1 {
		t.Fatalf("pending = %d, want 1", e.fence.pending())
	}
	e.fence.Release(tx)
	if e.fence.pending() != 0 {
		t.Fatalf("pending = %d after Release", e.fence.pending())
	}
	_, err = e.fence.Check(ctx, tx, f.binding(e))
	wantCode(t, err, glovo.CodeUnavailable)
}

// The kind PreLock fenced is the kind Check sees: a row that turns into another
// kind between the two is refused permanently.
func TestFenceRefusesAKindChangedAfterPreLock(t *testing.T) {
	e := newEnv(t)
	f := e.reserved("")
	ctx := context.Background()
	tx, err := e.rtp.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := e.fence.PreLock(ctx, tx, e.caller, f.cmd); err != nil {
		t.Fatal(err)
	}
	e.setCommand(f.cmd, `operation_kind='cancel_order_fake'`)
	_, err = e.fence.Check(ctx, tx, f.binding(e))
	wantCode(t, err, glovo.CodeApprovalInvalid)
}
