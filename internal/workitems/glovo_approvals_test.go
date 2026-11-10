package workitems

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/glovo"
)

func wantCode(t *testing.T, err error, code glovo.Code) {
	t.Helper()
	if !errors.Is(err, glovo.Refuse(code)) {
		t.Fatalf("got %v, want refusal %s", err, code)
	}
}

// Task 0: the ids match the bridge patterns, a generic id is not_found, a
// rollback leaves no row.
func TestGlovoExecutionTx(t *testing.T) {
	g := newGlovoEnv(t)
	ctx := context.Background()
	var wi, we string
	g.tx(t, func(tx pgx.Tx) {
		var err error
		wi, we, err = g.store.CreateGlovoExecutionTx(ctx, tx, GlovoExecutionInput{
			Tenant: testTenant, OwnerPrincipalID: testOwner, WorkflowID: "wf-1", Actor: "service:glovo-prepare"})
		if err != nil {
			t.Fatal(err)
		}
	})
	if !glovoWorkItemIDRE.MatchString(wi) || !glovoExecutionRE.MatchString(we) || len(wi) != 29 || len(we) != 29 {
		t.Fatalf("ids %q %q do not match the bridge patterns", wi, we)
	}
	tenant, owner, gotWI, wf, err := g.store.ExecutionBindingTx(ctx, g.rtp, we)
	if err != nil || tenant != testTenant || owner != testOwner || gotWI != wi || wf != "wf-1" {
		t.Fatalf("binding: %q %q %q %q %v", tenant, owner, gotWI, wf, err)
	}
	var events int
	var engine, surface string
	if err := g.rtp.QueryRow(ctx, `SELECT (SELECT count(*) FROM work_item_events WHERE work_item_id=$1 AND kind='created'),
		(SELECT origin_surface FROM work_items WHERE id=$1),
		(SELECT engine||'|'||engine_ref||'|'||phase FROM work_item_executions WHERE id=$2)`, wi, we).Scan(&events, &surface, &engine); err != nil {
		t.Fatal(err)
	}
	if events != 1 || surface != "glovo" || engine != "temporal|wf-1|Pending" {
		t.Fatalf("rows: events=%d surface=%q execution=%q", events, surface, engine)
	}
	// A generic work item and execution (hyphenated ids) are not_found.
	item, _, err := g.store.Create(ctx, CreateInput{Mutation: Mutation{Actor: "oidc:x"}, Tenant: testTenant,
		Visibility: VisibilityTenant, OriginSurface: "cli", Title: "generic"})
	if err != nil {
		t.Fatal(err)
	}
	genericExec := ExecutionIDPrefix + "11111111-2222-3333-4444-555555555555"
	if _, err := g.wiPool().Exec(ctx, `INSERT INTO work_item_executions (id, work_item_id, engine, engine_ref, attempt, phase, started_at)
		VALUES ($1,$2,'temporal','wf-g',1,'Pending',now())`, genericExec, item.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := g.store.ExecutionBindingTx(ctx, g.rtp, genericExec); !errors.Is(err, ErrNotFound) {
		t.Fatalf("generic execution: %v", err)
	}
	// Same shape as a Glovo id, but a generic work item: not_found.
	shaped := "we_" + strings.Repeat("Z", 26)
	if _, err := g.wiPool().Exec(ctx, `INSERT INTO work_item_executions (id, work_item_id, engine, engine_ref, attempt, phase, started_at)
		VALUES ($1,$2,'temporal','wf-h',2,'Succeeded',now())`, shaped, item.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := g.store.ExecutionBindingTx(ctx, g.rtp, shaped); !errors.Is(err, ErrNotFound) {
		t.Fatalf("glovo-shaped id of a generic item: %v", err)
	}
	// Rollback leaves nothing.
	tx, err := g.rtp.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rwi, rwe, err := g.store.CreateGlovoExecutionTx(ctx, tx, GlovoExecutionInput{
		Tenant: testTenant, OwnerPrincipalID: testOwner, WorkflowID: "wf-r", Actor: "service:glovo-prepare"})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := g.rtp.QueryRow(ctx, `SELECT (SELECT count(*) FROM work_items WHERE id=$1) + (SELECT count(*) FROM work_item_executions WHERE id=$2)`, rwi, rwe).Scan(&n); err != nil || n != 0 {
		t.Fatalf("rollback left %d rows (%v)", n, err)
	}
	for _, bad := range []GlovoExecutionInput{
		{OwnerPrincipalID: testOwner, WorkflowID: "wf", Actor: "a"},
		{Tenant: "t", OwnerPrincipalID: "oidc:notprn", WorkflowID: "wf", Actor: "a"},
		{Tenant: "t", OwnerPrincipalID: testOwner, Actor: "a"},
	} {
		g.tx(t, func(tx pgx.Tx) {
			if _, _, err := g.store.CreateGlovoExecutionTx(ctx, tx, bad); !errors.Is(err, ErrInvalid) {
				t.Errorf("%+v: %v", bad, err)
			}
		})
	}
}

func (g *glovoEnv) wiPool() *pgxpool.Pool { return g.splitEnv.pool(g.wiURL) }

// Task 3, T8, T9: the whole happy path, replay and final states.
func TestGlovoApprovalLifecycle(t *testing.T) {
	g := newGlovoEnv(t)
	ctx := context.Background()
	f := g.prepare(t)
	if len(g.orders.calls) != 1 || !strings.HasSuffix(g.orders.calls[0], "|"+f.in.OrderRef+"|"+f.aar) ||
		!strings.Contains(g.orders.calls[0], "|"+testOwner+"|system|service:glovo-prepare|") {
		t.Fatalf("BindApproval call: %v", g.orders.calls)
	}
	// Create is idempotent on the order; a different basket on the same key is a replay refusal.
	g.tx(t, func(tx pgx.Tx) {
		a, created, err := g.store.CreateGlovoApprovalTx(ctx, tx, f.in)
		if err != nil || created || a.ID != f.aar {
			t.Fatalf("idempotent create: %v created=%v", err, created)
		}
		in := f.in
		in.BasketFingerprint = "sha256:" + strings.Repeat("cd", 32)
		_, _, err = g.store.CreateGlovoApprovalTx(ctx, tx, in)
		wantCode(t, err, glovo.CodeApprovalReplayed)
	})
	if len(g.orders.calls) != 1 {
		t.Fatalf("a replayed create called BindApproval again: %v", g.orders.calls)
	}
	// A second aar_ for the same order, under another idempotency key, hits UNIQUE (order_ref).
	func() {
		tx, err := g.rtp.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		var id string
		if err := tx.QueryRow(ctx, `SELECT 'aar_' || md5(random()::text)`).Scan(&id); err != nil {
			t.Fatal(err)
		}
		row := rawGlovoRow(map[string]any{"id": id, "idempotency_key": "other-key", "execution_id": f.in.ExecutionID, "work_item_id": f.in.WorkItemID})
		if _, err := tx.Exec(ctx, row.sql, row.args...); err != nil {
			t.Fatalf("raw insert: %v", err)
		}
		_, err = tx.Exec(ctx, `INSERT INTO glovo.approval_bindings (`+glovoBindingColumns+`)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'',now())`, id, f.in.Tenant, f.in.OwnerPrincipalID, f.in.ExecutionID,
			f.in.WorkItemID, f.in.OrderRef, f.in.ConnectionRef, f.in.InstallID, f.in.InstallRevision, f.in.BasketFingerprint, f.in.Provider)
		if err == nil || !errors.Is(mapGlovoPgErr("x", err), glovo.Refuse(glovo.CodeApprovalReplayed)) {
			t.Fatalf("second aar_ for the order: %v", err)
		}
	}()

	// Reserve needs approval.
	cmd := newCmdID(t)
	g.tx(t, func(tx pgx.Tx) {
		_, err := g.store.ReserveGlovoApprovalTx(ctx, tx, f.aar, f.reserveCmd(cmd))
		wantCode(t, err, glovo.CodeApprovalInvalid)
	})
	// A non-owner cannot decide.
	g.tx(t, func(tx pgx.Tx) {
		_, err := g.store.DecideGlovoApprovalTx(ctx, tx, ActionDecisionInput{ID: f.aar, DecidedBy: "oidc:x",
			DecidedByPrincipalID: "prn_SOMEONE0000000000000000001", Decision: DecisionApprove, AuthorityBasis: GlovoAuthorityBasis})
		if !errors.Is(err, ErrNotGlovoOwner) {
			t.Fatalf("non-owner: %v", err)
		}
		_, err = g.store.DecideGlovoApprovalTx(ctx, tx, ActionDecisionInput{ID: f.aar, DecidedBy: "oidc:x",
			DecidedByPrincipalID: testOwner, Decision: DecisionApprove, AuthorityBasis: "platform_admin"})
		if !errors.Is(err, ErrNotGlovoOwner) {
			t.Fatalf("wrong basis: %v", err)
		}
	})
	a := g.decide(t, f, DecisionApprove)
	if a.State != ApprovalApproved || a.AuthorityBasis != "resource_owner" || a.DecidedByPrincipalID != testOwner || a.FreshUntil == nil {
		t.Fatalf("approved row: %+v", a)
	}
	g.tx(t, func(tx pgx.Tx) {
		_, err := g.store.DecideGlovoApprovalTx(ctx, tx, ActionDecisionInput{ID: f.aar, DecidedBy: "oidc:owner",
			DecidedByPrincipalID: testOwner, Decision: DecisionDeny, AuthorityBasis: GlovoAuthorityBasis})
		if !errors.Is(err, ErrApprovalAlreadyDecided) {
			t.Fatalf("second decision: %v", err)
		}
	})

	g.tx(t, func(tx pgx.Tx) {
		replayed, err := g.store.ReserveGlovoApprovalTx(ctx, tx, f.aar, f.reserveCmd(cmd))
		if err != nil || replayed {
			t.Fatalf("reserve: %v replayed=%v", err, replayed)
		}
	})
	if st, c := g.stored(t, f.aar); st != "reserved" || c != cmd {
		t.Fatalf("after reserve: %s %s", st, c)
	}
	// T8: the same command replays and changes nothing; another command is approval_replayed.
	g.tx(t, func(tx pgx.Tx) {
		replayed, err := g.store.ReserveGlovoApprovalTx(ctx, tx, f.aar, f.reserveCmd(cmd))
		if err != nil || !replayed {
			t.Fatalf("replay: %v replayed=%v", err, replayed)
		}
		_, err = g.store.ReserveGlovoApprovalTx(ctx, tx, f.aar, f.reserveCmd(newCmdID(t)))
		wantCode(t, err, glovo.CodeApprovalReplayed)
	})
	// Consume belongs to the fence: the wrong command is refused, the right one spends.
	g.tx(t, func(tx pgx.Tx) {
		wantCode(t, g.store.ConsumeGlovoApprovalTx(ctx, tx, f.aar, newCmdID(t)), glovo.CodeApprovalReplayed)
	})
	g.tx(t, func(tx pgx.Tx) {
		if err := g.store.ConsumeGlovoApprovalTx(ctx, tx, f.aar, cmd); err != nil {
			t.Fatal(err)
		}
	})
	if st, _ := g.stored(t, f.aar); st != "consumed" {
		t.Fatalf("after consume: %s", st)
	}
	// T9: a consumed aar_ cannot be decided, reserved, consumed or revoked; the exposed state is consumed.
	g.assertFinal(t, f, cmd, "consumed")
	g.tx(t, func(tx pgx.Tx) {
		// reserve of the same command on a consumed row is a replay, nothing else.
		replayed, err := g.store.ReserveGlovoApprovalTx(ctx, tx, f.aar, f.reserveCmd(cmd))
		if err != nil || !replayed {
			t.Fatalf("reserve on consumed, same command: %v %v", err, replayed)
		}
	})
}

// assertFinal: every transition out of a final state is refused, by the store
// and by the database.
func (g *glovoEnv) assertFinal(t *testing.T, f glovoFixture, cmd, state string) {
	// A denied row is revoked again as a success (idempotent retry); every other
	// final state is invalid_transition.
	t.Helper()
	ctx := context.Background()
	g.tx(t, func(tx pgx.Tx) {
		_, err := g.store.DecideGlovoApprovalTx(ctx, tx, ActionDecisionInput{ID: f.aar, DecidedBy: "oidc:owner",
			DecidedByPrincipalID: testOwner, Decision: DecisionApprove, AuthorityBasis: GlovoAuthorityBasis})
		if !errors.Is(err, ErrApprovalAlreadyDecided) {
			t.Errorf("decide on %s: %v", state, err)
		}
	})
	g.tx(t, func(tx pgx.Tx) {
		err := g.store.RevokeGlovoApprovalTx(ctx, tx, f.aar, "service:x")
		if state == "denied" {
			if err != nil {
				t.Errorf("revoke retry on denied: %v", err)
			}
		} else if !errors.Is(err, glovo.Refuse(glovo.CodeInvalidTransition)) {
			t.Errorf("revoke on %s: %v", state, err)
		}
	})
	g.tx(t, func(tx pgx.Tx) {
		if err := g.store.ConsumeGlovoApprovalTx(ctx, tx, f.aar, newCmdID(t)); err == nil {
			t.Errorf("consume on %s succeeded", state)
		}
	})
	for _, to := range []string{"approved", "pending", "reserved", "consumed", "denied", "unknown"} {
		if to == state {
			continue
		}
		tx, err := g.rtp.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		extra := ""
		switch to {
		case "consumed":
			extra = ", consumed_at=now()"
		case "reserved":
			extra = ", reserved_at=now()"
		}
		_, err = tx.Exec(ctx, `UPDATE public.action_approval_requests SET state=$2`+extra+` WHERE id=$1`, f.aar, to)
		_ = tx.Rollback(ctx)
		if err == nil {
			t.Errorf("raw %s -> %s was not refused", state, to)
		}
	}
}

// T7, T7b: expiry decisions are made on clock_timestamp().
func TestGlovoExpiryAndInputBounds(t *testing.T) {
	g := newGlovoEnv(t)
	ctx := context.Background()
	for _, d := range []time.Duration{0, -time.Second, MaxApprovalTTL + time.Second} {
		g.tx(t, func(tx pgx.Tx) {
			wi, we, err := g.store.CreateGlovoExecutionTx(ctx, tx, GlovoExecutionInput{
				Tenant: testTenant, OwnerPrincipalID: testOwner, WorkflowID: "wf", Actor: "service:glovo-prepare"})
			if err != nil {
				t.Fatal(err)
			}
			in := glovoFixtureInput(t, wi, we)
			in.ExpiresIn = d
			if _, _, err := g.store.CreateGlovoApprovalTx(ctx, tx, in); !errors.Is(err, ErrInvalid) {
				t.Errorf("ExpiresIn %s: %v", d, err)
			}
		})
	}
	var n int
	if err := g.rtp.QueryRow(ctx, `SELECT count(*) FROM public.action_approval_requests`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("bad inputs wrote %d rows (%v)", n, err)
	}

	// expires_at is clock_timestamp() + ExpiresIn: with a long statement before the insert, the
	// stored value is later than the transaction start plus ExpiresIn.
	var start, expires time.Time
	g.tx(t, func(tx pgx.Tx) {
		if err := tx.QueryRow(ctx, `SELECT now()`).Scan(&start); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT pg_sleep(0.3)`); err != nil {
			t.Fatal(err)
		}
		wi, we, err := g.store.CreateGlovoExecutionTx(ctx, tx, GlovoExecutionInput{
			Tenant: testTenant, OwnerPrincipalID: testOwner, WorkflowID: "wf", Actor: "service:glovo-prepare"})
		if err != nil {
			t.Fatal(err)
		}
		in := glovoFixtureInput(t, wi, we)
		in.ExpiresIn = time.Hour
		a, _, err := g.store.CreateGlovoApprovalTx(ctx, tx, in)
		if err != nil {
			t.Fatal(err)
		}
		expires = a.ExpiresAt
	})
	if d := expires.Sub(start); d < time.Hour+250*time.Millisecond {
		t.Fatalf("expires_at %s after the transaction start: computed from now(), not clock_timestamp()", d)
	}

	// Decide past expires_at is refused.
	f := g.prepare(t)
	g.expireNow(t, f.aar)
	g.tx(t, func(tx pgx.Tx) {
		_, err := g.store.DecideGlovoApprovalTx(ctx, tx, ActionDecisionInput{ID: f.aar, DecidedBy: "oidc:owner",
			DecidedByPrincipalID: testOwner, Decision: DecisionApprove, AuthorityBasis: GlovoAuthorityBasis})
		if !errors.Is(err, ErrApprovalExpired) {
			t.Fatalf("decide past expiry: %v", err)
		}
	})
	if err := g.assertExposed(t, f.aar, "expired"); err != nil {
		t.Fatal(err)
	}

	// fresh_until inside ReservePermitMargin at Reserve: approval_expired, still approved.
	f = g.prepare(t)
	g.decideWithFresh(t, f, ReservePermitMargin-30*time.Second)
	g.tx(t, func(tx pgx.Tx) {
		_, err := g.store.ReserveGlovoApprovalTx(ctx, tx, f.aar, f.reserveCmd(newCmdID(t)))
		wantCode(t, err, glovo.CodeApprovalExpired)
	})
	if st, c := g.stored(t, f.aar); st != "approved" || c != "" {
		t.Fatalf("a refused reserve burned the approval: %s %q", st, c)
	}

	// A fresh_until that passes between Reserve and the permit: the fence's consume refuses it
	// and the row stays reserved; a reserved row past expiry can become unknown, never consumed.
	f = g.prepare(t)
	g.decideWithFresh(t, f, ReservePermitMargin+2*time.Second)
	cmd := newCmdID(t)
	g.tx(t, func(tx pgx.Tx) {
		if _, err := g.store.ReserveGlovoApprovalTx(ctx, tx, f.aar, f.reserveCmd(cmd)); err != nil {
			t.Fatal(err)
		}
	})
	time.Sleep(2500 * time.Millisecond)
	g.rawBackdateFresh(t, f.aar)
	tx, err := g.rtp.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	wantCode(t, g.store.ConsumeGlovoApprovalTx(ctx, tx, f.aar, cmd), glovo.CodeApprovalExpired)
	_ = tx.Rollback(ctx)
	if err := g.assertExposed(t, f.aar, "expired"); err != nil {
		t.Fatal(err)
	}
	g.tx(t, func(tx pgx.Tx) {
		if err := g.store.MarkGlovoApprovalUnknownTx(ctx, tx, f.aar, cmd); err != nil {
			t.Fatal(err)
		}
	})
	if err := g.assertExposed(t, f.aar, "unknown"); err != nil {
		t.Fatal(err)
	}
	g.assertFinal(t, f, cmd, "unknown")
}

func glovoFixtureInput(t *testing.T, wi, we string) GlovoApprovalInput {
	t.Helper()
	return GlovoApprovalInput{
		Tenant: testTenant, OwnerPrincipalID: testOwner, WorkItemID: wi, ExecutionID: we,
		OrderRef: randTok(t, "ordr_", 26), ConnectionRef: randTok(t, "gcn_", 26), InstallID: "install-1",
		InstallRevision: "3", BasketFingerprint: "sha256:" + strings.Repeat("ab", 32), Provider: "fake", ExpiresIn: time.Hour,
	}
}

func (g *glovoEnv) decideWithFresh(t *testing.T, f glovoFixture, fresh time.Duration) {
	t.Helper()
	g.tx(t, func(tx pgx.Tx) {
		if _, err := g.store.DecideGlovoApprovalTx(context.Background(), tx, ActionDecisionInput{
			ID: f.aar, DecidedBy: "oidc:owner", DecidedByPrincipalID: testOwner, Decision: DecisionApprove,
			AuthorityBasis: GlovoAuthorityBasis, FreshFor: fresh}); err != nil {
			t.Fatal(err)
		}
	})
}

// expireNow moves expires_at into the past. The guard makes it immutable for
// the runtime role, so the migration role (the table owner) does it with the
// triggers off for this one statement.
func (g *glovoEnv) expireNow(t *testing.T, id string) {
	g.ownerExec(t, `expires_at = now() - interval '1 second'`, id)
}

func (g *glovoEnv) rawBackdateFresh(t *testing.T, id string) {
	g.ownerExec(t, `fresh_until = now() - interval '1 second'`, id)
}

func (g *glovoEnv) ownerExec(t *testing.T, set, id string) {
	t.Helper()
	ctx := context.Background()
	c := g.conn(g.migURL)
	tx, err := c.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, s := range []string{
		`ALTER TABLE public.action_approval_requests DISABLE TRIGGER aar_guard`,
		`UPDATE public.action_approval_requests SET ` + set + ` WHERE id='` + id + `'`,
		`ALTER TABLE public.action_approval_requests ENABLE TRIGGER aar_guard`,
	} {
		if _, err := tx.Exec(ctx, s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func (g *glovoEnv) assertExposed(t *testing.T, id, want string) error {
	t.Helper()
	st, err := g.store.GlovoApprovalStatus(context.Background(), g.rtp, []string{testTenant}, id)
	if err != nil {
		return err
	}
	if st.State != want {
		return fmt.Errorf("exposed state %s, want %s", st.State, want)
	}
	return nil
}

// T6 (reserve half): one subtest per ReserveCommand field changed and one per
// field empty; the aar_ stays approved.
func TestGlovoReserveBindingMismatch(t *testing.T) {
	g := newGlovoEnv(t)
	ctx := context.Background()
	f := g.prepare(t)
	g.decide(t, f, DecisionApprove)
	good := f.reserveCmd(newCmdID(t))
	fields := map[string]struct {
		set  func(*ReserveCommand, string)
		code glovo.Code
	}{
		"command_id":         {func(c *ReserveCommand, v string) { c.CommandID = v }, glovo.CodeInvalidRequest},
		"tenant":             {func(c *ReserveCommand, v string) { c.Tenant = v }, glovo.CodeIntentMismatch},
		"owner":              {func(c *ReserveCommand, v string) { c.OwnerPrincipalID = v }, glovo.CodeIntentMismatch},
		"execution":          {func(c *ReserveCommand, v string) { c.ExecutionID = v }, glovo.CodeIntentMismatch},
		"order":              {func(c *ReserveCommand, v string) { c.OrderRef = v }, glovo.CodeIntentMismatch},
		"connection":         {func(c *ReserveCommand, v string) { c.ConnectionRef = v }, glovo.CodeIntentMismatch},
		"install_revision":   {func(c *ReserveCommand, v string) { c.InstallRevision = v }, glovo.CodeIntentMismatch},
		"intent_hash":        {func(c *ReserveCommand, v string) { c.IntentHash = v }, glovo.CodeIntentMismatch},
		"basket_fingerprint": {func(c *ReserveCommand, v string) { c.BasketFingerprint = v }, glovo.CodeBasketChanged},
	}
	for name, fld := range fields {
		for _, mode := range []string{"changed", "empty"} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				c := good
				v := ""
				if mode == "changed" {
					v = "changed-value"
					if name == "command_id" {
						v = "cmd_short"
					}
				}
				fld.set(&c, v)
				tx, err := g.rtp.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = tx.Rollback(ctx) }()
				_, err = g.store.ReserveGlovoApprovalTx(ctx, tx, f.aar, c)
				want := fld.code
				if mode == "empty" {
					want = glovo.CodeIntentMismatch
				}
				wantCode(t, err, want)
			})
		}
	}
	if st, c := g.stored(t, f.aar); st != "approved" || c != "" {
		t.Fatalf("a refused reserve moved the row: %s %q", st, c)
	}
}

// T20: revoke and unknown are idempotent as specified; the status read returns ids and enums only.
func TestGlovoRevokeUnknownAndStatus(t *testing.T) {
	g := newGlovoEnv(t)
	ctx := context.Background()
	for _, startApproved := range []bool{false, true} {
		f := g.prepare(t)
		if startApproved {
			g.decide(t, f, DecisionApprove)
		}
		g.tx(t, func(tx pgx.Tx) {
			if err := g.store.RevokeGlovoApprovalTx(ctx, tx, f.aar, "service:cancel"); err != nil {
				t.Fatal(err)
			}
			// idempotent retry
			if err := g.store.RevokeGlovoApprovalTx(ctx, tx, f.aar, "service:cancel"); err != nil {
				t.Fatalf("retry: %v", err)
			}
		})
		if err := g.assertExposed(t, f.aar, "refused"); err != nil {
			t.Fatal(err)
		}
		var by, reason string
		if err := g.rtp.QueryRow(ctx, `SELECT decided_by, reason FROM public.action_approval_requests WHERE id=$1`, f.aar).Scan(&by, &reason); err != nil || by != "service:cancel" || reason != "order_cancelled" {
			t.Fatalf("revoke record: %q %q %v", by, reason, err)
		}
		g.assertFinal(t, f, newCmdID(t), "denied")
	}
	// A reserved row is not revocable; MarkUnknown is exact about the command.
	f := g.prepare(t)
	g.decide(t, f, DecisionApprove)
	cmd := newCmdID(t)
	g.tx(t, func(tx pgx.Tx) {
		if _, err := g.store.ReserveGlovoApprovalTx(ctx, tx, f.aar, f.reserveCmd(cmd)); err != nil {
			t.Fatal(err)
		}
	})
	g.tx(t, func(tx pgx.Tx) {
		wantCode(t, g.store.RevokeGlovoApprovalTx(ctx, tx, f.aar, "service:cancel"), glovo.CodeInvalidTransition)
	})
	g.tx(t, func(tx pgx.Tx) {
		if err := g.store.MarkGlovoApprovalUnknownTx(ctx, tx, f.aar, newCmdID(t)); !errors.Is(err, glovo.ErrNotFound) {
			t.Fatalf("another command: %v", err)
		}
	})
	g.tx(t, func(tx pgx.Tx) {
		if err := g.store.MarkGlovoApprovalUnknownTx(ctx, tx, f.aar, cmd); err != nil {
			t.Fatal(err)
		}
		if err := g.store.MarkGlovoApprovalUnknownTx(ctx, tx, f.aar, cmd); err != nil {
			t.Fatalf("second mark: %v", err)
		}
	})
	if err := g.assertExposed(t, f.aar, "unknown"); err != nil {
		t.Fatal(err)
	}
	// A consumed row: MarkUnknown is a no-op and writes nothing.
	f2 := g.prepare(t)
	g.decide(t, f2, DecisionApprove)
	cmd2 := newCmdID(t)
	g.tx(t, func(tx pgx.Tx) {
		if _, err := g.store.ReserveGlovoApprovalTx(ctx, tx, f2.aar, f2.reserveCmd(cmd2)); err != nil {
			t.Fatal(err)
		}
		if err := g.store.ConsumeGlovoApprovalTx(ctx, tx, f2.aar, cmd2); err != nil {
			t.Fatal(err)
		}
	})
	g.tx(t, func(tx pgx.Tx) {
		if err := g.store.MarkGlovoApprovalUnknownTx(ctx, tx, f2.aar, cmd2); err != nil {
			t.Fatalf("mark on consumed: %v", err)
		}
	})
	if err := g.assertExposed(t, f2.aar, "consumed"); err != nil {
		t.Fatal(err)
	}
	// Status: not_found outside tenants, for a generic row and for an unknown id.
	if _, err := g.store.GlovoApprovalStatus(ctx, g.rtp, []string{"other"}, f2.aar); !errors.Is(err, glovo.ErrNotFound) {
		t.Fatalf("foreign tenant: %v", err)
	}
	if _, err := g.store.GlovoApprovalStatus(ctx, g.rtp, []string{testTenant}, "aar_"+strings.Repeat("0", 32)); !errors.Is(err, glovo.ErrNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
	st, err := g.store.GlovoApprovalStatus(ctx, g.rtp, []string{testTenant}, f2.aar)
	if err != nil || st.ApprovalRef != f2.aar || st.OrderRef != f2.in.OrderRef || st.CommandID != cmd2 || st.State != "consumed" {
		t.Fatalf("status: %+v %v", st, err)
	}
	// The work-items role cannot read schema glovo (T20).
	if _, err := g.store.GlovoApprovalStatus(ctx, g.wiPool(), []string{testTenant}, f2.aar); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("work-items pool read: %v", err)
	}
}

// T5: 20 concurrent approve/refuse pairs, one winner per aar_.
func TestGlovoConcurrentDecisions(t *testing.T) {
	g := newGlovoEnv(t)
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		f := g.prepare(t)
		var wg sync.WaitGroup
		results := make([]error, 2)
		for j, d := range []string{DecisionApprove, DecisionDeny} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				tx, err := g.rtp.Begin(ctx)
				if err != nil {
					results[j] = err
					return
				}
				defer func() { _ = tx.Rollback(ctx) }()
				_, err = g.store.DecideGlovoApprovalTx(ctx, tx, ActionDecisionInput{ID: f.aar, DecidedBy: "oidc:owner",
					DecidedByPrincipalID: testOwner, Decision: d, AuthorityBasis: GlovoAuthorityBasis})
				if err == nil {
					err = tx.Commit(ctx)
				}
				results[j] = err
			}()
		}
		wg.Wait()
		wins := 0
		for _, e := range results {
			if e == nil {
				wins++
			} else if !errors.Is(e, ErrApprovalAlreadyDecided) {
				t.Fatalf("loser: %v", e)
			}
		}
		if wins != 1 {
			t.Fatalf("pair %d: %d winners", i, wins)
		}
	}
}

// Nil collaborator: not_ready.
func TestGlovoNilCollaboratorIsNotReady(t *testing.T) {
	g := newGlovoEnv(t)
	bare := &Store{now: time.Now}
	g.tx(t, func(tx pgx.Tx) {
		_, _, err := bare.CreateGlovoApprovalTx(context.Background(), tx, glovoFixtureInput(t, "wi_"+strings.Repeat("A", 26), "we_"+strings.Repeat("A", 26)))
		wantCode(t, err, glovo.CodeNotReady)
	})
}
