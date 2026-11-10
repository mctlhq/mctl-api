package receipt

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/governance"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// T16: the joint-state table of design section 7.
func TestClassifyTable(t *testing.T) {
	type tc struct {
		j       Joint
		verdict string
		reason  string
	}
	cmd := func(state, status, effect string, permit bool) Joint {
		return Joint{State: state, CommandID: "cmd_x", HaveCommand: true, CommandStatus: status, EffectState: effect, HavePermit: permit}
	}
	for _, c := range []tc{
		{cmd("reserved", "pending", "none", false), VerdictOK, ""},
		{cmd("reserved", "leased", "none", false), VerdictOK, ""},
		{cmd("reserved", "cancelled", "none", false), VerdictSweepDue, ""},
		{cmd("reserved", "expired", "none", false), VerdictSweepDue, ""},
		{cmd("reserved", "completed", "none", false), VerdictSweepDue, ""},
		{cmd("reserved", "leased", "permitted", true), VerdictViolation, "reserved_with_permit"},
		{cmd("reserved", "leased", "permitted", false), VerdictViolation, "reserved_effect_not_none"},
		{Joint{State: "reserved", CommandID: "cmd_x"}, VerdictViolation, "reserved_command_missing"},
		{cmd("consumed", "leased", "permitted", true), VerdictOK, ""},
		{cmd("consumed", "completed", "succeeded", true), VerdictOK, ""},
		{cmd("consumed", "leased", "none", true), VerdictViolation, "consumed_effect_none"},
		{cmd("consumed", "leased", "permitted", false), VerdictViolation, "consumed_without_permit"},
		{Joint{State: "consumed", CommandID: "cmd_x"}, VerdictViolation, "consumed_command_missing"},
		{cmd("unknown", "cancelled", "none", false), VerdictOK, ""},
		{cmd("unknown", "expired", "not_performed", false), VerdictOK, ""},
		{cmd("unknown", "completed", "unknown", false), VerdictOK, ""},
		{cmd("unknown", "leased", "none", false), VerdictViolation, "unknown_command_not_ended"},
		{cmd("unknown", "completed", "succeeded", false), VerdictViolation, "unknown_effect_succeeded"},
		{cmd("unknown", "completed", "none", true), VerdictViolation, "unknown_with_permit"},
		{Joint{State: "unknown", CommandID: "cmd_x"}, VerdictViolation, "unknown_command_missing"},
		{Joint{State: "approved"}, VerdictOK, ""},
		{Joint{State: "pending"}, VerdictOK, ""},
		{Joint{State: "approved", CommandID: "cmd_x"}, VerdictViolation, "command_bound_in_approved"},
		{Joint{State: "denied", CommandID: "cmd_x"}, VerdictViolation, "command_bound_in_denied"},
	} {
		v, r := Classify(c.j)
		if v != c.verdict || r != c.reason {
			t.Errorf("%+v: got (%s, %s), want (%s, %s)", c.j, v, r, c.verdict, c.reason)
		}
	}
}

// T16: Audit over real rows: a reserved approval with a live command is ok, a
// spent approval without a permit is a violation, a cancelled command is due.
func TestAuditOverRealRows(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ok := e.reserved("")
	res, err := Audit(ctx, e.rtp)
	if err != nil {
		t.Fatal(err)
	}
	if res.Checked != 1 || len(res.Violations) != 0 || res.SweepDue != 0 {
		t.Fatalf("clean state: %+v", res)
	}
	if _, err := e.run(ok, ok.binding(e)); err != nil { // consumed, but the test wrote no permit
		t.Fatal(err)
	}
	res, err = Audit(ctx, e.rtp)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Violations) != 1 || res.Violations[0].Reason != "consumed_without_permit" || res.Violations[0].ApprovalID != ok.aar {
		t.Fatalf("want one consumed_without_permit violation, got %+v", res)
	}
	due := e.reserved("")
	if _, err := e.mp.Exec(ctx, `UPDATE bridge_commands SET status='cancelled' WHERE command_id=$1`, due.cmd); err != nil {
		t.Fatal(err)
	}
	res, err = Audit(ctx, e.rtp)
	if err != nil {
		t.Fatal(err)
	}
	if res.SweepDue != 1 {
		t.Fatalf("sweep due = %d, want 1: %+v", res.SweepDue, res)
	}
}

func TestAuditReadFailureIsAnError(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if res, err := Audit(ctx, e.rtp); err == nil || res != nil {
		t.Fatalf("a failed read must be an error, got %+v %v", res, err)
	}
}

// T13: the sweeper moves a reserved approval whose command ended without a
// permit, and only that one.
func TestSweeper(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	live := e.reserved("")
	ended := e.reserved("")
	permitted := e.reserved("")
	for _, c := range []string{ended.cmd, permitted.cmd} {
		if _, err := e.mp.Exec(ctx, `UPDATE bridge_commands SET status='cancelled' WHERE command_id=$1`, c); err != nil {
			t.Fatal(err)
		}
	}
	// A command that ended but holds a permit row is never swept.
	if _, err := e.mp.Exec(ctx, `INSERT INTO bridge_write_permits (command_id, operation_key, approval_ref, fence_ref, lease_epoch)
		VALUES ($1,'op','`+permitted.aar+`','afr_x',1)`, permitted.cmd); err != nil {
		t.Fatal(err)
	}
	sw := &Sweeper{Begin: func(ctx context.Context) (pgx.Tx, error) { return e.rtp.Begin(ctx) }, Approvals: e.store}
	n, err := sw.Sweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("swept %d, want exactly 1", n)
	}
	for aar, want := range map[string]string{live.aar: workitems.ApprovalReserved, ended.aar: workitems.ApprovalUnknown, permitted.aar: workitems.ApprovalReserved} {
		if got := e.state(aar); got != want {
			t.Errorf("%s: state %s, want %s", aar, got, want)
		}
	}
	if n2, err := sw.Sweep(ctx); err != nil || n2 != 0 {
		t.Fatalf("second tick: %d %v, want 0", n2, err)
	}
}

func isNotReady(err error) bool {
	var ge *glovo.Error
	return errors.As(err, &ge) && ge.Code == glovo.CodeNotReady
}

func TestSweeperNeedsItsDependencies(t *testing.T) {
	var nilStore *workitems.Store
	for name, s := range map[string]*Sweeper{
		"nil sweeper": nil,
		"no begin":    {Approvals: nilStore},
		"nil store":   {Begin: func(context.Context) (pgx.Tx, error) { return nil, errors.New("unused") }, Approvals: nilStore},
	} {
		if _, err := s.Sweep(context.Background()); !isNotReady(err) {
			t.Errorf("%s: err = %v, want not_ready", name, err)
		}
	}
}

// T21: two permit transactions for the same approval serialize on L4; exactly
// one spends it, the other is refused, and neither is a deadlock.
func TestConcurrentFencesSerialize(t *testing.T) {
	e := newEnv(t)
	f := e.reserved("")
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := context.Background()
			tx, err := e.rtp.Begin(ctx)
			if err != nil {
				errs[i] = err
				return
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if err := e.fence.PreLock(ctx, tx, e.caller, f.cmd); err != nil {
				errs[i] = err
				return
			}
			if _, err := e.fence.Check(ctx, tx, f.binding(e)); err != nil {
				errs[i] = err
				return
			}
			errs[i] = tx.Commit(ctx)
		}()
	}
	wg.Wait()
	won := 0
	for _, err := range errs {
		if err == nil {
			won++
			continue
		}
		var pg interface{ SQLState() string }
		if errors.As(err, &pg) && pg.SQLState() == "40P01" {
			t.Fatalf("deadlock: %v", err)
		}
		if _, ok := CodeOf(err); !ok {
			t.Fatalf("loser is not a typed refusal: %v", err)
		}
	}
	if won != 1 {
		t.Fatalf("%d fences won, want exactly 1: %v", won, errs)
	}
}

// T18: Ready names the first missing item, and is nil only when everything is
// wired.
func TestReady(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ok := func(context.Context) error { return nil }
	good := func() Deps {
		return Deps{GlovoURLExplicit: true, WorkItemsURLExplicit: true, GlovoStoreReady: ok, ProveOneDatabase: ok,
			Glovo: e.rtp, Audit: e.rtp, Policies: governance.Policies, WorkItems: e.store, Bridge: e, Orders: e.ord,
			Conns: e.conns, Members: e.members, WireVersionsEnabled: func() bool { return true }}
	}
	if err := Ready(ctx, good()); err != nil {
		t.Fatalf("fully wired Ready: %v", err)
	}
	var nilStore *workitems.Store
	for name, c := range map[string]struct {
		mut    func(*Deps)
		reason string
	}{
		"glovo url":       {func(d *Deps) { d.GlovoURLExplicit = false }, NotReadyGlovoURL},
		"work items url":  {func(d *Deps) { d.WorkItemsURLExplicit = false }, NotReadyWorkItemsURL},
		"typed nil store": {func(d *Deps) { d.WorkItems = nilStore }, NotReadyCollaborator},
		"no orders":       {func(d *Deps) { d.Orders = nil }, NotReadyCollaborator},
		"no members":      {func(d *Deps) { d.Members = nil }, NotReadyCollaborator},
		"no wire func":    {func(d *Deps) { d.WireVersionsEnabled = nil }, NotReadyCollaborator},
		"glovo store":     {func(d *Deps) { d.GlovoStoreReady = func(context.Context) error { return errors.New("x") } }, NotReadyGlovoStore},
		"one database":    {func(d *Deps) { d.ProveOneDatabase = func(context.Context) error { return errors.New("x") } }, NotReadyOneDatabase},
		"policy":          {func(d *Deps) { d.Policies = governance.PolicySet{} }, NotReadyPolicy},
		"wire versions":   {func(d *Deps) { d.WireVersionsEnabled = func() bool { return false } }, NotReadyWireVersions},
	} {
		t.Run(name, func(t *testing.T) {
			d := good()
			c.mut(&d)
			err := Ready(ctx, d)
			var nr *glovo.NotReadyError
			if !errors.As(err, &nr) || nr.Reason != c.reason {
				t.Fatalf("err = %v, want not_ready %s", err, c.reason)
			}
		})
	}
	t.Run("approval schema", func(t *testing.T) {
		// The work-items role is not the Glovo runtime role: grants differ.
		d := good()
		d.Glovo = e.mp // the migration role owns the tables
		var nr *glovo.NotReadyError
		if err := Ready(ctx, d); !errors.As(err, &nr) || nr.Reason != NotReadySchema {
			t.Fatalf("err = %v, want not_ready %s", err, NotReadySchema)
		}
	})
	t.Run("audit violation", func(t *testing.T) {
		f := e.reserved("")
		if _, err := e.run(f, f.binding(e)); err != nil { // consumed without a permit
			t.Fatal(err)
		}
		var nr *glovo.NotReadyError
		if err := Ready(ctx, good()); !errors.As(err, &nr) || nr.Reason != NotReadyAudit {
			t.Fatalf("err = %v, want not_ready %s", err, NotReadyAudit)
		}
	})
}
