package api

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/temporalclient"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// issue-931 T9: the sweeper against real PostgreSQL and a recording fake.

type runDescriber struct {
	*fakeDevLoopClient
	status     string
	err        error
	start      time.Time
	calls      [][2]string
	ctxErrSeen error
}

func (d *runDescriber) DescribeDevLoopRun(ctx context.Context, wf, runID string) (*temporalclient.DevLoopExecution, error) {
	d.calls = append(d.calls, [2]string{wf, runID})
	d.ctxErrSeen = ctx.Err()
	if d.err != nil {
		return nil, d.err
	}
	return &temporalclient.DevLoopExecution{Status: d.status, RunID: runID, StartTime: d.start}, nil
}

type orphanCase struct {
	store *workitems.Store
	item  string
	exec  *workitems.Execution
}

func (e *workItemsEnv) orphanFixture(store *workitems.Store, engine, ref string, queue bool) orphanCase {
	e.t.Helper()
	ctx := context.Background()
	svc := auth.NewServiceUser()
	item := e.open(svc, nil)
	id := item["id"].(string)
	mut := workitems.Mutation{Actor: "service:mctl-agent", Surface: "cli", RequestID: "r-1"}
	ex, _, err := store.AttachExecution(ctx, workitems.ExecutionInput{Mutation: mut, WorkItemID: id, Engine: engine, EngineRef: ref, Phase: workitems.PhaseRunning})
	if err != nil {
		e.t.Fatal(err)
	}
	if queue {
		m := workitems.Mutation{Actor: "github:alice", Surface: "cli", RequestID: "r-2"}
		if _, _, err := store.CreateExecutionRequest(ctx, workitems.ExecutionRequestInput{Mutation: m, WorkItemID: id,
			Kind: workitems.ExecutionRequestResume, ExpectedStateVersion: int64(item["state_version"].(float64))}); err != nil {
			e.t.Fatal(err)
		}
	}
	return orphanCase{store: store, item: id, exec: ex}
}

func (c orphanCase) phase(t *testing.T) string {
	t.Helper()
	x, err := c.store.ExecutionByID(context.Background(), c.exec.ID)
	if err != nil {
		t.Fatal(err)
	}
	return x.Phase
}

func (c orphanCase) kinds(t *testing.T) (orphan int) {
	t.Helper()
	evs, err := c.store.Events(context.Background(), c.item)
	if err != nil {
		t.Fatal(err)
	}
	for i := range evs {
		if evs[i].Kind == workitems.EventExecutionOrphanClosed {
			orphan++
		}
	}
	return
}

func queueingStore(t *testing.T, e *workItemsEnv) *workitems.Store {
	t.Helper()
	s, err := workitems.NewStore(context.Background(), e.connStr, workitems.WithQueueWhileActive(true))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestReconcileOrphans_ClosesOnlyWhatIsProvablyClosed(t *testing.T) {
	late := time.Now().Add(time.Hour) // "now" far enough for the minimum age
	type tc struct {
		name   string
		status string
		err    error
		want   string
	}
	cases := []tc{
		{"completed", "Completed", nil, "Error"}, {"failed", "Failed", nil, "Error"}, {"canceled", "Canceled", nil, "Error"},
		{"terminated", "Terminated", nil, "Error"}, {"timedout", "TimedOut", nil, "Error"},
		{"not found", "", temporalclient.ErrRunNotFound, "Error"},
		{"running", "Running", nil, "Running"}, {"continued", "ContinuedAsNew", nil, "Running"}, {"unknown", "Unknown", nil, "Running"},
		{"describe error", "", errors.New("unavailable"), "Running"},
		{"deadline", "", context.DeadlineExceeded, "Running"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newWorkItemsEnv(t)
			store := queueingStore(t, e)
			f := e.orphanFixture(store, workitems.EngineTemporal, "wf-"+e.tenant+"#run_r1", true)
			d := &runDescriber{fakeDevLoopClient: &fakeDevLoopClient{}, status: c.status, err: c.err}
			n := ReconcileOrphanedExecutions(context.Background(), store, d, late)
			if got := f.phase(t); got != c.want {
				t.Fatalf("phase = %s, want %s", got, c.want)
			}
			if (c.want == "Error") != (n == 1) || (c.want == "Error") != (f.kinds(t) == 1) {
				t.Fatalf("closed=%d orphan events=%d", n, f.kinds(t))
			}
			if len(d.calls) != 1 || d.calls[0][1] != "r1" {
				t.Fatalf("describe calls %v, want the pinned run r1", d.calls)
			}
			if c.want == "Error" {
				x, _ := store.ExecutionByID(context.Background(), f.exec.ID)
				if x.EndedAt == nil {
					t.Fatal("ended_at not set")
				}
				// the queued request is claimable again, fields unchanged
				got, _, err := store.ClaimExecutionRequest(context.Background(), workitems.ClaimInput{
					Mutation: workitems.Mutation{Actor: "service:mctl-agent", Surface: "cli", RequestID: "r-3"}, Lease: time.Minute})
				if err != nil || got == nil || got.RequestedBy != "github:alice" {
					t.Fatalf("claim after orphan close = %+v %v", got, err)
				}
			}
		})
	}
}

func TestReconcileOrphans_LeavesAloneWhatItShould(t *testing.T) {
	late := time.Now().Add(time.Hour)
	closed := func() *runDescriber {
		return &runDescriber{fakeDevLoopClient: &fakeDevLoopClient{}, status: "Terminated"}
	}
	t.Run("no queued request", func(t *testing.T) {
		e := newWorkItemsEnv(t)
		s := queueingStore(t, e)
		f := e.orphanFixture(s, workitems.EngineTemporal, "wf-"+e.tenant+"#run_r1", false)
		d := closed()
		if n := ReconcileOrphanedExecutions(context.Background(), s, d, late); n != 0 || f.phase(t) != "Running" || len(d.calls) != 0 {
			t.Fatalf("closed %d phase %s calls %v", n, f.phase(t), d.calls)
		}
	})
	t.Run("younger than the minimum age", func(t *testing.T) {
		e := newWorkItemsEnv(t)
		s := queueingStore(t, e)
		f := e.orphanFixture(s, workitems.EngineTemporal, "wf-"+e.tenant+"#run_r1", true)
		d := closed()
		if n := ReconcileOrphanedExecutions(context.Background(), s, d, time.Now()); n != 0 || f.phase(t) != "Running" || len(d.calls) != 0 {
			t.Fatalf("closed %d phase %s calls %v", n, f.phase(t), d.calls)
		}
	})
	t.Run("not a temporal execution", func(t *testing.T) {
		e := newWorkItemsEnv(t)
		s := queueingStore(t, e)
		f := e.orphanFixture(s, workitems.EngineArgo, "argo-"+e.tenant, true)
		d := closed()
		if n := ReconcileOrphanedExecutions(context.Background(), s, d, late); n != 0 || f.phase(t) != "Running" || len(d.calls) != 0 {
			t.Fatalf("closed %d phase %s calls %v", n, f.phase(t), d.calls)
		}
	})
	t.Run("already terminal", func(t *testing.T) {
		e := newWorkItemsEnv(t)
		s := queueingStore(t, e)
		f := e.orphanFixture(s, workitems.EngineTemporal, "wf-"+e.tenant+"#run_r1", true)
		if _, _, err := s.AttachExecution(context.Background(), workitems.ExecutionInput{
			Mutation:   workitems.Mutation{Actor: "service:mctl-agent", Surface: "cli", RequestID: "r-9"},
			WorkItemID: f.item, Engine: workitems.EngineTemporal, EngineRef: "wf-" + e.tenant + "#run_r1", Phase: workitems.PhaseSucceeded}); err != nil {
			t.Fatal(err)
		}
		d := closed()
		if n := ReconcileOrphanedExecutions(context.Background(), s, d, late); n != 0 || f.phase(t) != "Succeeded" || len(d.calls) != 0 {
			t.Fatalf("closed %d phase %s calls %v", n, f.phase(t), d.calls)
		}
	})
	t.Run("unpinned ref and a newer latest run", func(t *testing.T) {
		e := newWorkItemsEnv(t)
		s := queueingStore(t, e)
		f := e.orphanFixture(s, workitems.EngineTemporal, "wf-"+e.tenant, true)
		d := closed()
		d.start = time.Now().Add(2 * time.Hour) // later than the execution
		if n := ReconcileOrphanedExecutions(context.Background(), s, d, late); n != 0 || f.phase(t) != "Running" {
			t.Fatalf("closed %d phase %s", n, f.phase(t))
		}
		if len(d.calls) != 1 || d.calls[0][1] != "" {
			t.Fatalf("unpinned must describe the latest run: %v", d.calls)
		}
		// An older closed latest run does close it.
		d.start = time.Now().Add(-2 * time.Hour)
		if n := ReconcileOrphanedExecutions(context.Background(), s, d, late); n != 1 || f.phase(t) != "Error" {
			t.Fatalf("older latest run: closed %d phase %s", n, f.phase(t))
		}
	})
	t.Run("nil collaborators and cancelled context", func(t *testing.T) {
		e := newWorkItemsEnv(t)
		s := queueingStore(t, e)
		f := e.orphanFixture(s, workitems.EngineTemporal, "wf-"+e.tenant+"#run_r1", true)
		if ReconcileOrphanedExecutions(context.Background(), nil, closed(), late) != 0 || ReconcileOrphanedExecutions(context.Background(), s, nil, late) != 0 {
			t.Fatal("nil collaborator closed something")
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if n := ReconcileOrphanedExecutions(ctx, s, closed(), late); n != 0 || f.phase(t) != "Running" {
			t.Fatalf("cancelled ctx closed %d phase %s", n, f.phase(t))
		}
	})
}

// A sweep walks every page of candidates (page size 20) with a keyset cursor,
// describing each candidate exactly once.
func TestReconcileOrphans_BatchIsBounded(t *testing.T) {
	e := newWorkItemsEnv(t)
	s := queueingStore(t, e)
	for i := 0; i < 23; i++ {
		e.orphanFixture(s, workitems.EngineTemporal, "wf-"+e.tenant+"-"+string(rune('a'+i))+"#run_r", true)
	}
	d := &runDescriber{fakeDevLoopClient: &fakeDevLoopClient{}, status: "Running"}
	ReconcileOrphanedExecutions(context.Background(), s, d, time.Now().Add(time.Hour))
	if len(d.calls) != 23 {
		t.Fatalf("%d describes, want 23 (every candidate, paged by 20)", len(d.calls))
	}
}

// HTTP contract: 201 with queued_behind_execution_id when on; the replay is
// 200 and returns the original; 409 execution_active when off.
func TestCreateExecutionRequest_HTTPQueuedVsRefused(t *testing.T) {
	for _, on := range []bool{false, true} {
		e := newWorkItemsEnv(t)
		if on {
			e.h.opts.WorkItems = queueingStore(t, e)
		}
		svc := auth.NewServiceUser()
		item := e.open(svc, nil)
		id := item["id"].(string)
		execID := e.attachExecution(svc, id, "wf#run_1", "Running")
		body := map[string]any{"kind": "resume", "expected_state_version": item["state_version"], "idempotency_key": "k-http"}
		res := e.do(rootAdmin, "POST", "/api/v1/work-items/"+id+"/execution-requests", body)
		if !on {
			if res.code != 409 || code(res) != "execution_active" {
				t.Fatalf("off: %d %s", res.code, res.raw)
			}
			continue
		}
		x, _ := res.body["execution_request"].(map[string]any)
		if res.code != 201 || x["state"] != "pending" || x["queued_behind_execution_id"] != execID {
			t.Fatalf("on: %d %s", res.code, res.raw)
		}
		again := e.do(rootAdmin, "POST", "/api/v1/work-items/"+id+"/execution-requests", body)
		y, _ := again.body["execution_request"].(map[string]any)
		if again.code != 200 || y["id"] != x["id"] {
			t.Fatalf("replay: %d %s", again.code, again.raw)
		}
		if _, has := y["queued_behind_execution_id"]; has {
			t.Logf("note: replay body also carries queued_behind_execution_id")
		}
	}
}

// perRunDescriber answers by workflow id, so one sweep can see both live and
// closed runs.
type perRunDescriber struct {
	*fakeDevLoopClient
	closed map[string]bool
	calls  int
}

func (d *perRunDescriber) DescribeDevLoopRun(ctx context.Context, wf, runID string) (*temporalclient.DevLoopExecution, error) {
	d.calls++
	if d.closed[wf] {
		return &temporalclient.DevLoopExecution{Status: "Completed", RunID: runID}, nil
	}
	return &temporalclient.DevLoopExecution{Status: "Running", RunID: runID}, nil
}

// Starvation: more than orphanBatch older executions the sweeper cannot close
// must not hide a newer one it can. RED on 23734bf (oldest-20 window).
func TestReconcileOrphans_UnclosableOldRowsDoNotStarveALaterOrphan(t *testing.T) {
	e := newWorkItemsEnv(t)
	s := queueingStore(t, e)
	for i := 0; i < 21; i++ {
		e.orphanFixture(s, workitems.EngineTemporal, fmt.Sprintf("wf-%s-live-%02d#run_r", e.tenant, i), true)
	}
	deadWF := "wf-" + e.tenant + "-dead"
	dead := e.orphanFixture(s, workitems.EngineTemporal, deadWF+"#run_r", true)
	d := &perRunDescriber{fakeDevLoopClient: &fakeDevLoopClient{}, closed: map[string]bool{deadWF: true}}
	late := time.Now().Add(time.Hour)
	for sweep := 1; sweep <= 2; sweep++ {
		ReconcileOrphanedExecutions(context.Background(), s, d, late)
	}
	if got := dead.phase(t); got != "Error" {
		t.Fatalf("closable orphan still %s after 2 sweeps (%d describes): the oldest %d unclosable rows starve it", got, d.calls, orphanBatch)
	}
}
