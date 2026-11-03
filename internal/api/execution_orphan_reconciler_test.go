package api

import (
	"context"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/temporalclient"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

func TestParseTemporalRef(t *testing.T) {
	for ref, want := range map[string][3]any{
		"wf#run_abc": {"wf", "abc", true},
		"wf":         {"wf", "", false},
		"wf#xr_1":    {"wf", "", false},
		"wf#run_":    {"wf", "", false},
	} {
		wf, run, pinned := parseTemporalRef(ref)
		if wf != want[0] || run != want[1] || pinned != want[2] {
			t.Errorf("%q = %q %q %v", ref, wf, run, pinned)
		}
	}
}

func TestOrphanEngineStatus_FailsClosed(t *testing.T) {
	started := time.Now().Add(-time.Hour)
	e := workitems.Execution{ID: "we_1", EngineRef: "wf#run_1", StartedAt: started}
	cases := map[string]struct {
		d    *temporalclient.DevLoopExecution
		err  error
		want bool
	}{
		"completed":      {d: &temporalclient.DevLoopExecution{Status: "Completed"}, want: true},
		"terminated":     {d: &temporalclient.DevLoopExecution{Status: "Terminated"}, want: true},
		"not found":      {err: temporalclient.ErrRunNotFound, want: true},
		"running":        {d: &temporalclient.DevLoopExecution{Status: "Running"}},
		"continued":      {d: &temporalclient.DevLoopExecution{Status: "ContinuedAsNew"}},
		"unknown":        {d: &temporalclient.DevLoopExecution{Status: "Unknown"}},
		"describe error": {err: context.DeadlineExceeded},
	}
	for name, c := range cases {
		tc := &fakeDevLoopClient{describeExec: c.d, describeExecErr: c.err}
		if _, ok := orphanEngineStatus(context.Background(), tc, e); ok != c.want {
			t.Errorf("%s: closable = %v, want %v", name, ok, c.want)
		}
	}
	// An unpinned ref is closable only when the latest run is older than
	// the execution.
	e.EngineRef = "wf"
	newer := &fakeDevLoopClient{describeExec: &temporalclient.DevLoopExecution{Status: "Completed", StartTime: started.Add(time.Minute)}}
	if _, ok := orphanEngineStatus(context.Background(), newer, e); ok {
		t.Error("a newer latest run must not close the execution")
	}
	older := &fakeDevLoopClient{describeExec: &temporalclient.DevLoopExecution{Status: "Completed", StartTime: started.Add(-time.Minute)}}
	if _, ok := orphanEngineStatus(context.Background(), older, e); !ok {
		t.Error("an older closed latest run should close the execution")
	}
}
