package api

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/temporalclient"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

const (
	// OrphanReconcileInterval is how often the sweeper runs.
	OrphanReconcileInterval = 2 * time.Minute
	// orphanMinAge keeps a just-started execution out of reach: its run may
	// not be visible to Temporal yet.
	orphanMinAge = 5 * time.Minute
	// orphanBatch is the page size of the keyset-paged candidate query; a sweep walks all pages within its deadline.
	orphanBatch = 20
)

// orphanRunClosed lists the Temporal statuses that prove the owning run is
// over. Running, ContinuedAsNew and Unknown never close an execution.
var orphanRunClosed = map[string]bool{
	"Completed": true, "Failed": true, "Canceled": true, "Terminated": true, "TimedOut": true,
}

// ReconcileOrphanedExecutions closes Temporal-owned executions that have a
// request queued behind them when their owning run has already closed (or
// no longer exists), so the queued request is not blocked forever. It is
// fail closed: a run it cannot read is never treated as closed. The closed
// execution becomes Error, since its outcome was never reported. It returns
// how many executions it closed.
func ReconcileOrphanedExecutions(ctx context.Context, store *workitems.Store, tc DevLoopClient, now time.Time) int {
	if store == nil || tc == nil {
		return 0
	}
	actor := workitems.Mutation{Actor: principalOf(auth.NewServiceUser())}
	closed := 0
	var cursor *workitems.Execution
	// Page with a keyset cursor so executions that cannot be closed (still
	// running, unreadable) do not starve the ones behind them.
	for ctx.Err() == nil {
		execs, err := store.OpenExecutionsWithQueuedRequests(ctx, workitems.EngineTemporal, now.Add(-orphanMinAge), orphanBatch, cursor)
		if err != nil {
			slog.Warn("orphan reconcile: list candidates failed", "error", err)
			return closed
		}
		for i := range execs {
			e := &execs[i]
			status, ok := orphanEngineStatus(ctx, tc, *e)
			if !ok {
				continue
			}
			_, did, err := store.CloseOrphanedExecution(ctx, workitems.OrphanCloseInput{
				Mutation: actor, ExecutionID: e.ID, ExpectedPhase: e.Phase, EngineStatus: status,
			})
			if err != nil {
				slog.Warn("orphan reconcile: close failed", "execution_id", e.ID, "error", err)
				continue
			}
			if did {
				closed++
				slog.Info("orphan reconcile: closed execution", "execution_id", e.ID, "engine_ref", e.EngineRef, "engine_status", status)
			}
		}
		if len(execs) < orphanBatch {
			break
		}
		cursor = &execs[len(execs)-1]
	}
	return closed
}

// orphanEngineStatus reports the engine status that licenses closing e, and
// whether it does.
func orphanEngineStatus(ctx context.Context, tc DevLoopClient, e workitems.Execution) (string, bool) {
	wf, runID, pinned := parseTemporalRef(e.EngineRef)
	if wf == "" {
		slog.Warn("orphan reconcile: unparsable engine_ref", "execution_id", e.ID, "engine_ref", e.EngineRef)
		return "", false
	}
	d, err := tc.DescribeDevLoopRun(ctx, wf, runID)
	if errors.Is(err, temporalclient.ErrRunNotFound) {
		return "not_found", true
	}
	if err != nil {
		slog.Warn("orphan reconcile: describe failed; leaving execution open", "execution_id", e.ID, "error", err)
		return "", false
	}
	if !orphanRunClosed[d.Status] {
		slog.Debug("orphan reconcile: run not closed", "execution_id", e.ID, "status", d.Status)
		return "", false
	}
	if !pinned && !d.StartTime.Before(e.StartedAt) {
		// The latest run began after this execution: it cannot be shown
		// which run owns the execution, so leave it.
		slog.Warn("orphan reconcile: latest run is newer than the execution; cannot prove ownership",
			"execution_id", e.ID, "engine_ref", e.EngineRef)
		return "", false
	}
	return d.Status, true
}

// parseTemporalRef splits an engine_ref: "<wf>#run_<id>" pins a run;
// "<wf>" and "<wf>#xr_..." name only the workflow (latest run).
func parseTemporalRef(ref string) (wf, runID string, pinned bool) {
	wf, suffix, _ := strings.Cut(ref, "#")
	if id, ok := strings.CutPrefix(suffix, "run_"); ok && id != "" {
		return wf, id, true
	}
	return wf, "", false
}
