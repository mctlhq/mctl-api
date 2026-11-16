package api

import (
	"context"
	"log/slog"
	"time"

	"github.com/mctlhq/mctl-api/internal/deployplan"
	"github.com/mctlhq/mctl-api/internal/operations"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// DeployRecordReconcileStore is the slice of the deploy-plan store the
// deployment record reconciler needs.
type DeployRecordReconcileStore interface {
	RecordsToReconcile(ctx context.Context, since, afterCreated time.Time, afterID string, limit int) ([]*deployplan.Record, error)
	SetRecordSubmission(ctx context.Context, id, status, workflow string) (*deployplan.Record, error)
	SetRunResult(ctx context.Context, id, result, imageDigest string) (*deployplan.Record, error)
}

// workflowOutcomeGetter is the slice of operations.Executor it needs.
type workflowOutcomeGetter interface {
	GetWorkflowOutcome(ctx context.Context, namespace, name string) (*operations.WorkflowOutcome, error)
}

// deployRecordReconciler completes deployment records from what Argo shows
// (mctl-api#1047): a submit whose outcome was ambiguous becomes submitted
// once its workflow is seen, or submit_failed once it has stayed absent
// long enough that no create can still land; a submitted record gets its
// run result and the image digest the run reports. Every write is
// conditional on the record's current state, so replicas running it at
// once write at most once. A read that fails changes nothing: an
// unreachable Argo is not an absent workflow (AGENTS.md, detectors).
type deployRecordReconciler struct {
	store DeployRecordReconcileStore
	exec  workflowOutcomeGetter
	op    operations.Operation
	now   func() time.Time

	interval time.Duration
	// absentAfter is how long a submitting record's workflow may be missing
	// before the create is taken as never made. A create is one apiserver
	// request; nothing lands minutes after it returned.
	absentAfter time.Duration
	// gcGrace: past it, a missing workflow may have been garbage-collected
	// (Argo keeps finished workflows 72h), so absence proves nothing. It also
	// bounds the queue: an older record can no longer be resolved, so it is
	// not examined at all, and records that never resolve (a workflow
	// collected before it was seen) cannot crowd out newer ones.
	gcGrace       time.Duration
	lookupTimeout time.Duration
	batch         int
	maxPerPass    int
}

func newDeployRecordReconciler(store DeployRecordReconcileStore, exec workflowOutcomeGetter, op operations.Operation) *deployRecordReconciler {
	return &deployRecordReconciler{
		store: store, exec: exec, op: op, now: time.Now,
		interval: time.Minute, absentAfter: 10 * time.Minute,
		gcGrace: 72 * time.Hour, lookupTimeout: 10 * time.Second, batch: 100, maxPerPass: 1000,
	}
}

func (r *deployRecordReconciler) Run(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.reconcileOnce(ctx)
		}
	}
}

func (r *deployRecordReconciler) reconcileOnce(ctx context.Context) {
	since := r.now().Add(-r.gcGrace)
	var afterCreated time.Time
	var afterID string
	for examined := 0; examined < r.maxPerPass; {
		recs, err := r.store.RecordsToReconcile(ctx, since, afterCreated, afterID, r.batch)
		if err != nil {
			slog.Error("deploy record reconcile: queue read failed", "error", err)
			return
		}
		for _, rec := range recs {
			if ctx.Err() != nil {
				return
			}
			r.reconcileRecord(ctx, rec)
		}
		if len(recs) < r.batch {
			return
		}
		last := recs[len(recs)-1]
		afterCreated, afterID = last.CreatedAt, last.ID
		examined += len(recs)
	}
}

func (r *deployRecordReconciler) reconcileRecord(ctx context.Context, rec *deployplan.Record) {
	name := rec.Workflow
	if name == "" {
		name = rec.WorkflowRef
	}
	if name == "" {
		return
	}
	ns := operations.WorkflowNamespace(r.op.WorkflowTemplate, rec.Tenant)
	lookupCtx, cancel := context.WithTimeout(ctx, r.lookupTimeout)
	out, err := r.exec.GetWorkflowOutcome(lookupCtx, ns, name)
	cancel()
	age := r.now().Sub(rec.CreatedAt)
	switch {
	case apierrors.IsNotFound(err):
		if rec.Status == deployplan.RecordSubmitting && age > r.absentAfter && age < r.gcGrace {
			r.write("submit_failed", rec.ID, func() error {
				_, err := r.store.SetRecordSubmission(ctx, rec.ID, deployplan.RecordSubmitFailed, "")
				return err
			})
		}
		// Submitted but gone: collected or deleted before its result was
		// seen. The result stays unrecorded; nothing here can know it.
		return
	case err != nil:
		slog.Warn("deploy record reconcile: workflow lookup failed", "deployment", rec.ID, "workflow", name, "namespace", ns, "error", err)
		return
	}

	if rec.Status == deployplan.RecordSubmitting {
		ok := r.write("submitted", rec.ID, func() error {
			_, err := r.store.SetRecordSubmission(ctx, rec.ID, deployplan.RecordSubmitted, rec.WorkflowRef)
			return err
		})
		if !ok {
			return
		}
	}

	var result, digest string
	switch out.Phase {
	case "Succeeded":
		result = deployplan.RunSucceeded
		digest = out.Outputs["image_digest"]
		if digest != "" && !deployplan.ValidImageDigest(digest) {
			slog.Error("deploy record reconcile: workflow reported a malformed image digest; not recorded",
				"deployment", rec.ID, "workflow", name)
			digest = ""
		}
	case "Failed", "Error":
		result = deployplan.RunFailed
	default:
		return // still running, or a phase this does not know: not an outcome
	}
	r.write("run result", rec.ID, func() error {
		_, err := r.store.SetRunResult(ctx, rec.ID, result, digest)
		return err
	})
}

// write runs one conditional update. Losing to another replica fails the
// condition and is logged like any other refused write; the next pass
// re-reads the record.
func (r *deployRecordReconciler) write(what, id string, f func() error) bool {
	if err := f(); err != nil {
		slog.Warn("deploy record reconcile: write not applied", "what", what, "deployment", id, "error", err)
		return false
	}
	return true
}

// StartDeployRecordReconciler runs the reconciler until ctx is cancelled.
func StartDeployRecordReconciler(ctx context.Context, store DeployRecordReconcileStore, exec *operations.Executor, registry *operations.Registry) {
	if store == nil || exec == nil || registry == nil {
		slog.Info("deploy record reconciler disabled: missing dependency")
		return
	}
	op, ok := registry.Get(previewDeployOp)
	if !ok {
		slog.Error("deploy record reconciler disabled: preview-deploy is not registered")
		return
	}
	newDeployRecordReconciler(store, exec, op).Run(ctx)
}
