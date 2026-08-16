package api

import (
	"context"
	"log/slog"
	"time"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/operations"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// auditReconciler closes out audit rows the completion webhook never reached.
//
// The webhook alone is not enough, and not as a matter of resilience: the
// global-workflow-completion-hook reads ARGO_WEBHOOK_SECRET from an
// ExternalSecret that exists only in the argo-workflows namespace, and exits
// silently when it is absent. operations.WorkflowNamespace sends only
// create-tenant, delete-tenant*, openclaw-*, platform-skill-* and mctl-agents-*
// there. Everything else — deploy-service, provision-database, retire-service,
// preview-deploy, scale-service, rollback-service — runs in the tenant's own
// namespace, where the secret does not exist and the hook therefore never
// fires. Those are the majority of operations by volume.
//
// Distributing the HMAC secret to tenant namespaces would fix the coverage and
// break the authentication: any tenant workload could then read it and forge
// completion events for other tenants' workflows. So the second path reads
// Argo directly instead, using mctl-api's own RBAC.
// workflowStatusGetter is the slice of operations.Executor the reconciler
// needs. Narrow, so reconcileOnce's branching can be tested without a
// Kubernetes API.
type workflowStatusGetter interface {
	GetWorkflowStatus(ctx context.Context, namespace, name string) (map[string]interface{}, error)
}

type auditReconciler struct {
	log      audit.Log
	exec     workflowStatusGetter
	registry *operations.Registry

	// interval between passes.
	interval time.Duration
	// lookback bounds how far back to consider rows; older ones are past any
	// hope of resolution and would be rescanned forever.
	lookback time.Duration
	// batch caps rows examined per pass.
	batch int
	// gcGrace is how long after submission a missing workflow object is treated
	// as garbage-collected rather than not-yet-created. Argo's ttlStrategy uses
	// secondsAfterFailure: 259200 (72h), so anything older than that with no
	// object is gone for good.
	gcGrace time.Duration
	// lookupTimeout bounds each workflow lookup. Without it a single slow or
	// unreachable Argo read blocks the whole pass on the process-lifetime
	// context, and neither rest.Config nor the caller sets a client timeout.
	lookupTimeout time.Duration
}

func newAuditReconciler(log audit.Log, exec workflowStatusGetter, registry *operations.Registry) *auditReconciler {
	return &auditReconciler{
		log:           log,
		exec:          exec,
		registry:      registry,
		interval:      3 * time.Minute,
		lookback:      7 * 24 * time.Hour,
		batch:         200,
		gcGrace:       72 * time.Hour,
		lookupTimeout: 10 * time.Second,
	}
}

// Run reconciles until ctx is cancelled.
func (r *auditReconciler) Run(ctx context.Context) {
	if r.log == nil || r.exec == nil || r.registry == nil {
		slog.Info("audit reconciler disabled: missing dependency")
		return
	}
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

func (r *auditReconciler) reconcileOnce(ctx context.Context) {
	pending := r.log.ListByStatus("submitted", r.lookback, r.batch)
	if len(pending) == 0 {
		return
	}

	var closed, gone int
	for _, e := range pending {
		select {
		case <-ctx.Done():
			return
		default:
		}

		op, ok := r.registry.Get(e.Operation)
		if !ok {
			// Operation removed from the registry since submission; without its
			// WorkflowTemplate the namespace cannot be derived. Leave the row
			// alone rather than guess.
			continue
		}
		ns := operations.WorkflowNamespace(op.WorkflowTemplate, auditEntryTenant(&e))
		if ns == "" {
			continue
		}

		lookupCtx, cancel := context.WithTimeout(ctx, r.lookupTimeout)
		status, err := r.exec.GetWorkflowStatus(lookupCtx, ns, e.WorkflowName)
		cancel()
		if err != nil {
			if apierrors.IsNotFound(err) && time.Since(e.Timestamp) > r.gcGrace {
				if r.log.UpdateStatus(e.WorkflowName, "expired",
					"workflow object was garbage-collected before its outcome was recorded") {
					gone++
				}
			}
			if !apierrors.IsNotFound(err) {
				// Left for the next pass either way, but log it: without this an
				// operator cannot tell "stuck because Argo is unreachable or
				// denying us" from "not resolved yet".
				slog.Warn("audit reconcile: workflow lookup failed",
					"workflow", e.WorkflowName, "namespace", ns, "error", err)
			}
			// A NotFound inside the grace period means the workflow may simply
			// not be created yet, so it is left alone without noise.
			continue
		}

		// GetWorkflowStatus returns a trimmed object, not a flat status:
		// phase lives under the nested "status" block.
		inner, _ := status["status"].(map[string]interface{})
		if inner == nil {
			continue
		}
		phase, _ := inner["phase"].(string)
		opStatus := operations.PhaseToOpStatus(phase)
		if !audit.IsTerminal(opStatus) {
			continue
		}
		var msg string
		if opStatus != "succeeded" {
			msg = "argo workflow phase " + phase
			if m, _ := inner["message"].(string); m != "" {
				msg += ": " + m
			}
		}
		if r.log.UpdateStatus(e.WorkflowName, opStatus, msg) {
			closed++
		}
	}

	if closed > 0 || gone > 0 {
		slog.Info("audit reconcile pass complete",
			"examined", len(pending), "closed", closed, "expired", gone)
	}
}

// StartAuditReconciler runs the reconciler until ctx is cancelled. Exported so
// cmd/api can start it without exposing the type.
func StartAuditReconciler(ctx context.Context, log audit.Log, exec *operations.Executor, registry *operations.Registry) {
	if exec == nil {
		slog.Info("audit reconciler disabled: no executor")
		return
	}
	newAuditReconciler(log, exec, registry).Run(ctx)
}
