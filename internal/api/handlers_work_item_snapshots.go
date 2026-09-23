package api

import (
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Sealed ContextSnapshots (mctl-agents#431). One immutable snapshot per
// execution; the store verifies the bytes against their hash on every write
// and read. Only the agents that run executions seal them.

// maxSnapshotBodyBytes bounds a seal request: the base64 of at most
// workitems.MaxSnapshotBytes plus the small metadata fields.
const maxSnapshotBodyBytes = (workitems.MaxSnapshotBytes/3+1)*4 + 16<<10

const (
	wiCodeSnapshotDivergence = "snapshot_divergence"
	wiCodePriorSnapshot      = "prior_snapshot_invalid"
	wiCodeSnapshotNotFound   = "snapshot_not_found"
	wiCodeExecutionNotFound  = "execution_not_found"
	wiCodeSnapshotForbidden  = "snapshot_writer_forbidden"
)

type snapshotBody struct {
	ExecutionSequence int    `json:"execution_sequence"`
	CanonicalB64      string `json:"canonical_b64"`
	ContentHash       string `json:"content_hash"`
	Strategy          string `json:"strategy"`
	StrategyVersion   string `json:"strategy_version"`
	PriorExecutionID  string `json:"prior_execution_id,omitempty"`
	PriorSnapshotID   string `json:"prior_snapshot_id,omitempty"`
}

// writeSnapshotError maps the snapshot-specific errors, then defers to
// writeWorkItemError. The not-found cases get their own codes: a client
// reads work_item_not_found as "the work item is gone".
func writeSnapshotError(w http.ResponseWriter, err error) {
	var details map[string]interface{}
	var ce *workitems.ConflictError
	if errors.As(err, &ce) && ce.Current != nil {
		details = map[string]interface{}{"state": ce.Current.State, "state_version": ce.Current.StateVersion}
	}
	switch {
	case errors.Is(err, workitems.ErrSnapshotDivergence):
		writeErrorCode(w, http.StatusConflict, wiCodeSnapshotDivergence, err.Error(), details)
	case errors.Is(err, workitems.ErrPriorSnapshot):
		writeErrorCode(w, http.StatusConflict, wiCodePriorSnapshot, err.Error(), details)
	case errors.Is(err, workitems.ErrSnapshotNotFound):
		writeErrorCode(w, http.StatusNotFound, wiCodeSnapshotNotFound, "context snapshot not found", nil)
	case errors.Is(err, workitems.ErrExecutionNotFound):
		writeErrorCode(w, http.StatusNotFound, wiCodeExecutionNotFound, "execution not found on this work item", nil)
	default:
		writeWorkItemError(w, err)
	}
}

// SealWorkItemSnapshot handles
// POST /api/v1/work-items/{id}/executions/{execution_id}/snapshot.
// 201 stores a new snapshot; 200 returns the one this execution already
// sealed with the same bytes; 409 snapshot_divergence refuses different
// bytes for the same execution.
func (h *Handlers) SealWorkItemSnapshot(w http.ResponseWriter, r *http.Request) {
	user, ok := h.workItemsUser(w, r)
	if !ok {
		return
	}
	// Executions are run by services; a person or a relayed surface never
	// seals what an execution saw.
	if _, relayed := user.RelaySurface(); relayed || !user.IsService() {
		writeErrorCode(w, http.StatusForbidden, wiCodeSnapshotForbidden,
			"only the service running an execution may seal its context snapshot", nil)
		return
	}
	item, ok := h.visibleWorkItem(w, r, user)
	if !ok {
		return
	}
	var body snapshotBody
	if !decodeWorkItemBodyLimit(w, r, &body, maxSnapshotBodyBytes) {
		return
	}
	canonical, err := base64.StdEncoding.Strict().DecodeString(body.CanonicalB64)
	if err != nil {
		writeErrorCode(w, http.StatusBadRequest, wiCodeInvalid, "canonical_b64 is not standard base64", nil)
		return
	}
	m, ok := mutationFor(w, r, user, "snapshot", item.ID, "", "", body)
	if !ok {
		return
	}
	snap, created, err := h.opts.WorkItems.SealSnapshot(r.Context(), workitems.SnapshotInput{
		Mutation:          m,
		WorkItemID:        item.ID,
		ExecutionID:       chi.URLParam(r, "execution_id"),
		ExecutionSequence: body.ExecutionSequence,
		Canonical:         canonical,
		ContentHash:       body.ContentHash,
		Strategy:          body.Strategy,
		StrategyVersion:   body.StrategyVersion,
		PriorExecutionID:  body.PriorExecutionID,
		PriorSnapshotID:   body.PriorSnapshotID,
	})
	if err != nil {
		writeSnapshotError(w, err)
		return
	}
	if created {
		h.auditWorkItem(r, user, "work_item.snapshot", item.ID, item.Tenant, map[string]string{
			"snapshot_id": snap.ID, "execution_id": snap.ExecutionID, "content_hash": snap.ContentHash,
		})
	}
	writeJSON(w, createdStatus(created), map[string]any{"schema_version": workitems.SchemaVersion, "snapshot": snap})
}

// GetWorkItemExecutionSnapshot handles
// GET /api/v1/work-items/{id}/executions/{execution_id}/snapshot.
func (h *Handlers) GetWorkItemExecutionSnapshot(w http.ResponseWriter, r *http.Request) {
	user, ok := h.workItemsUser(w, r)
	if !ok {
		return
	}
	item, ok := h.visibleWorkItem(w, r, user)
	if !ok {
		return
	}
	snap, err := h.opts.WorkItems.ExecutionSnapshot(r.Context(), item.ID, chi.URLParam(r, "execution_id"))
	if err != nil {
		writeSnapshotError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"schema_version": workitems.SchemaVersion, "snapshot": snap})
}

// GetWorkItemSnapshot handles GET /api/v1/work-items/{id}/snapshots/{snapshot_id}.
func (h *Handlers) GetWorkItemSnapshot(w http.ResponseWriter, r *http.Request) {
	user, ok := h.workItemsUser(w, r)
	if !ok {
		return
	}
	item, ok := h.visibleWorkItem(w, r, user)
	if !ok {
		return
	}
	snap, err := h.opts.WorkItems.Snapshot(r.Context(), item.ID, chi.URLParam(r, "snapshot_id"))
	if err != nil {
		writeSnapshotError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"schema_version": workitems.SchemaVersion, "snapshot": snap})
}

// ListWorkItemSnapshots handles GET /api/v1/work-items/{id}/snapshots,
// oldest execution first.
func (h *Handlers) ListWorkItemSnapshots(w http.ResponseWriter, r *http.Request) {
	user, ok := h.workItemsUser(w, r)
	if !ok {
		return
	}
	item, ok := h.visibleWorkItem(w, r, user)
	if !ok {
		return
	}
	snaps, err := h.opts.WorkItems.Snapshots(r.Context(), item.ID)
	if err != nil {
		writeSnapshotError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"schema_version": workitems.SchemaVersion, "snapshots": snaps})
}
