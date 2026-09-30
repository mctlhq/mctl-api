package api

// Work-item intent reads (mctl-api#430). Intents are provenance and input --
// a bounded record of what was asked for -- never authorization or approval
// state. A retention-swept intent (mctl-api#353) reads back with an empty
// text and text_redacted: true; that emptiness is never "no intent", only
// "the text is gone".

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/workitems"
)

// writeIntentError maps the intent-specific not-found error, then defers to
// writeWorkItemError. Modeled on writeSnapshotError.
func writeIntentError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, workitems.ErrIntentNotFound):
		writeErrorCode(w, http.StatusNotFound, xrCodeIntentNotFound, "intent_id names no intent of this work item", nil)
	default:
		writeWorkItemError(w, err)
	}
}

// ListWorkItemIntents handles
// GET /api/v1/work-items/{id}/intents?after_id=&limit=, oldest first.
func (h *Handlers) ListWorkItemIntents(w http.ResponseWriter, r *http.Request) {
	user, ok := h.workItemsUser(w, r)
	if !ok {
		return
	}
	item, ok := h.visibleWorkItem(w, r, user)
	if !ok {
		return
	}
	q := r.URL.Query()
	var afterID int64
	if v := q.Get("after_id"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			writeErrorCode(w, http.StatusBadRequest, wiCodeInvalid, "after_id must be a non-negative integer", nil)
			return
		}
		afterID = n
	}
	limit := workitems.DefaultIntentPageLimit
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > workitems.MaxIntentPageLimit {
			writeErrorCode(w, http.StatusBadRequest, wiCodeInvalid,
				"limit must be an integer from 1 to "+strconv.Itoa(workitems.MaxIntentPageLimit), nil)
			return
		}
		limit = n
	}
	page, err := h.opts.WorkItems.Intents(r.Context(), item.ID, afterID, limit)
	if err != nil {
		writeIntentError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": workitems.SchemaVersion,
		"intents":        page.Intents,
		"truncated":      page.Truncated,
		"limit":          page.Limit,
	})
}

// GetWorkItemIntent handles GET /api/v1/work-items/{id}/intents/{intent_id}.
func (h *Handlers) GetWorkItemIntent(w http.ResponseWriter, r *http.Request) {
	user, ok := h.workItemsUser(w, r)
	if !ok {
		return
	}
	item, ok := h.visibleWorkItem(w, r, user)
	if !ok {
		return
	}
	intent, err := h.opts.WorkItems.Intent(r.Context(), item.ID, chi.URLParam(r, "intent_id"))
	if err != nil {
		writeIntentError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"schema_version": workitems.SchemaVersion, "intent": intent})
}
