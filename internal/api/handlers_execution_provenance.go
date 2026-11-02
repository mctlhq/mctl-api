package api

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

const (
	codeExecutionProvenanceAbsent      = "execution_provenance_absent"
	codeExecutionProvenanceUnavailable = "execution_provenance_unavailable"
)

// GetExecutionProvenance handles GET /api/v1/executions/{execution_id}/provenance
// (mctl-api#896): the stored execution_attempt_v1 record, never recomputed.
// Allowed for a platform administrator and for the agent run token bound to
// the same execution. A store that cannot be read is 503, never 404.
func (h *Handlers) GetExecutionProvenance(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	id := chi.URLParam(r, "execution_id")
	own := user.IsAgent() && user.ExecutionID() != "" && user.ExecutionID() == id
	if !own && !user.IsAdmin() {
		writeError(w, http.StatusForbidden, "execution provenance is readable by administrators and by the run bound to that execution")
		return
	}
	if h.opts.WorkItems == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, codeExecutionProvenanceUnavailable, "work-items store not configured", nil)
		return
	}
	p, err := h.opts.WorkItems.ExecutionProvenance(r.Context(), id)
	switch {
	case errors.Is(err, workitems.ErrProvenanceAbsent):
		writeErrorCode(w, http.StatusNotFound, codeExecutionProvenanceAbsent, "no provenance is recorded for this execution", nil)
	case err != nil:
		slog.Error("execution provenance read failed", "execution_id", id, "error", err)
		writeErrorCode(w, http.StatusServiceUnavailable, codeExecutionProvenanceUnavailable, "execution provenance could not be read", nil)
	default:
		writeJSON(w, http.StatusOK, p)
	}
}
