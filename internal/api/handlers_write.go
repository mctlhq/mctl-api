package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// ExecuteOperation validates input, checks RBAC, and submits an Argo Workflow.
func (h *Handlers) ExecuteOperation(w http.ResponseWriter, r *http.Request) {
	opName := chi.URLParam(r, "name")

	// Look up the operation.
	op, ok := h.Registry.Get(opName)
	if !ok {
		writeError(w, http.StatusNotFound, "operation not found: "+opName)
		return
	}

	// Parse input parameters.
	var input map[string]string
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}

	// Get authenticated user.
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// RBAC: check tenant access.
	tenantParam := extractTenantParam(op, input)
	if tenantParam != "" && !user.HasTenantAccess(tenantParam) {
		h.AuditLog.Log(audit.Entry{
			ID:        chi.URLParam(r, "requestID"),
			UserID:    user.ID,
			Operation: opName,
			Status:    "denied",
			RiskLevel: string(op.RiskLevel),
			Message:   "access denied: user " + user.ID + " cannot operate on tenant " + tenantParam,
		})
		writeError(w, http.StatusForbidden, "access denied: you don't have access to tenant "+tenantParam)
		return
	}

	// Apply defaults and validate.
	input = h.Registry.ApplyDefaults(op, input)
	validationErrors := h.Registry.ValidateInput(op, input)
	if len(validationErrors) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":            "validation failed",
			"validationErrors": validationErrors,
		})
		return
	}

	// Redact secrets from the audit parameters.
	auditParams := redactSecrets(op, input)

	// Submit the workflow.
	result, err := h.Executor.Submit(r.Context(), op, input, user.ID)
	if err != nil {
		h.AuditLog.Log(audit.Entry{
			UserID:    user.ID,
			Operation: opName,
			Parameters: auditParams,
			Status:    "failed",
			RiskLevel: string(op.RiskLevel),
			Message:   "submit failed: " + err.Error(),
		})
		writeError(w, http.StatusInternalServerError, "failed to submit workflow: "+err.Error())
		return
	}

	// Log successful submission.
	h.AuditLog.Log(audit.Entry{
		UserID:       user.ID,
		Operation:    opName,
		Parameters:   auditParams,
		WorkflowName: result.WorkflowName,
		Status:       "submitted",
		RiskLevel:    string(op.RiskLevel),
	})

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"operation": opName,
		"workflow":  result,
		"message":   "Operation submitted. Use GET /api/v1/workflows/" + result.WorkflowName + " to track progress.",
	})
}

// extractTenantParam returns the tenant name from input parameters.
func extractTenantParam(op operations.Operation, input map[string]string) string {
	// Operations use different parameter names for the tenant.
	for _, name := range []string{"tenant_name", "team_name"} {
		if v, ok := input[name]; ok && v != "" {
			return v
		}
	}
	return ""
}

// redactSecrets returns a copy of input with secret values replaced.
func redactSecrets(op operations.Operation, input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	secretFields := make(map[string]bool)
	for _, p := range op.Parameters {
		if p.Secret {
			secretFields[p.Name] = true
		}
	}
	for k, v := range input {
		if secretFields[k] {
			result[k] = "[REDACTED]"
		} else {
			result[k] = v
		}
	}
	return result
}
