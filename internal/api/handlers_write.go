// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// ExecuteOperation validates input, enforces RBAC, and submits an Argo Workflow.
func (h *Handlers) ExecuteOperation(w http.ResponseWriter, r *http.Request) {
	opName := chi.URLParam(r, "name")

	op, ok := h.opts.Registry.Get(opName)
	if !ok {
		writeError(w, http.StatusNotFound, "operation not found: "+opName)
		return
	}

	// HandlerOnly operations skip this generic execute path on purpose — the
	// dedicated REST handler enforces owner-gate / quota / secret-scan /
	// rate-limit checks that are not part of the generic path's RBAC, so
	// allowing execute here would let a tenant member bypass them.
	if op.HandlerOnly {
		writeError(w, http.StatusMethodNotAllowed, "operation "+opName+" is not submittable via /operations/{name}/execute; use its dedicated REST endpoint")
		return
	}

	var input map[string]string
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}

	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// AdminOnly platform-scoped ops (e.g. mctl-agents triggers) skip the
	// tenant-access check — they have no team_name parameter and are
	// gated only by admin group membership. The Executor labels them with
	// the sentinel team "platform" for audit/UI grouping.
	tenantParam := extractTenantParam(op, input)
	if op.AdminOnly {
		if !user.IsAdmin() {
			h.opts.AuditLog.Log(audit.Entry{
				UserID:    user.ID,
				Operation: opName,
				Status:    "denied",
				RiskLevel: string(op.RiskLevel),
				Message:   fmt.Sprintf("user %q not in admins group; %q is admin-only", user.ID, opName),
			})
			writeError(w, http.StatusForbidden, "operation requires admin group membership")
			return
		}
		if tenantParam == "" {
			tenantParam = "platform"
		}
	} else if tenantParam == "" {
		// Non-admin tenant-scoped ops: tenant is mandatory.
		writeError(w, http.StatusBadRequest, "team/tenant is required for workflow operations")
		return
	}

	if opName == "create-tenant" {
		// Self-service: any authenticated user can create ONE workspace.
		// Admins bypass the one-tenant limit (they manage the platform).
		if !user.IsAdmin() {
			existing := filterNonAdmin(user.Groups)
			if len(existing) > 0 {
				h.opts.AuditLog.Log(audit.Entry{
					UserID:    user.ID,
					Operation: opName,
					Status:    "denied",
					RiskLevel: string(op.RiskLevel),
					Message:   fmt.Sprintf("user %q already belongs to tenant %q", user.ID, existing[0]),
				})
				writeError(w, http.StatusForbidden,
					"you already belong to workspace \""+existing[0]+"\"; only one workspace per user is allowed")
				return
			}
		}
		// Force creator_user_id from the authenticated session (prevent spoofing).
		input["creator_user_id"] = user.ID
	} else if !user.HasTenantAccess(tenantParam) {
		h.opts.AuditLog.Log(audit.Entry{
			UserID:    user.ID,
			Operation: opName,
			Status:    "denied",
			RiskLevel: string(op.RiskLevel),
			Message:   fmt.Sprintf("user %q cannot operate on tenant %q", user.ID, tenantParam),
		})
		writeError(w, http.StatusForbidden, "access denied: you don't have access to tenant "+tenantParam)
		return
	}

	if opName == "preview-deploy" {
		if err := operations.PreparePreviewDeployInput(input); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	// Apply defaults then validate.
	input = h.opts.Registry.ApplyDefaults(op, input)
	if errs := h.opts.Registry.ValidateInput(op, input); len(errs) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":            "validation failed",
			"validationErrors": errs,
		})
		return
	}

	auditParams := redactSecrets(op, input)

	// For create-tenant: also notify Backstage for immediate catalog sync.
	if opName == "create-tenant" && h.opts.BackstageURL != "" {
		go h.notifyBackstage(input)
	}

	// Submit the Argo Workflow in the team's namespace (team-{name}).
	result, err := h.opts.Executor.Submit(r.Context(), op, input, user.ID, tenantParam)
	if err != nil {
		h.opts.AuditLog.Log(audit.Entry{
			UserID:     user.ID,
			Operation:  opName,
			Parameters: auditParams,
			Status:     "failed",
			RiskLevel:  string(op.RiskLevel),
			Message:    "submit failed: " + err.Error(),
		})
		writeError(w, http.StatusInternalServerError, "failed to submit workflow: "+err.Error())
		return
	}

	h.opts.AuditLog.Log(audit.Entry{
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
		"message":   fmt.Sprintf("Operation submitted. Track progress: GET /api/v1/workflows/%s", result.WorkflowName),
	})
}

// notifyBackstage calls the Backstage tenant API to register the new tenant
// immediately in the Backstage catalog, without waiting for TenantSync (5 min).
// Failures are non-fatal: the Argo Workflow is the source of truth.
func (h *Handlers) notifyBackstage(input map[string]string) {
	payload := map[string]string{
		"tenantName":     input["tenant_name"],
		"displayName":    input["display_name"],
		"description":    input["description"],
		"contactEmail":   input["contact_email"],
		"quotaCpuReq":    input["quota_cpu_req"],
		"quotaCpuLim":    input["quota_cpu_lim"],
		"quotaMemoryReq": input["quota_memory_req"],
		"quotaMemoryLim": input["quota_memory_lim"],
		"quotaPods":      input["quota_pods"],
		"creatorUserId":  input["creator_user_id"],
	}
	if v, ok := input["allow_internet_egress"]; ok {
		payload["allowInternetEgress"] = v
	}

	body, err := json.Marshal(payload)
	if err != nil {
		slog.Warn("backstage notify: marshal failed", "error", err)
		return
	}

	url := h.opts.BackstageURL + "/api/plugin-tenant/v0/tenants"
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		slog.Warn("backstage notify: create request failed", "error", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+h.opts.BackstageToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		slog.Warn("backstage notify: request failed", "error", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		slog.Warn("backstage notify: API returned error", "status", resp.StatusCode)
		return
	}

	slog.Info("backstage notified: tenant registered in catalog", "tenant", input["tenant_name"])
}

func extractTenantParam(op operations.Operation, input map[string]string) string {
	for _, name := range []string{"tenant_name", "team_name"} {
		if v, ok := input[name]; ok && v != "" {
			return v
		}
	}
	return ""
}

func redactSecrets(op operations.Operation, input map[string]string) map[string]string {
	secretFields := make(map[string]bool)
	for _, p := range op.Parameters {
		if p.Secret {
			secretFields[p.Name] = true
		}
	}
	result := make(map[string]string, len(input))
	for k, v := range input {
		if secretFields[k] {
			result[k] = "[REDACTED]"
		} else {
			result[k] = v
		}
	}
	return result
}

// filterNonAdmin returns group names that are NOT the "admins" group.
// Used to check if a user already belongs to a tenant.
func filterNonAdmin(groups []string) []string {
	var out []string
	for _, g := range groups {
		if g != "admins" {
			out = append(out, g)
		}
	}
	return out
}
