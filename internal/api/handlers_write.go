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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
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
			h.logAudit(r, audit.Entry{
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
				h.logAudit(r, audit.Entry{
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
		h.logAudit(r, audit.Entry{
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
		h.logAudit(r, audit.Entry{
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

	h.logAudit(r, audit.Entry{
		UserID:       user.ID,
		Operation:    opName,
		Parameters:   auditParams,
		WorkflowName: result.WorkflowName,
		Status:       "submitted",
		RiskLevel:    string(op.RiskLevel),
	})

	writeJSON(w, http.StatusAccepted, map[string]any{
		"message":   fmt.Sprintf("Operation submitted. Track progress: GET /api/v1/workflows/%s", result.WorkflowName),
		"operation": opName,
		"workflow":  result,
	})
}

// ArgoCompletionPayload represents the notification payload sent by Argo when a workflow completes.
type ArgoCompletionPayload struct {
	WorkflowName string `json:"workflow_name"`
	Phase        string `json:"phase"`
	FinishedAt   string `json:"finished_at,omitempty"`
}

const maxArgoWebhookBytes = 1 << 20 // 1 MiB

// HandleArgoWorkflowComplete receives completion events from Argo Workflows.
// Authenticated with HMAC-SHA256 of the raw body (header X-MCTL-Signature:
// sha256=<hex>). Fail-closed when ArgoWebhookSecret is unset so the public
// spoof/log-injection surface cannot be used.
func (h *Handlers) HandleArgoWorkflowComplete(w http.ResponseWriter, r *http.Request) {
	secret := h.opts.ArgoWebhookSecret
	if secret == "" {
		writeError(w, http.StatusUnauthorized, "webhook secret not configured")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxArgoWebhookBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read body")
		return
	}
	if len(body) > maxArgoWebhookBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "payload too large")
		return
	}
	if !validArgoWebhookHMAC(secret, body, r.Header.Get("X-MCTL-Signature")) {
		writeError(w, http.StatusUnauthorized, "invalid signature")
		return
	}

	var payload ArgoCompletionPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json payload: "+err.Error())
		return
	}

	if payload.WorkflowName == "" {
		writeError(w, http.StatusBadRequest, "workflow_name is required")
		return
	}

	slog.Info("received argo workflow completion event",
		"workflow_name", payload.WorkflowName,
		"phase", payload.Phase,
		"finished_at", payload.FinishedAt,
	)

	// Close out the audit row. Until this existed, every operation stayed
	// "submitted" forever — the status was written on submit and nothing ever
	// wrote it again, so the audit log recorded intent but never outcome.
	if h.opts.AuditLog != nil {
		if status := operations.PhaseToOpStatus(payload.Phase); audit.IsTerminal(status) {
			// Only annotate failures. The payload carries no error detail, so on
			// success there is nothing to say that "succeeded" doesn't already
			// say, and an empty message leaves any existing one intact.
			var msg string
			if status != "succeeded" {
				msg = fmt.Sprintf("argo workflow phase %s", payload.Phase)
				if payload.FinishedAt != "" {
					msg += " at " + payload.FinishedAt
				}
			}
			if h.opts.AuditLog.UpdateStatus(payload.WorkflowName, status, msg) {
				slog.Info("audit status closed by argo webhook",
					"workflow_name", payload.WorkflowName, "status", status)
			}
		}
	}

	// Always acknowledge, including when no row matched. Cron workflows have no
	// audit entry at all, and a 4xx here would only add noise to the Argo exit
	// hook, which cannot act on it anyway.
	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "acknowledged",
		"workflow_name": payload.WorkflowName,
		"phase":         payload.Phase,
	})
}

func validArgoWebhookHMAC(secret string, body []byte, header string) bool {
	const prefix = "sha256="
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	got, err := hex.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return hmac.Equal(mac.Sum(nil), got)
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
