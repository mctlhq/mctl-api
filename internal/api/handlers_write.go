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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/mctlhq/mctl-api/internal/telemetry"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
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

	// Span is started only for a registered operation so the caller-controlled
	// name never reaches span names or attributes unvalidated.
	ctx, span := telemetry.Tracer().Start(r.Context(), "operation.execute "+opName)
	defer span.End()
	span.SetAttributes(telemetry.OperationName(opName))
	r = r.WithContext(ctx)

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

	// A CI principal has no tenant membership or role: it is authorized
	// here, on the raw input before anything is stripped or defaulted, and
	// only that decision lets it past the tenant checks below (mctl-api#530).
	ciAuthorized := false
	if user.IsCI() {
		if !h.authorizeCIDeploy(w, r, user, opName, op, input) {
			return
		}
		ciAuthorized = true
	}

	// Drop anything the operation does not declare, before RBAC reads the
	// input and before it reaches Argo — but AFTER the authentication check,
	// so an unauthenticated caller cannot spend the server's CPU sorting keys
	// or fill the log with parameter names of its own choosing (agy P2).
	//
	// An undeclared key skipped validation
	// entirely (ValidateInput only walks op.Parameters) and was still
	// forwarded verbatim as a workflow parameter, which let a caller set
	// config_patch — a raw yq expression run against values.yaml by
	// tpl-git-commit — from the request body (gitops#997).
	//
	// Dropped rather than rejected: a 400 here would fail closed on any live
	// caller that happens to send an extra field. The MCP tool surface was
	// audited against the registry when this landed and sends no undeclared
	// parameter through this path, so the log line below is expected to stay
	// silent; if it does, this can be tightened to a rejection.
	input, dropped := h.opts.Registry.StripUndeclared(op, input)
	if len(dropped) > 0 {
		slog.Warn("ignoring undeclared operation parameters",
			"operation", opName, "parameters", strings.Join(dropped, ", "))
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
		// The owner entry is keyed by the creator's canonical principal too:
		// principal-mode authorization grants by members[].principalId alone
		// (mctl-api#377), so without it the creator would be locked out of
		// the tenant they just made. Taken from the session like the login;
		// a caller-supplied value is never forwarded. A creator whose
		// principal could not be established is refused in every mode:
		// sending none would land a login-only owner on gitops main (the
		// workflow pushes directly), and the login is not an authorization
		// key. 503, not 403: the identity is unknown, not denied.
		delete(input, "creator_principal_id")
		pid := user.PrincipalID()
		if !auth.ValidPrincipalID(pid) {
			h.logAudit(r, audit.Entry{
				UserID:    user.ID,
				Operation: opName,
				Status:    "failed",
				RiskLevel: string(op.RiskLevel),
				Message:   "create-tenant refused: the creator has no resolved principal",
			})
			slog.Warn("create-tenant refused: no resolved creator principal", "user", user.ID)
			writeErrorCode(w, http.StatusServiceUnavailable, "creator_principal_unavailable",
				"your account's platform identity could not be established; try again later", nil)
			return
		}
		input["creator_principal_id"] = pid
	} else if !ciAuthorized && !user.HasTenantAccess(tenantParam) {
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

	// Membership is not permission (mctl-api#478). Being a member of the
	// tenant got the caller this far; what they may do to it is decided by
	// their role there against the operation's minimum. Before this check a
	// developer, or a read-only viewer, could delete the tenant they belong
	// to. create-tenant is the one operation with no tenant to hold a role
	// in; its own rules are the branch above.
	if opName != "create-tenant" && !ciAuthorized && !h.requireTenantRole(w, r, user, tenantParam, op.MinRole, opName, op.RiskLevel) {
		return
	}

	if opName == "preview-deploy" {
		if err := operations.PreparePreviewDeployInput(input); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	// mctl-agents-approve records approval provenance in gitops — it is the
	// thing that writes approved_by into .status.yaml and into the commit
	// message. The approver is therefore a fact about who called, not a field
	// the caller fills in (gitops#986).
	//
	// Previously the caller's identity was only a DEFAULT and "an explicit
	// approver still wins", so any authenticated admin could POST
	// {"approver":"someone-else"} and attribute an approval to a colleague.
	//
	// The one caller that legitimately names someone else is the Temporal
	// worker: it submits under the mctl-agent service principal while
	// relaying the human approver from its signal payload, which the dev-loop
	// approve endpoint took from ITS authenticated caller. So the relay is
	// allowed for that principal alone, and asserted by nobody else.
	//
	// The audit log below records user.ID either way, so the relayed value
	// never displaces the record of who actually made the request.
	//
	// The relay is being retired (mctl-api#571): an approval will be
	// exercised through a server-held action-approval grant instead of a
	// string. Until mctl-agents has moved over, every relay is audited as
	// approver.legacy_relay, so "is anything still using it?" is a query;
	// MCTL_AGENTS_APPROVE_LEGACY_APPROVER=false then refuses it.
	if opName == "mctl-agents-approve" {
		if user.IsService() {
			relayed := input["approver"]
			switch {
			case relayed == "" || relayed == user.ID:
				input["approver"] = user.ID
			case h.opts.LegacyApproverDisabled:
				h.logAudit(r, audit.Entry{
					UserID:     user.ID,
					Operation:  opName,
					Status:     "denied",
					RiskLevel:  string(op.RiskLevel),
					Message:    "free-text approver relay refused: MCTL_AGENTS_APPROVE_LEGACY_APPROVER is off",
					Parameters: legacyRelayParams(user, opName, input),
				})
				writeErrorCode(w, http.StatusBadRequest, "legacy_approver_disabled",
					"the free-text approver relay is disabled; approve through an action-approval grant", nil)
				return
			default:
				h.logAudit(r, audit.Entry{
					UserID:     user.ID,
					Operation:  "approver.legacy_relay",
					Status:     "success",
					RiskLevel:  string(op.RiskLevel),
					Message:    fmt.Sprintf("%s relayed approver %q on %s", user.ID, relayed, opName),
					Parameters: legacyRelayParams(user, opName, input),
				})
			}
		} else {
			if input["approver"] != "" && input["approver"] != user.ID {
				// Audited like the other denials in this handler. An attempt
				// to attribute an approval to a colleague is exactly the event
				// worth having a record of, and this path returns before
				// Submit, so without this it would leave none (claude P2).
				h.logAudit(r, audit.Entry{
					UserID:    user.ID,
					Operation: opName,
					Status:    "denied",
					RiskLevel: string(op.RiskLevel),
					Message: fmt.Sprintf("user %q tried to record %q as the approver",
						user.ID, input["approver"]),
				})
				writeError(w, http.StatusBadRequest,
					"approver is not an input: it is taken from the authenticated caller. Remove the field from the request body.")
				return
			}
			input["approver"] = user.ID
		}
	}

	// Apply defaults then validate.
	input = h.opts.Registry.ApplyDefaults(op, input)
	if errs := h.opts.Registry.ValidateInput(op, input); len(errs) > 0 {
		// The reasons go into "error" as well as validationErrors: callers
		// that read only "error" (the MCP tools' doRequest, shell clients)
		// would otherwise report a bare "validation failed". The prefix is
		// unchanged for anything that matches on it.
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":            "validation failed: " + strings.Join(errs, "; "),
			"validationErrors": errs,
		})
		return
	}

	auditParams := redactSecrets(op, input)

	// create-tenant makes a new tenant; it never joins one. For an existing
	// name the workflow would skip writing the tenant and carry on
	// provisioning, so a non-admin is refused here, before anything is
	// submitted. Admins may re-run it to finish or redo a tenant's
	// provisioning. A checkout that cannot answer refuses too: "could not
	// check" is not "does not exist".
	if opName == "create-tenant" && !user.IsAdmin() {
		if status, msg := h.checkTenantIsNew(tenantParam); status != 0 {
			h.logAudit(r, audit.Entry{
				UserID:     user.ID,
				Operation:  opName,
				Parameters: auditParams,
				Status:     "denied",
				RiskLevel:  string(op.RiskLevel),
				Message:    msg,
			})
			writeError(w, status, msg)
			return
		}
	}

	// A repository to build must belong to the caller's team, and so must the
	// image name it is built into and run from (build_repo_gate.go).
	// A refusal of the input is shown as is (403). Anything else is a check
	// that could not be made: its detail can carry internal URLs and
	// checkout paths, so it goes to the log and the caller gets a generic
	// 503. Both refuse.
	if err := h.checkBuildInputs(r.Context(), op, input, user, tenantParam, ciAuthorized); err != nil {
		status, msg := http.StatusForbidden, err.Error()
		if !errors.Is(err, errBuildRepoRefused) && !errors.Is(err, gitops.ErrImageNameRefused) {
			slog.Error("build input check could not be made", "operation", opName, "team", tenantParam, "error", err)
			status, msg = http.StatusServiceUnavailable, errBuildCheckUnavailable.Error()
		}
		h.logAudit(r, audit.Entry{
			UserID:     user.ID,
			Operation:  opName,
			Parameters: auditParams,
			Status:     "denied",
			RiskLevel:  string(op.RiskLevel),
			Message:    msg,
		})
		writeError(w, status, msg)
		return
	}

	// A new tenant name must not share an Application name space with an
	// existing tenant: "labs-x" next to "labs" (or the reverse) would let one
	// tenant's <tenant>-<service> spell the other's Application. This applies
	// to admins too; re-running create-tenant for the same name is not a
	// collision. A tenant list that cannot be read refuses.
	if opName == "create-tenant" {
		if status, msg := h.checkTenantNameCollision(tenantParam); status != 0 {
			h.logAudit(r, audit.Entry{
				UserID:     user.ID,
				Operation:  opName,
				Parameters: auditParams,
				Status:     "denied",
				RiskLevel:  string(op.RiskLevel),
				Message:    msg,
			})
			writeError(w, status, msg)
			return
		}
	}

	// An operation on an existing service must name one that exists for this
	// team in gitops. The workflows build the Argo CD Application name as
	// <team>-<component> and act on it, so without this check the pair is
	// only as safe as the caller's choice of it. A checkout that cannot
	// answer refuses: "could not check" is not "exists".
	if team, component, ok := operations.ServiceTarget(op, input); ok && requiresExistingService(opName, input) {
		if status, msg := h.checkServiceExists(team, component); status != 0 {
			h.logAudit(r, audit.Entry{
				UserID:     user.ID,
				Operation:  opName,
				Parameters: auditParams,
				Status:     "denied",
				RiskLevel:  string(op.RiskLevel),
				Message:    msg,
			})
			writeError(w, status, msg)
			return
		}
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
		// Executor.Submit refuses a reserved tenant name on its own. The
		// validation above normally gets there first; mapping it here keeps
		// the backstop from masquerading as a platform fault.
		if errors.Is(err, operations.ErrReservedTenantName) || errors.Is(err, operations.ErrReservedServiceApplication) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
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

	resp := map[string]any{
		"message":   fmt.Sprintf("Operation submitted. Track progress: GET /api/v1/workflows/%s", result.WorkflowName),
		"operation": opName,
		"workflow":  result,
	}
	if tid := telemetry.TraceIDFrom(r.Context()); tid != "" {
		resp["trace_id"] = tid
	}
	writeJSON(w, http.StatusAccepted, resp)
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
	for i := range op.Parameters {
		p := &op.Parameters[i]
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

// checkTenantIsNew returns 0 when tenant does not exist in the gitops
// checkout, 409 when it does, and 503 when the checkout cannot tell.
func (h *Handlers) checkTenantIsNew(tenant string) (status int, msg string) {
	if h.opts.GitReader == nil {
		return http.StatusServiceUnavailable, "cannot check whether workspace \"" + tenant + "\" exists: gitops reader not configured"
	}
	exists, err := h.opts.GitReader.TenantExists(tenant)
	if err != nil {
		// The error can carry checkout paths; it goes to the log, not the
		// caller.
		slog.Error("create-tenant existence check failed", "tenant", tenant, "error", err)
		return http.StatusServiceUnavailable, "cannot check whether workspace \"" + tenant + "\" exists right now; try again later"
	}
	if exists {
		return http.StatusConflict, "workspace \"" + tenant + "\" already exists"
	}
	return 0, ""
}

// requiresExistingService reports whether opName, which names a service,
// acts on one that must already exist. It is fail-closed: every such
// operation is gated unless listed here. deploy-service's onboard action
// creates the service; provision-database may run before a service is
// onboarded and preview-delete must still clean up after one is retired, and
// neither acts on the <team>-<component> Application.
func requiresExistingService(opName string, input map[string]string) bool {
	switch opName {
	case "provision-database", "preview-delete":
		return false
	case "deploy-service":
		return input["action"] != "onboard"
	}
	return true
}

// checkServiceExists returns 0 when team/component is a service in the
// gitops checkout, 404 when the checkout says it is not, and 503 when the
// checkout cannot tell.
func (h *Handlers) checkServiceExists(team, component string) (status int, msg string) {
	if h.opts.GitReader == nil {
		return http.StatusServiceUnavailable, "cannot check whether service \"" + team + "/" + component + "\" exists: gitops reader not configured"
	}
	exists, err := h.opts.GitReader.ServiceExists(team, component)
	if err != nil {
		// The error can carry checkout paths; it goes to the log, not the
		// caller.
		slog.Error("service existence check failed", "team", team, "component", component, "error", err)
		return http.StatusServiceUnavailable, "cannot check whether service \"" + team + "/" + component + "\" exists right now; try again later"
	}
	if !exists {
		return http.StatusNotFound, "service \"" + component + "\" not found in workspace \"" + team + "\" (a service created in the last minute may not be visible yet)"
	}
	return 0, ""
}

// checkTenantNameCollision returns 0 when tenant shares no hyphen prefix with
// an existing tenant, 400 when it does, and 503 when the tenant list cannot
// be read.
func (h *Handlers) checkTenantNameCollision(tenant string) (status int, msg string) {
	if h.opts.GitReader == nil {
		return http.StatusServiceUnavailable, "cannot check workspace name \"" + tenant + "\": gitops reader not configured"
	}
	names, err := h.opts.GitReader.TenantNames()
	if err != nil {
		slog.Error("create-tenant name collision check failed", "tenant", tenant, "error", err)
		return http.StatusServiceUnavailable, "cannot check workspace name \"" + tenant + "\" right now; try again later"
	}
	if other, collides := operations.TenantNameCollision(tenant, names); collides {
		return http.StatusBadRequest, "tenant_name: \"" + tenant + "\" overlaps the name of existing workspace \"" + other + "\"; choose a name that neither extends nor is extended by another workspace name"
	}
	return 0, ""
}

// legacyRelayParams is the evidence one approver relay leaves: who was
// named, who named them, and for which proposal. Only the input the caller
// sent; nothing here is resolved or trusted.
func legacyRelayParams(user *auth.User, opName string, input map[string]string) map[string]string {
	return map[string]string{
		"approver":          input["approver"],
		"calling_principal": user.ID,
		"operation":         opName,
		"service":           input["service"],
		"slug":              input["slug"],
	}
}
