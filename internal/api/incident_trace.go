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
	"context"
	"encoding/json"
	"log/slog"
	"regexp"
	"time"

	"github.com/mctlhq/mctl-api/internal/alerts"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/telemetry"
	"k8s.io/apimachinery/pkg/util/validation"
)

// trace_unavailable reasons. Exactly one is set when no trace id is returned.
const (
	traceNotReported      = "not_reported"
	traceNotDerivedOnList = "not_derived_on_list"
	// traceNotDerived marks write responses (create, patch, ack, resolve),
	// which return the stored row without running the audit derivation.
	traceNotDerived       = "not_derived"
	traceWorkflowUnknown  = "workflow_name_unknown"
	traceAuditUnavailable = "audit_unavailable"
	traceAuditNotFound    = "audit_record_not_found"
	traceNoTraceparent    = "no_traceparent_in_audit_record"
	traceAuditForbidden   = "audit_record_forbidden"
)

// trace_source values.
const (
	traceSourceReported    = "reported"
	traceSourceAuditDerive = "workflow_audit"
)

const (
	incidentSourceArgo   = "argo-workflows"
	incidentAuditTimeout = 2 * time.Second
)

// workflowURLRe finds the Argo UI link the onExit incident legs put in the
// summary. It is the fallback for rows posted without workflow_name (every
// argo incident today); producers that send workflow_name never reach it.
// The name must end alphanumeric so sentence punctuation after the URL is
// not captured, and the URL may follow whitespace or an opening parenthesis.
var workflowURLRe = regexp.MustCompile(`(?:^|[\s(])https://workflows\.mctl\.ai/workflows/[a-z0-9-]+/([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)`)

// workflowNameFromSummary returns the workflow named by the Argo UI link in
// summary, or "" if there is none.
func workflowNameFromSummary(summary string) string {
	if m := workflowURLRe.FindStringSubmatch(summary); len(m) == 2 && len(validation.IsDNS1123Subdomain(m[1])) == 0 {
		return m[1]
	}
	return ""
}

// labelStoredTrace sets the response-only trace fields from the stored row
// alone, for responses that do not run deriveIncidentTrace. underived is the
// reason given to an argo incident whose trace could still be derived by
// GET /incidents/{id}; any other source without a trace is not_reported.
func labelStoredTrace(a *alerts.Alert, underived string) {
	a.TraceSource, a.TraceUnavailable = "", ""
	switch {
	case a.TraceID != "":
		a.TraceSource = traceSourceReported
	case a.Source == incidentSourceArgo:
		a.TraceUnavailable = underived
	default:
		a.TraceUnavailable = traceNotReported
	}
}

// canReadAuditEntry is the gate for deriving a trace from a workflow's audit
// record. The workflow name is caller-controlled (summary, workflow_name), so
// a non-admin may only read entries of a team they belong to. An entry with
// no team is an AdminOnly platform operation and is admin-only here, as in
// GetWorkflowLogs. This is deliberately stricter than GetWorkflow, which
// tolerates an empty team: the incident path has no reason to widen access,
// and argo incidents are posted to the admins tenant anyway.
func canReadAuditEntry(user *auth.User, e *audit.Entry) bool {
	if user.IsAdmin() {
		return true
	}
	team := auditEntryTenant(e)
	return team != "" && user.HasTenantAccess(team)
}

// workflowAuditLookup finds the audit record of a workflow. (nil, nil) means
// there is no such record.
type workflowAuditLookup interface {
	LookupByWorkflow(ctx context.Context, name string) (*audit.Entry, error)
}

// validIncidentTraceID returns the trace id in raw if it is a JSON string
// holding a valid trace id, else "". Never fails the request.
func validIncidentTraceID(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil || !telemetry.ValidTraceID(s) {
		if string(raw) != "null" {
			slog.Debug("incident: ignoring invalid trace_id")
		}
		return ""
	}
	return s
}

// validIncidentWorkflowName returns the workflow name in raw if it is a JSON
// string holding a valid Kubernetes object name, else "".
func validIncidentWorkflowName(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil || s == "" || len(validation.IsDNS1123Subdomain(s)) > 0 {
		if string(raw) != "null" {
			slog.Debug("incident: ignoring invalid workflow_name")
		}
		return ""
	}
	return s
}

// deriveIncidentTrace fills the response-only trace fields of a. It never
// writes anything back and never fails.
func deriveIncidentTrace(ctx context.Context, a *alerts.Alert, lookup workflowAuditLookup, canRead func(*audit.Entry) bool) {
	a.TraceSource, a.TraceUnavailable = "", ""
	if a.TraceID != "" {
		a.TraceSource = traceSourceReported
		return
	}
	if a.Source != incidentSourceArgo {
		a.TraceUnavailable = traceNotReported
		return
	}

	name := a.WorkflowName
	if name == "" {
		name = workflowNameFromSummary(a.Summary)
	}
	if name == "" {
		a.TraceUnavailable = traceWorkflowUnknown
		return
	}
	if lookup == nil {
		a.TraceUnavailable = traceAuditUnavailable
		return
	}

	lctx, cancel := context.WithTimeout(ctx, incidentAuditTimeout)
	defer cancel()
	entry, err := lookup.LookupByWorkflow(lctx, name)
	if err != nil {
		slog.Warn("incident: audit lookup for trace failed", "workflow", name, "error", err)
		a.TraceUnavailable = traceAuditUnavailable
		return
	}
	if entry == nil {
		a.TraceUnavailable = traceAuditNotFound
		return
	}
	if entry.ParametersUnreadable {
		// Neither the owning team nor the traceparent can be read, so this is
		// an unreadable record, not a forbidden one or one without a trace.
		slog.Warn("incident: audit record for trace has unreadable parameters", "workflow", name, "id", entry.ID)
		a.TraceUnavailable = traceAuditUnavailable
		return
	}
	if canRead != nil && !canRead(entry) {
		a.TraceUnavailable = traceAuditForbidden
		return
	}
	id, ok := telemetry.TraceIDFromTraceparent(entry.Parameters["traceparent"])
	if !ok {
		a.TraceUnavailable = traceNoTraceparent
		return
	}
	a.TraceID = id
	a.TraceSource = traceSourceAuditDerive
}
