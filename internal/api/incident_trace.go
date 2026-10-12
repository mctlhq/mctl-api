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
	"github.com/mctlhq/mctl-api/internal/telemetry"
	"k8s.io/apimachinery/pkg/util/validation"
)

// trace_unavailable reasons. Exactly one is set when no trace id is returned.
const (
	traceNotReported       = "not_reported"
	traceNotDerivedOnList  = "not_derived_on_list"
	traceWorkflowUnknown   = "workflow_name_unknown"
	traceAuditUnavailable  = "audit_unavailable"
	traceAuditNotFound     = "audit_record_not_found"
	traceNoTraceparent     = "no_traceparent_in_audit_record"
	traceAuditForbidden    = "audit_record_forbidden"
	incidentSourceArgo     = "argo-workflows"
	incidentAuditTimeout   = 2 * time.Second
	traceSourceReported    = "reported"
	traceSourceAuditDerive = "workflow_audit"
)

var workflowURLRe = regexp.MustCompile(`(?:^|\s)https://workflows\.mctl\.ai/workflows/[a-z0-9-]+/([a-z0-9][a-z0-9.-]*)`)

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
		if m := workflowURLRe.FindStringSubmatch(a.Summary); len(m) == 2 && len(validation.IsDNS1123Subdomain(m[1])) == 0 {
			name = m[1]
		}
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
