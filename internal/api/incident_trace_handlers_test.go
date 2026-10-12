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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/mctlhq/mctl-api/internal/alerts"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
)

const (
	daeTraceID     = "431486061c652efb376a860d9d656f25"
	otherTraceID   = "008ad8979d34c0509e74d8062b7f92ca"
	daeIncidentID  = "argo-mctl-agents-implement-dae24112-1791756910"
	daeWorkflow    = "mctl-agents-implement-dae24112"
	daeTraceparent = "00-431486061c652efb376a860d9d656f25-7a16c732dc164e9e-01"
	// Copied verbatim from the production incident (mctl_get_incident, 2026-10-12).
	daeSummary = "implement implement issue-757-tool-availability-sli-counts-caller-erro Failed after 437.333132s — https://workflows.mctl.ai/workflows/argo-workflows/mctl-agents-implement-dae24112"
)

// countingAuditLog records how often the incident handlers consult the audit
// log, so a test can prove the list endpoint never does.
type countingAuditLog struct {
	*audit.Logger
	lookups int
}

func (c *countingAuditLog) LookupByWorkflow(ctx context.Context, name string) (*audit.Entry, error) {
	c.lookups++
	return c.Logger.LookupByWorkflow(ctx, name)
}

func decodeIncident(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return m
}

// mctl-api#585 T4: an invalid trace_id is ignored, never rejected. Each body
// still creates the incident (201) and stores no trace; a later PATCH with an
// invalid value keeps the stored trace and a valid one replaces it.
func TestIncidentTrace_InvalidInputIgnoredNotRejected(t *testing.T) {
	store := newTestAlertStore(t)
	h := &Handlers{opts: Options{AlertStore: store, AuditLog: audit.NewLogger()}}
	admin := adminUser()

	for name, traceJSON := range map[string]string{
		"uppercase":    `"431486061C652EFB376A860D9D656F25"`,
		"31 chars":     `"` + daeTraceID[:31] + `"`,
		"all zeros":    `"00000000000000000000000000000000"`,
		"number":       `123`,
		"object":       `{"id":"x"}`,
		"bad workflow": `"` + daeTraceID + `", "workflow_name": 5`,
	} {
		t.Run("create "+name, func(t *testing.T) {
			id := "trace-in-" + uuid.NewString()[:8]
			body := `{"id":"` + id + `","source":"manual","type":"workflow_failed","tenant":"admins",` +
				`"summary":"s","severity":"warning","fingerprint":"fp-` + id + `","trace_id":` + traceJSON + `}`
			rec := httptest.NewRecorder()
			h.CreateIncident(rec, withUser(httptest.NewRequest(http.MethodPost, "/api/v1/incidents", strings.NewReader(body)), admin))
			if rec.Code != http.StatusCreated {
				t.Fatalf("status %d, want 201: %s", rec.Code, rec.Body.String())
			}
			if resp := decodeIncident(t, rec); name != "bad workflow" && resp["trace_unavailable"] != "not_reported" {
				t.Fatalf("create response for a manual incident without a trace: %v", resp["trace_unavailable"])
			}
			stored, err := store.Get(context.Background(), id)
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if name == "bad workflow" {
				// The trace is valid; only the workflow name is dropped.
				if stored.TraceID != daeTraceID || stored.WorkflowName != "" {
					t.Fatalf("stored trace=%q workflow=%q", stored.TraceID, stored.WorkflowName)
				}
				return
			}
			if stored.TraceID != "" {
				t.Fatalf("invalid trace_id %s was stored as %q", traceJSON, stored.TraceID)
			}
		})
	}

	// Seed one incident with a valid trace, then PATCH it.
	id := "trace-patch-" + uuid.NewString()[:8]
	if _, err := store.Create(context.Background(), &alerts.Alert{
		ID: id, Source: "manual", Type: "workflow_failed", Tenant: "admins", Summary: "s",
		Severity: "warning", Status: alerts.StatusOpen, Fingerprint: "fp-" + id, TraceID: daeTraceID,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	patch := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.UpdateIncident(rec, withURLParam(withUser(httptest.NewRequest(http.MethodPatch, "/api/v1/incidents/"+id, strings.NewReader(body)), admin), "id", id))
		return rec
	}
	for _, bad := range []string{`{"trace_id":"NOT-HEX"}`, `{"trace_id":42}`, `{"trace_id":null}`, `{"analysis":"a","trace_id":""}`} {
		if rec := patch(bad); rec.Code != http.StatusOK {
			t.Fatalf("PATCH %s: status %d, want 200: %s", bad, rec.Code, rec.Body.String())
		}
		if got, _ := store.Get(context.Background(), id); got.TraceID != daeTraceID {
			t.Fatalf("PATCH %s replaced the stored trace with %q", bad, got.TraceID)
		}
	}
	if rec := patch(`{"trace_id":"` + otherTraceID + `"}`); rec.Code != http.StatusOK {
		t.Fatalf("valid PATCH: status %d: %s", rec.Code, rec.Body.String())
	}
	if got, _ := store.Get(context.Background(), id); got.TraceID != otherTraceID {
		t.Fatalf("valid PATCH did not replace the trace: %q", got.TraceID)
	}
}

// mctl-api#585 T8: the list endpoint never runs the audit derivation, and an
// item without a stored trace says so instead of looking traceless.
func TestIncidentTrace_ListMarksAbsenceWithoutAuditLookup(t *testing.T) {
	store := newTestAlertStore(t)
	log := &countingAuditLog{Logger: audit.NewLogger()}
	log.Log(audit.Entry{ID: uuid.NewString(), UserID: "mctl-agent", Operation: "mctl-agents-implement",
		WorkflowName: daeWorkflow, Status: "failed", Parameters: map[string]string{"traceparent": daeTraceparent}})
	h := &Handlers{opts: Options{AlertStore: store, AuditLog: log}}

	ctx := context.Background()
	if _, err := store.Create(ctx, &alerts.Alert{ID: "with-trace", Source: "manual", Type: "workflow_failed",
		Tenant: "admins", Summary: "s", Severity: "warning", Status: alerts.StatusOpen,
		Fingerprint: "fp-with-trace", TraceID: otherTraceID}); err != nil {
		t.Fatalf("seed reported: %v", err)
	}
	if _, err := store.Create(ctx, &alerts.Alert{ID: daeIncidentID, Source: "argo-workflows", Type: "workflow_failed",
		Tenant: "admins", Service: "mctl-agents", Summary: daeSummary, Severity: "warning",
		Status: alerts.StatusOpen, Fingerprint: "fp-dae"}); err != nil {
		t.Fatalf("seed argo: %v", err)
	}

	if _, err := store.Create(ctx, &alerts.Alert{ID: "manual-untraced", Source: "manual", Type: "workflow_failed",
		Tenant: "admins", Summary: "s", Severity: "warning", Status: alerts.StatusOpen,
		Fingerprint: "fp-manual-untraced"}); err != nil {
		t.Fatalf("seed manual: %v", err)
	}

	rec := httptest.NewRecorder()
	h.ListIncidents(rec, withUser(httptest.NewRequest(http.MethodGet, "/api/v1/incidents", nil), adminUser()))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	byID := map[string]map[string]any{}
	for _, it := range resp.Items {
		byID[it["id"].(string)] = it
	}

	reported := byID["with-trace"]
	if reported["trace_id"] != otherTraceID || reported["trace_source"] != "reported" || reported["trace_unavailable"] != nil {
		t.Fatalf("reported item: %v", reported)
	}
	argo := byID[daeIncidentID]
	if _, ok := argo["trace_id"]; ok {
		t.Fatalf("list derived a trace it must not derive: %v", argo)
	}
	if argo["trace_unavailable"] != "not_derived_on_list" {
		t.Fatalf("argo item without a stored trace is unmarked: %v", argo)
	}
	// Derivation could never produce a trace for a non-argo incident, so the
	// list gives the terminal reason rather than sending callers to GET it.
	if manual := byID["manual-untraced"]; manual["trace_unavailable"] != "not_reported" {
		t.Fatalf("non-argo item without a trace: %v", manual)
	}
	if log.lookups != 0 {
		t.Fatalf("list consulted the audit log %d times, want 0", log.lookups)
	}
}

// mctl-api#585 acceptance, end to end through the handler: the production
// dae24112 incident resolves to its trace from the workflow's audit record.
func TestIncidentTrace_GetDerivesDae24112FromAudit(t *testing.T) {
	store := newTestAlertStore(t)
	log := &countingAuditLog{Logger: audit.NewLogger()}
	log.Log(audit.Entry{ID: uuid.NewString(), UserID: "mctl-agent", Operation: "mctl-agents-implement",
		WorkflowName: daeWorkflow, Status: "failed", Parameters: map[string]string{"traceparent": daeTraceparent}})
	h := &Handlers{opts: Options{AlertStore: store, AuditLog: log}}

	if _, err := store.Create(context.Background(), &alerts.Alert{ID: daeIncidentID, Source: "argo-workflows",
		Type: "workflow_failed", Tenant: "admins", Service: "mctl-agents", Summary: daeSummary,
		Severity: "warning", Status: alerts.StatusResolved,
		Fingerprint: "workflow_failed:implement:mctl-telegram:issue-757-tool-availability-sli-counts-caller-erro"}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rec := httptest.NewRecorder()
	h.GetIncident(rec, withURLParam(withUser(httptest.NewRequest(http.MethodGet, "/api/v1/incidents/"+daeIncidentID, nil), adminUser()), "id", daeIncidentID))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	got := decodeIncident(t, rec)
	if got["trace_id"] != daeTraceID || got["trace_source"] != "workflow_audit" {
		t.Fatalf("got trace_id=%v trace_source=%v unavailable=%v", got["trace_id"], got["trace_source"], got["trace_unavailable"])
	}
	if log.lookups != 1 {
		t.Fatalf("audit lookups = %d, want 1", log.lookups)
	}
	// The derived trace is response-only: the row stays without a trace.
	if stored, _ := store.Get(context.Background(), daeIncidentID); stored.TraceID != "" {
		t.Fatalf("GET wrote the derived trace back: %q", stored.TraceID)
	}
}

// The trace derivation must not hand a non-admin the audit record of a
// workflow outside their teams. The workflow name is caller-controlled, and
// an entry without a team is an AdminOnly platform operation.
func TestCanReadAuditEntry(t *testing.T) {
	platform := &audit.Entry{Parameters: map[string]string{"traceparent": daeTraceparent}}
	acme := &audit.Entry{Parameters: map[string]string{"tenant_name": "acme", "traceparent": daeTraceparent}}
	member := &auth.User{ID: "dev", Groups: []string{"acme"}}
	outsider := &auth.User{ID: "dev2", Groups: []string{"other"}}

	for name, tc := range map[string]struct {
		user  *auth.User
		entry *audit.Entry
		want  bool
	}{
		"admin, platform entry":      {adminUser(), platform, true},
		"admin, tenant entry":        {adminUser(), acme, true},
		"member, own tenant":         {member, acme, true},
		"outsider, other tenant":     {outsider, acme, false},
		"non-admin, platform entry":  {member, platform, false},
		"non-admin, entry no params": {member, &audit.Entry{}, false},
	} {
		if got := canReadAuditEntry(tc.user, tc.entry); got != tc.want {
			t.Errorf("%s: canReadAuditEntry = %v, want %v", name, got, tc.want)
		}
	}
}

// The summary fallback must find the workflow name wherever the URL sits in
// ordinary prose: at the end of a sentence, inside parentheses.
func TestDeriveIncidentTrace_SummaryURLInProse(t *testing.T) {
	entry := &audit.Entry{Parameters: map[string]string{"traceparent": daeTraceparent}}
	for _, summary := range []string{
		daeSummary,
		"Workflow failed: https://workflows.mctl.ai/workflows/argo-workflows/" + daeWorkflow + ".",
		"Workflow failed (https://workflows.mctl.ai/workflows/argo-workflows/" + daeWorkflow + ")",
		"Workflow failed (https://workflows.mctl.ai/workflows/argo-workflows/" + daeWorkflow + ").",
		"see https://workflows.mctl.ai/workflows/argo-workflows/" + daeWorkflow + "-",
	} {
		var asked string
		lookup := lookupFunc(func(_ context.Context, name string) (*audit.Entry, error) {
			asked = name
			return entry, nil
		})
		a := &alerts.Alert{Source: "argo-workflows", Summary: summary}
		deriveIncidentTrace(context.Background(), a, lookup, func(*audit.Entry) bool { return true })
		if asked != daeWorkflow || a.TraceID != daeTraceID {
			t.Errorf("summary %q: looked up %q, trace %q (unavailable=%q)", summary, asked, a.TraceID, a.TraceUnavailable)
		}
	}
}

type lookupFunc func(context.Context, string) (*audit.Entry, error)

func (f lookupFunc) LookupByWorkflow(ctx context.Context, name string) (*audit.Entry, error) {
	return f(ctx, name)
}
