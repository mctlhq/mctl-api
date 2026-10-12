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

package api_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// mctl-api#586: a failed or unreadable audit read must never be answered as
// "no record" (a 404, the cron fallback, or the ownerless 403).

// failingAuditLog reports every workflow lookup as a failed read.
type failingAuditLog struct{ *audit.Logger }

func (failingAuditLog) LookupByWorkflow(context.Context, string) (*audit.Entry, error) {
	return nil, errors.New("pool closed")
}

// unreadableAuditLog serves one row whose params could not be decoded, from
// both the lookup and the listing.
type unreadableAuditLog struct{ *audit.Logger }

func unreadableEntry() audit.Entry {
	return audit.Entry{ID: "a-1", WorkflowName: "wf-x", Operation: "deploy-service",
		UserID: "someone", Status: "submitted", ParametersUnreadable: true}
}

func (unreadableAuditLog) LookupByWorkflow(context.Context, string) (*audit.Entry, error) {
	e := unreadableEntry()
	return &e, nil
}

func (unreadableAuditLog) List(int) []audit.Entry { return []audit.Entry{unreadableEntry()} }

// countingExecutor records every live status lookup, so a test can prove the
// cron fallback was not taken.
type countingExecutor struct {
	*fakeExecutor
	namespaces []string
}

func (c *countingExecutor) GetWorkflowStatus(ctx context.Context, namespace, name string) (map[string]interface{}, error) {
	c.namespaces = append(c.namespaces, namespace)
	return c.fakeExecutor.GetWorkflowStatus(ctx, namespace, name)
}

func auditRouter(log audit.Log) (http.Handler, *countingExecutor) {
	exec := &countingExecutor{fakeExecutor: &fakeExecutor{}}
	return mctlapi.NewRouter(mctlapi.Options{
		Registry:           operations.NewRegistry(),
		GitReader:          &fakeGitReader{},
		ArgoCD:             &fakeArgoCD{apps: map[string]*argocd.AppStatus{}},
		AuditLog:           log,
		Executor:           exec,
		WorkflowLogArchive: archiveOfFailedPoll(),
	}), exec
}

var acmeMember = &auth.User{ID: "dev", Groups: []string{"acme"}}

func wantStatus(t *testing.T, label string, got, want int, body string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: status %d, want %d (body %s)", label, got, want, body)
	}
}

// T1: an audit outage is a 503 for everyone, and the cron fallback is not
// consulted.
func TestGetWorkflow_AuditReadFailureIs503(t *testing.T) {
	for _, u := range []*auth.User{adminUser, acmeMember} {
		router, exec := auditRouter(failingAuditLog{audit.NewLogger()})
		w := getAs(t, router, "/api/v1/workflows/wf-x", u)
		wantStatus(t, "GetWorkflow as "+u.ID, w.Code, http.StatusServiceUnavailable, w.Body.String())
		if !strings.Contains(w.Body.String(), "audit log unavailable, workflow may exist") {
			t.Errorf("%s: body %s", u.ID, w.Body.String())
		}
		if len(exec.namespaces) != 0 {
			t.Errorf("%s: live lookup ran in %v; a failed audit read must not take the cron fallback", u.ID, exec.namespaces)
		}
	}
}

// T2: the logs gate answers an audit outage with 503, not the ownerless 403.
func TestGetWorkflowLogs_AuditReadFailureIs503(t *testing.T) {
	router, _ := auditRouter(failingAuditLog{audit.NewLogger()})
	w := getAs(t, router, "/api/v1/workflows/wf-x/logs", acmeMember)
	wantStatus(t, "GetWorkflowLogs", w.Code, http.StatusServiceUnavailable, w.Body.String())
}

// T3: a genuine miss keeps today's behaviour: 404 for a non-admin, the cron
// fallback in argo-workflows for an admin.
func TestGetWorkflow_NoAuditRecordKeepsFallback(t *testing.T) {
	router, exec := auditRouter(audit.NewLogger())
	w := getAs(t, router, "/api/v1/workflows/wf-cron", acmeMember)
	wantStatus(t, "non-admin", w.Code, http.StatusNotFound, w.Body.String())
	if !strings.Contains(w.Body.String(), "workflow record not found in audit log") || len(exec.namespaces) != 0 {
		t.Errorf("non-admin: body %s, live lookups %v", w.Body.String(), exec.namespaces)
	}

	w = getAs(t, router, "/api/v1/workflows/wf-cron", adminUser)
	wantStatus(t, "admin", w.Code, http.StatusOK, w.Body.String())
	body := decodeJSON(t, w)
	if body["namespace"] != "argo-workflows" || body["note"] == nil {
		t.Errorf("admin: body %v, want the cron fallback", body)
	}
	if len(exec.namespaces) != 1 || exec.namespaces[0] != "argo-workflows" {
		t.Errorf("admin: live lookups %v, want one in argo-workflows", exec.namespaces)
	}
}

// T4: a genuine miss on the logs gate is still the ownerless 403.
func TestGetWorkflowLogs_NoAuditRecordIsOwnerless403(t *testing.T) {
	router, _ := auditRouter(audit.NewLogger())
	w := getAs(t, router, "/api/v1/workflows/wf-cron/logs", acmeMember)
	wantStatus(t, "GetWorkflowLogs", w.Code, http.StatusForbidden, w.Body.String())
	if !strings.Contains(w.Body.String(), "no owning team") {
		t.Errorf("body %s", w.Body.String())
	}
}

// T5: a row whose owning team cannot be read is refused on both endpoints,
// for an admin too (no namespace can be derived), and is never routed.
func TestAuditUnreadableParameters_Refused(t *testing.T) {
	for _, u := range []*auth.User{adminUser, acmeMember} {
		router, exec := auditRouter(unreadableAuditLog{audit.NewLogger()})
		w := getAs(t, router, "/api/v1/workflows/wf-x", u)
		wantStatus(t, "GetWorkflow as "+u.ID, w.Code, http.StatusServiceUnavailable, w.Body.String())
		if len(exec.namespaces) != 0 {
			t.Errorf("%s: live lookup ran in %v for an unreadable row", u.ID, exec.namespaces)
		}
	}
	router, _ := auditRouter(unreadableAuditLog{audit.NewLogger()})
	w := getAs(t, router, "/api/v1/workflows/wf-x/logs", acmeMember)
	wantStatus(t, "GetWorkflowLogs", w.Code, http.StatusServiceUnavailable, w.Body.String())
}

// Sweep: the list endpoints treat an empty team as "platform" and show it to
// everyone. An unreadable row's empty team means "unknown", so a non-admin
// must not see it; an admin still does.
func TestAuditUnreadableParameters_HiddenFromNonAdminLists(t *testing.T) {
	router, _ := auditRouter(unreadableAuditLog{audit.NewLogger()})
	for _, path := range []string{"/api/v1/workflows", "/api/v1/audit"} {
		w := getAs(t, router, path, acmeMember)
		wantStatus(t, path+" as member", w.Code, http.StatusOK, w.Body.String())
		if strings.Contains(w.Body.String(), "wf-x") {
			t.Errorf("%s: a non-admin sees the unreadable row: %s", path, w.Body.String())
		}
		w = getAs(t, router, path, adminUser)
		wantStatus(t, path+" as admin", w.Code, http.StatusOK, w.Body.String())
		if !strings.Contains(w.Body.String(), "wf-x") {
			t.Errorf("%s: an admin lost the unreadable row: %s", path, w.Body.String())
		}
	}
}

// T6: a readable row answers as before.
func TestGetWorkflow_ReadableRowUnchanged(t *testing.T) {
	log := audit.NewLogger()
	log.Log(audit.Entry{WorkflowName: "wf-ok", Operation: "deploy-service", Status: "submitted",
		Parameters: map[string]string{"tenant_name": "acme"}})
	router, _ := auditRouter(log)
	w := getAs(t, router, "/api/v1/workflows/wf-ok", acmeMember)
	wantStatus(t, "GetWorkflow", w.Code, http.StatusOK, w.Body.String())
	body := decodeJSON(t, w)
	for _, k := range []string{"workflow", "audit", "namespace", "live"} {
		if _, ok := body[k]; !ok {
			t.Errorf("response lost key %q: %v", k, body)
		}
	}
}
