// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/k8s"
)

type stubWorkload struct {
	calls     int
	err       error
	lastQuery k8s.EventQuery
	events    []k8s.Event
	truncated bool
}

func (s *stubWorkload) ListServicePods(context.Context, string, string) ([]k8s.PodState, error) {
	s.calls++
	return []k8s.PodState{{Name: "acme-web-1"}}, s.err
}

func (s *stubWorkload) ListEvents(_ context.Context, _ string, q k8s.EventQuery) ([]k8s.Event, bool, error) {
	s.calls++
	s.lastQuery = q
	return s.events, s.truncated, s.err
}

// workloadTenants registers acme and other; "broken" is a checkout that
// cannot be read, and every other name (kube-system, argocd) is absent.
type workloadTenants struct{ GitReader }

func (workloadTenants) TenantExists(name string) (bool, error) {
	switch name {
	case "acme", "other":
		return true, nil
	case "broken":
		return false, errors.New("checkout unreadable")
	}
	return false, nil
}

func workloadRouter(rd WorkloadReader) http.Handler {
	h := &Handlers{opts: Options{WorkloadReader: rd, GitReader: workloadTenants{}}}
	r := chi.NewRouter()
	r.Get("/api/v1/pods/{team}/{app}", h.GetServicePods)
	r.Get("/api/v1/events/{team}", h.ListNamespaceEvents)
	return r
}

func TestWorkloadReads_TenantGate(t *testing.T) {
	stub := &stubWorkload{}
	r := workloadRouter(stub)
	u := auth.NewGitHubUser("u1", []string{"acme"})
	for _, p := range []string{"/api/v1/pods/acme/web", "/api/v1/events/acme"} {
		if rec := serveUser(r, u, "GET", p); rec.Code != 200 {
			t.Errorf("%s own = %d", p, rec.Code)
		}
	}
	before := stub.calls
	for _, p := range []string{"/api/v1/pods/other/web", "/api/v1/events/other"} {
		if rec := serveUser(r, u, "GET", p); rec.Code != 403 {
			t.Errorf("%s cross-tenant = %d, want 403", p, rec.Code)
		}
	}
	if stub.calls != before {
		t.Error("reader called for a forbidden tenant")
	}
	if rec := serveUser(r, u, "GET", "/api/v1/pods/Acme_x/web"); rec.Code != 400 {
		t.Errorf("bad label = %d", rec.Code)
	}
}

func TestListNamespaceEvents_Params(t *testing.T) {
	stub := &stubWorkload{truncated: true}
	r := workloadRouter(stub)
	u := auth.NewGitHubUser("u1", []string{"acme"})
	for _, q := range []string{"since=48h", "since=abc", "since=30s", "type=Bogus"} {
		if rec := serveUser(r, u, "GET", "/api/v1/events/acme?"+q); rec.Code != 400 {
			t.Errorf("%s = %d, want 400", q, rec.Code)
		}
	}
	rec := serveUser(r, u, "GET", "/api/v1/events/acme?type=Warning&app=web&since=2h")
	if rec.Code != 200 {
		t.Fatalf("code %d", rec.Code)
	}
	if stub.lastQuery.Type != "Warning" || stub.lastQuery.Workload != "acme-web" || stub.lastQuery.Limit != 200 {
		t.Errorf("query = %+v", stub.lastQuery)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["truncated"] != true {
		t.Errorf("truncated = %v", body["truncated"])
	}
	if items, ok := body["items"].([]any); !ok || len(items) != 0 {
		t.Errorf("items = %v, want empty array", body["items"])
	}
}

func TestWorkloadReads_Unavailable(t *testing.T) {
	u := auth.NewGitHubUser("u1", []string{"acme"})
	raw := "forbidden: system:serviceaccount:mctl-api:mctl-api cannot list pods"
	for name, rd := range map[string]WorkloadReader{"nil": nil, "failed": &stubWorkload{err: errors.New(raw)}} {
		r := workloadRouter(rd)
		for _, p := range []string{"/api/v1/pods/acme/web", "/api/v1/events/acme"} {
			rec := serveUser(r, u, "GET", p)
			if rec.Code != 503 {
				t.Errorf("%s %s = %d", name, p, rec.Code)
			}
			if strings.Contains(rec.Body.String(), "serviceaccount") {
				t.Errorf("%s %s leaks raw error: %s", name, p, rec.Body.String())
			}
		}
	}
}

func TestListWorkflows_PlatformRowsHiddenFromTenants(t *testing.T) {
	log := audit.NewLogger()
	log.Log(audit.Entry{Operation: "deploy-service", WorkflowName: "wf-acme", Parameters: map[string]string{"team_name": "acme"}})
	log.Log(audit.Entry{Operation: "deploy-service", WorkflowName: "wf-other", Parameters: map[string]string{"team_name": "other"}})
	log.Log(audit.Entry{Operation: "mctl-agents-run", WorkflowName: "wf-platform", Parameters: map[string]string{"x": "y"}})
	log.Log(audit.Entry{Operation: "deploy-service", WorkflowName: "wf-bad", ParametersUnreadable: true})
	h := &Handlers{opts: Options{AuditLog: log}}
	r := chi.NewRouter()
	r.Get("/api/v1/workflows", h.ListWorkflows)

	names := func(u *auth.User) map[string]bool {
		rec := serveUser(r, u, "GET", "/api/v1/workflows")
		var body struct {
			Items []map[string]any `json:"items"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		out := map[string]bool{}
		for _, it := range body.Items {
			out[it["workflowName"].(string)] = true
		}
		return out
	}
	member := names(auth.NewGitHubUser("u1", []string{"acme"}))
	if len(member) != 1 || !member["wf-acme"] {
		t.Errorf("member sees %v, want only wf-acme", member)
	}
	investigator := names(investigatorRun("wi_own"))
	if !investigator["wf-acme"] || !investigator["wf-other"] || !investigator["wf-platform"] || investigator["wf-bad"] {
		t.Errorf("investigator sees %v", investigator)
	}
	if sup := names(supportRun("acme")); len(sup) != 1 || !sup["wf-acme"] {
		t.Errorf("support sees %v", sup)
	}
}

// {team} is used as the Kubernetes namespace. Admins and ReadAllTenants
// scopes pass HasTenantAccess for any name, so the handlers must refuse a
// name that is not a registered tenant before the reader runs: 404 for a
// definite absence, 503 when the lookup fails.
func TestWorkloadReads_OnlyRegisteredTenants(t *testing.T) {
	stub := &stubWorkload{}
	r := workloadRouter(stub)
	callers := map[string]*auth.User{
		"admin":        auth.NewGitHubUser("root", []string{"admins"}),
		"investigator": investigatorRun("wi_own"),
	}
	for who, u := range callers {
		for p, want := range map[string]int{
			"/api/v1/pods/kube-system/coredns": 404,
			"/api/v1/events/argocd":            404,
			"/api/v1/pods/broken/web":          503,
			"/api/v1/events/broken":            503,
		} {
			before := stub.calls
			if rec := serveUser(r, u, "GET", p); rec.Code != want {
				t.Errorf("%s %s = %d, want %d", who, p, rec.Code, want)
			}
			if stub.calls != before {
				t.Errorf("%s %s reached the reader", who, p)
			}
		}
		if rec := serveUser(r, u, "GET", "/api/v1/events/acme"); rec.Code != 200 {
			t.Errorf("%s registered tenant = %d", who, rec.Code)
		}
	}
}
