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
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/ghactions"
)

// fakeDispatcher implements WorkflowDispatcher and records the one call it
// is given. Recording the arguments is the point: the endpoint takes no
// parameters, so "which workflow on which ref did this start" is a property
// of the handler's constants and nothing else would catch a typo in them.
type fakeDispatcher struct {
	err                       error
	calls                     int
	owner, repo, wf, ref      string
	inputs                    map[string]string
	lastCtxDeadlineWasPresent bool
}

func (f *fakeDispatcher) Dispatch(ctx context.Context, owner, repo, workflowFile, ref string, inputs map[string]string) error {
	f.calls++
	f.owner, f.repo, f.wf, f.ref, f.inputs = owner, repo, workflowFile, ref, inputs
	_, f.lastCtxDeadlineWasPresent = ctx.Deadline()
	return f.err
}

func TestDispatchPortalServerAuthApply_NotConfigured(t *testing.T) {
	h := &Handlers{opts: Options{}} // WorkflowDispatcher left nil

	req := adminCtx(httptest.NewRequest("POST", "/api/v1/cloudflare/portal/server-auth/apply", nil))
	rec := httptest.NewRecorder()
	h.DispatchPortalServerAuthApply(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 with no dispatcher configured, got %d: %s", rec.Code, rec.Body.String())
	}
}

// The auth branches are asserted with a dispatcher CONFIGURED, so they
// exercise the checks themselves instead of short-circuiting on the 503
// above — which is what the WorkflowDispatcher interface exists for.
func TestDispatchPortalServerAuthApply_RequiresAdmin(t *testing.T) {
	fake := &fakeDispatcher{}
	h := &Handlers{opts: Options{WorkflowDispatcher: fake}}

	req := httptest.NewRequest("POST", "/api/v1/cloudflare/portal/server-auth/apply", nil)
	rec := httptest.NewRecorder()
	h.DispatchPortalServerAuthApply(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: expected 401, got %d: %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest("POST", "/api/v1/cloudflare/portal/server-auth/apply", nil)
	req = req.WithContext(auth.WithUser(req.Context(), &auth.User{ID: "tester", Groups: []string{"some-tenant"}}))
	rec = httptest.NewRecorder()
	h.DispatchPortalServerAuthApply(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}

	if fake.calls != 0 {
		t.Fatalf("a non-admin caller reached the dispatcher %d time(s); the workflow must not be startable without admin", fake.calls)
	}
}

func TestDispatchPortalServerAuthApply_DispatchesTheOneWorkflowOnMain(t *testing.T) {
	fake := &fakeDispatcher{}
	logger := audit.NewLogger()
	h := &Handlers{opts: Options{WorkflowDispatcher: fake, AuditLog: logger}}

	req := adminCtx(httptest.NewRequest("POST", "/api/v1/cloudflare/portal/server-auth/apply", nil))
	rec := httptest.NewRecorder()
	h.DispatchPortalServerAuthApply(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	if fake.calls != 1 {
		t.Fatalf("expected exactly one dispatch, got %d", fake.calls)
	}
	// Pinned, not derived from a request: the endpoint exposes no
	// repo/workflow/ref parameter, and this asserts it stays that way.
	if fake.owner != "mctlhq" || fake.repo != "mctl-gitops" {
		t.Errorf("dispatched to %s/%s, want mctlhq/mctl-gitops", fake.owner, fake.repo)
	}
	if fake.wf != "cloudflare-apply.yml" {
		t.Errorf("dispatched workflow %q, want cloudflare-apply.yml", fake.wf)
	}
	// main and nothing else: the workflow's jobs carry
	// `if: github.ref == 'refs/heads/main'` and the cloudflare-apply
	// environment's branch policy allows main alone, so any other ref
	// produces a run that starts and immediately skips.
	if fake.ref != "main" {
		t.Errorf("dispatched ref %q, want main", fake.ref)
	}
	// The security property of this endpoint, not a detail: cloudflare-apply.yml
	// applies whichever OpenTofu root its `root` input names -- the Cloudflare
	// zone and account roots included -- and maps that root to a matching write
	// credential. The root must therefore come from this package's constant and
	// never from the caller, who sends no body at all.
	if got, want := fake.inputs["root"], "infrastructure/cloudflare/portal"; got != want {
		t.Errorf("dispatched root %q, want %q", got, want)
	}
	if len(fake.inputs) != 1 {
		t.Errorf("sent inputs %v; only the pinned root belongs there", fake.inputs)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	// The response must not read as if Cloudflare changed. It did not: the
	// apply job is still waiting on a required reviewer, and a caller that
	// believes otherwise stops watching at exactly the wrong moment.
	msg, _ := body["message"].(string)
	if !strings.Contains(msg, "Nothing has been written to Cloudflare yet") {
		t.Errorf("response message does not say the write has not happened yet: %q", msg)
	}
	if body["runs_url"] == "" || body["runs_url"] == nil {
		t.Error("no runs_url in the response; the dispatch API returns no run id, so the link is the only handle the caller gets")
	}

	entries := logger.List(10)
	if len(entries) != 1 {
		t.Fatalf("expected one audit entry, got %d", len(entries))
	}
	if entries[0].Status != "succeeded" || entries[0].Operation != "portal-server-auth-apply" {
		t.Errorf("audit entry is %+v, want a succeeded portal-server-auth-apply", entries[0])
	}
	// "succeeded" here means the dispatch succeeded. The entry has to say so,
	// or the audit log records an apply that may never have been approved.
	if !strings.Contains(entries[0].Message, "environment approval") {
		t.Errorf("audit message does not distinguish a dispatch from an apply: %q", entries[0].Message)
	}
}

func TestDispatchPortalServerAuthApply_GitHubRefusalIs502(t *testing.T) {
	fake := &fakeDispatcher{err: errors.New("github answered 422: workflow does not have workflow_dispatch trigger")}
	logger := audit.NewLogger()
	h := &Handlers{opts: Options{WorkflowDispatcher: fake, AuditLog: logger}}

	req := adminCtx(httptest.NewRequest("POST", "/api/v1/cloudflare/portal/server-auth/apply", nil))
	rec := httptest.NewRecorder()
	h.DispatchPortalServerAuthApply(rec, req)

	// Not 500: the request was well-formed and the caller can do nothing
	// differently. The far side refused.
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 for a GitHub refusal, got %d: %s", rec.Code, rec.Body.String())
	}
	entries := logger.List(10)
	if len(entries) != 1 || entries[0].Status != "failed" {
		t.Fatalf("expected one failed audit entry, got %+v", entries)
	}
}

// A dispatcher constructed with no token reports ErrNotConfigured at call
// time rather than at startup, so the handler has to map that to the same
// 503 the nil-dispatcher case gets — otherwise an empty GITOPS_ACTIONS_TOKEN
// reads as "GitHub is down".
func TestDispatchPortalServerAuthApply_ErrNotConfiguredIs503(t *testing.T) {
	fake := &fakeDispatcher{err: ghactions.ErrNotConfigured}
	h := &Handlers{opts: Options{WorkflowDispatcher: fake, AuditLog: audit.NewLogger()}}

	req := adminCtx(httptest.NewRequest("POST", "/api/v1/cloudflare/portal/server-auth/apply", nil))
	rec := httptest.NewRecorder()
	h.DispatchPortalServerAuthApply(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for ErrNotConfigured, got %d: %s", rec.Code, rec.Body.String())
	}
}
