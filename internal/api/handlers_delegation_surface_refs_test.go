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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/httprate"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// surfaceRefRows counts the work_item_surface_refs rows on id naming actor.
func (e *sidEnv) surfaceRefRows(id, actor string) int {
	e.t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), `SELECT count(*) FROM work_item_surface_refs
		WHERE work_item_id=$1 AND actor_external_id=$2`, id, actor).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

// mctl-api#376 slice B: under delegation, POST .../surface-refs may only
// bind the delegated subject's OWN live surface identity. Otherwise an agent
// delegating as alice could write the binding row for bob's identity and
// then present bob's sil_ ref (resolveSurfaceLink binds through exactly that
// row). The route stays on the delegation allowlist.
func TestDelegatedSurfaceRef_BindsOnlyTheSubjectsOwnIdentity(t *testing.T) {
	e := newSIDEnv(t)
	e.link("alice", "telegram", "4242")
	e.link("bob", "telegram", "5555")
	revoked := e.link("alice", "portal", "p-alice")
	if code, _ := e.do("alice", "POST", "/api/v1/surface-identities/"+revoked+"/revoke", nil); code != http.StatusOK {
		t.Fatalf("revoke = %d", code)
	}
	_, created := e.relayCreate("telegram", "4242", nil)
	id := created["work_item"].(map[string]any)["id"].(string)
	agent := auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: "we_1", WorkItemID: id})
	e.users["as-alice"] = auth.NewDelegatedUser("alice", []string{e.tenant}, agent)
	path := "/api/v1/work-items/" + id + "/surface-refs"

	// The subject's own identity: allowed and written.
	if code, body := e.do("as-alice", "POST", path, map[string]any{
		"surface": "telegram", "external_id": "chat-1", "actor_external_id": "4242",
	}); code != http.StatusCreated {
		t.Fatalf("own identity = %d %v", code, body)
	}
	if e.surfaceRefRows(id, "4242") != 1 {
		t.Fatal("own identity was not written")
	}

	// Another human's identity, one that does not exist, and the subject's
	// own revoked one: the same refusal for all three, and nothing written.
	var refusals []map[string]any
	for _, tc := range []struct{ surface, actor string }{
		{"telegram", "5555"},    // bob's
		{"telegram", "9999999"}, // nobody's
		{"portal", "p-alice"},   // alice's, revoked
	} {
		code, body := e.do("as-alice", "POST", path, map[string]any{
			"surface": tc.surface, "external_id": "chat-" + tc.actor, "actor_external_id": tc.actor,
		})
		if code != http.StatusForbidden || body["code"] != delegationCodeNotBound {
			t.Errorf("actor %s:%s = %d %v, want 403 %s", tc.surface, tc.actor, code, body, delegationCodeNotBound)
		}
		if n := e.surfaceRefRows(id, tc.actor); n != 0 {
			t.Errorf("actor %s:%s wrote %d rows before refusing", tc.surface, tc.actor, n)
		}
		refusals = append(refusals, body)
	}
	// No existence oracle: another human's identity and an unknown one read
	// back identically.
	if refusals[0]["code"] != refusals[1]["code"] || refusals[0]["error"] != refusals[1]["error"] || refusals[0]["error"] == nil {
		t.Errorf("bob's identity %v and an unknown one %v are distinguishable", refusals[0], refusals[1])
	}

	// Rewriting an existing ref's actor goes through the same check (the
	// upsert would otherwise overwrite actor_external_id on conflict).
	if code, body := e.do("as-alice", "POST", path, map[string]any{
		"surface": "telegram", "external_id": "chat-1", "actor_external_id": "5555",
	}); code != http.StatusForbidden || body["code"] != delegationCodeNotBound {
		t.Errorf("overwrite with bob's identity = %d %v", code, body)
	}
	if e.surfaceRefRows(id, "5555") != 0 {
		t.Error("an existing ref was re-pointed at bob's identity")
	}

	// No actor_external_id binds nothing and stays allowed.
	if code, body := e.do("as-alice", "POST", path, map[string]any{"surface": "telegram", "external_id": "chat-2"}); code != http.StatusCreated {
		t.Errorf("delegated ref without an actor = %d %v", code, body)
	}

	refused := 0
	for _, entry := range e.audit.List(100) {
		if entry.Operation == "agent_identity.delegation_refused" && entry.Parameters["reason"] == delegationCodeNotBound {
			refused++
		}
	}
	if refused != 4 {
		t.Errorf("audited refusals = %d, want 4", refused)
	}
}

// The non-delegated flows are unchanged: the surface relay and a direct
// caller still store actor_external_id as given.
func TestDelegatedSurfaceRef_NonDelegatedFlowsAreUnchanged(t *testing.T) {
	e := newSIDEnv(t)
	e.link("alice", "telegram", "4242")
	_, created := e.relayCreate("telegram", "4242", nil)
	id := created["work_item"].(map[string]any)["id"].(string)
	path := "/api/v1/work-items/" + id + "/surface-refs"

	if code, body := e.do("telegram", "POST", path, map[string]any{
		"external_id": "chat-relay", "actor_external_id": "4242",
	}, SurfaceActorHeader, "4242"); code != http.StatusCreated {
		t.Fatalf("relayed surface-ref = %d %v", code, body)
	}
	if code, body := e.do("service", "POST", path, map[string]any{
		"surface": "telegram", "external_id": "chat-svc", "actor_external_id": "8888",
	}); code != http.StatusCreated {
		t.Fatalf("direct surface-ref = %d %v", code, body)
	}
	if e.surfaceRefRows(id, "4242") != 1 || e.surfaceRefRows(id, "8888") != 1 {
		t.Fatal("a non-delegated surface-ref was not written as given")
	}
}

// agentAggregateLimit caps an agent principal as a whole: every run token of
// one agent shares the budget, another agent has its own, and a non-agent
// caller is never metered by it.
func TestAgentAggregateLimit_CapsTheAgentNotTheRunOrOthers(t *testing.T) {
	const limit = 3
	mw := agentAggregateLimit(httprate.Limit(limit, time.Minute, httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
		return "agent-total:" + auth.UserFromContext(r.Context()).ID, nil
	})))
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	call := func(u *auth.User) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, asUser(httptest.NewRequest("GET", "/api/v1/services", nil), u))
		return rec.Code
	}
	runA := auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: "we_A", WorkItemID: "wi_1"})
	runB := auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: "we_B", WorkItemID: "wi_2"})
	for i := 0; i < limit; i++ {
		if code := call(runA); code != http.StatusNoContent {
			t.Fatalf("call %d within the ceiling = %d", i, code)
		}
	}
	if code := call(runA); code != http.StatusTooManyRequests {
		t.Errorf("over the ceiling = %d, want 429", code)
	}
	if code := call(runB); code != http.StatusTooManyRequests {
		t.Errorf("another run token of the same agent = %d, want 429 (shared budget)", code)
	}
	other := auth.NewAgentUser("shepherd", auth.AgentRun{ExecutionID: "we_C", WorkItemID: "wi_1"})
	if code := call(other); code != http.StatusNoContent {
		t.Errorf("another agent = %d, want its own budget", code)
	}
	human := auth.NewGitHubUser("alice", nil)
	for i := 0; i < limit+2; i++ {
		if code := call(human); code != http.StatusNoContent {
			t.Fatalf("a non-agent caller was metered: call %d = %d", i, code)
		}
	}
}
