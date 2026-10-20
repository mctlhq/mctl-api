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
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/decisions"
	"github.com/mctlhq/mctl-api/internal/evidence"
)

// Decision routes (mctl-api#701): the widened writer gate, admin-only reads,
// 503 for an unconfigured store or an unobservable reference.

func TestIsDecisionWriteRoute(t *testing.T) {
	for path, want := range map[string]bool{
		"/api/v1/decisions":                     true,
		"/api/v1/decisions/dec_1/attempts":      true,
		"/api/v1/decisions/":                    false,
		"/api/v1/decisions//attempts":           false,
		"/api/v1/decisions/dec_1":               false,
		"/api/v1/decisions/a/b/attempts":        false,
		"/api/v1/decisions/dec_1/attempts/":     false,
		"/api/v1/decisions/dec_1/attempts/x":    false,
		"/api/v1/decisionsx":                    false,
		"/api/v1/work-items/wi_1/decisions":     false,
		"/api/v1/decisions/dec_1/attemptsextra": false,
	} {
		r := httptest.NewRequest(http.MethodPost, path, nil)
		if got := isDecisionWriteRoute(r); got != want {
			t.Errorf("POST %s: %v, want %v", path, got, want)
		}
	}
	if isDecisionWriteRoute(httptest.NewRequest(http.MethodGet, "/api/v1/decisions", nil)) {
		t.Error("GET /api/v1/decisions counted as a write route")
	}
}

// Through the real router: the evidence writer reaches the two decision
// append routes (their handlers answer 503 with no store, which only a
// request that got through the gate can see) and nothing else new.
func TestEvidenceWriter_ReachesDecisionAppendsOnly(t *testing.T) {
	router := NewRouter(Options{AuthMiddleware: injectUser(evidenceWriter(t))})
	for _, path := range []string{"/api/v1/decisions", "/api/v1/decisions/dec_1/attempts"} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte("{}"))))
		if rec.Code != http.StatusServiceUnavailable || bodyCode(rec) != codeDecisionStoreUnavailable {
			t.Errorf("POST %s: got %d %s, want 503 from the handler", path, rec.Code, rec.Body.String())
		}
	}
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/decisions"},
		{http.MethodGet, "/api/v1/decisions/dec_1"},
		{http.MethodPut, "/api/v1/decisions"},
		{http.MethodPost, "/api/v1/decisions/dec_1"},
		{http.MethodDelete, "/api/v1/decisions/dec_1/attempts"},
	} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, bytes.NewReader([]byte("{}"))))
		if rec.Code != http.StatusForbidden || bodyCode(rec) != codeEvidenceWriterForbidden {
			t.Errorf("%s %s: got %d %s, want 403 %s", c.method, c.path, rec.Code, rec.Body.String(), codeEvidenceWriterForbidden)
		}
	}
}

func TestDecisions_UnconfiguredStoreAnswers503(t *testing.T) {
	router := NewRouter(Options{AuthMiddleware: injectUser(adminUser())})
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/decisions"},
		{http.MethodPost, "/api/v1/decisions/dec_1/attempts"},
		{http.MethodGet, "/api/v1/decisions/dec_1"},
		{http.MethodGet, "/api/v1/decisions?execution_id=we_1"},
	} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, bytes.NewReader([]byte("{}"))))
		if rec.Code != http.StatusServiceUnavailable || bodyCode(rec) != codeDecisionStoreUnavailable {
			t.Errorf("%s %s: got %d %s, want 503", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
}

func newDecisionStore(t *testing.T) *decisions.Store {
	t.Helper()
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed decision handler test")
	}
	s, err := decisions.NewStore(context.Background(), connStr)
	if err != nil {
		t.Fatalf("decisions.NewStore: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

type stubEvidence struct{ err error }

func (s *stubEvidence) Get(_ context.Context, id string) (*evidence.Evidence, error) {
	if s.err != nil {
		return nil, s.err
	}
	return nil, evidence.ErrEvidenceNotFound
}

func doJSON(t *testing.T, router http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(method, path, &buf))
	return rec
}

// The whole chain over HTTP: the writer records a decision and a retried
// attempt, an admin reconstructs it from the id, a non-admin cannot, and an
// unreadable reference is 503 rather than a partial chain.
func TestDecisions_RecordAttemptAndReconstruct(t *testing.T) {
	store := newDecisionStore(t)
	ev := &stubEvidence{}
	store.SetLookups(nil, ev)
	writer := NewRouter(Options{AuthMiddleware: injectUser(evidenceWriter(t)), Decisions: store})
	admin := NewRouter(Options{AuthMiddleware: injectUser(adminUser()), Decisions: store})
	member := NewRouter(Options{AuthMiddleware: injectUser(auth.NewGitHubUser("alice", []string{"t"})), Decisions: store})

	exec := "we_" + uuid.NewString()
	body := map[string]any{
		"execution_id": exec, "policy_version": "mctl-agents/policy/v1", "rule_id": "github-pr-comment",
		"verdict": "allow", "code": "allowed", "policy_reasons": []string{"rule.github-pr-comment"},
		"actor": "agent:implementer", "action_kind": "github.pr.comment", "operation": "comment",
		"target_digest": decisions.TargetDigest("mctlhq/mctl-api#1"), "args_digest": decisions.TargetDigest("a"),
		"action_digest": decisions.TargetDigest("d"), "decided_at": time.Now().UTC().Format(time.RFC3339Nano),
		"idempotency_key": "k-" + uuid.NewString(),
	}
	rec := doJSON(t, writer, http.MethodPost, "/api/v1/decisions", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("record: %d %s", rec.Code, rec.Body.String())
	}
	var created struct{ Decision decisions.Decision }
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	id := created.Decision.ID
	if rec := doJSON(t, writer, http.MethodPost, "/api/v1/decisions", body); rec.Code != http.StatusOK {
		t.Fatalf("replay: %d, want 200", rec.Code)
	}
	body["unexpected"] = "x"
	if rec := doJSON(t, writer, http.MethodPost, "/api/v1/decisions", body); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d, want 400", rec.Code)
	}

	attempts := "/api/v1/decisions/" + id + "/attempts"
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for i, e := range []map[string]any{
		{"phase": "started", "occurred_at": now, "idempotency_key": "s1"},
		{"phase": "failed", "attempt_no": 1, "error_code": "github.timeout", "occurred_at": now, "idempotency_key": "f1"},
		{"phase": "started", "occurred_at": now, "idempotency_key": "s2"},
		{"phase": "succeeded", "attempt_no": 2, "evidence_id": "ev-00000000000000e1", "occurred_at": now, "idempotency_key": "d2"},
	} {
		if rec := doJSON(t, writer, http.MethodPost, attempts, e); rec.Code != http.StatusCreated {
			t.Fatalf("event %d: %d %s", i, rec.Code, rec.Body.String())
		}
	}
	rec = doJSON(t, writer, http.MethodPost, attempts, map[string]any{"phase": "started", "occurred_at": now, "idempotency_key": "s3"})
	if rec.Code != http.StatusConflict || bodyCode(rec) != codeDecisionAlreadySucceeded {
		t.Fatalf("start after success: %d %s", rec.Code, rec.Body.String())
	}

	if rec := doJSON(t, member, http.MethodGet, "/api/v1/decisions/"+id, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("member read: %d, want 403", rec.Code)
	}
	rec = doJSON(t, admin, http.MethodGet, "/api/v1/decisions/"+id, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("chain: %d %s", rec.Code, rec.Body.String())
	}
	var chain decisions.Chain
	if err := json.Unmarshal(rec.Body.Bytes(), &chain); err != nil {
		t.Fatal(err)
	}
	if chain.Result != decisions.ResultSucceeded || len(chain.Attempts) != 2 ||
		chain.Attempts[0].Status != decisions.PhaseFailed || len(chain.Evidence) != 1 ||
		chain.Evidence[0].Status != decisions.RefNotFound {
		t.Fatalf("chain: %s", rec.Body.String())
	}
	if rec := doJSON(t, admin, http.MethodGet, "/api/v1/decisions?execution_id="+exec, nil); rec.Code != http.StatusOK ||
		!bytes.Contains(rec.Body.Bytes(), []byte(id)) {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doJSON(t, admin, http.MethodGet, "/api/v1/decisions/dec_missing", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("missing: %d, want 404", rec.Code)
	}

	ev.err = errors.New("connection reset")
	rec = doJSON(t, admin, http.MethodGet, "/api/v1/decisions/"+id, nil)
	if rec.Code != http.StatusServiceUnavailable || bodyCode(rec) != codeDecisionUnobservable {
		t.Fatalf("unreadable evidence: %d %s, want 503 %s", rec.Code, rec.Body.String(), codeDecisionUnobservable)
	}
}
