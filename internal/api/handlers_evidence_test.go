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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/evidence"
)

// Evidence routes (mctl-api#409): the writer gate, admin-only reads, the
// work-item read's 404-not-403 visibility and 503 for an unconfigured store.

func evidenceWriter(t *testing.T) *auth.User {
	t.Helper()
	u := auth.NewEvidenceWriterUser()
	if err := auth.AttachPrincipal(context.Background(), fixedPrincipal("prn_evidencewriter"), u); err != nil {
		t.Fatalf("AttachPrincipal: %v", err)
	}
	return u
}

func adminUser() *auth.User {
	return &auth.User{ID: "root", Groups: []string{"admins"}}
}

// sealTestEnvelope builds a sealed, ASCII-only envelope (so encoding/json's
// sorted, compact output equals the canonical form) bound to workItemID.
func sealTestEnvelope(t *testing.T, workItemID, trace string) []byte {
	t.Helper()
	content := map[string]any{
		"api_version": evidence.APIVersionV1Alpha1,
		"kind":        evidence.KindV1Alpha1,
		"execution": map[string]any{
			"execution_id": "we_" + trace,
			"work_item_id": workItemID,
			"trace_id":     trace,
		},
		"outcome": map[string]any{"code": "succeeded", "reason_code": "test"},
	}
	canonical, err := json.Marshal(content)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	hash := "sha256:" + hex.EncodeToString(sum[:])
	content["content_hash"] = hash
	content["evidence_id"] = "ev-" + hash[7:23]
	content["created_at"] = "2026-01-15T12:00:00Z"
	raw, err := json.Marshal(content)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newEvidenceStore(t *testing.T) *evidence.Store {
	t.Helper()
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed evidence handler test")
	}
	s, err := evidence.NewStore(context.Background(), connStr)
	if err != nil {
		t.Fatalf("evidence.NewStore: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

func bodyCode(rec *httptest.ResponseRecorder) string {
	var body struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return body.Code
}

// Through the real router: the evidence writer is refused on every route
// except POST /api/v1/evidence/records, including the evidence reads.
func TestEvidenceWriter_IsConfinedToAppendingRecords(t *testing.T) {
	router := NewRouter(Options{AuthMiddleware: injectUser(evidenceWriter(t))})
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/evidence"},
		{http.MethodGet, "/api/v1/evidence/ev-0123456789abcdef"},
		{http.MethodGet, "/api/v1/work-items/wi_x/evidence"},
		{http.MethodGet, "/api/v1/usage/records"},
		{http.MethodPost, "/api/v1/usage/records"},
		{http.MethodGet, "/api/v1/whoami"},
		{http.MethodPost, "/api/v1/work-items"},
		{http.MethodPut, "/api/v1/evidence/records"},
		{http.MethodPost, "/api/v1/evidence/records/"},
	} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, bytes.NewReader([]byte("{}"))))
		if rec.Code != http.StatusForbidden || bodyCode(rec) != codeEvidenceWriterForbidden {
			t.Errorf("%s %s: got %d %s, want 403 %s", c.method, c.path, rec.Code, rec.Body.String(), codeEvidenceWriterForbidden)
		}
	}
	// The one route passes the gate: with no store configured its own
	// handler answers 503, which only a request that got through can see.
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/evidence/records", bytes.NewReader([]byte(`{"envelope_b64":""}`))))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("POST /api/v1/evidence/records: got %d %s, want 503 from the handler", rec.Code, rec.Body.String())
	}
}

// An unconfigured store is 503 with a typed code on every evidence route,
// never an empty list.
func TestEvidence_UnconfiguredStoreAnswers503(t *testing.T) {
	h := &Handlers{}
	r := chi.NewRouter()
	r.Post("/api/v1/evidence/records", h.IngestEvidence)
	r.Get("/api/v1/evidence", h.ListEvidence)
	r.Get("/api/v1/evidence/{id}", h.GetEvidence)
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/evidence/records"},
		{http.MethodGet, "/api/v1/evidence"},
		{http.MethodGet, "/api/v1/evidence/ev-0123456789abcdef"},
	} {
		req := httptest.NewRequest(c.method, c.path, bytes.NewReader([]byte(`{}`)))
		req = req.WithContext(auth.WithUser(req.Context(), adminUser()))
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable || bodyCode(rec) != codeEvidenceStoreUnavailable {
			t.Errorf("%s %s: got %d %s, want 503 %s", c.method, c.path, rec.Code, rec.Body.String(), codeEvidenceStoreUnavailable)
		}
	}
}

// A tenant member who is not an admin cannot use the admin reads, even
// with a configured store.
func TestEvidence_AdminReadsRefuseNonAdmins(t *testing.T) {
	h := &Handlers{opts: Options{Evidence: newEvidenceStore(t)}}
	r := chi.NewRouter()
	r.Get("/api/v1/evidence", h.ListEvidence)
	r.Get("/api/v1/evidence/{id}", h.GetEvidence)
	member := auth.NewGitHubUser("alice", []string{"some-tenant"})
	for _, path := range []string{"/api/v1/evidence", "/api/v1/evidence/ev-0123456789abcdef"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req = req.WithContext(auth.WithUser(req.Context(), member))
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("GET %s as a non-admin: got %d %s, want 403", path, rec.Code, rec.Body.String())
		}
	}
}

// The writer can append; a replay answers 200 with the first record; an
// over-large body gets the documented evidence_too_large code.
func TestEvidence_WriterIngestsAndReplays(t *testing.T) {
	h := &Handlers{opts: Options{Evidence: newEvidenceStore(t)}}
	post := func(u *auth.User, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/records", bytes.NewReader(body))
		req = req.WithContext(auth.WithUser(req.Context(), u))
		rec := httptest.NewRecorder()
		h.IngestEvidence(rec, req)
		return rec
	}
	env := sealTestEnvelope(t, "wi_handler-ingest", uniqueTrace())
	body, _ := json.Marshal(map[string]string{"envelope_b64": base64.StdEncoding.EncodeToString(env)})

	first := post(evidenceWriter(t), body)
	if first.Code != http.StatusCreated {
		t.Fatalf("first ingest: got %d %s, want 201", first.Code, first.Body.String())
	}
	replay := post(evidenceWriter(t), body)
	if replay.Code != http.StatusOK {
		t.Fatalf("replay: got %d %s, want 200", replay.Code, replay.Body.String())
	}

	huge := []byte(`{"envelope_b64":"` + strings.Repeat("A", maxEvidenceBodyBytes+1) + `"}`)
	rec := post(evidenceWriter(t), huge)
	if rec.Code != http.StatusBadRequest || bodyCode(rec) != codeEvidenceTooLarge {
		t.Errorf("over-large body: got %d %s, want 400 %s", rec.Code, rec.Body.String(), codeEvidenceTooLarge)
	}
}

// GET /api/v1/work-items/{id}/evidence reuses the work item's own
// visibility: a caller who cannot see the item gets 404, never 403, so the
// item's existence does not leak; one who can sees its evidence.
func TestEvidence_WorkItemReadFollowsItemVisibility(t *testing.T) {
	e := newWorkItemsEnv(t)
	store := newEvidenceStore(t)
	e.h.opts.Evidence = store
	e.router.Get("/api/v1/work-items/{id}/evidence", e.h.ListWorkItemEvidence)

	owner := e.user("alice")
	item := e.open(owner, nil)
	itemID := item["id"].(string)
	if _, _, err := store.Ingest(context.Background(), evidence.IngestInput{
		EnvelopeBytes: sealTestEnvelope(t, itemID, uniqueTrace()), IngestedBy: "test:writer",
	}); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	outsider := auth.NewGitHubUser("mallory", []string{"another-tenant"})
	res := e.do(outsider, http.MethodGet, "/api/v1/work-items/"+itemID+"/evidence", nil)
	if res.code != http.StatusNotFound {
		t.Fatalf("outsider: got %d %s, want 404 (not 403)", res.code, res.raw)
	}

	res = e.do(owner, http.MethodGet, "/api/v1/work-items/"+itemID+"/evidence", nil)
	if res.code != http.StatusOK {
		t.Fatalf("owner: got %d %s, want 200", res.code, res.raw)
	}
	list, _ := res.body["evidence"].([]any)
	if len(list) != 1 {
		t.Errorf("owner sees %d evidence records, want 1", len(list))
	}

	e.h.opts.Evidence = nil
	res = e.do(owner, http.MethodGet, "/api/v1/work-items/"+itemID+"/evidence", nil)
	if res.code != http.StatusServiceUnavailable || code(res) != codeEvidenceStoreUnavailable {
		t.Errorf("unconfigured store: got %d %s, want 503 %s", res.code, res.raw, codeEvidenceStoreUnavailable)
	}
}

var traceCounter int

func uniqueTrace() string {
	traceCounter++
	return strings.ReplaceAll(strings.ToLower(time.Now().UTC().Format("20060102t150405.000000000")), ".", "") + strconv.Itoa(traceCounter)
}
