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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
	mctlmcp "github.com/mctlhq/mctl-api/internal/mcp"
	"github.com/mctlhq/mctl-api/internal/usage"
)

// The usage-writer principal (mctlhq/.github#50, variant B) holds one
// capability: appending usage records. These tests pin that it can do
// exactly that, that every row it writes names it, and that it can do
// nothing else.

type fixedPrincipal string

func (p fixedPrincipal) ResolvePrincipal(context.Context, auth.Identity) (string, error) {
	return string(p), nil
}

func usageWriter(t *testing.T) *auth.User {
	t.Helper()
	u := auth.NewUsageWriterUser()
	if err := auth.AttachPrincipal(context.Background(), fixedPrincipal("prn_usagewriter"), u); err != nil {
		t.Fatalf("AttachPrincipal: %v", err)
	}
	return u
}

func injectUser(u *auth.User) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), u)))
		})
	}
}

// Through the real router: every route but POST /usage/records is refused
// before its handler runs, whatever that handler's own checks would say.
func TestUsageWriter_IsConfinedToAppendingRecords(t *testing.T) {
	router := NewRouter(Options{
		AuthMiddleware: injectUser(usageWriter(t)),
		// Mounted so /mcp is a real route: its tools act with the caller's
		// token, and the writer must not reach them either.
		MCPServer: mctlmcp.NewServer("http://127.0.0.1:1", ""),
	})
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/usage/records"},
		{http.MethodGet, "/api/v1/usage/summary"},
		{http.MethodGet, "/api/v1/whoami"},
		{http.MethodGet, "/api/v1/tenants"},
		{http.MethodPost, "/api/v1/lifecycle/ownership/acquire"},
		{http.MethodPost, "/api/v1/agents/dev-loop/dev-loop-mctlhq-mctl-api-1/approve"},
		{http.MethodPost, "/api/v1/work-items"},
		{http.MethodPost, "/mcp"},
		{http.MethodGet, "/mcp"},
		{http.MethodPut, "/api/v1/usage/records"},
		{http.MethodPost, "/api/v1/usage/records/"},
	} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, bytes.NewReader([]byte("{}"))))
		var body struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code != http.StatusForbidden || body.Code != "usage_writer_route_not_allowed" {
			t.Errorf("%s %s: got %d %s, want 403 usage_writer_route_not_allowed", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
	// The one route passes the gate: with no ledger configured its own
	// handler answers 503, which only a request that got through can see.
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/usage/records", bytes.NewReader([]byte(`{"records":[]}`))))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("POST /api/v1/usage/records: got %d %s, want 503 from the handler", rec.Code, rec.Body.String())
	}
}

// Everyone else is unaffected by the gate.
func TestUsageWriterGate_LeavesOtherCallersAlone(t *testing.T) {
	router := NewRouter(Options{AuthMiddleware: injectUser(&auth.User{ID: "t", Groups: []string{"some-tenant"}})})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/usage/records", nil))
	if rec.Code == http.StatusForbidden && bytes.Contains(rec.Body.Bytes(), []byte("usage_writer_route_not_allowed")) {
		t.Fatalf("the gate refused a caller that is not the usage writer: %s", rec.Body.String())
	}
}

func postUsageAs(t *testing.T, h *Handlers, u *auth.User, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/usage/records", bytes.NewReader(raw))
	req = req.WithContext(auth.WithUser(req.Context(), u))
	rec := httptest.NewRecorder()
	h.IngestUsageRecords(rec, req)
	return rec
}

func TestUsageWriter_AppendsAttributedRecordsIdempotently(t *testing.T) {
	store, prefix := newTestUsageStore(t)
	h := &Handlers{opts: Options{Usage: store}}
	writer := usageWriter(t)
	record := usageRecordBody(prefix, "writer")
	// A producer cannot choose the attribution: the server overwrites it.
	record["ingested_by"] = "somebody-else"
	record["ingested_by_principal_id"] = "prn_forged"
	body := map[string]any{"records": []any{record}}

	rec := postUsageAs(t, h, writer, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("writer ingest: %d %s", rec.Code, rec.Body.String())
	}
	var first ingestUsageResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &first); err != nil || first.AcceptedCount != 1 {
		t.Fatalf("first: %+v %v", first, err)
	}

	// Dedupe is unchanged: the same record again, even from an admin, is a
	// no-op that keeps the first write's attribution.
	rec = postUsage(t, h, body, true)
	var second ingestUsageResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &second); err != nil || second.AcceptedCount != 0 || second.DedupedCount != 1 {
		t.Fatalf("replay: %d %s", rec.Code, rec.Body.String())
	}

	got, err := store.List(context.Background(), usage.Filter{TemporalWorkflowID: prefix + "-wf"})
	if err != nil || len(got.Records) != 1 {
		t.Fatalf("list: %v %+v", err, got)
	}
	r := got.Records[0]
	if r.IngestedBy != auth.UsageWriterUserID || r.IngestedByPrincipalID != "prn_usagewriter" {
		t.Fatalf("attribution = %q / %q, want %q / prn_usagewriter", r.IngestedBy, r.IngestedByPrincipalID, auth.UsageWriterUserID)
	}
}

// The usage writer cannot read the ledger even when a handler is reached
// directly: reads stay admin-only.
func TestUsageWriter_CannotReadTheLedger(t *testing.T) {
	store, _ := newTestUsageStore(t)
	h := &Handlers{opts: Options{Usage: store}}
	for name, fn := range map[string]http.HandlerFunc{"list": h.ListUsageRecords, "summary": h.GetUsageSummary} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/usage/records", nil)
		req = req.WithContext(auth.WithUser(req.Context(), usageWriter(t)))
		rec := httptest.NewRecorder()
		fn(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s as the usage writer: want 403, got %d", name, rec.Code)
		}
	}
}
