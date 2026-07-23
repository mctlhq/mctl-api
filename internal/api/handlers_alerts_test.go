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
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mctlhq/mctl-api/internal/alerts"
	"github.com/mctlhq/mctl-api/internal/auth"
)

// newTestAlertStore connects to a real Postgres instance, matching the
// TEST_DATABASE_URL-gated pattern used by internal/alerts/store_test.go —
// this repo has no Postgres service in CI, so these tests only run when
// pointed at a local/ephemeral instance. Cleanup uses a second pool since
// alerts.Store doesn't expose its underlying pool outside its own package.
func newTestAlertStore(t *testing.T) *alerts.Store {
	t.Helper()
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed handler test")
	}

	ctx := context.Background()
	s, err := alerts.NewStore(ctx, connStr)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	cleanupPool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("cleanup pool: %v", err)
	}
	t.Cleanup(func() {
		_, _ = cleanupPool.Exec(ctx, "DELETE FROM alert_evidence")
		_, _ = cleanupPool.Exec(ctx, "DELETE FROM alerts")
		cleanupPool.Close()
	})
	if _, err := cleanupPool.Exec(ctx, "DELETE FROM alert_evidence"); err != nil {
		t.Fatalf("cleanup evidence: %v", err)
	}
	if _, err := cleanupPool.Exec(ctx, "DELETE FROM alerts"); err != nil {
		t.Fatalf("cleanup alerts: %v", err)
	}
	return s
}

// TestCreateIncident_CallerSuppliedOccurrenceCount_Ignored guards against a
// caller POSTing occurrence_count directly: the handler must zero it out
// before calling the store, so the store's own dedup counter is always the
// source of truth.
func TestCreateIncident_CallerSuppliedOccurrenceCount_Ignored(t *testing.T) {
	store := newTestAlertStore(t)
	h := &Handlers{opts: Options{AlertStore: store}}

	body := `{
		"id": "handler-occ-1",
		"source": "manual",
		"type": "workflow_failed",
		"tenant": "admins",
		"summary": "test",
		"severity": "warning",
		"occurrence_count": 99
	}`

	req := httptest.NewRequest("POST", "/api/v1/incidents", bytes.NewBufferString(body))
	req = req.WithContext(auth.WithUser(req.Context(), &auth.User{ID: "tester", Groups: []string{"admins"}}))
	rec := httptest.NewRecorder()

	h.CreateIncident(rec, req)

	if rec.Code != 201 {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var got alerts.Alert
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if got.OccurrenceCount != 1 {
		t.Fatalf("expected caller-supplied occurrence_count=99 to be ignored and stored as 1, got %d", got.OccurrenceCount)
	}
}
