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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mctlhq/mctl-api/internal/alerts"
	"github.com/mctlhq/mctl-api/internal/auth"
)

func postIncident(t *testing.T, h *Handlers, id, extra string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"id":"` + id + `","source":"manual","type":"workflow_failed",` +
		`"tenant":"admins","summary":"test","severity":"warning"` + extra + `}`
	req := httptest.NewRequest("POST", "/api/v1/incidents", bytes.NewBufferString(body))
	req = req.WithContext(auth.WithUser(req.Context(), &auth.User{ID: "tester", Groups: []string{"admins"}}))
	rec := httptest.NewRecorder()
	h.CreateIncident(rec, req)
	return rec
}

// TestCreateIncident_RejectsServerOwnedLifecycle: a caller must not be able
// to create an incident that is already acknowledged or resolved. Each case
// is refused with 400 and nothing is stored.
func TestCreateIncident_RejectsServerOwnedLifecycle(t *testing.T) {
	store := newTestAlertStore(t)
	h := &Handlers{opts: Options{AlertStore: store}}

	cases := map[string]string{
		"status resolved":     `,"status":"resolved"`,
		"status suppressed":   `,"status":"suppressed"`,
		"status acknowledged": `,"status":"acknowledged"`,
		"status unknown":      `,"status":"closed"`,
		"resolved_at":         `,"resolved_at":"2026-01-01T00:00:00Z"`,
		"resolved_by":         `,"resolved_by":"user:mallory"`,
		"acknowledged_by":     `,"acknowledged_by":"user:mallory"`,
		"acknowledged_at":     `,"acknowledged_at":"2026-01-01T00:00:00Z"`,
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			rec := postIncident(t, h, "lifecycle-1", extra)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
			}
			if _, err := store.Get(context.Background(), "lifecycle-1"); !errors.Is(err, alerts.ErrNotFound) {
				t.Fatalf("refused create must store nothing, Get err = %v", err)
			}
		})
	}
}

// TestCreateIncident_AcceptsProducerWorkingStates: the working states a
// producer pipeline creates in stay accepted (mctl-agent creates in
// `analyzing`), and an explicit null for a lifecycle field is no value.
func TestCreateIncident_AcceptsProducerWorkingStates(t *testing.T) {
	store := newTestAlertStore(t)
	h := &Handlers{opts: Options{AlertStore: store}}

	for i, status := range []string{"", alerts.StatusOpen, alerts.StatusAnalyzing, alerts.StatusFixProposed} {
		extra := `,"resolved_at":null`
		if status != "" {
			extra += `,"status":"` + status + `"`
		}
		rec := postIncident(t, h, fmt.Sprintf("lifecycle-ok-%d", i), extra)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status %q: expected 201, got %d: %s", status, rec.Code, rec.Body.String())
		}
		var got alerts.Alert
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		want := status
		if want == "" {
			want = alerts.StatusOpen
		}
		if got.Status != want || got.ResolvedAt != nil || got.AcknowledgedAt != nil {
			t.Fatalf("case %d: got status=%q resolved_at=%v acknowledged_at=%v", i, got.Status, got.ResolvedAt, got.AcknowledgedAt)
		}
	}
}
