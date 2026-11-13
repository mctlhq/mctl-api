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
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/alerts"
	"github.com/mctlhq/mctl-api/internal/auth"
)

// A tenant's incidents must not disappear because other tenants have newer
// ones: before scoping moved into SQL, a non-admin's list and summary were
// cut from the newest 50 rows across all tenants and filtered afterwards.
func TestIncidentReads_NonAdminScopeAppliesBeforeLimit(t *testing.T) {
	store := newTestAlertStore(t)
	h := &Handlers{opts: Options{AlertStore: store}}
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Hour)
	add := func(id, tenant string, at time.Time) {
		a := &alerts.Alert{ID: id, Source: alerts.SourceManual, Type: "workflow_failed", Tenant: tenant,
			Summary: "s", Severity: alerts.SeverityWarning, Status: alerts.StatusOpen, CreatedAt: at}
		if _, err := store.Create(ctx, a); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}
	for i := 0; i < 3; i++ {
		add(fmt.Sprintf("quiet-%d", i), "quiet", base.Add(time.Duration(i)*time.Second))
	}
	for i := 0; i < 60; i++ {
		add(fmt.Sprintf("noisy-%02d", i), "noisy", base.Add(time.Minute+time.Duration(i)*time.Second))
	}
	add("other-0", "other", base.Add(2*time.Minute))

	call := func(u *auth.User, path string, list bool) map[string]json.RawMessage {
		t.Helper()
		req := httptest.NewRequest("GET", path, nil)
		req = req.WithContext(auth.WithUser(req.Context(), u))
		rec := httptest.NewRecorder()
		if list {
			h.ListIncidents(rec, req)
		} else {
			h.IncidentSummary(rec, req)
		}
		if rec.Code != 200 {
			t.Fatalf("%s: status %d: %s", path, rec.Code, rec.Body.String())
		}
		var out map[string]json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		return out
	}
	num := func(raw json.RawMessage) int {
		var n int
		if err := json.Unmarshal(raw, &n); err != nil {
			t.Fatalf("decode %s: %v", raw, err)
		}
		return n
	}

	cases := []struct {
		name        string
		user        *auth.User
		wantList    int
		wantSummary int
	}{
		{"member of a quiet tenant", auth.NewGitHubUser("q", []string{"quiet"}), 3, 3},
		{"member of a tenant above the page size", auth.NewGitHubUser("n", []string{"noisy"}), 50, 60},
		{"member of two tenants", auth.NewGitHubUser("qo", []string{"quiet", "other"}), 4, 4},
		{"member of no tenant", auth.NewGitHubUser("none", nil), 0, 0},
		{"tenant-bound agent run", auth.NewAgentUser("support", auth.AgentRun{Scope: auth.AgentScopeSupport, Tenant: "quiet"}), 3, 3},
		{"admin", auth.NewServiceUser(), 50, 64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			list := call(tc.user, "/api/v1/incidents", true)
			if got := num(list["count"]); got != tc.wantList {
				t.Errorf("list count %d, want %d", got, tc.wantList)
			}
			var items []alerts.Alert
			if err := json.Unmarshal(list["items"], &items); err != nil {
				t.Fatalf("items: %v", err)
			}
			for _, a := range items {
				if !tc.user.HasTenantAccess(a.Tenant) {
					t.Errorf("list leaked %s of tenant %q", a.ID, a.Tenant)
				}
			}
			sum := call(tc.user, "/api/v1/incidents/summary", false)
			if got := num(sum["total"]); got != tc.wantSummary {
				t.Errorf("summary total %d, want %d", got, tc.wantSummary)
			}
		})
	}
}
