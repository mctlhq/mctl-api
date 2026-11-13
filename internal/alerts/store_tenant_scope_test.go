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

package alerts

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// seedTenantScope stores 3 active + 1 resolved incidents for "quiet", all
// older than 60 active incidents for "noisy", so the default page of 50 is
// entirely "noisy" unless the tenant filter runs before LIMIT.
func seedTenantScope(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Hour)
	add := func(id, tenant, status string, at time.Time) {
		a := newAlert(id, "")
		a.Tenant, a.Status, a.CreatedAt = tenant, status, at
		if _, err := s.Create(ctx, a); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}
	for i := 0; i < 3; i++ {
		add(fmt.Sprintf("quiet-%d", i), "quiet", StatusOpen, base.Add(time.Duration(i)*time.Second))
	}
	add("quiet-resolved", "quiet", StatusResolved, base.Add(5*time.Second))
	for i := 0; i < 60; i++ {
		add(fmt.Sprintf("noisy-%02d", i), "noisy", StatusOpen, base.Add(time.Minute+time.Duration(i)*time.Second))
	}
}

func TestList_TenantsFilterRunsBeforeLimit(t *testing.T) {
	s := newTestStore(t)
	seedTenantScope(t, s)
	ctx := context.Background()

	cases := []struct {
		name    string
		tenants []string
		want    int
	}{
		{"scoped to quiet", []string{"quiet"}, 4},
		{"scoped to both", []string{"quiet", "noisy"}, 50},
		{"empty scope matches nothing", []string{}, 0},
		{"nil is unrestricted", nil, 50},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.List(ctx, ListFilter{Tenants: tc.tenants})
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if len(got) != tc.want {
				t.Fatalf("got %d rows, want %d", len(got), tc.want)
			}
			if tc.tenants != nil {
				for _, a := range got {
					if !contains(tc.tenants, a.Tenant) {
						t.Fatalf("row %s of tenant %q is outside scope %v", a.ID, a.Tenant, tc.tenants)
					}
				}
			}
		})
	}

	// Tenants narrows Tenant; it never widens it.
	got, err := s.List(ctx, ListFilter{Tenant: "noisy", Tenants: []string{"quiet"}})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Tenant outside Tenants returned %d rows, want 0", len(got))
	}
}

func TestSummary_TenantScopeCountsEveryRow(t *testing.T) {
	s := newTestStore(t)
	seedTenantScope(t, s)
	ctx := context.Background()

	cases := []struct {
		name    string
		tenants []string
		want    int
	}{
		{"scoped to quiet", []string{"quiet"}, 3},
		{"scoped to noisy, above the list page size", []string{"noisy"}, 60},
		{"empty scope counts nothing", []string{}, 0},
		{"nil counts every tenant", nil, 63},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sum, err := s.Summary(ctx, tc.tenants)
			if err != nil {
				t.Fatalf("summary: %v", err)
			}
			if sum.Total != tc.want {
				t.Fatalf("total %d, want %d", sum.Total, tc.want)
			}
			if sum.ByStatus[StatusOpen] != tc.want || sum.BySeverity[SeverityWarning] != tc.want || sum.ByType["workflow_failed"] != tc.want {
				t.Fatalf("breakdown does not add up to %d: %+v", tc.want, sum)
			}
			if sum.ByStatus[StatusResolved] != 0 {
				t.Fatalf("resolved incidents counted: %+v", sum)
			}
		})
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
