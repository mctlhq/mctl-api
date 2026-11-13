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

package auth

import (
	"slices"
	"testing"
)

// TenantScope feeds SQL filters that replace per-row HasTenantAccess checks,
// so the two must admit exactly the same tenants for every kind of principal.
func TestTenantScopeMatchesHasTenantAccess(t *testing.T) {
	users := map[string]*User{
		"nil":                  nil,
		"github member":        NewGitHubUser("alice", []string{"team-a", "team-b", "team-a"}),
		"github no groups":     NewGitHubUser("bob", nil),
		"legacy admins group":  NewGitHubUser("carol", []string{"admins"}),
		"principal admins grp": {ID: "p", Groups: []string{"admins", "team-a"}, principalAuthz: true},
		"service":              NewServiceUser(),
		"agent bound":          NewAgentUser("support", AgentRun{Scope: AgentScopeSupport, Tenant: "team-a"}),
		"agent bound empty":    NewAgentUser("support", AgentRun{Scope: AgentScopeSupport}),
		"agent read all":       NewAgentUser("investigate", AgentRun{Scope: AgentScopeInvestigate}),
		"agent review":         NewAgentUser("review", AgentRun{Scope: AgentScopeReview, Tenant: "team-a"}),
		"agent unscoped":       NewAgentUser("legacy", AgentRun{}),
	}
	candidates := []string{"", "team-a", "team-b", "team-c", "admins"}

	for name, u := range users {
		t.Run(name, func(t *testing.T) {
			tenants, all := u.TenantScope()
			if !all && tenants == nil {
				t.Fatal("a restricted scope must be a non-nil set; nil reads as unrestricted")
			}
			if all && tenants != nil {
				t.Fatalf("all=true with tenants %v", tenants)
			}
			for _, c := range candidates {
				want := u != nil && u.HasTenantAccess(c)
				got := all || slices.Contains(tenants, c)
				if got != want {
					t.Errorf("tenant %q: TenantScope admits %v, HasTenantAccess %v (tenants=%v all=%v)", c, got, want, tenants, all)
				}
			}
			seen := map[string]bool{}
			for _, tn := range tenants {
				if seen[tn] {
					t.Errorf("duplicate tenant %q in %v", tn, tenants)
				}
				seen[tn] = true
			}
		})
	}
}
