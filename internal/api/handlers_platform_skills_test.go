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
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/gitops"
)

// policyOnlyGitReader stubs just GetPlatformPolicy; validateTenantSkillEnable
// touches no other GitReader method, so the embedded nil interface is safe.
type policyOnlyGitReader struct {
	GitReader
	policy *gitops.PlatformSkillPolicy
}

func (r policyOnlyGitReader) GetPlatformPolicy() (*gitops.PlatformSkillPolicy, error) {
	if r.policy != nil {
		return r.policy, nil
	}
	return &gitops.PlatformSkillPolicy{}, nil
}

// The allowlist semantics must match the materializer in
// mctl-gitops/scripts/materialize-openclaw-platform-skills.py: an absent
// tenant key is unrestricted, a present key — even an empty list — is an
// exhaustive allowlist (deny-all when empty).
func TestValidateTenantSkillEnable_AllowlistSemantics(t *testing.T) {
	activeTenantSkill := gitops.PlatformSkill{
		Metadata: gitops.PlatformSkillMetadata{
			Name:       "s1",
			Visibility: "tenant",
			Status:     "active",
		},
	}

	tests := []struct {
		name    string
		policy  *gitops.PlatformSkillPolicy
		skill   gitops.PlatformSkill
		wantErr string
	}{
		{
			name:   "no policy file",
			policy: nil,
			skill:  activeTenantSkill,
		},
		{
			name: "allowlist absent for tenant",
			policy: &gitops.PlatformSkillPolicy{
				TenantAllowlist: map[string][]string{"other": {}},
			},
			skill: activeTenantSkill,
		},
		{
			name: "explicitly empty allowlist denies all",
			policy: &gitops.PlatformSkillPolicy{
				TenantAllowlist: map[string][]string{"labs": {}},
			},
			skill:   activeTenantSkill,
			wantErr: "not allowed",
		},
		{
			name: "skill in allowlist",
			policy: &gitops.PlatformSkillPolicy{
				TenantAllowlist: map[string][]string{"labs": {"s1"}},
			},
			skill: activeTenantSkill,
		},
		{
			name: "skill missing from non-empty allowlist",
			policy: &gitops.PlatformSkillPolicy{
				TenantAllowlist: map[string][]string{"labs": {"s2"}},
			},
			skill:   activeTenantSkill,
			wantErr: "not allowed",
		},
		{
			name: "denylist wins over allowlist",
			policy: &gitops.PlatformSkillPolicy{
				TenantAllowlist: map[string][]string{"labs": {"s1"}},
				TenantDenylist:  map[string][]string{"labs": {"s1"}},
			},
			skill:   activeTenantSkill,
			wantErr: "denied",
		},
		{
			name: "deprecated skill",
			skill: gitops.PlatformSkill{
				Metadata: gitops.PlatformSkillMetadata{
					Name:       "s1",
					Visibility: "tenant",
					Status:     "deprecated",
				},
			},
			wantErr: "deprecated",
		},
		{
			name: "draft skill rejected before policy check",
			skill: gitops.PlatformSkill{
				Metadata: gitops.PlatformSkillMetadata{
					Name:       "s1",
					Visibility: "tenant",
					Status:     "draft",
				},
			},
			wantErr: "only active skills",
		},
		{
			name: "non-tenant visibility",
			skill: gitops.PlatformSkill{
				Metadata: gitops.PlatformSkillMetadata{
					Name:       "s1",
					Visibility: "admin",
					Status:     "active",
				},
			},
			wantErr: "tenant visibility",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handlers{opts: Options{GitReader: policyOnlyGitReader{policy: tt.policy}}}
			err := h.validateTenantSkillEnable("labs", tt.skill)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected nil error, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}
