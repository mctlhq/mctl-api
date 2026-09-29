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

import "testing"

func TestNewAgentUser_IsNotAdminHasNoGroupsIsNotService(t *testing.T) {
	u := NewAgentUser("implementer", AgentRun{
		ExecutionID: "we_1", WorkItemID: "wi_1", RunID: "art_1", Permissions: []string{"usage:write"},
	})

	if u.IsAdmin() {
		t.Error("agent principal must not be admin")
	}
	if len(u.Groups) != 0 {
		t.Errorf("agent principal must belong to no tenant, got %v", u.Groups)
	}
	if u.IsService() {
		t.Error("agent principal must not be IsService(), or isDirectService would start matching agents")
	}
	if !u.IsAgent() {
		t.Error("IsAgent() must be true")
	}
	if name, ok := u.AgentName(); !ok || name != "implementer" {
		t.Errorf("AgentName() = %q, %v, want \"implementer\", true", name, ok)
	}
	if u.ExecutionID() != "we_1" {
		t.Errorf("ExecutionID() = %q, want we_1", u.ExecutionID())
	}
	if u.WorkItemID() != "wi_1" {
		t.Errorf("WorkItemID() = %q, want wi_1", u.WorkItemID())
	}
	if u.AgentRunID() != "art_1" {
		t.Errorf("AgentRunID() = %q, want art_1", u.AgentRunID())
	}
}

func TestNewAgentUser_IdentityIsKindAgent(t *testing.T) {
	u := NewAgentUser("implementer", AgentRun{})
	id, ok := u.Identity()
	if !ok {
		t.Fatal("Identity() ok = false, want true")
	}
	if id.Kind != KindAgent {
		t.Errorf("Identity().Kind = %q, want %q", id.Kind, KindAgent)
	}
	if id.Provider != ProviderAgent {
		t.Errorf("Identity().Provider = %q, want %q", id.Provider, ProviderAgent)
	}
	if id.Subject != "agent:implementer" {
		t.Errorf("Identity().Subject = %q, want agent:implementer", id.Subject)
	}
}

func TestNewAgentUser_HasOnlyItsMintedPermissions(t *testing.T) {
	u := NewAgentUser("implementer", AgentRun{Permissions: []string{"usage:write"}})
	if !u.HasPermission("usage:write") {
		t.Error("expected the minted permission to be held")
	}
	if u.HasPermission("something:else") {
		t.Error("expected an unminted permission to be refused")
	}

	bare := NewAgentUser("implementer", AgentRun{})
	if bare.HasPermission("usage:write") {
		t.Error("an agent minted with no permissions must hold none, even ones an admin would")
	}
}

// The unexported-field forgery argument (oidc.go's comment on `service`,
// restated for `agent`): a GitHub login or Dex username spelled exactly like
// an agent principal's id must never read as one, because User is never
// unmarshalled from JSON and only NewAgentUser sets the discriminator.
func TestIsAgent_CannotBeForgedFromALoginSpelledLikeOne(t *testing.T) {
	forged := NewGitHubUser("agent:implementer", nil)
	if forged.IsAgent() {
		t.Error("a GitHub login spelled like an agent principal must not be IsAgent()")
	}
	if _, ok := forged.AgentName(); ok {
		t.Error("a GitHub login spelled like an agent principal must not produce an AgentName()")
	}
	id, ok := forged.Identity()
	if !ok {
		t.Fatal("Identity() ok = false, want true")
	}
	if id.Kind == KindAgent {
		t.Error("a forged login must never resolve to KindAgent")
	}
}

func TestAgentAccessors_NilSafe(t *testing.T) {
	var u *User
	if u.IsAgent() {
		t.Error("nil user must not be IsAgent()")
	}
	if _, ok := u.AgentName(); ok {
		t.Error("nil user must not produce an AgentName()")
	}
	if u.ExecutionID() != "" || u.WorkItemID() != "" || u.AgentRunID() != "" {
		t.Error("nil user must answer empty strings, not panic")
	}
}
