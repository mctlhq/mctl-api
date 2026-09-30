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
	"context"
	"testing"
)

// T6: NewDelegatedUser returns nil for a non-agent acting user and for an
// empty login; drops admins; yields IsAgent()==false, IsAdmin()==false,
// Identity().Kind==KindHuman, ActingPrincipal()=="agent:<name>",
// ViaPrincipalID() equal to the agent's prn_, and a preserved
// ExecutionID()/WorkItemID()/AgentRunID().
func TestNewDelegatedUser_ReturnsNilForNonAgentOrEmptyLogin(t *testing.T) {
	for name, acting := range map[string]*User{
		"github user":       NewGitHubUser("alice", nil),
		"service principal": NewServiceUser(),
		"surface principal": NewSurfaceUser("telegram"),
	} {
		if u := NewDelegatedUser("bob", nil, acting); u != nil {
			t.Errorf("%s: NewDelegatedUser = %+v, want nil", name, u)
		}
	}
	agent := NewAgentUser("implementer", AgentRun{ExecutionID: "we_1", WorkItemID: "wi_1", RunID: "art_1"})
	if u := NewDelegatedUser("", nil, agent); u != nil {
		t.Fatalf("empty login: NewDelegatedUser = %+v, want nil", u)
	}
}

func TestNewDelegatedUser_ShapeAndAdminFilter(t *testing.T) {
	agent := NewAgentUser("implementer", AgentRun{ExecutionID: "we_1", WorkItemID: "wi_1", RunID: "art_1"})
	agent.principalID = "prn_AGENT"

	u := NewDelegatedUser("alice", []string{"acme", "admins"}, agent)
	if u == nil {
		t.Fatal("NewDelegatedUser = nil, want a delegated subject")
	}
	if u.IsAgent() {
		t.Error("a delegated subject must not be an agent principal")
	}
	if u.IsAdmin() {
		t.Error("delegation must never confer admin")
	}
	if !u.HasTenantAccess("acme") {
		t.Error("delegation must keep the subject's non-admin tenant access")
	}
	for _, g := range u.Groups {
		if g == "admins" {
			t.Fatalf("Groups = %v, admins must be dropped", u.Groups)
		}
	}
	id, ok := u.Identity()
	if !ok || id.Kind != KindHuman {
		t.Fatalf("Identity() = %+v, %v; want KindHuman", id, ok)
	}
	if got := u.ActingPrincipal(); got != "agent:implementer" {
		t.Fatalf("ActingPrincipal() = %q, want agent:implementer", got)
	}
	if got := u.ViaPrincipalID(); got != "prn_AGENT" {
		t.Fatalf("ViaPrincipalID() = %q, want the agent's prn_", got)
	}
	if u.ExecutionID() != "we_1" || u.WorkItemID() != "wi_1" || u.AgentRunID() != "art_1" {
		t.Fatalf("execution/work-item/run ids = %q/%q/%q, want the agent's", u.ExecutionID(), u.WorkItemID(), u.AgentRunID())
	}
	if login, ok := u.GitHubLogin(); !ok || login != "alice" {
		t.Fatalf("GitHubLogin() = %q, %v; want alice, true", login, ok)
	}
	if s, ok := u.RelaySurface(); ok || s != "" {
		t.Fatalf("RelaySurface() = %q, %v; a delegated subject is never a surface relay", s, ok)
	}
}

// A delegated subject resolves its principal the same way any GitHub-proven
// human does: through the login-only identity path.
func TestNewDelegatedUser_ResolvesPrincipalThroughGitHubLogin(t *testing.T) {
	agent := NewAgentUser("implementer", AgentRun{})
	u := NewDelegatedUser("alice", nil, agent)
	pr := &fakePrincipals{answers: map[string]string{"login:alice": "prn_ALICE"}}
	if err := AttachPrincipal(context.Background(), pr, u); err != nil {
		t.Fatal(err)
	}
	if u.PrincipalID() != "prn_ALICE" {
		t.Fatalf("PrincipalID() = %q, want prn_ALICE", u.PrincipalID())
	}
}
