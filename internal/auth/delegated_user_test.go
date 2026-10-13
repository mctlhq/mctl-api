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
	"errors"
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

// checkOnly is a PrincipalChecker that records what it checked and answers
// err; it resolves nothing.
type checkOnly struct {
	err     error
	checked []string
}

func (c *checkOnly) ResolvePrincipal(context.Context, Identity) (string, error) {
	return "", errors.New("a stored principal must not be resolved from a name")
}

func (c *checkOnly) CheckPrincipal(_ context.Context, principalID string) error {
	c.checked = append(c.checked, principalID)
	return c.err
}

// mctl-api#571 R9: the delegated subject is the grant's stored principal,
// checked, never resolved from its name; a disabled one is cleared and
// refused; an empty one is never built.
func TestNewDelegatedPrincipalUser(t *testing.T) {
	agent := NewAgentUser("implementer", AgentRun{ExecutionID: "we_1", WorkItemID: "wi_1", RunID: "art_1"})
	if u := NewDelegatedPrincipalUser("zed", "", false, nil, agent); u != nil {
		t.Fatalf("empty principal: %+v, want nil", u)
	}
	if u := NewDelegatedPrincipalUser("zed", "prn_ZED", false, nil, NewGitHubUser("bob", nil)); u != nil {
		t.Fatalf("non-agent acting user: %+v, want nil", u)
	}

	u := NewDelegatedPrincipalUser("zed", "prn_ZED", false, []string{"acme", "admins"}, agent)
	c := &checkOnly{}
	if err := AttachPrincipal(context.Background(), c, u); err != nil {
		t.Fatal(err)
	}
	if u.PrincipalID() != "prn_ZED" || len(c.checked) != 1 || c.checked[0] != "prn_ZED" {
		t.Fatalf("principal %q, checked %v", u.PrincipalID(), c.checked)
	}
	if _, gh := u.GitHubLogin(); gh {
		t.Error("a non-GitHub subject must carry no GitHub login")
	}
	if u.IsAdmin() || u.IsAgent() {
		t.Errorf("admin=%v agent=%v, want neither", u.IsAdmin(), u.IsAgent())
	}
	if id, _ := u.Identity(); id.Kind != KindHuman || id.Subject != "prn_ZED" {
		t.Errorf("Identity() = %+v, want the principal as a human", id)
	}
	if a, ok := u.DelegatingAgent(); !ok || a != "implementer" || u.ExecutionID() != "we_1" || u.AgentRunID() != "art_1" {
		t.Errorf("delegation fields lost: agent %q exec %q run %q", a, u.ExecutionID(), u.AgentRunID())
	}

	gh := NewDelegatedPrincipalUser("alice", "prn_ALICE", true, nil, agent)
	if login, ok := gh.GitHubLogin(); !ok || login != "alice" {
		t.Errorf("GitHub subject login = %q %v", login, ok)
	}
	if err := AttachPrincipal(context.Background(), &checkOnly{}, gh); err != nil || gh.PrincipalID() != "prn_ALICE" {
		t.Errorf("GitHub subject: principal %q err %v, want the stored one checked", gh.PrincipalID(), err)
	}

	off := NewDelegatedPrincipalUser("zed", "prn_ZED", false, nil, agent)
	if err := AttachPrincipal(context.Background(), &checkOnly{err: ErrPrincipalDisabled}, off); !errors.Is(err, ErrPrincipalDisabled) || off.PrincipalID() != "" {
		t.Errorf("disabled: err %v principal %q, want ErrPrincipalDisabled and cleared", err, off.PrincipalID())
	}
}
