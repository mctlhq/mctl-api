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
)

// Agent principals and execution-scoped run tokens (mctl-api#376).
//
// Every agent run today authenticates as the one static admin service
// principal (ServiceUserID), so audit cannot say which agent, on which run,
// did a thing. An agent run token makes the agent a first-class, non-admin,
// per-execution actor: it binds an agent name to a canonical principal
// (auth.KindAgent) and a run token to that principal plus the one execution
// and work item it was minted for -- and to nothing else. In particular, a
// run token carries no subject: it cannot say who the agent is acting for.
// Delegation (the X-MCTL-On-Behalf-Of header, mctl-api#376 slice B) is a
// separate mechanism layered on top, not part of authentication.

// AgentRunTokenPrefix labels a minted run token's plaintext bearer secret,
// so Middleware can route to AgentRunResolver before trying the JWT/GitHub
// chain or the federation registry -- neither of which could otherwise ever
// resolve it. It is unrelated to the token's own row id, which carries the
// same textual prefix for the same reason every other id in this codebase
// is prefixed (readable in an audit row), but is never itself the bearer
// credential.
const AgentRunTokenPrefix = "art_"

// ErrAgentRunNotFound is returned by AgentRunResolver for a bearer secret
// that is unknown, expired, explicitly revoked, or bound to a
// WorkItemExecution that has since reached a terminal phase. Middleware
// never falls back to any other principal on it.
var ErrAgentRunNotFound = errors.New("agent run token not found, expired, or revoked")

// AgentRun is what a resolved agent run token grants: the agent it
// authenticates, the execution and work item it is bound to, its own row id
// (for audit correlation, never the secret itself), and the permissions it
// carries. Deliberately no subject field: the mint binds execution and work
// item only (design.md "Execution-scoped credentials").
type AgentRun struct {
	Agent       string
	ExecutionID string
	WorkItemID  string
	// RunID is the token's own id (art_<ulid>), safe to log and audit.
	RunID       string
	Permissions []string
}

// AgentRunResolver resolves a presented run-token bearer secret to the
// AgentRun it authenticates. Defined here, not in internal/workitems, so
// this package stays store-free -- the same shape PrincipalResolver already
// uses; cmd/api/main.go wires in the internal/workitems implementation.
type AgentRunResolver interface {
	ResolveAgentRun(ctx context.Context, token string) (*AgentRun, error)
}

// NewAgentUser builds the principal for one agent run token. Exported so
// tests can construct the same principal auth.Middleware does, like
// NewServiceUser and NewSurfaceUser; only Middleware mints it from a
// resolved token. It is never an admin, belongs to no tenant, and its only
// permissions are the ones run.Permissions lists.
func NewAgentUser(name string, run AgentRun) *User {
	return &User{
		ID:               AgentPrincipalPrefix + name,
		agent:            name,
		execID:           run.ExecutionID,
		workItemID:       run.WorkItemID,
		runID:            run.RunID,
		agentPermissions: append([]string(nil), run.Permissions...),
	}
}

// IsAgent reports whether this principal authenticated with an agent run
// token.
func (u *User) IsAgent() bool { return u != nil && u.agent != "" }

// AgentName returns the agent this principal authenticated as, and false
// for every other principal.
func (u *User) AgentName() (string, bool) {
	if u == nil || u.agent == "" {
		return "", false
	}
	return u.agent, true
}

// ExecutionID is the WorkItemExecution (we_...) an agent run token is bound
// to, or "" for every other principal.
func (u *User) ExecutionID() string {
	if u == nil {
		return ""
	}
	return u.execID
}

// WorkItemID is the work item (wi_...) an agent run token is bound to, or ""
// for every other principal.
func (u *User) WorkItemID() string {
	if u == nil {
		return ""
	}
	return u.workItemID
}

// AgentRunID is the run token's own id (art_...), or "" for every other
// principal.
func (u *User) AgentRunID() string {
	if u == nil {
		return ""
	}
	return u.runID
}
