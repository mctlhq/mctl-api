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
	"log/slog"
	"os"
	"strings"
)

// Orchestrator DevLoop principal (mctl-api#963). The Codex orchestrator on
// the Mac mini starts DevLoop for issues it has triaged, and reads those
// loops back, and does nothing else: it never approves a proposal (that
// stays a human admin's decision, #571), never reaches /mcp and never runs
// the direct-Argo investigate path.
//
// It authenticates as a ZITADEL machine user through the existing federated
// OIDC verification (MCTL_OIDC_PROVIDERS), so the credential on the mini is a
// JWT-profile key that never leaves it and the bearer the API sees is
// short-lived. The verified (provider, subject) pair named by
// MCTL_ORCHESTRATOR_DEVLOOP_PROVIDER and MCTL_ORCHESTRATOR_DEVLOOP_SUBJECT is
// mapped to this principal instead of to the generic OIDC user, so the
// machine user's groups, whatever its token carries, are dropped. With
// either variable unset the mapping is off and the identity is an ordinary
// OIDC caller, as it is today.
//
// It is not an admin, belongs to no tenant, holds no named permission and is
// confined by the API's orchestrator-devloop gate.
const (
	OrchestratorDevLoopUserID      = "service:mctl-orchestrator-devloop"
	orchestratorDevLoopProviderEnv = "MCTL_ORCHESTRATOR_DEVLOOP_PROVIDER"
	orchestratorDevLoopSubjectEnv  = "MCTL_ORCHESTRATOR_DEVLOOP_SUBJECT"
)

// orchestratorDevLoopIdentity reads the configured (provider, subject), or
// false when the mapping is off or misconfigured.
func orchestratorDevLoopIdentity() (string, string, bool) {
	provider := strings.TrimSpace(os.Getenv(orchestratorDevLoopProviderEnv))
	subject := strings.TrimSpace(os.Getenv(orchestratorDevLoopSubjectEnv))
	switch {
	case provider == "" && subject == "":
		return "", "", false
	case provider == "" || subject == "":
		slog.Error("orchestrator-devloop identity half-configured; principal disabled",
			"provider_env", orchestratorDevLoopProviderEnv, "subject_env", orchestratorDevLoopSubjectEnv)
		return "", "", false
	case reservedProviderNames[provider] || provider == ProviderDex:
		// Not a federated machine-user namespace: a built-in principal type,
		// or the legacy Dex slot, which userFromVerified maps before this.
		slog.Error("orchestrator-devloop provider names a reserved identity namespace; principal disabled",
			"env", orchestratorDevLoopProviderEnv, "provider", provider)
		return "", "", false
	}
	return provider, subject, true
}

// IsOrchestratorDevLoopIdentity reports whether a verified identity is the
// configured orchestrator machine user: the exact provider and subject, and
// never a customer.
func IsOrchestratorDevLoopIdentity(id Identity) bool {
	provider, subject, ok := orchestratorDevLoopIdentity()
	return ok && id.Customer == nil && id.Provider == provider && id.Subject == subject
}

// NewOrchestratorDevLoopUser builds the orchestrator principal for the
// verified identity id. Exported for tests; only authentication mints it.
func NewOrchestratorDevLoopUser(id Identity) *User {
	return &User{
		ID:                  OrchestratorDevLoopUserID,
		orchestratorDevLoop: true,
		oidcProviderName:    id.Provider,
		oidcIssuer:          id.Issuer,
		oidcSubject:         id.Subject,
		oidcKind:            KindService,
	}
}

// IsOrchestratorDevLoop reports whether this principal is the orchestrator
// machine user.
func (u *User) IsOrchestratorDevLoop() bool { return u != nil && u.orchestratorDevLoop }
