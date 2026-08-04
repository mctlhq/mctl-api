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

// Package agentregistry stores what mctl-agents' AgentManifest publishes:
// immutable per-agent versions and which version is released to which
// environment. It is the phase-2 storage layer for the dev-workflow control
// plane plan — see mctl-agents/agents/_manifests/<agent>/agent.yaml for the
// manifest contract this stores, and mctl-agents/orchestrator/validate_manifest.py
// for how a manifest is checked before it's ever published here.
package agentregistry

import "time"

// Environments v1 knows about. Add dev/stage when something actually
// consumes them — see the plan's phase 2 note on this.
const (
	EnvironmentProduction = "production"
	EnvironmentShadow     = "shadow"
)

// ReleaseStatus values.
const (
	ReleaseStatusActive = "active"
)

// AgentDefinition is the top-level record for one agent name — the same
// name used in docs/agent-inventory.yaml and agents/_manifests/<name>/.
type AgentDefinition struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Owner       string     `json:"owner"`
	CreatedAt   time.Time  `json:"created_at"`
	ArchivedAt  *time.Time `json:"archived_at,omitempty"`
}

// AgentVersion is an immutable, published version of one agent. ManifestJSON
// is the full agent.yaml (as JSON) at publish time — the durable record of
// what this version's manifest claimed, not just the fields this store
// happens to index. PromptHash covers every entry in the manifest's
// spec.prompt.sources, per that field's contract in mctl-agents.
type AgentVersion struct {
	ID              int       `json:"id"`
	Agent           string    `json:"agent"`
	Version         string    `json:"version"`
	ManifestJSON    string    `json:"manifest_json"`
	GitSHA          string    `json:"git_sha"`
	ImageRepository string    `json:"image_repository"`
	ImageDigest     string    `json:"image_digest,omitempty"`
	PromptHash      string    `json:"prompt_hash"`
	CreatedAt       time.Time `json:"created_at"`
	CreatedBy       string    `json:"created_by,omitempty"`
}

// AgentRelease is which version is live in one environment. TrafficWeight
// exists from day one but is always 100 in v1 — see plan phase L2 (weighted
// canary) for when it starts meaning anything.
type AgentRelease struct {
	Agent         string    `json:"agent"`
	Environment   string    `json:"environment"`
	Version       string    `json:"version"`
	Status        string    `json:"status"`
	TrafficWeight int       `json:"traffic_weight"`
	UpdatedAt     time.Time `json:"updated_at"`
	UpdatedBy     string    `json:"updated_by,omitempty"`
}

// AgentPromotion is an audit-log row: every release change, whether a
// forward promotion or a rollback, in order.
type AgentPromotion struct {
	ID          int       `json:"id"`
	Agent       string    `json:"agent"`
	Environment string    `json:"environment"`
	FromVersion string    `json:"from_version,omitempty"`
	ToVersion   string    `json:"to_version"`
	Reason      string    `json:"reason,omitempty"`
	Actor       string    `json:"actor,omitempty"`
	// RollbackOf points at the agent_promotions row this promotion undid —
	// nil for a forward promotion.
	RollbackOf *int      `json:"rollback_of,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}
