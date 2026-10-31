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

// This file holds the TelegramAssistant definition kind (mctl-api#876): a
// v1alpha2 DefinitionVersion whose spec is the materialized TelegramAssistant
// document mctl-telegram builds. It lives in the same agent_definition_versions
// table as every AgentDefinition; only the profile rules and the read paths
// below differ.
package agentregistry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// KindTelegramAssistant is the spec "kind" of a Telegram assistant
// definition. It is the only profile-less kind: the Telegram worker does not
// execute ExecutionProfile ceilings (maxTokens, maxToolCalls,
// timeoutSeconds), so a placeholder profile would advertise limits nobody
// enforces. A profile is added only once the worker enforces them.
const KindTelegramAssistant = "TelegramAssistant"

// Assistant visibility and status values (metadata.visibility,
// metadata.status of the materialized document). "tenant" visibility has no
// tenant-binding model yet, so it is refused at publish.
const (
	AssistantVisibilityPublic = "public"
	AssistantVisibilityAdmin  = "admin"

	AssistantStatusDraft      = "draft"
	AssistantStatusActive     = "active"
	AssistantStatusDeprecated = "deprecated"
)

// ErrProfilelessDefinition refuses a binding, rollback or resolve against a
// definition kind that does not bind to an ExecutionProfile.
var ErrProfilelessDefinition = errors.New("agentregistry: definition kind does not bind to an execution profile")

// DefinitionKind returns the top-level "kind" of specJSON, or "" when the
// spec is not a JSON object or carries no string kind. Only that one field
// is read; the rest of the spec stays opaque.
func DefinitionKind(specJSON string) string {
	var head struct {
		Kind any `json:"kind"`
	}
	if err := json.Unmarshal([]byte(specJSON), &head); err != nil {
		return ""
	}
	kind, _ := head.Kind.(string)
	return kind
}

// IsProfileless reports whether a definition with this spec is published
// without a profileRange and can never be bound to a profile.
func IsProfileless(specJSON string) bool {
	return DefinitionKind(specJSON) == KindTelegramAssistant
}

// AssistantDocument is the subset of the materialized TelegramAssistant
// document the registry reads: what the publish check validates and what the
// public catalog projects. Everything else in the spec (instructions,
// tools, records, escalation, ...) is never decoded here.
type AssistantDocument struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name        string   `json:"name"`
		Title       string   `json:"title"`
		Description string   `json:"description"`
		Version     string   `json:"version"`
		Visibility  string   `json:"visibility"`
		Status      string   `json:"status"`
		Tags        []string `json:"tags"`
		Examples    []string `json:"examples"`
	} `json:"metadata"`
	Spec struct {
		Variables []AssistantVariable `json:"variables"`
		Intents   []AssistantIntent   `json:"intents"`
		Defaults  struct {
			Mode       string          `json:"mode"`
			Limits     json.RawMessage `json:"limits"`
			Disclosure struct {
				Policy string `json:"policy"`
			} `json:"disclosure"`
		} `json:"defaults"`
	} `json:"spec"`
}

// AssistantVariable is one spec.variables entry, as far as it is read.
type AssistantVariable struct {
	Name        string          `json:"name"`
	Type        string          `json:"type"`
	Required    bool            `json:"required"`
	Secret      bool            `json:"secret"`
	Default     json.RawMessage `json:"default"`
	Choices     []string        `json:"choices"`
	Description string          `json:"description"`
}

// AssistantIntent is one spec.intents entry, as far as it is read.
type AssistantIntent struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Tier        string `json:"tier"`
}

// ParseAssistantDocument decodes the fields AssistantDocument names. A spec
// whose named fields have the wrong JSON type is ErrInvalidSpec.
func ParseAssistantDocument(specJSON string) (*AssistantDocument, error) {
	doc := &AssistantDocument{}
	if err := json.Unmarshal([]byte(specJSON), doc); err != nil {
		return nil, fmt.Errorf("%w: TelegramAssistant document: %v", ErrInvalidSpec, err)
	}
	return doc, nil
}

// validateAssistantDefinition is the publish-time check for a
// TelegramAssistant: the document must decode, name the same agent and
// version it is published under, and carry a supported visibility and
// status. The catalog filters on visibility and status, so a value it cannot
// classify must never be stored.
func validateAssistantDefinition(d *DefinitionVersion) error {
	doc, err := ParseAssistantDocument(d.SpecJSON)
	if err != nil {
		return err
	}
	if doc.Metadata.Name != d.Agent {
		return fmt.Errorf("%w: metadata.name %q does not match agent %q", ErrInvalidSpec, doc.Metadata.Name, d.Agent)
	}
	if doc.Metadata.Version != d.Version {
		return fmt.Errorf("%w: metadata.version %q does not match version %q", ErrInvalidSpec, doc.Metadata.Version, d.Version)
	}
	switch doc.Metadata.Visibility {
	case AssistantVisibilityPublic, AssistantVisibilityAdmin:
	default:
		return fmt.Errorf("%w: metadata.visibility %q is not supported (public, admin)", ErrInvalidSpec, doc.Metadata.Visibility)
	}
	switch doc.Metadata.Status {
	case AssistantStatusDraft, AssistantStatusActive, AssistantStatusDeprecated:
	default:
		return fmt.Errorf("%w: metadata.status %q is not supported (draft, active, deprecated)", ErrInvalidSpec, doc.Metadata.Status)
	}
	return nil
}

// ListDefinitionVersionsByKind returns every definition version whose spec
// kind is kind, across all agents, ordered by agent name and then by
// version, highest first.
func (s *Store) ListDefinitionVersionsByKind(ctx context.Context, kind string) ([]DefinitionVersion, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, agent, version, api_version, spec_json, owner, source_repo, source_path, source_git_sha,
		   source_content_hash, profile_range, lifecycle, lifecycle_reason, lifecycle_at, lifecycle_by, created_at, created_by
		 FROM agent_definition_versions WHERE spec_json->>'kind' = $1 ORDER BY agent, id DESC`,
		kind,
	)
	if err != nil {
		return nil, fmt.Errorf("agentregistry: list definition versions by kind: %w", err)
	}
	defer rows.Close()

	var versions []DefinitionVersion
	for rows.Next() {
		var v DefinitionVersion
		if err := rows.Scan(&v.ID, &v.Agent, &v.Version, &v.APIVersion, &v.SpecJSON, &v.Owner,
			&v.SourceManifest.Repo, &v.SourceManifest.Path, &v.SourceManifest.GitSHA, &v.SourceManifest.ContentHash,
			&v.ProfileRange, &v.Lifecycle, &v.LifecycleReason, &v.LifecycleAt, &v.LifecycleBy, &v.CreatedAt, &v.CreatedBy); err != nil {
			return nil, fmt.Errorf("agentregistry: scan definition version: %w", err)
		}
		versions = append(versions, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("agentregistry: list definition versions by kind: %w", err)
	}
	sortByAgentThenVersionDesc(versions)
	return versions, nil
}

// sortByAgentThenVersionDesc orders by semver rather than by insertion id:
// a patch to an older line published after a newer minor would otherwise be
// listed first. Every stored version parsed at publish.
func sortByAgentThenVersionDesc(versions []DefinitionVersion) {
	sort.SliceStable(versions, func(i, j int) bool {
		if versions[i].Agent != versions[j].Agent {
			return versions[i].Agent < versions[j].Agent
		}
		vi, errI := ParseVersion(versions[i].Version)
		vj, errJ := ParseVersion(versions[j].Version)
		if errI != nil || errJ != nil {
			return false
		}
		return vi.Compare(vj) > 0
	})
}

// GetDefinitionVersion returns one exact (agent, version) definition row.
func (s *Store) GetDefinitionVersion(ctx context.Context, agent, version string) (*DefinitionVersion, error) {
	return s.definitionVersion(ctx, agent, version)
}
