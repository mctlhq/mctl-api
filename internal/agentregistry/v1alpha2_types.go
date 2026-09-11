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

package agentregistry

import (
	"errors"
	"time"
)

// APIVersionV1Alpha2 is the schema version this layer implements — see ADR
// 007. It is distinct from the v1 agent_versions/agent_releases tables,
// which this file's tables sit alongside without changing.
const APIVersionV1Alpha2 = "agents.mctl.ai/v1alpha2"

// Lifecycle states for a definition or profile version. Immutable spec_json
// aside, lifecycle is the only thing that may change on a published row, and
// only along published -> deprecated -> disabled.
const (
	LifecyclePublished  = "published"
	LifecycleDeprecated = "deprecated"
	LifecycleDisabled   = "disabled"
)

// BindingSource values a ReleaseBinding may declare. Mirrors the
// bindingSource field on a mctl-gitops ReleaseBindingIntent.
const (
	BindingSourceRegistry             = "registry"
	BindingSourceManual               = "manual"
	BindingSourceCompatibilityFixture = "compatibility-fixture"
)

// Sentinel errors for the v1alpha2 layer — handlers map these to specific
// HTTP statuses, same convention as the v1 errors above.
var (
	ErrDefinitionVersionNotFound  = errors.New("agentregistry: definition version not found")
	ErrProfileVersionNotFound     = errors.New("agentregistry: profile version not found")
	ErrVersionDeprecated          = errors.New("agentregistry: version is deprecated")
	ErrVersionDisabled            = errors.New("agentregistry: version is disabled")
	ErrIncompatibleProfile        = errors.New("agentregistry: profile version does not satisfy the definition's compatibility range")
	ErrFixtureNotPromotable       = errors.New("agentregistry: compatibility-fixture binding source is not promotable")
	ErrBindingNotFound            = errors.New("agentregistry: no binding for agent/environment")
	ErrInvalidRange               = errors.New("agentregistry: invalid compatibility range")
	ErrInvalidLifecycleTransition = errors.New("agentregistry: invalid lifecycle transition")
	ErrMissingPolicyFields        = errors.New("agentregistry: execution profile is missing required policy fields")
	ErrMissingRequiredFields      = errors.New("agentregistry: missing required fields")
)

// RequiredProfilePolicyFields names the fields an ExecutionProfile's
// spec_json must carry for the profile to be published. See requirements.md
// open questions: the exact field names ADR 007 / mctl-gitops#950 use are
// unverified from this clone, so this is a single named constant that can be
// corrected in one place when that schema is read.
var RequiredProfilePolicyFields = []string{
	"maxTokens",
	"maxToolCalls",
	"timeoutSeconds",
}

// SourceManifest is the provenance of an immutable published version: the
// repo/path/gitSha it was published from, plus a content hash of the spec
// itself so a later re-read can detect drift independent of git history.
type SourceManifest struct {
	Repo        string `json:"repo"`
	Path        string `json:"path"`
	GitSHA      string `json:"gitSha"`
	ContentHash string `json:"contentHash"`
}

// DefinitionVersion is an immutable, published version of one agent's
// v1alpha2 AgentDefinition. ProfileRange is the declared ExecutionProfile
// compatibility range a bound profile version must satisfy.
type DefinitionVersion struct {
	ID              int            `json:"id"`
	Agent           string         `json:"agent"`
	Version         string         `json:"version"`
	APIVersion      string         `json:"apiVersion"`
	SpecJSON        string         `json:"spec"`
	Owner           string         `json:"owner"`
	SourceManifest  SourceManifest `json:"sourceManifest"`
	ProfileRange    string         `json:"profileRange"`
	Lifecycle       string         `json:"lifecycle"`
	LifecycleReason string         `json:"lifecycleReason,omitempty"`
	LifecycleAt     *time.Time     `json:"lifecycleAt,omitempty"`
	LifecycleBy     string         `json:"lifecycleBy,omitempty"`
	CreatedAt       time.Time      `json:"createdAt"`
	CreatedBy       string         `json:"createdBy,omitempty"`
}

// ProfileVersion is an immutable, published version of one ExecutionProfile.
// Names are global (not namespaced per agent) — see requirements.md open
// questions.
type ProfileVersion struct {
	ID              int            `json:"id"`
	Profile         string         `json:"profile"`
	Version         string         `json:"version"`
	SpecJSON        string         `json:"spec"`
	Owner           string         `json:"owner"`
	SourceManifest  SourceManifest `json:"sourceManifest"`
	Lifecycle       string         `json:"lifecycle"`
	LifecycleReason string         `json:"lifecycleReason,omitempty"`
	LifecycleAt     *time.Time     `json:"lifecycleAt,omitempty"`
	LifecycleBy     string         `json:"lifecycleBy,omitempty"`
	CreatedAt       time.Time      `json:"createdAt"`
	CreatedBy       string         `json:"createdBy,omitempty"`
}

// ReleaseBinding is one append-only revision binding a compatible
// definition+profile version pair to an (agent, environment) pair. There is
// no "active" flag anywhere: the active binding for a pair is always the
// highest revision.
type ReleaseBinding struct {
	ID                int       `json:"id"`
	Agent             string    `json:"agent"`
	Environment       string    `json:"environment"`
	Revision          int       `json:"revision"`
	DefinitionVersion string    `json:"definitionVersion"`
	Profile           string    `json:"profile"`
	ProfileVersion    string    `json:"profileVersion"`
	ProfileRange      string    `json:"profileRange"`
	BindingSource     string    `json:"bindingSource"`
	IntentRepo        string    `json:"intentRepo,omitempty"`
	IntentPath        string    `json:"intentPath,omitempty"`
	IntentGitSHA      string    `json:"intentGitSha,omitempty"`
	RollbackOf        *int      `json:"rollbackOf,omitempty"`
	Reason            string    `json:"reason,omitempty"`
	CreatedAt         time.Time `json:"createdAt"`
	CreatedBy         string    `json:"createdBy,omitempty"`
}

// ResolvedBinding is the consumer-facing envelope returned by resolve
// (either by (agent, environment) or by an explicit definition/profile
// version pin). See docs/agent-platform-registry.md for the frozen contract
// orchestrator/resolver.py reads.
type ResolvedBinding struct {
	APIVersion    string                `json:"apiVersion"`
	Agent         string                `json:"agent"`
	Environment   string                `json:"environment,omitempty"`
	Revision      int                   `json:"revision,omitempty"`
	Definition    ResolvedDefinition    `json:"definition"`
	Profile       ResolvedProfile       `json:"profile"`
	Compatibility ResolvedCompatibility `json:"compatibility"`
	BindingSource string                `json:"bindingSource"`
	Intent        *ResolvedIntent       `json:"intent,omitempty"`
	RollbackOf    *int                  `json:"rollbackOf"`
	CreatedAt     time.Time             `json:"createdAt"`
	CreatedBy     string                `json:"createdBy,omitempty"`
}

// ResolvedDefinition is the definition half of a ResolvedBinding envelope.
type ResolvedDefinition struct {
	Version        string         `json:"version"`
	Lifecycle      string         `json:"lifecycle"`
	Owner          string         `json:"owner"`
	SourceManifest SourceManifest `json:"sourceManifest"`
	Spec           string         `json:"spec"`
}

// ResolvedProfile is the profile half of a ResolvedBinding envelope.
type ResolvedProfile struct {
	Name           string         `json:"name"`
	Version        string         `json:"version"`
	Lifecycle      string         `json:"lifecycle"`
	SourceManifest SourceManifest `json:"sourceManifest"`
	Spec           string         `json:"spec"`
}

// ResolvedCompatibility reports the compatibility range evaluated to produce
// this binding, and whether it was satisfied (always true for a binding that
// exists — CreateBinding rejects an incompatible pair before it is stored —
// but explicit-pin resolve computes and reports it even without a binding).
type ResolvedCompatibility struct {
	Range     string `json:"range"`
	Satisfied bool   `json:"satisfied"`
}

// ResolvedIntent is the gitops provenance of a registry-sourced binding.
type ResolvedIntent struct {
	Repo   string `json:"repo,omitempty"`
	Path   string `json:"path,omitempty"`
	GitSHA string `json:"gitSha,omitempty"`
}

// CreateBindingRequest is the input to Store.CreateBinding.
type CreateBindingRequest struct {
	Agent             string
	Environment       string
	DefinitionVersion string
	Profile           string
	ProfileVersion    string
	BindingSource     string
	IntentRepo        string
	IntentPath        string
	IntentGitSHA      string
	Reason            string
	Actor             string
}
