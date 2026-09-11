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

// This file holds the v1alpha2 agent-platform handlers: immutable
// AgentDefinition/ExecutionProfile versions and append-only ReleaseBinding
// revisions per (agent, environment). See design.md's "REST surface"
// section for the route table and docs/agent-platform-registry.md for the
// consumer contract. Every handler below reuses requireAgentRegistryAdmin
// (handlers_agent_registry.go) and extends the SAME *agentregistry.Store —
// no v1 route, request field or response shape changes as a result of this
// file existing.
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-api/internal/agentregistry"
)

// sourceManifestRequest mirrors agentregistry.SourceManifest on the wire.
type sourceManifestRequest struct {
	Repo        string `json:"repo"`
	Path        string `json:"path"`
	GitSHA      string `json:"git_sha"`
	ContentHash string `json:"content_hash"`
}

func (s sourceManifestRequest) toDomain() agentregistry.SourceManifest {
	return agentregistry.SourceManifest{Repo: s.Repo, Path: s.Path, GitSHA: s.GitSHA, ContentHash: s.ContentHash}
}

type publishDefinitionVersionRequest struct {
	Version        string                `json:"version"`
	Spec           string                `json:"spec"`
	Owner          string                `json:"owner"`
	SourceManifest sourceManifestRequest `json:"source_manifest"`
	ProfileRange   string                `json:"profile_range"`
}

type publishProfileVersionRequest struct {
	Version        string                `json:"version"`
	Spec           string                `json:"spec"`
	Owner          string                `json:"owner"`
	SourceManifest sourceManifestRequest `json:"source_manifest"`
}

type setLifecycleRequest struct {
	Lifecycle string `json:"lifecycle"`
	Reason    string `json:"reason,omitempty"`
}

type intentRequest struct {
	Repo   string `json:"repo,omitempty"`
	Path   string `json:"path,omitempty"`
	GitSHA string `json:"git_sha,omitempty"`
}

type createBindingRequest struct {
	Environment       string         `json:"environment"`
	DefinitionVersion string         `json:"definition_version"`
	Profile           string         `json:"profile"`
	ProfileVersion    string         `json:"profile_version"`
	BindingSource     string         `json:"binding_source,omitempty"`
	Intent            *intentRequest `json:"intent,omitempty"`
	Reason            string         `json:"reason,omitempty"`
}

type rollbackBindingRequest struct {
	Environment string `json:"environment"`
	Revision    int    `json:"revision"`
	Reason      string `json:"reason,omitempty"`
}

// writeAgentPlatformError maps a v1alpha2 sentinel error to its documented
// HTTP status and, where design.md's error-code table names one, an
// explicit machine-readable code via writeErrorCode. Order matters only
// where a wrapped error could satisfy two errors.Is checks; the sentinels
// below are mutually exclusive so it does not arise in practice.
func writeAgentPlatformError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, agentregistry.ErrVersionConflict):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, agentregistry.ErrDefinitionNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, agentregistry.ErrDefinitionVersionNotFound):
		writeErrorCode(w, http.StatusNotFound, "version_not_found", err.Error(), nil)
	case errors.Is(err, agentregistry.ErrProfileVersionNotFound):
		writeErrorCode(w, http.StatusNotFound, "version_not_found", err.Error(), nil)
	case errors.Is(err, agentregistry.ErrBindingNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, agentregistry.ErrVersionDeprecated):
		writeErrorCode(w, http.StatusUnprocessableEntity, "version_deprecated", err.Error(), nil)
	case errors.Is(err, agentregistry.ErrVersionDisabled):
		writeErrorCode(w, http.StatusUnprocessableEntity, "version_disabled", err.Error(), nil)
	case errors.Is(err, agentregistry.ErrIncompatibleProfile):
		writeErrorCode(w, http.StatusUnprocessableEntity, "incompatible_profile", err.Error(), nil)
	case errors.Is(err, agentregistry.ErrFixtureNotPromotable):
		writeErrorCode(w, http.StatusUnprocessableEntity, "fixture_not_promotable", err.Error(), nil)
	case errors.Is(err, agentregistry.ErrMissingPolicyFields):
		writeErrorCode(w, http.StatusBadRequest, "missing_policy_fields", err.Error(), nil)
	case errors.Is(err, agentregistry.ErrInvalidRange):
		writeErrorCode(w, http.StatusBadRequest, "invalid_range", err.Error(), nil)
	case errors.Is(err, agentregistry.ErrInvalidLifecycleTransition):
		writeErrorCode(w, http.StatusConflict, "invalid_lifecycle_transition", err.Error(), nil)
	case errors.Is(err, agentregistry.ErrInvalidEnvironment):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}

// ListAgents handles GET /api/v1/agents.
func (h *Handlers) ListAgents(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAgentRegistryAdmin(w, r); !ok {
		return
	}
	agents, err := h.opts.AgentRegistry.ListCatalog(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list agents: "+err.Error())
		return
	}
	if agents == nil {
		agents = []agentregistry.CatalogSummary{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": agents,
		"count": len(agents),
	})
}

// GetAgent handles GET /api/v1/agents/{name} — the 2-segment route
// router.go's "Agent registry" comment anticipated. "/agents/executions"
// stays reachable because chi's radix tree prefers that static match over
// this dynamic one; internal/api/router_test.go pins it.
func (h *Handlers) GetAgent(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAgentRegistryAdmin(w, r); !ok {
		return
	}
	name := chi.URLParam(r, "name")
	entry, err := h.opts.AgentRegistry.GetCatalogEntry(r.Context(), name)
	if err != nil {
		writeAgentPlatformError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, entry)
}

// PublishDefinitionVersion handles POST /api/v1/agents/{name}/definition-versions.
func (h *Handlers) PublishDefinitionVersion(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireAgentRegistryAdmin(w, r)
	if !ok {
		return
	}
	agent := chi.URLParam(r, "name")

	var body publishDefinitionVersionRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.Version == "" || body.Spec == "" {
		writeError(w, http.StatusBadRequest, "missing required fields: version, spec")
		return
	}

	stored, err := h.opts.AgentRegistry.PublishDefinitionVersion(r.Context(), &agentregistry.DefinitionVersion{
		Agent:          agent,
		Version:        body.Version,
		SpecJSON:       body.Spec,
		Owner:          body.Owner,
		SourceManifest: body.SourceManifest.toDomain(),
		ProfileRange:   body.ProfileRange,
		CreatedBy:      user.ID,
	})
	if err != nil {
		if errors.Is(err, agentregistry.ErrVersionConflict) || errors.Is(err, agentregistry.ErrDefinitionNotFound) || errors.Is(err, agentregistry.ErrInvalidRange) {
			writeAgentPlatformError(w, err)
			return
		}
		// Missing required field errors from the store are plain (unwrapped)
		// messages naming every missing field — see missingRequiredFields.
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, stored)
}

// ListDefinitionVersions handles GET /api/v1/agents/{name}/definition-versions.
func (h *Handlers) ListDefinitionVersions(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAgentRegistryAdmin(w, r); !ok {
		return
	}
	agent := chi.URLParam(r, "name")
	versions, err := h.opts.AgentRegistry.ListDefinitionVersions(r.Context(), agent)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list definition versions: "+err.Error())
		return
	}
	if versions == nil {
		versions = []agentregistry.DefinitionVersion{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": versions,
		"count": len(versions),
	})
}

// SetDefinitionVersionLifecycle handles
// POST /api/v1/agents/{name}/definition-versions/{version}/lifecycle.
func (h *Handlers) SetDefinitionVersionLifecycle(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireAgentRegistryAdmin(w, r)
	if !ok {
		return
	}
	agent := chi.URLParam(r, "name")
	version := chi.URLParam(r, "version")

	var body setLifecycleRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.Lifecycle == "" {
		writeError(w, http.StatusBadRequest, "missing required field: lifecycle")
		return
	}

	stored, err := h.opts.AgentRegistry.SetDefinitionVersionLifecycle(r.Context(), agent, version, body.Lifecycle, body.Reason, user.ID)
	if err != nil {
		writeAgentPlatformError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, stored)
}

// PublishProfileVersion handles POST /api/v1/agent-profiles/{profile}/versions.
func (h *Handlers) PublishProfileVersion(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireAgentRegistryAdmin(w, r)
	if !ok {
		return
	}
	profile := chi.URLParam(r, "profile")

	var body publishProfileVersionRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.Version == "" || body.Spec == "" {
		writeError(w, http.StatusBadRequest, "missing required fields: version, spec")
		return
	}

	stored, err := h.opts.AgentRegistry.PublishProfileVersion(r.Context(), &agentregistry.ProfileVersion{
		Profile:        profile,
		Version:        body.Version,
		SpecJSON:       body.Spec,
		Owner:          body.Owner,
		SourceManifest: body.SourceManifest.toDomain(),
		CreatedBy:      user.ID,
	})
	if err != nil {
		if errors.Is(err, agentregistry.ErrVersionConflict) || errors.Is(err, agentregistry.ErrMissingPolicyFields) {
			writeAgentPlatformError(w, err)
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, stored)
}

// ListProfileVersions handles GET /api/v1/agent-profiles/{profile}/versions.
func (h *Handlers) ListProfileVersions(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAgentRegistryAdmin(w, r); !ok {
		return
	}
	profile := chi.URLParam(r, "profile")
	versions, err := h.opts.AgentRegistry.ListProfileVersions(r.Context(), profile)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list profile versions: "+err.Error())
		return
	}
	if versions == nil {
		versions = []agentregistry.ProfileVersion{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": versions,
		"count": len(versions),
	})
}

// SetProfileVersionLifecycle handles
// POST /api/v1/agent-profiles/{profile}/versions/{version}/lifecycle.
func (h *Handlers) SetProfileVersionLifecycle(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireAgentRegistryAdmin(w, r)
	if !ok {
		return
	}
	profile := chi.URLParam(r, "profile")
	version := chi.URLParam(r, "version")

	var body setLifecycleRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.Lifecycle == "" {
		writeError(w, http.StatusBadRequest, "missing required field: lifecycle")
		return
	}

	stored, err := h.opts.AgentRegistry.SetProfileVersionLifecycle(r.Context(), profile, version, body.Lifecycle, body.Reason, user.ID)
	if err != nil {
		writeAgentPlatformError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, stored)
}

// CreateBinding handles POST /api/v1/agents/{name}/bindings.
func (h *Handlers) CreateBinding(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireAgentRegistryAdmin(w, r)
	if !ok {
		return
	}
	agent := chi.URLParam(r, "name")

	var body createBindingRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.Environment == "" || body.DefinitionVersion == "" || body.Profile == "" || body.ProfileVersion == "" {
		writeError(w, http.StatusBadRequest,
			"missing required fields: environment, definition_version, profile, profile_version")
		return
	}
	bindingSource := body.BindingSource
	if bindingSource == "" {
		bindingSource = agentregistry.BindingSourceRegistry
	}

	req := agentregistry.CreateBindingRequest{
		Agent:             agent,
		Environment:       body.Environment,
		DefinitionVersion: body.DefinitionVersion,
		Profile:           body.Profile,
		ProfileVersion:    body.ProfileVersion,
		BindingSource:     bindingSource,
		Reason:            body.Reason,
		Actor:             user.ID,
	}
	if body.Intent != nil {
		req.IntentRepo = body.Intent.Repo
		req.IntentPath = body.Intent.Path
		req.IntentGitSHA = body.Intent.GitSHA
	}

	stored, err := h.opts.AgentRegistry.CreateBinding(r.Context(), req)
	if err != nil {
		writeAgentPlatformError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, stored)
}

// ListBindings handles GET /api/v1/agents/{name}/bindings?environment=.
func (h *Handlers) ListBindings(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAgentRegistryAdmin(w, r); !ok {
		return
	}
	agent := chi.URLParam(r, "name")
	environment := r.URL.Query().Get("environment")
	if environment == "" {
		writeError(w, http.StatusBadRequest, "missing required query parameter: environment")
		return
	}
	bindings, err := h.opts.AgentRegistry.ListBindings(r.Context(), agent, environment)
	if err != nil {
		writeAgentPlatformError(w, err)
		return
	}
	if bindings == nil {
		bindings = []agentregistry.ReleaseBinding{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": bindings,
		"count": len(bindings),
	})
}

// GetBinding handles GET /api/v1/agents/{name}/bindings/{revision}?environment=.
// The static "resolve" and "rollback" siblings win chi's radix tree over
// this dynamic segment — see the route registration comment in router.go.
func (h *Handlers) GetBinding(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAgentRegistryAdmin(w, r); !ok {
		return
	}
	agent := chi.URLParam(r, "name")
	environment := r.URL.Query().Get("environment")
	if environment == "" {
		writeError(w, http.StatusBadRequest, "missing required query parameter: environment")
		return
	}
	revision, err := strconv.Atoi(chi.URLParam(r, "revision"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "revision must be an integer")
		return
	}
	binding, err := h.opts.AgentRegistry.GetBinding(r.Context(), agent, environment, revision)
	if err != nil {
		writeAgentPlatformError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, binding)
}

// ResolveBinding handles GET /api/v1/agents/{name}/bindings/resolve. Accepts
// either ?environment=production (the active binding for that pair) or
// ?definition_version=&profile=&profile_version= (an explicit pin, no
// environment consulted) — never both, never neither. profile_version may
// be omitted from the explicit-pin form: the highest published version of
// `profile` that satisfies the definition's declared compatibility range is
// used. See docs/agent-platform-registry.md for the full contract.
func (h *Handlers) ResolveBinding(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAgentRegistryAdmin(w, r); !ok {
		return
	}
	agent := chi.URLParam(r, "name")
	query := r.URL.Query()
	environment := query.Get("environment")
	definitionVersion := query.Get("definition_version")
	profile := query.Get("profile")
	profileVersion := query.Get("profile_version")

	explicitPin := definitionVersion != "" || profile != ""
	switch {
	case environment != "" && explicitPin:
		writeError(w, http.StatusBadRequest,
			"specify either environment or definition_version+profile, not both")
		return
	case environment == "" && !explicitPin:
		writeError(w, http.StatusBadRequest,
			"missing selector: specify environment, or definition_version and profile")
		return
	case explicitPin && (definitionVersion == "" || profile == ""):
		writeError(w, http.StatusBadRequest,
			"an explicit pin requires both definition_version and profile")
		return
	}

	var resolved *agentregistry.ResolvedBinding
	var err error
	if environment != "" {
		resolved, err = h.opts.AgentRegistry.ResolveBinding(r.Context(), agent, environment)
	} else {
		resolved, err = h.opts.AgentRegistry.ResolveExplicit(r.Context(), agent, definitionVersion, profile, profileVersion)
	}
	if err != nil {
		writeAgentPlatformError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resolved)
}

// RollbackBinding handles POST /api/v1/agents/{name}/bindings/rollback.
func (h *Handlers) RollbackBinding(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireAgentRegistryAdmin(w, r)
	if !ok {
		return
	}
	agent := chi.URLParam(r, "name")

	var body rollbackBindingRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.Environment == "" || body.Revision == 0 {
		writeError(w, http.StatusBadRequest, "missing required fields: environment, revision")
		return
	}

	stored, err := h.opts.AgentRegistry.RollbackBinding(r.Context(), agent, body.Environment, body.Revision, body.Reason, user.ID)
	if err != nil {
		writeAgentPlatformError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, stored)
}
