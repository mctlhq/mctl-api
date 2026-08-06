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
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-api/internal/agentregistry"
	"github.com/mctlhq/mctl-api/internal/auth"
)

type createAgentDefinitionRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Owner       string `json:"owner"`
}

type publishAgentVersionRequest struct {
	Version         string `json:"version"`
	ManifestJSON    string `json:"manifest_json"`
	GitSHA          string `json:"git_sha"`
	ImageRepository string `json:"image_repository"`
	ImageDigest     string `json:"image_digest"`
	PromptHash      string `json:"prompt_hash"`
}

// isBareImageRepository reports whether repo carries no embedded tag or
// digest. orchestrator/temporal/activities/registry.py appends ":{version}"
// or "@{digest}" itself when it resolves a release into an Argo Workflow
// parameter — an image_repository that already carries one silently doubles
// into an invalid image reference (incident 2026-08-06: the mctl-academy
// smoke test's investigate pod stuck on InvalidImageName with
// "...:1.22.0:1.22.0", traced back to a published row whose image_repository
// already included the tag).
func isBareImageRepository(repo string) bool {
	if strings.Contains(repo, "@") {
		return false
	}
	last := repo
	if i := strings.LastIndex(repo, "/"); i != -1 {
		last = repo[i+1:]
	}
	return !strings.Contains(last, ":")
}

// recordExecutionRequest is what orchestrator/temporal/activities/state.py
// POSTs after each DevLoopWorkflow step reaches a terminal Argo phase.
type recordExecutionRequest struct {
	TemporalWorkflowID string `json:"temporal_workflow_id"`
	Agent              string `json:"agent"`
	Environment        string `json:"environment"`
	Version            string `json:"version,omitempty"`
	ImageRef           string `json:"image_ref,omitempty"`
	TargetRepo         string `json:"target_repo,omitempty"`
	ArgoWorkflowName   string `json:"argo_workflow_name,omitempty"`
	Phase              string `json:"phase"`
}

// agentReleaseRequest drives both promotion and rollback through one
// endpoint: Rollback=true ignores Version and reverts to whatever the
// environment had immediately before its current release.
type agentReleaseRequest struct {
	Environment string `json:"environment"`
	Version     string `json:"version,omitempty"`
	Rollback    bool   `json:"rollback,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// requireAgentRegistryAdmin does the checks every agent-registry handler
// needs before touching the store: registry configured, caller
// authenticated, caller an admin. Returns the user and false to write the
// response and return early on any failure; true to proceed.
func (h *Handlers) requireAgentRegistryAdmin(w http.ResponseWriter, r *http.Request) (*auth.User, bool) {
	if h.opts.AgentRegistry == nil {
		writeError(w, http.StatusServiceUnavailable, "agent registry not configured")
		return nil, false
	}
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}
	if !user.IsAdmin() {
		writeError(w, http.StatusForbidden, "agent registry is admin-only")
		return nil, false
	}
	return user, true
}

// CreateAgentDefinition handles POST /api/v1/agents.
func (h *Handlers) CreateAgentDefinition(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAgentRegistryAdmin(w, r); !ok {
		return
	}

	var body createAgentDefinitionRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.Name == "" {
		writeError(w, http.StatusBadRequest, "missing required field: name")
		return
	}

	def, err := h.opts.AgentRegistry.CreateDefinition(r.Context(), body.Name, body.Description, body.Owner)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create agent definition: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, def)
}

// PublishAgentVersion handles POST /api/v1/agents/{name}/versions. Intended
// caller: CI, after orchestrator/validate_manifest.py has passed.
func (h *Handlers) PublishAgentVersion(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireAgentRegistryAdmin(w, r)
	if !ok {
		return
	}

	agent := chi.URLParam(r, "name")

	var body publishAgentVersionRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.Version == "" || body.ManifestJSON == "" || body.GitSHA == "" || body.ImageRepository == "" || body.PromptHash == "" {
		writeError(w, http.StatusBadRequest,
			"missing required fields: version, manifest_json, git_sha, image_repository, prompt_hash")
		return
	}
	if !isBareImageRepository(body.ImageRepository) {
		writeError(w, http.StatusBadRequest,
			"image_repository must be a bare repository with no tag or digest — the version field "+
				"supplies the tag when a release is resolved: got "+body.ImageRepository)
		return
	}

	stored, err := h.opts.AgentRegistry.PublishVersion(r.Context(), &agentregistry.AgentVersion{
		Agent:           agent,
		Version:         body.Version,
		ManifestJSON:    body.ManifestJSON,
		GitSHA:          body.GitSHA,
		ImageRepository: body.ImageRepository,
		ImageDigest:     body.ImageDigest,
		PromptHash:      body.PromptHash,
		CreatedBy:       user.ID,
	})
	if err != nil {
		if errors.Is(err, agentregistry.ErrVersionConflict) {
			writeError(w, http.StatusConflict, "version already published: "+agent+"@"+body.Version)
			return
		}
		if errors.Is(err, agentregistry.ErrDefinitionNotFound) {
			writeError(w, http.StatusNotFound, "agent has no definition yet — POST /api/v1/agents first: "+agent)
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to publish agent version: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, stored)
}

// ListAgentVersions handles GET /api/v1/agents/{name}/versions.
func (h *Handlers) ListAgentVersions(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAgentRegistryAdmin(w, r); !ok {
		return
	}

	agent := chi.URLParam(r, "name")
	versions, err := h.opts.AgentRegistry.ListVersions(r.Context(), agent)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list agent versions: "+err.Error())
		return
	}
	if versions == nil {
		versions = []agentregistry.AgentVersion{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": versions,
		"count": len(versions),
	})
}

// UpdateAgentRelease handles POST /api/v1/agents/{name}/releases — promotes
// to an explicit version, or rolls back to the prior one when the request
// sets rollback=true.
func (h *Handlers) UpdateAgentRelease(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireAgentRegistryAdmin(w, r)
	if !ok {
		return
	}

	agent := chi.URLParam(r, "name")

	var body agentReleaseRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.Environment == "" {
		writeError(w, http.StatusBadRequest, "missing required field: environment")
		return
	}
	if !body.Rollback && body.Version == "" {
		writeError(w, http.StatusBadRequest, "version is required unless rollback is true")
		return
	}
	if body.Rollback && body.Version != "" {
		// Silently ignoring version here would be a footgun: a caller
		// meaning "promote to 1.0.0" who also (mistakenly) sets
		// rollback=true would instead get rolled back to whatever the store
		// considers the prior version, not 1.0.0.
		writeError(w, http.StatusBadRequest, "version must not be set when rollback is true — they express contradictory intent")
		return
	}

	var release *agentregistry.AgentRelease
	var err error
	if body.Rollback {
		release, err = h.opts.AgentRegistry.Rollback(r.Context(), agent, body.Environment, body.Reason, user.ID)
	} else {
		release, err = h.opts.AgentRegistry.PromoteRelease(r.Context(), agent, body.Environment, body.Version, body.Reason, user.ID)
	}
	if err != nil {
		switch {
		case errors.Is(err, agentregistry.ErrInvalidEnvironment):
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, agentregistry.ErrVersionNotFound):
			writeError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, agentregistry.ErrNoRollbackTarget):
			writeError(w, http.StatusConflict, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "failed to update agent release: "+err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, release)
}

// ResolveAgentRelease handles GET /api/v1/agents/{name}/resolve?environment=production.
// This is the read path a Temporal DevLoopWorkflow activity calls once per
// agent step to pin an immutable version for the rest of that workflow run.
func (h *Handlers) ResolveAgentRelease(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAgentRegistryAdmin(w, r); !ok {
		return
	}

	agent := chi.URLParam(r, "name")
	environment := r.URL.Query().Get("environment")
	if environment == "" {
		writeError(w, http.StatusBadRequest, "missing required query parameter: environment")
		return
	}

	release, err := h.opts.AgentRegistry.ResolveRelease(r.Context(), agent, environment)
	if err != nil {
		if errors.Is(err, agentregistry.ErrInvalidEnvironment) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, agentregistry.ErrReleaseNotFound) {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to resolve agent release: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, release)
}

// RecordAgentExecution handles POST /api/v1/agents/executions — the phase-4
// Temporal worker's durable audit trail for one DevLoopWorkflow step. Not
// gated on the agent already having a definition/release: a step that ran
// before its first mctl_promote_agent still gets recorded (version/image_ref
// empty), which is the expected case for an agent the registry doesn't yet
// track.
func (h *Handlers) RecordAgentExecution(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAgentRegistryAdmin(w, r); !ok {
		return
	}

	var body recordExecutionRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.TemporalWorkflowID == "" || body.Agent == "" || body.Environment == "" || body.Phase == "" {
		writeError(w, http.StatusBadRequest,
			"missing required fields: temporal_workflow_id, agent, environment, phase")
		return
	}

	execution, err := h.opts.AgentRegistry.RecordExecution(r.Context(), &agentregistry.AgentExecution{
		TemporalWorkflowID: body.TemporalWorkflowID,
		Agent:              body.Agent,
		Environment:        body.Environment,
		Version:            body.Version,
		ImageRef:           body.ImageRef,
		TargetRepo:         body.TargetRepo,
		ArgoWorkflowName:   body.ArgoWorkflowName,
		Phase:              body.Phase,
	})
	if err != nil {
		if errors.Is(err, agentregistry.ErrInvalidEnvironment) || errors.Is(err, agentregistry.ErrInvalidPhase) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to record agent execution: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, execution)
}

// ListAgentExecutions handles GET /api/v1/agents/executions?agent=&workflow_id=&limit=.
// All query parameters are optional and independent — omitting agent/workflow_id
// lists across every agent/workflow; limit defaults to 20, clamped to 100 by the store.
func (h *Handlers) ListAgentExecutions(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAgentRegistryAdmin(w, r); !ok {
		return
	}

	agent := r.URL.Query().Get("agent")
	workflowID := r.URL.Query().Get("workflow_id")
	limit := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "limit must be an integer")
			return
		}
		limit = parsed
	}

	executions, err := h.opts.AgentRegistry.ListExecutions(r.Context(), agent, workflowID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list agent executions: "+err.Error())
		return
	}
	if executions == nil {
		executions = []agentregistry.AgentExecution{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": executions,
		"count": len(executions),
	})
}
