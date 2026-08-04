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
