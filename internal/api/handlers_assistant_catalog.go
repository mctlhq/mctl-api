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

// This file holds the Telegram assistant catalog (mctl-api#876): two public
// reads projecting TelegramAssistant definition versions out of the v1alpha2
// registry, and one service read of the full materialized definition for the
// Telegram worker. All three read the same agent_definition_versions rows the
// admin registry routes write; publishing stays on those admin routes.
package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-api/internal/agentregistry"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/surfaceid"
)

// assistantCatalogEntry is the public projection of one TelegramAssistant
// version. It is an allowlist: instructions, tools, records, escalation,
// owner and provenance are never copied into it, whatever the spec holds.
type assistantCatalogEntry struct {
	Name        string                     `json:"name"`
	Version     string                     `json:"version"`
	Title       string                     `json:"title"`
	Description string                     `json:"description"`
	Tags        []string                   `json:"tags"`
	Examples    []string                   `json:"examples"`
	Lifecycle   string                     `json:"lifecycle"`
	Digest      string                     `json:"digest"`
	Variables   []assistantCatalogVariable `json:"variables"`
	Intents     []assistantCatalogIntent   `json:"intents"`
	Defaults    assistantCatalogDefaults   `json:"defaults"`
}

type assistantCatalogVariable struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Required bool   `json:"required"`
	// Default is omitted for a secret variable: a default secret value
	// would otherwise be published to anyone.
	Default     json.RawMessage `json:"default,omitempty"`
	Choices     []string        `json:"choices,omitempty"`
	Description string          `json:"description"`
}

type assistantCatalogIntent struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Tier        string `json:"tier"`
}

type assistantCatalogDefaults struct {
	Mode       string                     `json:"mode"`
	Limits     json.RawMessage            `json:"limits,omitempty"`
	Disclosure assistantCatalogDisclosure `json:"disclosure"`
}

type assistantCatalogDisclosure struct {
	Policy string `json:"policy"`
}

// assistantDefinitionResponse is the service read: the stored spec as the
// full materialized document, with its lifecycle and digest.
type assistantDefinitionResponse struct {
	Name        string          `json:"name"`
	Version     string          `json:"version"`
	Lifecycle   string          `json:"lifecycle"`
	ContentHash string          `json:"contentHash"`
	Definition  json.RawMessage `json:"definition"`
}

// publicAssistant reports whether a version may appear in the public catalog
// at all: a TelegramAssistant, visibility public, not a draft. Lifecycle is
// judged by the caller, since the list and the single read differ on it.
// Anything not exactly "public" is not public, so a "tenant" or an unknown
// visibility never leaks.
func publicAssistant(doc *agentregistry.AssistantDocument) bool {
	return doc.Kind == agentregistry.KindTelegramAssistant &&
		doc.Metadata.Visibility == agentregistry.AssistantVisibilityPublic &&
		doc.Metadata.Status != agentregistry.AssistantStatusDraft
}

func projectAssistant(v *agentregistry.DefinitionVersion, doc *agentregistry.AssistantDocument) assistantCatalogEntry {
	entry := assistantCatalogEntry{
		Name:        v.Agent,
		Version:     v.Version,
		Title:       doc.Metadata.Title,
		Description: doc.Metadata.Description,
		Tags:        doc.Metadata.Tags,
		Examples:    doc.Metadata.Examples,
		Lifecycle:   v.Lifecycle,
		Digest:      v.SourceManifest.ContentHash,
		Variables:   make([]assistantCatalogVariable, 0, len(doc.Spec.Variables)),
		Intents:     make([]assistantCatalogIntent, 0, len(doc.Spec.Intents)),
		Defaults: assistantCatalogDefaults{
			Mode:       doc.Spec.Defaults.Mode,
			Limits:     doc.Spec.Defaults.Limits,
			Disclosure: assistantCatalogDisclosure{Policy: doc.Spec.Defaults.Disclosure.Policy},
		},
	}
	if entry.Tags == nil {
		entry.Tags = []string{}
	}
	if entry.Examples == nil {
		entry.Examples = []string{}
	}
	for _, variable := range doc.Spec.Variables {
		out := assistantCatalogVariable{
			Name: variable.Name, Type: variable.Type, Required: variable.Required,
			Choices: variable.Choices, Description: variable.Description,
		}
		if !variable.Secret {
			out.Default = variable.Default
		}
		entry.Variables = append(entry.Variables, out)
	}
	for _, intent := range doc.Spec.Intents {
		entry.Intents = append(entry.Intents, assistantCatalogIntent{Name: intent.Name, Description: intent.Description, Tier: intent.Tier})
	}
	return entry
}

// ListAssistantCatalog handles GET /api/v1/assistant-catalog. Public: no
// authentication. Lists every published, public, non-draft TelegramAssistant
// version, by name and then by version, highest first. A deprecated version
// is not listed; it stays readable by its exact version for existing pins.
func (h *Handlers) ListAssistantCatalog(w http.ResponseWriter, r *http.Request) {
	if h.opts.AgentRegistry == nil {
		writeError(w, http.StatusServiceUnavailable, "agent registry not configured")
		return
	}
	versions, err := h.opts.AgentRegistry.ListDefinitionVersionsByKind(r.Context(), agentregistry.KindTelegramAssistant)
	if err != nil {
		slog.Error("failed to list assistant catalog", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to list assistant catalog")
		return
	}
	items := make([]assistantCatalogEntry, 0, len(versions))
	for i := range versions {
		v := &versions[i]
		if v.Lifecycle != agentregistry.LifecyclePublished {
			continue
		}
		doc, err := agentregistry.ParseAssistantDocument(v.SpecJSON)
		if err != nil {
			// Publish validates this shape, so a stored row that does not
			// decode is a fault, not an entry to drop quietly: a catalog
			// missing an assistant must not read as one that has none.
			slog.Error("stored assistant definition does not decode", "agent", v.Agent, "version", v.Version, "error", err)
			writeError(w, http.StatusInternalServerError, "failed to read assistant catalog")
			return
		}
		if !publicAssistant(doc) {
			continue
		}
		items = append(items, projectAssistant(v, doc))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
}

// GetAssistantCatalogVersion handles
// GET /api/v1/assistant-catalog/{name}/versions/{version}. Public. Answers
// a published or deprecated version that is a public, non-draft
// TelegramAssistant; everything else, disabled included, is 404, so the
// endpoint never confirms that a non-public entry exists.
func (h *Handlers) GetAssistantCatalogVersion(w http.ResponseWriter, r *http.Request) {
	if h.opts.AgentRegistry == nil {
		writeError(w, http.StatusServiceUnavailable, "agent registry not configured")
		return
	}
	v, ok := h.loadAssistantVersion(w, r)
	if !ok {
		return
	}
	doc, err := agentregistry.ParseAssistantDocument(v.SpecJSON)
	if err != nil {
		slog.Error("stored assistant definition does not decode", "agent", v.Agent, "version", v.Version, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to read assistant definition")
		return
	}
	if !publicAssistant(doc) || v.Lifecycle == agentregistry.LifecycleDisabled {
		writeAssistantNotFound(w)
		return
	}
	writeJSON(w, http.StatusOK, projectAssistant(v, doc))
}

// GetAssistantDefinition handles
// GET /api/v1/assistant-catalog/{name}/versions/{version}/definition: the
// full materialized document, instructions included, with its lifecycle and
// digest, for the Telegram worker's install path and lifecycle refresh.
// Only the telegram surface principal or an admin may read it. Every
// lifecycle is answered, disabled included, because that is what a refresh
// has to learn; visibility admin and draft status are answered too, since
// the worker decides what to install. The spec is returned as stored
// (JSONB), so key order and whitespace are Postgres's, not the publisher's:
// a digest check has to canonicalize first.
func (h *Handlers) GetAssistantDefinition(w http.ResponseWriter, r *http.Request) {
	if h.opts.AgentRegistry == nil {
		writeError(w, http.StatusServiceUnavailable, "agent registry not configured")
		return
	}
	if !h.requireAssistantDefinitionReader(w, r) {
		return
	}
	v, ok := h.loadAssistantVersion(w, r)
	if !ok {
		return
	}
	doc, err := agentregistry.ParseAssistantDocument(v.SpecJSON)
	if err != nil {
		slog.Error("stored assistant definition does not decode", "agent", v.Agent, "version", v.Version, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to read assistant definition")
		return
	}
	// Publish refuses tenant visibility; this is the read-side half of the
	// same rule, in case a row ever predates it.
	if doc.Metadata.Visibility != agentregistry.AssistantVisibilityPublic &&
		doc.Metadata.Visibility != agentregistry.AssistantVisibilityAdmin {
		writeAssistantNotFound(w)
		return
	}
	writeJSON(w, http.StatusOK, assistantDefinitionResponse{
		Name:        v.Agent,
		Version:     v.Version,
		Lifecycle:   v.Lifecycle,
		ContentHash: v.SourceManifest.ContentHash,
		Definition:  json.RawMessage(v.SpecJSON),
	})
}

// requireAssistantDefinitionReader admits the telegram surface principal
// and admins. The surface reaches this route through surfaceRoutes; the
// check here is what keeps the portal surface out.
func (h *Handlers) requireAssistantDefinitionReader(w http.ResponseWriter, r *http.Request) bool {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return false
	}
	if surface, isSurface := user.Surface(); isSurface {
		if surface == surfaceid.SurfaceTelegram {
			return true
		}
		writeError(w, http.StatusForbidden, "assistant definitions are readable only by the telegram surface or an admin")
		return false
	}
	if !user.IsAdmin() {
		writeError(w, http.StatusForbidden, "assistant definitions are readable only by the telegram surface or an admin")
		return false
	}
	return true
}

// loadAssistantVersion reads {name}@{version} and refuses anything that is
// not a TelegramAssistant with the same 404 as a missing row.
func (h *Handlers) loadAssistantVersion(w http.ResponseWriter, r *http.Request) (*agentregistry.DefinitionVersion, bool) {
	name := chi.URLParam(r, "name")
	version := chi.URLParam(r, "version")
	v, err := h.opts.AgentRegistry.GetDefinitionVersion(r.Context(), name, version)
	if err != nil {
		if errors.Is(err, agentregistry.ErrDefinitionVersionNotFound) {
			writeAssistantNotFound(w)
			return nil, false
		}
		slog.Error("failed to read assistant definition", "agent", name, "version", version, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to read assistant definition")
		return nil, false
	}
	if agentregistry.DefinitionKind(v.SpecJSON) != agentregistry.KindTelegramAssistant {
		writeAssistantNotFound(w)
		return nil, false
	}
	return v, true
}

func writeAssistantNotFound(w http.ResponseWriter) {
	writeErrorCode(w, http.StatusNotFound, "assistant_not_found", "assistant version not found", nil)
}
