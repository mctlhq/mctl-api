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
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mctlhq/mctl-api/internal/roadmap"
)

// Roadmap read model (mctl-api#333). Every answer here is selected from the
// RoadmapPublication that mctlhq/.github publishes to its roadmap-state
// branch; nothing is evaluated, inferred or written. A publication that is
// missing or fails verification answers 503, which means "cannot say", never
// "nothing is ready".

const (
	roadmapCodeUnavailable  = "roadmap_unavailable"
	roadmapCodeEpicNotFound = "epic_not_found"
	roadmapCodeInvalid      = "invalid_request"
)

func (h *Handlers) roadmapPublication(w http.ResponseWriter) (*roadmap.Publication, bool) {
	pub, err := h.opts.Roadmap.Current()
	if err != nil {
		slog.Warn("roadmap publication unavailable", "error", err)
		writeErrorCode(w, http.StatusServiceUnavailable, roadmapCodeUnavailable, err.Error(), nil)
		return nil, false
	}
	return pub, true
}

func writeRoadmapLookupError(w http.ResponseWriter, err error) {
	if errors.Is(err, roadmap.ErrEpicNotFound) {
		writeErrorCode(w, http.StatusNotFound, roadmapCodeEpicNotFound, err.Error(), nil)
		return
	}
	writeError(w, http.StatusInternalServerError, "roadmap lookup failed")
}

// ListRoadmapEpics handles GET /api/v1/roadmap/epics.
func (h *Handlers) ListRoadmapEpics(w http.ResponseWriter, r *http.Request) {
	pub, ok := h.roadmapPublication(w)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"epics":      pub.Epics(),
		"provenance": pub.Provenance(time.Now()),
	})
}

// GetRoadmapEpicStatus handles GET /api/v1/roadmap/epic-status?epic=<name or owner/repo#N>.
func (h *Handlers) GetRoadmapEpicStatus(w http.ResponseWriter, r *http.Request) {
	epic := strings.TrimSpace(r.URL.Query().Get("epic"))
	if epic == "" {
		writeErrorCode(w, http.StatusBadRequest, roadmapCodeInvalid, "epic is required: a name or a root issue such as mctlhq/.github#57", nil)
		return
	}
	pub, ok := h.roadmapPublication(w)
	if !ok {
		return
	}
	status, err := pub.EpicStatus(epic, time.Now())
	if err != nil {
		writeRoadmapLookupError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// GetRoadmapReadyWorkItems handles GET /api/v1/roadmap/ready?epic=&required_only=.
// Without epic it answers for every active epic. required_only defaults to
// true: the safe wave-selection default.
func (h *Handlers) GetRoadmapReadyWorkItems(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	requiredOnly := true
	if v := strings.TrimSpace(q.Get("required_only")); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			writeErrorCode(w, http.StatusBadRequest, roadmapCodeInvalid, "required_only must be true or false", nil)
			return
		}
		requiredOnly = b
	}
	pub, ok := h.roadmapPublication(w)
	if !ok {
		return
	}
	ready, err := pub.ReadyWorkItems(q.Get("epic"), requiredOnly, time.Now())
	if err != nil {
		writeRoadmapLookupError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ready)
}
