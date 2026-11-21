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
	"strings"

	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/auth"
)

// GetSyncWindows handles GET /api/v1/sync-windows?project=<p>[&application=<a>]:
// the sync windows configured in one Argo CD AppProject and, when an
// application is named, whether it may sync right now. Read-only and
// admin-only: windows are changed only by a gitops PR on the AppProject.
//
// Either part failing fails the request. A project that was read but an
// application that was not is not reported as a project with no state.
func (h *Handlers) GetSyncWindows(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !user.IsAdmin() {
		writeError(w, http.StatusForbidden, "sync windows are admin-only")
		return
	}
	reader, ok := h.opts.ArgoCD.(ArgoSyncWindowsReader)
	if h.opts.ArgoCD == nil || !ok {
		writeError(w, http.StatusServiceUnavailable, "argocd sync windows reader not configured")
		return
	}
	project := strings.TrimSpace(r.URL.Query().Get("project"))
	app := strings.TrimSpace(r.URL.Query().Get("application"))
	if project == "" {
		writeError(w, http.StatusBadRequest, "project is required")
		return
	}

	pw, err := reader.GetProjectSyncWindows(project)
	if err != nil {
		h.writeSyncWindowsError(w, "project", project, err)
		return
	}
	resp := map[string]any{"project": pw.Project, "windows": pw.Windows}
	if app != "" {
		aw, err := reader.GetAppSyncWindows(project, app)
		if err != nil {
			h.writeSyncWindowsError(w, "application", app, err)
			return
		}
		resp["application"] = map[string]any{
			"name":            aw.Application,
			"canSync":         aw.CanSync,
			"activeWindows":   aw.ActiveWindows,
			"assignedWindows": aw.AssignedWindows,
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handlers) writeSyncWindowsError(w http.ResponseWriter, what, name string, err error) {
	switch {
	case errors.Is(err, argocd.ErrNotFound):
		writeError(w, http.StatusNotFound, what+" "+name+" not found")
	case errors.Is(err, argocd.ErrForbidden):
		// The server-side Argo CD role lacks "projects, get" or the object is
		// outside its scope: say so, never an empty list.
		slog.Error("argocd refused sync windows read", "what", what, "name", name, "error", err)
		writeError(w, http.StatusBadGateway, "argocd refused the sync windows read ("+what+"); the mctl-api role needs projects, get")
	default:
		slog.Error("failed to read sync windows", "what", what, "name", name, "error", err)
		writeError(w, http.StatusBadGateway, "failed to read sync windows from argocd")
	}
}
