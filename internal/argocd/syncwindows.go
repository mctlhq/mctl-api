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

package argocd

import (
	"encoding/json"
	"fmt"
	neturl "net/url"
)

// SyncWindow is one window as configured in an AppProject (spec.syncWindows).
// In Argo CD 3.6 the API type is InlineSyncWindow; the wire fields are the
// same as before the rename.
type SyncWindow struct {
	Kind         string   `json:"kind"`
	Schedule     string   `json:"schedule"`
	Duration     string   `json:"duration"`
	TimeZone     string   `json:"timeZone,omitempty"`
	Applications []string `json:"applications,omitempty"`
	Namespaces   []string `json:"namespaces,omitempty"`
	Clusters     []string `json:"clusters,omitempty"`
	ManualSync   bool     `json:"manualSync"`
	AndOperator  bool     `json:"andOperator,omitempty"`
	Description  string   `json:"description,omitempty"`
}

// ProjectSyncWindows is the windows configured in one AppProject
// (spec.syncWindows), read from the project itself.
type ProjectSyncWindows struct {
	Project string `json:"project"`
	// Windows is never nil after a successful read: no windows is [].
	Windows []SyncWindow `json:"windows"`
}

// AppSyncWindow is one window that applies to an application. ArgoCD returns
// only kind, schedule, duration and manualSync here.
type AppSyncWindow struct {
	Kind       string `json:"kind"`
	Schedule   string `json:"schedule"`
	Duration   string `json:"duration"`
	ManualSync bool   `json:"manualSync"`
}

// AppSyncWindows is the answer of GET /api/v1/applications/{name}/syncwindows.
type AppSyncWindows struct {
	Application     string          `json:"application"`
	CanSync         bool            `json:"canSync"`
	ActiveWindows   []AppSyncWindow `json:"activeWindows"`
	AssignedWindows []AppSyncWindow `json:"assignedWindows"`
}

// GetProjectSyncWindows returns the windows CONFIGURED in one AppProject, that
// is its spec.syncWindows. It reads the project itself (GET /api/v1/projects/
// {name}), not GET /api/v1/projects/{name}/syncwindows: that endpoint answers
// the windows in effect right now, so for a project whose windows are all
// closed at the moment it answers an empty list while spec.syncWindows holds
// them (observed 2026-11-23 on `apps`). An empty answer from it would read as
// "no windows configured", which nobody observed. It needs the "projects, get"
// ArgoCD permission.
func (c *Client) GetProjectSyncWindows(project string) (*ProjectSyncWindows, error) {
	if project == "" {
		return nil, fmt.Errorf("project name is required")
	}
	body, err := c.doGet(fmt.Sprintf("%s/api/v1/projects/%s", c.baseURL, neturl.PathEscape(project)))
	if err != nil {
		return nil, err
	}
	// The body must be the AppProject that was asked for: a metadata.name that
	// is the project and a spec object. Anything else (an error page, another
	// kind of object, a spec that is not there) is a failed read, never an
	// empty list. Within a spec that is there, syncWindows absent or null is
	// Argo CD's own "none configured" (the field is omitempty): returned as [].
	var out struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Spec *struct {
			SyncWindows []SyncWindow `json:"syncWindows"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("parsing argocd project response: %w", err)
	}
	if out.Metadata.Name != project {
		return nil, fmt.Errorf("parsing argocd project response: metadata.name %q is not project %q", out.Metadata.Name, project)
	}
	if out.Spec == nil {
		return nil, fmt.Errorf("parsing argocd project response: project %q has no spec", project)
	}
	windows := out.Spec.SyncWindows
	if windows == nil {
		windows = []SyncWindow{}
	}
	return &ProjectSyncWindows{Project: project, Windows: windows}, nil
}

// GetAppSyncWindows returns the windows that apply to one application and
// whether a sync is allowed right now. The project scopes the lookup so an
// unknown application is a 404 (ErrNotFound), not a 403. The query field is
// the singular `project` (ApplicationSyncWindowsQuery, field 3 in Argo CD
// 3.6.2's application.proto); the plural `projects` of ApplicationQuery,
// which GetProjectAppStatus sends, is an unknown field here and is dropped
// by grpc-gateway without an error.
func (c *Client) GetAppSyncWindows(project, app string) (*AppSyncWindows, error) {
	if app == "" {
		return nil, fmt.Errorf("application name is required")
	}
	u := fmt.Sprintf("%s/api/v1/applications/%s/syncwindows", c.baseURL, neturl.PathEscape(app))
	if project != "" {
		u += "?" + neturl.Values{"project": {project}}.Encode()
	}
	body, err := c.doGet(u)
	if err != nil {
		return nil, err
	}
	// canSync is a boolean the API always sends; an absent one is not "false".
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(body, &probe); err != nil {
		return nil, fmt.Errorf("parsing argocd syncwindows response: %w", err)
	}
	if _, ok := probe["canSync"]; !ok {
		return nil, fmt.Errorf("parsing argocd syncwindows response: missing \"canSync\"")
	}
	var out AppSyncWindows
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("parsing argocd syncwindows response: %w", err)
	}
	out.Application = app
	if out.ActiveWindows == nil {
		out.ActiveWindows = []AppSyncWindow{}
	}
	if out.AssignedWindows == nil {
		out.AssignedWindows = []AppSyncWindow{}
	}
	return &out, nil
}
