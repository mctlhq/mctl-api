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

// ProjectSyncWindows is the answer of GET /api/v1/projects/{name}/syncwindows.
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

// GetProjectSyncWindows returns the windows configured in one AppProject.
// It needs the "projects, get" ArgoCD permission.
func (c *Client) GetProjectSyncWindows(project string) (*ProjectSyncWindows, error) {
	if project == "" {
		return nil, fmt.Errorf("project name is required")
	}
	body, err := c.doGet(fmt.Sprintf("%s/api/v1/projects/%s/syncwindows", c.baseURL, neturl.PathEscape(project)))
	if err != nil {
		return nil, err
	}
	// A project with no windows answers 200 with "windows" absent (the field
	// is omitempty) or null: Argo CD's own empty signal, returned as []. A
	// body that is not the expected object, or a "windows" that is not a
	// list, fails to unmarshal and is an error, never an empty answer.
	var out ProjectSyncWindows
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("parsing argocd syncwindows response: %w", err)
	}
	out.Project = project
	if out.Windows == nil {
		out.Windows = []SyncWindow{}
	}
	return &out, nil
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
