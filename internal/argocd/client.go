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
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"sort"
	"strings"
	"time"
)

// ErrNotFound is returned when an ArgoCD application does not exist.
var ErrNotFound = errors.New("argocd application not found")

// ErrUnauthenticated is returned when the ArgoCD token is invalid or expired (HTTP 401).
var ErrUnauthenticated = errors.New("argocd token invalid or expired")

// ErrForbidden is returned when the ArgoCD token lacks permissions (HTTP 403).
var ErrForbidden = errors.New("argocd access denied")

// Client communicates with the ArgoCD API to read application status.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// AppStatus represents the health and sync status of an ArgoCD Application.
type AppStatus struct {
	Name       string    `json:"name"`
	Health     string    `json:"health"`     // Healthy, Degraded, Progressing, Missing, Unknown
	SyncStatus string    `json:"syncStatus"` // Synced, OutOfSync, Unknown
	Revision   string    `json:"revision"`
	Message    string    `json:"message,omitempty"`
	UpdatedAt  time.Time `json:"updatedAt"`
	Namespace  string    `json:"namespace"`
	Project    string    `json:"project"`
}

// AppList is a list of ArgoCD applications.
type AppList struct {
	Items []AppStatus `json:"items"`
}

// NewClient creates an ArgoCD API client.
func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// GetAppStatus returns the status of a specific ArgoCD application.
func (c *Client) GetAppStatus(appName string) (*AppStatus, error) {
	url := fmt.Sprintf("%s/api/v1/applications/%s", c.baseURL, appName)
	body, err := c.doGet(url)
	if err != nil {
		return nil, err
	}

	var raw struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Spec struct {
			Project string `json:"project"`
		} `json:"spec"`
		Status struct {
			Health struct {
				Status  string `json:"status"`
				Message string `json:"message"`
			} `json:"health"`
			Sync struct {
				Status   string `json:"status"`
				Revision string `json:"revision"`
			} `json:"sync"`
			ReconciledAt string `json:"reconciledAt"`
		} `json:"status"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parsing argocd response: %w", err)
	}

	updatedAt, _ := time.Parse(time.RFC3339, raw.Status.ReconciledAt)

	return &AppStatus{
		Name:       raw.Metadata.Name,
		Health:     raw.Status.Health.Status,
		SyncStatus: raw.Status.Sync.Status,
		Revision:   raw.Status.Sync.Revision,
		Message:    raw.Status.Health.Message,
		UpdatedAt:  updatedAt,
		Namespace:  raw.Metadata.Namespace,
		Project:    raw.Spec.Project,
	}, nil
}

// ListApps lists ArgoCD applications matching a project or label selector.
func (c *Client) ListApps(project string) ([]AppStatus, error) {
	url := fmt.Sprintf("%s/api/v1/applications?project=%s", c.baseURL, project)
	body, err := c.doGet(url)
	if err != nil {
		return nil, err
	}

	var raw struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Spec struct {
				Project string `json:"project"`
			} `json:"spec"`
			Status struct {
				Health struct {
					Status string `json:"status"`
				} `json:"health"`
				Sync struct {
					Status   string `json:"status"`
					Revision string `json:"revision"`
				} `json:"sync"`
				ReconciledAt string `json:"reconciledAt"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parsing argocd list response: %w", err)
	}

	apps := make([]AppStatus, 0, len(raw.Items))
	for _, item := range raw.Items {
		updatedAt, _ := time.Parse(time.RFC3339, item.Status.ReconciledAt)
		apps = append(apps, AppStatus{
			Name:       item.Metadata.Name,
			Health:     item.Status.Health.Status,
			SyncStatus: item.Status.Sync.Status,
			Revision:   item.Status.Sync.Revision,
			UpdatedAt:  updatedAt,
			Namespace:  item.Metadata.Namespace,
			Project:    item.Spec.Project,
		})
	}
	return apps, nil
}

// Workload is an ArgoCD Application as the service listing needs it: where it
// deploys, what it exposes and where it comes from. It is separate from
// AppStatus because the source fields must not leak through the endpoints
// that return AppStatus to tenant members.
type Workload struct {
	Name          string
	Project       string
	DestNamespace string
	Health        string
	SyncStatus    string
	Hosts         []string
	Images        []string
	SourceRepo    string
	SourcePath    string
}

// workloadFields trims the list response to what Workload needs; the full
// Application objects carry every managed resource and are large.
const workloadFields = "items.metadata.name,items.spec.project,items.spec.destination.namespace," +
	"items.spec.source.repoURL,items.spec.source.path,items.spec.sources," +
	"items.status.health.status,items.status.sync.status,items.status.summary"

// ListWorkloads lists every ArgoCD application the token can read, across all
// projects. An error means the listing could not be observed; callers must not
// treat it as an empty list.
func (c *Client) ListWorkloads() ([]Workload, error) {
	body, err := c.doGet(fmt.Sprintf("%s/api/v1/applications?fields=%s", c.baseURL, neturl.QueryEscape(workloadFields)))
	if err != nil {
		return nil, err
	}

	type source struct {
		RepoURL string `json:"repoURL"`
		Path    string `json:"path"`
	}
	var raw struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Spec struct {
				Project     string `json:"project"`
				Destination struct {
					Namespace string `json:"namespace"`
				} `json:"destination"`
				Source  *source  `json:"source"`
				Sources []source `json:"sources"`
			} `json:"spec"`
			Status struct {
				Health struct {
					Status string `json:"status"`
				} `json:"health"`
				Sync struct {
					Status string `json:"status"`
				} `json:"sync"`
				Summary struct {
					ExternalURLs []string `json:"externalURLs"`
					Images       []string `json:"images"`
				} `json:"summary"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parsing argocd list response: %w", err)
	}

	workloads := make([]Workload, 0, len(raw.Items))
	for i := range raw.Items {
		item := &raw.Items[i]
		if item.Metadata.Name == "" {
			// A nameless item cannot be attributed to anything. Dropping it
			// would turn a malformed body into a shorter list.
			return nil, fmt.Errorf("parsing argocd list response: item %d has no metadata.name", i)
		}
		w := Workload{
			Name:          item.Metadata.Name,
			Project:       item.Spec.Project,
			DestNamespace: item.Spec.Destination.Namespace,
			Health:        item.Status.Health.Status,
			SyncStatus:    item.Status.Sync.Status,
			Hosts:         hostsFromURLs(item.Status.Summary.ExternalURLs),
			Images:        item.Status.Summary.Images,
		}
		switch {
		case item.Spec.Source != nil:
			w.SourceRepo, w.SourcePath = item.Spec.Source.RepoURL, item.Spec.Source.Path
		case len(item.Spec.Sources) > 0:
			w.SourceRepo, w.SourcePath = item.Spec.Sources[0].RepoURL, item.Spec.Sources[0].Path
		}
		workloads = append(workloads, w)
	}
	return workloads, nil
}

// hostsFromURLs reduces ArgoCD's externalURLs to a sorted set of host names.
// ArgoCD derives the scheme from the Ingress TLS block, which says nothing
// about what the edge serves, so the scheme and path are dropped.
func hostsFromURLs(urls []string) []string {
	seen := make(map[string]struct{}, len(urls))
	var hosts []string
	for _, raw := range urls {
		u, err := neturl.Parse(raw)
		if err != nil {
			continue
		}
		host := u.Hostname()
		if host == "" && !strings.Contains(raw, "//") {
			// A bare "host", "host/path" or "host:port", as an external-link
			// annotation may carry, parses as a path or as an opaque scheme
			// rather than as a URL with an authority.
			host, _, _ = strings.Cut(raw, "/")
			host, _, _ = strings.Cut(host, ":")
		}
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts
}

func (c *Client) doGet(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("argocd request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		// success
	case http.StatusNotFound:
		return nil, fmt.Errorf("%w: %s", ErrNotFound, string(body))
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("%w: %s", ErrUnauthenticated, string(body))
	case http.StatusForbidden:
		return nil, fmt.Errorf("%w: %s", ErrForbidden, string(body))
	default:
		return nil, fmt.Errorf("argocd returned %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}
