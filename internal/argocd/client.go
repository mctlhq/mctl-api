package argocd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ErrNotFound is returned when an ArgoCD application does not exist.
var ErrNotFound = errors.New("argocd application not found")

// ErrUnauthenticated is returned when the ArgoCD token is invalid or expired.
var ErrUnauthenticated = errors.New("argocd token invalid or expired")

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
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("%w: %s", ErrUnauthenticated, string(body))
	default:
		return nil, fmt.Errorf("argocd returned %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}
