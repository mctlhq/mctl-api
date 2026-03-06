package gitops

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Reader provides read access to the GitOps mono-repo state.
// It clones the repo locally and refreshes periodically.
type Reader struct {
	repoURL   string
	branch    string
	localPath string
	mu        sync.RWMutex
	lastSync  time.Time
}

// Tenant represents a workspace read from the GitOps repo.
type Tenant struct {
	Name         string            `json:"name"`
	DisplayName  string            `json:"displayName"`
	Description  string            `json:"description"`
	ContactEmail string            `json:"contactEmail"`
	Quotas       map[string]string `json:"quotas"`
	Members      []TenantMember    `json:"members,omitempty"`
}

// TenantMember represents a member of a tenant.
type TenantMember struct {
	UserID string `json:"userId"`
	Role   string `json:"role,omitempty"`
}

// Service represents a deployed service read from the GitOps repo.
type Service struct {
	Team          string `json:"team"`
	Name          string `json:"name"`
	ImageTag      string `json:"imageTag,omitempty"`
	Host          string `json:"host,omitempty"`
	Port          string `json:"port,omitempty"`
	ComponentType string `json:"componentType,omitempty"`
	HasDatabase   bool   `json:"hasDatabase"`
}

// NewReader creates a new gitops reader.
func NewReader(repoURL, branch, localPath string) (*Reader, error) {
	r := &Reader{
		repoURL:   repoURL,
		branch:    branch,
		localPath: localPath,
	}
	return r, nil
}

// RefreshLoop periodically refreshes the local repo clone.
func (r *Reader) RefreshLoop(ctx context.Context, interval time.Duration) {
	// Initial sync.
	if err := r.refresh(); err != nil {
		slog.Error("initial gitops sync failed", "error", err)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.refresh(); err != nil {
				slog.Error("gitops refresh failed", "error", err)
			}
		}
	}
}

func (r *Reader) refresh() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// For local development / PoC: if the path exists, treat it as a local checkout.
	// In production, this would do a git pull.
	if _, err := os.Stat(r.localPath); os.IsNotExist(err) {
		slog.Info("gitops repo not found locally, will use mock data", "path", r.localPath)
	}

	r.lastSync = time.Now()
	slog.Debug("gitops refreshed", "lastSync", r.lastSync)
	return nil
}

// ListTenants reads all tenants from the GitOps repo.
func (r *Reader) ListTenants() ([]Tenant, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tenantsDir := filepath.Join(r.localPath, "platform-gitops", "tenants")

	entries, err := os.ReadDir(tenantsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading tenants dir: %w", err)
	}

	var tenants []Tenant
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		t, err := r.readTenant(entry.Name())
		if err != nil {
			slog.Warn("failed to read tenant", "name", entry.Name(), "error", err)
			continue
		}
		tenants = append(tenants, *t)
	}
	return tenants, nil
}

// GetTenant reads a single tenant by name.
func (r *Reader) GetTenant(name string) (*Tenant, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.readTenant(name)
}

func (r *Reader) readTenant(name string) (*Tenant, error) {
	valuesPath := filepath.Join(r.localPath, "platform-gitops", "tenants", name, "values.yaml")
	data, err := os.ReadFile(valuesPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", valuesPath, err)
	}

	var raw struct {
		Tenant struct {
			Name         string `yaml:"name"`
			DisplayName  string `yaml:"displayName"`
			Description  string `yaml:"description"`
			ContactEmail string `yaml:"contactEmail"`
			Members      []struct {
				UserID string `yaml:"userId"`
				Role   string `yaml:"role"`
			} `yaml:"members"`
			Quotas map[string]string `yaml:"quotas"`
		} `yaml:"tenant"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", valuesPath, err)
	}

	t := &Tenant{
		Name:         raw.Tenant.Name,
		DisplayName:  raw.Tenant.DisplayName,
		Description:  raw.Tenant.Description,
		ContactEmail: raw.Tenant.ContactEmail,
		Quotas:       raw.Tenant.Quotas,
	}
	if t.Name == "" {
		t.Name = name
	}
	for _, m := range raw.Tenant.Members {
		t.Members = append(t.Members, TenantMember{UserID: m.UserID, Role: m.Role})
	}
	return t, nil
}

// ListServices reads all deployed services from the GitOps repo.
func (r *Reader) ListServices(teamFilter string) ([]Service, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	servicesDir := filepath.Join(r.localPath, "platform-gitops", "services")

	teamDirs, err := os.ReadDir(servicesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading services dir: %w", err)
	}

	var services []Service
	for _, teamDir := range teamDirs {
		if !teamDir.IsDir() {
			continue
		}
		team := teamDir.Name()
		if teamFilter != "" && team != teamFilter {
			continue
		}

		appDirs, err := os.ReadDir(filepath.Join(servicesDir, team))
		if err != nil {
			continue
		}

		for _, appDir := range appDirs {
			if !appDir.IsDir() {
				continue
			}
			svc, err := r.readService(team, appDir.Name())
			if err != nil {
				slog.Warn("failed to read service", "team", team, "app", appDir.Name(), "error", err)
				continue
			}
			services = append(services, *svc)
		}
	}
	return services, nil
}

// GetService reads a single service.
func (r *Reader) GetService(team, app string) (*Service, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.readService(team, app)
}

func (r *Reader) readService(team, app string) (*Service, error) {
	valuesPath := filepath.Join(r.localPath, "platform-gitops", "services", team, app, "values.yaml")
	data, err := os.ReadFile(valuesPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", valuesPath, err)
	}

	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", valuesPath, err)
	}

	svc := &Service{
		Team: team,
		Name: app,
	}

	if image, ok := raw["image"].(map[string]interface{}); ok {
		if tag, ok := image["tag"].(string); ok {
			svc.ImageTag = tag
		}
	}
	if host, ok := raw["host"].(string); ok {
		svc.Host = host
	}
	if port, ok := raw["port"]; ok {
		svc.Port = fmt.Sprintf("%v", port)
	}
	if _, ok := raw["dbSecret"]; ok {
		svc.HasDatabase = true
	}

	// Detect component type from values.
	content := string(data)
	if strings.Contains(content, "worker-service") {
		svc.ComponentType = "worker-service"
	} else {
		svc.ComponentType = "base-service"
	}

	return svc, nil
}

// GetTenantsForUser returns the list of tenant names a GitHub user belongs to.
// Implements auth.TenantResolver.
func (r *Reader) GetTenantsForUser(login string) ([]string, error) {
	tenants, err := r.ListTenants()
	if err != nil {
		return nil, err
	}

	login = strings.ToLower(login)
	var result []string
	for _, t := range tenants {
		for _, m := range t.Members {
			if strings.ToLower(m.UserID) == login {
				result = append(result, t.Name)
				break
			}
		}
	}
	return result, nil
}

// LastSync returns the time of the last successful repo sync.
func (r *Reader) LastSync() time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.lastSync
}
