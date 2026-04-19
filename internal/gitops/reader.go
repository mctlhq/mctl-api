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

package gitops

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Reader provides read access to the GitOps mono-repo state.
// It clones the repo locally and refreshes periodically.
type Reader struct {
	repoURL    string
	branch     string
	localPath  string
	token      string // GitHub token for HTTPS auth (optional)
	sshKeyPath string // Path to SSH private key (optional, takes precedence over token)
	mu         sync.RWMutex
	lastSync   time.Time
}

// Tenant represents a workspace read from the GitOps repo.
type Tenant struct {
	Name         string            `json:"name"`
	DisplayName  string            `json:"displayName"`
	Description  string            `json:"description"`
	ContactEmail string            `json:"contactEmail"`
	Quotas       map[string]string `json:"quotas"`
	Networking   map[string]bool   `json:"networking,omitempty"`
	Members      []TenantMember    `json:"members,omitempty"`
	Teams        []Team            `json:"teams,omitempty"` // optional: multi-team support
}

// Team represents a team within a multi-team tenant.
// Each team gets its own namespace: {tenant}-{team}.
type Team struct {
	Name        string         `json:"name"`
	DisplayName string         `json:"displayName,omitempty"`
	Members     []TenantMember `json:"members,omitempty"`
}

// TenantMember represents a member of a tenant.
type TenantMember struct {
	UserID string `json:"userId"`
	Role   string `json:"role,omitempty"`
}

// IsMultiTeam returns true if the tenant has explicit teams defined.
func (t *Tenant) IsMultiTeam() bool {
	return len(t.Teams) > 0
}

// Namespaces returns the list of K8s namespaces this tenant owns.
// For legacy tenants (no teams): returns [tenantName].
// For multi-team tenants: returns [tenant-team1, tenant-team2, ...].
func (t *Tenant) Namespaces() []string {
	if !t.IsMultiTeam() {
		return []string{t.Name}
	}
	ns := make([]string, 0, len(t.Teams))
	for _, team := range t.Teams {
		ns = append(ns, t.Name+"-"+team.Name)
	}
	return ns
}

// UserNamespaces returns the namespaces accessible to a specific user (case-insensitive).
// For legacy tenants: returns [tenantName] if user is a member.
// For multi-team: returns compound namespaces for teams the user belongs to.
func (t *Tenant) UserNamespaces(login string) []string {
	if !t.IsMultiTeam() {
		for _, m := range t.Members {
			if strings.EqualFold(m.UserID, login) {
				return []string{t.Name}
			}
		}
		return nil
	}
	// Multi-team: check team-level membership first, then tenant-level fallback.
	var ns []string
	isTenantMember := false
	for _, m := range t.Members {
		if strings.EqualFold(m.UserID, login) {
			isTenantMember = true
			break
		}
	}
	for _, team := range t.Teams {
		compound := t.Name + "-" + team.Name
		if isTenantMember {
			// Tenant-level members have access to all teams.
			ns = append(ns, compound)
			continue
		}
		for _, m := range team.Members {
			if strings.EqualFold(m.UserID, login) {
				ns = append(ns, compound)
				break
			}
		}
	}
	return ns
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
// token is an optional GitHub token for HTTPS auth.
// sshKeyPath is an optional path to an SSH private key for SSH auth.
// If sshKeyPath is set, it takes precedence and the repo URL should be SSH format.
func NewReader(repoURL, branch, localPath, token, sshKeyPath string) (*Reader, error) {
	r := &Reader{
		repoURL:    repoURL,
		branch:     branch,
		localPath:  localPath,
		token:      token,
		sshKeyPath: sshKeyPath,
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

	var cloneURL string
	var sshEnv []string

	switch {
	case r.sshKeyPath != "":
		// SSH auth: use key file, accept-new trusts on first connect (TOFU)
		cloneURL = r.repoURL
		sshCmd := fmt.Sprintf("ssh -i %s -o StrictHostKeyChecking=accept-new", r.sshKeyPath)
		sshEnv = []string{"GIT_SSH_COMMAND=" + sshCmd}
	case r.token != "":
		// HTTPS auth: inject token into URL
		if u, err := url.Parse(r.repoURL); err == nil {
			u.User = url.UserPassword("x-access-token", r.token)
			cloneURL = u.String()
		} else {
			cloneURL = r.repoURL
		}
	default:
		cloneURL = r.repoURL
	}

	gitDir := filepath.Join(r.localPath, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		slog.Info("cloning gitops repo", "url", r.repoURL, "branch", r.branch, "path", r.localPath)
		cmd := exec.Command("git", "clone", "--depth=1", "--branch="+r.branch, "--single-branch", cloneURL, r.localPath) //nolint:gosec // args are from trusted config
		cmd.Env = append(os.Environ(), sshEnv...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("git clone failed: %w\n%s", err, bytes.TrimSpace(out))
		}
		slog.Info("gitops repo cloned successfully")
	} else {
		args := []string{"-C", r.localPath, "pull", "--ff-only", cloneURL, r.branch}
		cmd := exec.Command("git", args...) //nolint:gosec // args are from trusted config
		cmd.Env = append(os.Environ(), sshEnv...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("git pull failed: %w\n%s", err, bytes.TrimSpace(out))
		}
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
	data, err := os.ReadFile(valuesPath) //nolint:gosec // path built from trusted repo root
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
			Teams []struct {
				Name        string `yaml:"name"`
				DisplayName string `yaml:"displayName"`
				Members     []struct {
					UserID string `yaml:"userId"`
					Role   string `yaml:"role"`
				} `yaml:"members"`
			} `yaml:"teams"`
			Quotas     map[string]string `yaml:"quotas"`
			Networking struct {
				AllowIntraNamespace bool `yaml:"allowIntraNamespace"`
				AllowClusterEgress  bool `yaml:"allowClusterEgress"`
				AllowInternetEgress bool `yaml:"allowInternetEgress"`
			} `yaml:"networking"`
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
		Networking: map[string]bool{
			"allowIntraNamespace": raw.Tenant.Networking.AllowIntraNamespace,
			"allowClusterEgress":  raw.Tenant.Networking.AllowClusterEgress,
			"allowInternetEgress": raw.Tenant.Networking.AllowInternetEgress,
		},
	}
	if t.Name == "" {
		t.Name = name
	}
	for _, m := range raw.Tenant.Members {
		t.Members = append(t.Members, TenantMember{UserID: m.UserID, Role: m.Role})
	}
	for _, team := range raw.Tenant.Teams {
		tm := Team{Name: team.Name, DisplayName: team.DisplayName}
		for _, m := range team.Members {
			tm.Members = append(tm.Members, TenantMember{UserID: m.UserID, Role: m.Role})
		}
		t.Teams = append(t.Teams, tm)
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
	data, err := os.ReadFile(valuesPath) //nolint:gosec // path built from trusted repo root
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

// GetTenantsForUser returns the list of namespace names a GitHub user has access to.
// For legacy tenants (no teams): returns the tenant name.
// For multi-team tenants: returns compound names ({tenant}-{team}) for teams the user belongs to.
// Implements auth.TenantResolver.
func (r *Reader) GetTenantsForUser(login string) ([]string, error) {
	tenants, err := r.ListTenants()
	if err != nil {
		return nil, err
	}

	var result []string
	for i := range tenants {
		ns := tenants[i].UserNamespaces(login)
		result = append(result, ns...)
	}
	return result, nil
}

// LastSync returns the time of the last successful repo sync.
func (r *Reader) LastSync() time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.lastSync
}

// OpenClawSkill describes a single SKILL.md file backed up in the gitops repo.
type OpenClawSkill struct {
	Name         string    `json:"name"`
	Size         int64     `json:"size"`
	LastModified time.Time `json:"lastModified"`
}

// ListOpenClawSkills lists .md files under platform-gitops/services/{team}/openclaw/skills/.
// Returns an empty slice (not an error) if the directory does not exist.
func (r *Reader) ListOpenClawSkills(team string) ([]OpenClawSkill, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	dir := filepath.Join(r.localPath, "platform-gitops", "services", team, "openclaw", "skills")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []OpenClawSkill{}, nil
		}
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}

	out := make([]OpenClawSkill, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".md") || name == "README.md" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		out = append(out, OpenClawSkill{
			Name:         strings.TrimSuffix(name, ".md"),
			Size:         info.Size(),
			LastModified: info.ModTime().UTC(),
		})
	}
	return out, nil
}

// ReadOpenClawSkill returns the raw text content of
// platform-gitops/services/{team}/openclaw/skills/{name}.md.
// Returns os.ErrNotExist wrapped if the file is missing.
func (r *Reader) ReadOpenClawSkill(team, name string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	path := filepath.Join(r.localPath, "platform-gitops", "services", team, "openclaw", "skills", name+".md")
	data, err := os.ReadFile(path) //nolint:gosec // path built from validated components
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	return string(data), nil
}
