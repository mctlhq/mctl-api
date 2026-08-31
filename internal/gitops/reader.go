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
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

// Reader provides read access to the GitOps mono-repo state.
// It clones the repo locally and refreshes periodically.
type Reader struct {
	repoURL        string
	branch         string
	localPath      string
	token          string // GitHub token for HTTPS auth (optional)
	sshKeyPath     string // Path to SSH private key (optional, takes precedence over token)
	knownHostsPath string // Path to a known_hosts file for SSH host-key pinning (optional; empty means "use the shipped embedded default, materialized lazily")
	mu             sync.RWMutex
	lastSync       time.Time

	// resolvedKnownHostsPath caches the on-disk path of the materialized
	// embedded default known_hosts file, computed lazily on first SSH-mode
	// refresh so the constructor and the HTTPS/token path never touch the
	// filesystem for it. Guarded by mu, which refresh() already holds for
	// its entire duration.
	resolvedKnownHostsPath string
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

// PlatformSkillMetadata is the policy-bearing metadata for a platform-wide skill.
type PlatformSkillMetadata struct {
	Name        string   `json:"name" yaml:"name"`
	Title       string   `json:"title" yaml:"title"`
	Description string   `json:"description" yaml:"description"`
	Visibility  string   `json:"visibility" yaml:"visibility"`
	Status      string   `json:"status" yaml:"status"`
	Owner       string   `json:"owner" yaml:"owner"`
	Runtimes    []string `json:"runtimes" yaml:"runtimes"`
}

// PlatformSkill is a skill entry from platform-gitops/platform-skills/catalog.
type PlatformSkill struct {
	Metadata     PlatformSkillMetadata `json:"metadata"`
	HasContent   bool                  `json:"hasContent"`
	Size         int64                 `json:"size,omitempty"`
	LastModified time.Time             `json:"lastModified,omitempty"`
}

// PlatformSkillBinding describes role- or tenant-level skill grants.
type PlatformSkillBinding struct {
	Tenant        string   `json:"tenant,omitempty" yaml:"tenant"`
	Role          string   `json:"role,omitempty" yaml:"role"`
	EnabledSkills []string `json:"enabledSkills" yaml:"enabledSkills"`
}

// PlatformSkillPolicy holds coarse allow/deny rules for tenant enables.
type PlatformSkillPolicy struct {
	TenantAllowlist map[string][]string `json:"tenantAllowlist,omitempty" yaml:"tenantAllowlist"`
	TenantDenylist  map[string][]string `json:"tenantDenylist,omitempty" yaml:"tenantDenylist"`
}

// NewReader creates a new gitops reader.
// token is an optional GitHub token for HTTPS auth.
// sshKeyPath is an optional path to an SSH private key for SSH auth.
// If sshKeyPath is set, it takes precedence and the repo URL should be SSH format.
// knownHostsPath is an optional path to a known_hosts file used to verify the
// SSH host key when sshKeyPath is set. If empty, a known_hosts file
// populated with GitHub's published host keys is materialized lazily on the
// first SSH-mode refresh. NewReader performs no filesystem I/O — it only
// stores knownHostsPath verbatim.
func NewReader(repoURL, branch, localPath, token, sshKeyPath, knownHostsPath string) *Reader {
	return &Reader{
		repoURL:        repoURL,
		branch:         branch,
		localPath:      localPath,
		token:          token,
		sshKeyPath:     sshKeyPath,
		knownHostsPath: knownHostsPath,
	}
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
		// SSH auth: use key file, verify the host key against a pinned
		// known_hosts file (fail closed — no trust-on-first-use).
		cloneURL = r.repoURL
		knownHostsPath, err := r.resolveKnownHostsPathLocked()
		if err != nil {
			return fmt.Errorf("resolving known_hosts path: %w", err)
		}
		sshEnv = []string{"GIT_SSH_COMMAND=" + buildSSHCommand(r.sshKeyPath, knownHostsPath)}
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
		if err := r.runGit(sshEnv, "fetch", "--depth=1", cloneURL, r.branch); err != nil {
			return fmt.Errorf("git fetch failed: %w", err)
		}
		if err := r.runGit(sshEnv, "reset", "--hard", "FETCH_HEAD"); err != nil {
			return fmt.Errorf("git reset failed: %w", err)
		}
		if err := r.runGit(sshEnv, "checkout", "-B", r.branch, "FETCH_HEAD"); err != nil {
			return fmt.Errorf("git checkout failed: %w", err)
		}
		if err := r.runGit(sshEnv, "clean", "-fd"); err != nil {
			return fmt.Errorf("git clean failed: %w", err)
		}
	}

	r.lastSync = time.Now()
	if head, err := r.gitOutput(sshEnv, "rev-parse", "--short", "HEAD"); err == nil {
		slog.Info("gitops refreshed",
			"branch", r.branch,
			"path", r.localPath,
			"head", strings.TrimSpace(string(head)),
			"lastSync", r.lastSync,
		)
	} else {
		slog.Info("gitops refreshed", "branch", r.branch, "path", r.localPath, "lastSync", r.lastSync)
	}
	return nil
}

// buildSSHCommand builds the GIT_SSH_COMMAND value used for SSH-based
// clone/fetch. It always pins host-key verification (StrictHostKeyChecking
// yes) against the given known_hosts file — there is no trust-on-first-use
// fallback of any kind.
//
// GlobalKnownHostsFile is neutralised on purpose: UserKnownHostsFile only
// replaces ~/.ssh/known_hosts, while OpenSSH keeps consulting
// /etc/ssh/ssh_known_hosts as well, even under StrictHostKeyChecking=yes. A
// github.com entry that ever lands in the base image would then satisfy
// verification without the pinned file being involved — exactly the trust
// path this pinning exists to close. With both set, the embedded keys are
// the sole source of truth.
//
// git runs GIT_SSH_COMMAND through a shell, so both paths are single-quoted.
// They come from operator-set env vars today, the same trust level as the
// other exec arguments here, but quoting is what makes a path containing a
// space work at all and keeps that trust assumption from being load-bearing.
func buildSSHCommand(sshKeyPath, knownHostsPath string) string {
	return fmt.Sprintf(
		"ssh -i %s -o StrictHostKeyChecking=yes -o UserKnownHostsFile=%s -o GlobalKnownHostsFile=/dev/null",
		shellQuote(sshKeyPath), shellQuote(knownHostsPath),
	)
}

// shellQuote renders s as a single shell word. Embedded single quotes are
// closed, escaped and reopened — the standard POSIX idiom — so any byte
// sequence survives intact and nothing in the path is interpreted.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// resolveKnownHostsPathLocked returns the known_hosts path to use for SSH
// host-key verification. Callers must hold r.mu (refresh() already does,
// for its full duration).
//
// If r.knownHostsPath is explicitly set, it is returned verbatim. Otherwise
// the embedded default (GitHub's published host keys) is materialized
// under a Reader-owned directory derived from localPath, and the resolved
// path is cached on the Reader so subsequent syncs do not rewrite it.
//
// That directory is deliberately a *sibling* of localPath (localPath +
// ".known-hosts"), never nested inside it: localPath is the git working
// tree that refresh() clones/fetches into, and `git clone` refuses a
// non-empty target directory while `git clean -fd` (run on every
// subsequent refresh()) deletes untracked files, so anything placed inside
// localPath itself would either break the initial clone or be silently
// wiped on the next sync.
//
// Unlike a fixed path under a shared location such as os.TempDir(), this
// directory is created with 0700 (owner-only) permissions, so a local
// attacker sharing the same host cannot even create sibling entries inside
// it to race us. Both the directory and, inside it, the known_hosts file
// are only ever created via os.Mkdir / O_CREATE|O_EXCL, so a pre-existing
// path (in particular a symlink planted before this Reader ever ran) is
// never followed or opened for writing. If either already exists (e.g.
// from a previous refresh() within this same process), it is reused only
// after Lstat confirms it is a real directory/regular file (not a
// symlink), owned by this process's effective UID, and carrying no
// group/world permission bits — and, for the file, that its contents
// already byte-match the embedded default. Any failed check is fatal
// (fail closed) rather than a silent overwrite.
func (r *Reader) resolveKnownHostsPathLocked() (string, error) {
	if r.knownHostsPath != "" {
		return r.knownHostsPath, nil
	}
	if r.resolvedKnownHostsPath != "" {
		return r.resolvedKnownHostsPath, nil
	}

	// filepath.Clean first: a configured GITOPS_LOCAL_PATH with a trailing
	// slash ("/data/mctl-gitops/") would otherwise concatenate into
	// "/data/mctl-gitops/.known-hosts" — nested inside the working tree,
	// which is exactly what the sibling requirement above exists to avoid.
	dir := filepath.Clean(r.localPath) + ".known-hosts"
	if err := ensurePrivateDirLocked(dir); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "known_hosts")

	//nolint:gosec // path is built from localPath, inside the owner-only dir verified above
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		// Close is checked, not deferred away: if Write succeeds but the
		// flush on Close fails (ENOSPC, EIO), the file on disk can be
		// short. Caching the path in that case would hand ssh a truncated
		// known_hosts and call it successfully materialized — a partial
		// pin is not a pin.
		if err := writeAndClose(f, githubKnownHosts); err != nil {
			return "", fmt.Errorf("writing embedded known_hosts to %s: %w", path, err)
		}
		r.resolvedKnownHostsPath = path
		return path, nil
	}
	if !errors.Is(err, fs.ErrExist) {
		return "", fmt.Errorf("creating known_hosts at %s: %w", path, err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("checking known_hosts path %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("refusing to use known_hosts path %s: not a regular file", path)
	}
	existing, err := os.ReadFile(path) //nolint:gosec // owner-only parent dir, verified regular file above
	if err != nil {
		return "", fmt.Errorf("reading existing known_hosts at %s: %w", path, err)
	}
	if !bytes.Equal(existing, githubKnownHosts) {
		return "", fmt.Errorf("known_hosts at %s exists with unexpected content and will not be overwritten", path)
	}
	if err := verifyOwnedPrivateLocked(path, info); err != nil {
		return "", err
	}
	r.resolvedKnownHostsPath = path
	return path, nil
}

// ensurePrivateDirLocked creates dir as an owner-only (0700) directory if
// it does not already exist. If it does exist, it must be a real directory
// (not a symlink, which would indicate a pre-plant attack), owned by this
// process's effective UID, with no group/world permission bits — otherwise
// resolution fails closed rather than trusting or reusing it.
func ensurePrivateDirLocked(dir string) error {
	if err := os.Mkdir(dir, 0o700); err == nil {
		return nil
	} else if !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("creating known_hosts directory %s: %w", dir, err)
	}

	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("checking known_hosts directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("refusing to use known_hosts directory %s: not a directory", dir)
	}
	return verifyOwnedPrivateLocked(dir, info)
}

// verifyOwnedPrivateLocked checks that path (already Lstat'd into info by
// the caller) is owned by this process's effective UID and carries no
// group/world permission bits.
func verifyOwnedPrivateLocked(path string, info fs.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("checking owner of %s: unsupported platform stat", path)
	}
	// Compare as int64 rather than converting Geteuid() to uint32: the
	// conversion is a lint-flagged narrowing, and widening both sides is
	// exact for every value either can hold.
	if euid := os.Geteuid(); int64(stat.Uid) != int64(euid) {
		return fmt.Errorf("refusing to use %s: owned by uid %d, not the current effective uid %d", path, stat.Uid, euid)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("refusing to use %s: permissions %v are not owner-only", path, info.Mode().Perm())
	}
	return nil
}

// writeAndClose writes b to f and closes it, reporting either failure. The
// close error matters as much as the write error here: it is where a
// buffered write actually reaches the disk.
func writeAndClose(f *os.File, b []byte) error {
	_, writeErr := f.Write(b)
	closeErr := f.Close()
	return errors.Join(writeErr, closeErr)
}

func (r *Reader) runGit(extraEnv []string, args ...string) error {
	_, err := r.gitOutput(extraEnv, args...)
	return err
}

func (r *Reader) gitOutput(extraEnv []string, args ...string) ([]byte, error) {
	fullArgs := append([]string{"-C", r.localPath}, args...)
	cmd := exec.Command("git", fullArgs...) //nolint:gosec // args are from trusted config
	cmd.Env = append(os.Environ(), extraEnv...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%w\n%s", err, bytes.TrimSpace(out))
	}
	return out, nil
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
	// Host: prefer top-level (legacy), then ingress.hosts[0] which is what
	// the base-service chart actually consumes. Without this fallback the
	// field always rendered empty since deploy-service writes the host into
	// `ingress.hosts`, not the top level.
	if host, ok := raw["host"].(string); ok && host != "" {
		svc.Host = host
	} else if ingress, ok := raw["ingress"].(map[string]interface{}); ok {
		if hosts, ok := ingress["hosts"].([]interface{}); ok && len(hosts) > 0 {
			switch v := hosts[0].(type) {
			case string:
				svc.Host = v
			case map[string]interface{}:
				// Some charts use the long form: {host: foo, paths: [...]}
				if h, ok := v["host"].(string); ok {
					svc.Host = h
				}
			}
		}
	}
	// Port: prefer top-level (legacy), then service.port (nested) which is
	// what the base-service chart's Service template reads.
	if port, ok := raw["port"]; ok && port != nil {
		svc.Port = fmt.Sprintf("%v", port)
	} else if service, ok := raw["service"].(map[string]interface{}); ok {
		if port, ok := service["port"]; ok && port != nil {
			svc.Port = fmt.Sprintf("%v", port)
		}
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

// ListPlatformSkills reads all platform-wide skills from
// platform-gitops/platform-skills/catalog.
func (r *Reader) ListPlatformSkills() ([]PlatformSkill, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	dir := filepath.Join(r.localPath, "platform-gitops", "platform-skills", "catalog")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []PlatformSkill{}, nil
		}
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}

	out := make([]PlatformSkill, 0, len(entries))
	seen := make(map[string]string, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		skill, err := r.readPlatformSkillLocked(entry.Name())
		if err != nil {
			return nil, err
		}
		if previous, ok := seen[skill.Metadata.Name]; ok {
			return nil, fmt.Errorf("duplicate platform skill name %q in %s and %s", skill.Metadata.Name, previous, entry.Name())
		}
		seen[skill.Metadata.Name] = entry.Name()
		out = append(out, *skill)
	}
	return out, nil
}

// GetPlatformSkill reads one platform-wide skill by name. The catalog
// directory name is enforced to match the metadata name at publish time
// (see validatePlatformSkillMetadata), so name can be used directly as the
// directory to read.
func (r *Reader) GetPlatformSkill(name string) (*PlatformSkill, string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	skill, err := r.readPlatformSkillLocked(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, "", fmt.Errorf("platform skill not found: %s: %w", name, fs.ErrNotExist)
		}
		return nil, "", err
	}
	contentPath := filepath.Join(r.localPath, "platform-gitops", "platform-skills", "catalog", name, "SKILL.md")
	data, err := os.ReadFile(contentPath) //nolint:gosec // path is constrained to catalog root
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, "", fmt.Errorf("platform skill not found: %s: %w", name, fs.ErrNotExist)
		}
		return nil, "", fmt.Errorf("reading %s: %w", contentPath, err)
	}
	return skill, string(data), nil
}

func (r *Reader) readPlatformSkillLocked(dirName string) (*PlatformSkill, error) {
	base := filepath.Join(r.localPath, "platform-gitops", "platform-skills", "catalog", dirName)
	metadataPath := filepath.Join(base, "metadata.yaml")
	data, err := os.ReadFile(metadataPath) //nolint:gosec // path is constrained to catalog root
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", metadataPath, err)
	}
	var meta PlatformSkillMetadata
	if err := yaml.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", metadataPath, err)
	}
	if err := validatePlatformSkillMetadata(dirName, meta); err != nil {
		return nil, fmt.Errorf("invalid %s: %w", metadataPath, err)
	}

	skill := &PlatformSkill{Metadata: meta}
	if info, err := os.Stat(filepath.Join(base, "SKILL.md")); err == nil {
		skill.HasContent = true
		skill.Size = info.Size()
		skill.LastModified = info.ModTime().UTC()
	}
	return skill, nil
}

func validatePlatformSkillMetadata(dirName string, meta PlatformSkillMetadata) error {
	if meta.Name == "" {
		return fmt.Errorf("name is required")
	}
	if meta.Name != dirName {
		return fmt.Errorf("name %q must match catalog directory %q", meta.Name, dirName)
	}
	if !validPlatformSkillName(meta.Name) {
		return fmt.Errorf("name must be kebab-case")
	}
	if meta.Title == "" {
		return fmt.Errorf("title is required")
	}
	if meta.Description == "" {
		return fmt.Errorf("description is required")
	}
	if !oneOf(meta.Visibility, "public", "tenant", "admin", "platform-internal") {
		return fmt.Errorf("visibility must be one of public, tenant, admin, platform-internal")
	}
	if !oneOf(meta.Status, "draft", "active", "deprecated") {
		return fmt.Errorf("status must be one of draft, active, deprecated")
	}
	if meta.Owner == "" {
		return fmt.Errorf("owner is required")
	}
	return nil
}

func validPlatformSkillName(name string) bool {
	if len(name) < 2 || len(name) > 64 {
		return false
	}
	first := name[0]
	if (first < 'a' || first > 'z') && (first < '0' || first > '9') {
		return false
	}
	last := name[len(name)-1]
	if (last < 'a' || last > 'z') && (last < '0' || last > '9') {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		return false
	}
	return true
}

func oneOf(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}

// ListPlatformTenantBindings reads tenant skill bindings.
func (r *Reader) ListPlatformTenantBindings() ([]PlatformSkillBinding, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.listPlatformBindingsLocked("tenants")
}

// ListPlatformRoleBindings reads role skill bindings.
func (r *Reader) ListPlatformRoleBindings() ([]PlatformSkillBinding, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.listPlatformBindingsLocked("roles")
}

func (r *Reader) listPlatformBindingsLocked(kind string) ([]PlatformSkillBinding, error) {
	dir := filepath.Join(r.localPath, "platform-gitops", "platform-skills", "bindings", kind)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []PlatformSkillBinding{}, nil
		}
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}
	out := make([]PlatformSkillBinding, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path) //nolint:gosec // path is constrained to bindings root
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
		var binding PlatformSkillBinding
		if err := yaml.Unmarshal(data, &binding); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		if kind == "tenants" && binding.Tenant == "" {
			return nil, fmt.Errorf("invalid %s: tenant is required", path)
		}
		if kind == "roles" && binding.Role == "" {
			return nil, fmt.Errorf("invalid %s: role is required", path)
		}
		out = append(out, binding)
	}
	return out, nil
}

// GetPlatformPolicy reads platform-skills/policy.yaml. Missing policy is empty.
func (r *Reader) GetPlatformPolicy() (*PlatformSkillPolicy, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	path := filepath.Join(r.localPath, "platform-gitops", "platform-skills", "policy.yaml")
	data, err := os.ReadFile(path) //nolint:gosec // path is constrained to platform-skills root
	if err != nil {
		if os.IsNotExist(err) {
			return &PlatformSkillPolicy{}, nil
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var policy PlatformSkillPolicy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &policy, nil
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

// OpenClawIdentityFile describes a single identity override file backed up in
// the gitops repo (one of AGENTS.md / SOUL.md / IDENTITY.md / USER.md /
// TOOLS.md). Naming mirrors OpenClawSkill but the filename is kept verbatim
// (including .md) since identity files are a fixed allowlist, not kebab-case
// slugs.
type OpenClawIdentityFile struct {
	Name         string    `json:"name"`
	Size         int64     `json:"size"`
	LastModified time.Time `json:"lastModified"`
}

// openClawIdentityFilenames is the fixed allowlist of identity override files
// a tenant can own. Kept in sync with openClawIdentityFileAllowlist in the api
// package (defense-in-depth also lives in the workflow templates). Mirrored
// here so the reader returns identity files consistently regardless of any
// stray markdown files a manual gitops edit might have dropped into the
// identity/ directory — otherwise the quota sum would drift against what
// save/delete paths actually manipulate.
var openClawIdentityFilenames = map[string]struct{}{
	"AGENTS.md":   {},
	"SOUL.md":     {},
	"IDENTITY.md": {},
	"USER.md":     {},
	"TOOLS.md":    {},
}

// ListOpenClawIdentity lists allowlisted identity override files under
// platform-gitops/services/{team}/openclaw/identity/.
// Returns an empty slice (not an error) if the directory does not exist —
// tenants without any overrides fall back to image defaults.
func (r *Reader) ListOpenClawIdentity(team string) ([]OpenClawIdentityFile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	dir := filepath.Join(r.localPath, "platform-gitops", "services", team, "openclaw", "identity")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []OpenClawIdentityFile{}, nil
		}
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}

	out := make([]OpenClawIdentityFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if _, ok := openClawIdentityFilenames[name]; !ok {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		out = append(out, OpenClawIdentityFile{
			Name:         name,
			Size:         info.Size(),
			LastModified: info.ModTime().UTC(),
		})
	}
	return out, nil
}

// ReadOpenClawIdentity returns the raw text content of
// platform-gitops/services/{team}/openclaw/identity/{fileName}.
// fileName must be validated by the caller against the identity allowlist
// before being passed in — this function does no validation of its own.
// Returns os.ErrNotExist wrapped if the file is missing.
func (r *Reader) ReadOpenClawIdentity(team, fileName string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	path := filepath.Join(r.localPath, "platform-gitops", "services", team, "openclaw", "identity", fileName)
	data, err := os.ReadFile(path) //nolint:gosec // path built from validated components
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	return string(data), nil
}
