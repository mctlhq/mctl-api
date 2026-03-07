package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// githubUserInfo holds cached GitHub user information.
type githubUserInfo struct {
	Login    string
	CachedAt time.Time
}

// GitHubValidator validates GitHub tokens and resolves user identity.
// Authorization (tenant access) is handled separately via gitops membership.
type GitHubValidator struct {
	mu         sync.RWMutex
	cache      map[string]*githubUserInfo // token → login (short-lived cache)
	ttl        time.Duration
	client     *http.Client
	adminUsers []string // GitHub logins that are always admins
}

// NewGitHubValidator creates a new GitHub token validator.
func NewGitHubValidator(adminUsers []string) *GitHubValidator {
	return &GitHubValidator{
		cache:      make(map[string]*githubUserInfo),
		ttl:        5 * time.Minute,
		client:     &http.Client{Timeout: 10 * time.Second},
		adminUsers: adminUsers,
	}
}

// Validate checks a GitHub token and returns the GitHub login.
// Results are cached for 5 minutes to avoid hammering the GitHub API.
// Authorization (which tenants the user can access) is resolved separately via gitops.
func (v *GitHubValidator) Validate(ctx context.Context, token string) (string, error) {
	// Check cache.
	v.mu.RLock()
	if cached, ok := v.cache[token]; ok && time.Since(cached.CachedAt) < v.ttl {
		v.mu.RUnlock()
		return cached.Login, nil
	}
	v.mu.RUnlock()

	login, err := v.fetchLogin(ctx, token)
	if err != nil {
		return "", fmt.Errorf("invalid GitHub token: %w", err)
	}

	v.mu.Lock()
	v.cache[token] = &githubUserInfo{Login: login, CachedAt: time.Now()}
	v.mu.Unlock()

	return login, nil
}

// IsAdmin returns true if the GitHub login is a configured admin.
func (v *GitHubValidator) IsAdmin(login string) bool {
	for _, u := range v.adminUsers {
		if strings.EqualFold(u, login) {
			return true
		}
	}
	return false
}

func (v *GitHubValidator) fetchLogin(ctx context.Context, token string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := v.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("GitHub API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", fmt.Errorf("token rejected by GitHub (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var user struct {
		Login string `json:"login"`
	}
	if err := json.Unmarshal(body, &user); err != nil || user.Login == "" {
		return "", fmt.Errorf("unexpected GitHub API response")
	}

	return user.Login, nil
}

