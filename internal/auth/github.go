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
	ID       int64
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
		client:     &http.Client{Timeout: 30 * time.Second},
		adminUsers: adminUsers,
	}
}

// Validate checks a GitHub token and returns the GitHub login.
// Results are cached for 5 minutes to avoid hammering the GitHub API.
// Authorization (which tenants the user can access) is resolved separately via gitops.
func (v *GitHubValidator) Validate(ctx context.Context, token string) (string, error) {
	login, _, err := v.ValidateIdentity(ctx, token)
	return login, err
}

// ValidateIdentity is Validate plus the numeric GitHub user id: the stable
// half of a GitHub identity (a login can be renamed, then taken by someone
// else), which the principal model keys on (mctl-api#373).
func (v *GitHubValidator) ValidateIdentity(ctx context.Context, token string) (string, int64, error) {
	// Check cache.
	v.mu.RLock()
	if cached, ok := v.cache[token]; ok && time.Since(cached.CachedAt) < v.ttl {
		v.mu.RUnlock()
		return cached.Login, cached.ID, nil
	}
	v.mu.RUnlock()

	login, id, err := v.fetchUser(ctx, token)
	if err != nil {
		return "", 0, fmt.Errorf("invalid GitHub token: %w", err)
	}

	v.mu.Lock()
	v.cache[token] = &githubUserInfo{Login: login, ID: id, CachedAt: time.Now()}
	v.mu.Unlock()

	return login, id, nil
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

func (v *GitHubValidator) fetchUser(ctx context.Context, token string) (string, int64, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := v.client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("GitHub API request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", 0, fmt.Errorf("token rejected by GitHub (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var user struct {
		Login string `json:"login"`
		ID    int64  `json:"id"`
	}
	if err := json.Unmarshal(body, &user); err != nil || user.Login == "" {
		return "", 0, fmt.Errorf("unexpected GitHub API response")
	}

	return user.Login, user.ID, nil
}
