package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// githubUserInfo holds cached GitHub user information.
type githubUserInfo struct {
	Login  string
	Name   string
	OrgMember bool
	CachedAt time.Time
}

// GitHubValidator validates GitHub tokens and resolves user identity.
type GitHubValidator struct {
	mu      sync.RWMutex
	cache   map[string]*githubUserInfo // token → user info (short-lived cache)
	ttl     time.Duration
	org     string // required GitHub org (e.g. "mctlhq"), empty = skip org check
	client  *http.Client
	adminUsers []string // GitHub logins that are always admins
}

// NewGitHubValidator creates a new GitHub token validator.
func NewGitHubValidator(org string, adminUsers []string) *GitHubValidator {
	return &GitHubValidator{
		cache:      make(map[string]*githubUserInfo),
		ttl:        5 * time.Minute,
		org:        org,
		client:     &http.Client{Timeout: 10 * time.Second},
		adminUsers: adminUsers,
	}
}

// Validate checks a GitHub token and returns the GitHub login.
// Results are cached for 5 minutes to avoid hammering the GitHub API.
func (v *GitHubValidator) Validate(ctx context.Context, token string) (string, error) {
	// Check cache.
	v.mu.RLock()
	if cached, ok := v.cache[token]; ok && time.Since(cached.CachedAt) < v.ttl {
		v.mu.RUnlock()
		if !cached.OrgMember && v.org != "" {
			return "", fmt.Errorf("user %q is not a member of the %s GitHub organization", cached.Login, v.org)
		}
		return cached.Login, nil
	}
	v.mu.RUnlock()

	// Call GitHub API.
	login, err := v.fetchLogin(ctx, token)
	if err != nil {
		return "", fmt.Errorf("invalid GitHub token: %w", err)
	}

	orgMember := true
	if v.org != "" {
		orgMember, err = v.checkOrgMembership(ctx, token, login)
		if err != nil {
			slog.Warn("org membership check failed — denying access (fail closed)", "user", login, "org", v.org, "error", err)
			return "", fmt.Errorf("org membership check failed: %w", err)
		}
	}

	// Cache the result.
	v.mu.Lock()
	v.cache[token] = &githubUserInfo{
		Login:     login,
		OrgMember: orgMember,
		CachedAt:  time.Now(),
	}
	v.mu.Unlock()

	if !orgMember {
		return "", fmt.Errorf("user %q is not a member of the %s GitHub organization", login, v.org)
	}

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

func (v *GitHubValidator) checkOrgMembership(ctx context.Context, token, login string) (bool, error) {
	// Primary check: list the authenticated user's own org memberships via /user/orgs.
	// This works regardless of whether the OAuth App is approved in the org, because
	// the user is querying their own data (not org resources).
	member, err := v.checkOrgMembershipViaUserOrgs(ctx, token)
	if err == nil {
		return member, nil
	}

	// Fallback: org-level membership check. Requires OAuth App to be approved in org.
	// If denied (403), the app is not approved — treat as non-member (fail closed).
	url := fmt.Sprintf("https://api.github.com/orgs/%s/members/%s", v.org, login)
	req, err2 := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err2 != nil {
		return false, err2
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err2 := v.client.Do(req)
	if err2 != nil {
		return false, err2
	}
	defer resp.Body.Close()

	// 204 = member, 302/404 = not a member, 403 = OAuth App not approved in org (deny)
	return resp.StatusCode == http.StatusNoContent, nil
}

// checkOrgMembershipViaUserOrgs uses GET /user/orgs to list the authenticated user's
// org memberships. This endpoint works even when the OAuth App is not approved in the
// target org, because the user is reading their own membership data.
func (v *GitHubValidator) checkOrgMembershipViaUserOrgs(ctx context.Context, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user/orgs?per_page=100", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := v.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("GET /user/orgs returned %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var orgs []struct {
		Login string `json:"login"`
	}
	if err := json.Unmarshal(body, &orgs); err != nil {
		return false, fmt.Errorf("failed to parse /user/orgs response: %w", err)
	}

	for _, org := range orgs {
		if strings.EqualFold(org.Login, v.org) {
			return true, nil
		}
	}
	return false, nil
}
