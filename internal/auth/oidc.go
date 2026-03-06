package auth

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"strings"
)

// contextKey is an unexported type for context keys in this package.
type contextKey string

const userContextKey contextKey = "user"

// User represents an authenticated user.
type User struct {
	ID     string   `json:"id"`
	Groups []string `json:"groups"` // tenant names this user belongs to
}

// IsAdmin checks if the user is a platform admin.
func (u *User) IsAdmin() bool {
	for _, g := range u.Groups {
		if g == "admins" {
			return true
		}
	}
	return false
}

// HasTenantAccess checks if the user can operate on a specific tenant.
func (u *User) HasTenantAccess(tenant string) bool {
	if u.IsAdmin() {
		return true
	}
	for _, g := range u.Groups {
		if g == tenant {
			return true
		}
	}
	return false
}

// UserFromContext returns the authenticated user from request context.
func UserFromContext(ctx context.Context) *User {
	u, _ := ctx.Value(userContextKey).(*User)
	return u
}

// TenantResolver resolves which tenants a GitHub user belongs to.
// Implemented by gitops.Reader.
type TenantResolver interface {
	GetTenantsForUser(login string) ([]string, error)
}

// Middleware returns HTTP middleware that validates GitHub tokens.
//
// Auth flow:
//  1. No token + AUTH_REQUIRED=false → dev-user admin (local development)
//  2. Bearer <github_token> → validate via GitHub API → resolve tenant groups
//
// The GitHub token is obtained via: gh auth token
func Middleware(validator *GitHubValidator, resolver TenantResolver) func(http.Handler) http.Handler {
	authRequired := os.Getenv("AUTH_REQUIRED") != "false"

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for health checks.
			if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
				next.ServeHTTP(w, r)
				return
			}

			authHeader := r.Header.Get("Authorization")

			// No token: allow in dev mode, reject in production.
			if authHeader == "" {
				if authRequired {
					writeUnauthorized(w, "authentication required — set Authorization: Bearer <gh auth token>")
					return
				}
				// Development: admin bypass.
				ctx := context.WithValue(r.Context(), userContextKey, &User{
					ID:     "dev-user",
					Groups: []string{"admins"},
				})
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")
			if token == authHeader {
				writeUnauthorized(w, "invalid Authorization header — expected: Bearer <token>")
				return
			}

			// Validate the GitHub token.
			login, err := validator.Validate(r.Context(), token)
			if err != nil {
				slog.Warn("auth failed", "error", err, "path", r.URL.Path)
				writeUnauthorized(w, err.Error())
				return
			}

			// Resolve tenant memberships from gitops.
			groups := resolveGroups(login, validator, resolver)

			ctx := context.WithValue(r.Context(), userContextKey, &User{
				ID:     login,
				Groups: groups,
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// resolveGroups builds the list of groups (tenant names) for a GitHub user.
// Admin users are always in the "admins" group.
func resolveGroups(login string, validator *GitHubValidator, resolver TenantResolver) []string {
	var groups []string

	if validator.IsAdmin(login) {
		groups = append(groups, "admins")
	}

	if resolver != nil {
		tenants, err := resolver.GetTenantsForUser(login)
		if err != nil {
			slog.Warn("failed to resolve tenant memberships", "user", login, "error", err)
		} else {
			groups = append(groups, tenants...)
		}
	}

	return groups
}

func writeUnauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(`{"error":"` + msg + `"}`))
}
