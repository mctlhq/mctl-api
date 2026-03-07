package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

// contextKey is an unexported type for context keys in this package.
type contextKey string

const (
	userContextKey  contextKey = "user"
	rawTokenKey     contextKey = "rawToken"
)

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

// WithUser returns a context with the given user injected. Useful in tests.
func WithUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, userContextKey, u)
}

// TokenFromContext returns the raw bearer token stored by the auth middleware.
// Tool handlers use this to forward auth to downstream API calls.
func TokenFromContext(ctx context.Context) string {
	t, _ := ctx.Value(rawTokenKey).(string)
	return t
}

// TenantResolver resolves which tenants a GitHub user belongs to.
// Implemented by gitops.Reader.
type TenantResolver interface {
	GetTenantsForUser(login string) ([]string, error)
}

// DexVerifier validates Dex-issued JWTs.
type DexVerifier struct {
	verifier *oidc.IDTokenVerifier
}

// NewDexVerifier creates a DexVerifier by fetching OIDC configuration from the issuer.
// If clientID is non-empty, JWTs are validated against the expected audience (recommended).
// If clientID is empty, audience check is skipped (for local development only).
func NewDexVerifier(ctx context.Context, issuerURL, clientID string) (*DexVerifier, error) {
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc provider init failed for %s: %w", issuerURL, err)
	}
	cfg := &oidc.Config{}
	if clientID != "" {
		cfg.ClientID = clientID
	} else {
		cfg.SkipClientIDCheck = true
	}
	verifier := provider.Verifier(cfg)
	return &DexVerifier{verifier: verifier}, nil
}

// Verify validates a Dex JWT and returns the authenticated user.
// Groups come directly from the token (Backstage populates them); no gitops lookup needed.
func (d *DexVerifier) Verify(ctx context.Context, token string) (*User, error) {
	idToken, err := d.verifier.Verify(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("invalid Dex JWT: %w", err)
	}

	var claims struct {
		Sub               string   `json:"sub"`
		PreferredUsername string   `json:"preferred_username"`
		Email             string   `json:"email"`
		Groups            []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	username := claims.PreferredUsername
	if username == "" {
		username = claims.Email
	}
	if username == "" {
		username = claims.Sub
	}

	return &User{ID: username, Groups: claims.Groups}, nil
}

// isJWT returns true if the token looks like a JWT (three dot-separated parts).
func isJWT(token string) bool {
	return strings.Count(token, ".") == 2
}

// Middleware returns HTTP middleware that validates GitHub tokens or Dex JWTs.
//
// Auth flow:
//  1. No token + AUTH_REQUIRED=false → dev-user admin (local development)
//  2. Bearer <jwt> (3 dot-separated parts) → validate via Dex JWKS → extract username + groups
//  3. Bearer <github_token> → validate via GitHub API → resolve groups from gitops
//
// dex may be nil; in that case JWT tokens are rejected with an error.
func Middleware(validator *GitHubValidator, resolver TenantResolver, dex *DexVerifier) func(http.Handler) http.Handler {
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
					writeUnauthorized(w, "authentication required — set Authorization: Bearer <token>")
					return
				}
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

			var (
				user *User
				err  error
			)

			if isJWT(token) {
				// Dex JWT path: validate and extract user + groups from claims.
				if dex == nil {
					writeUnauthorized(w, "JWT auth not configured on this server")
					return
				}
				user, err = dex.Verify(r.Context(), token)
				if err != nil {
					slog.Warn("dex JWT auth failed", "error", err, "path", r.URL.Path)
					writeUnauthorized(w, err.Error())
					return
				}
			} else {
				// GitHub token path: validate via GitHub API, resolve groups from gitops.
				login, ghErr := validator.Validate(r.Context(), token)
				if ghErr != nil {
					slog.Warn("github auth failed", "error", ghErr, "path", r.URL.Path)
					writeUnauthorized(w, ghErr.Error())
					return
				}
				groups := resolveGroups(login, validator, resolver)
				user = &User{ID: login, Groups: groups}
			}

			// Store user and raw token in context for downstream handlers.
			ctx := context.WithValue(r.Context(), userContextKey, user)
			ctx = context.WithValue(ctx, rawTokenKey, token)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// resolveGroups builds the list of groups (tenant names) for a GitHub user.
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
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
