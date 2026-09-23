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
	"crypto/subtle"
	"encoding/base64"
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
	userContextKey contextKey = "user"
	rawTokenKey    contextKey = "rawToken"
)

// User represents an authenticated user.
type User struct {
	ID     string   `json:"id"`
	Groups []string `json:"groups"` // tenant names this user belongs to

	// service records that this principal was authenticated by the service
	// token, and is deliberately UNEXPORTED: it is proof of how the caller
	// authenticated, not a claim anyone can make. Deriving that from
	// ID == ServiceUserID instead would hand the service principal's
	// privileges to a human whose GitHub login or Dex username happened to be
	// "mctl-agent" (claude P2 on gitops#986). Only NewServiceUser sets it, and
	// User is never unmarshalled from JSON, so it cannot be forged.
	service bool

	// githubLogin records that ID is a GitHub login proven by GitHub: the
	// GitHub token path, or a local OAuth JWT (minted only after the GitHub
	// OAuth callback validated the login). A Dex JWT's ID is
	// preferred_username, email or sub, which can equal some GitHub login
	// without being that person, so it is never set there. Unexported for
	// the same reason as service: it is how the caller authenticated, not a
	// claim.
	githubLogin bool

	// surface is set only on a per-surface service principal
	// ("surface:telegram"), authenticated by that surface's own token
	// (mctl-api#350). Unexported for the same reason as service.
	surface string

	// actingPrincipal and relaySurface are set only on a relayed subject:
	// the human a surface principal spoke for through a verified
	// SurfaceIdentityLink. The request is attributed to the human (ID), and
	// the surface that carried it is kept, never collapsed into it.
	actingPrincipal string
	relaySurface    string
}

// NewGitHubUser builds a principal whose ID is a GitHub-verified login.
func NewGitHubUser(login string, groups []string) *User {
	return &User{ID: login, Groups: groups, githubLogin: true}
}

// GitHubLogin returns the caller's GitHub login when authentication proved
// one, and false otherwise (Dex, the service principal, dev mode).
func (u *User) GitHubLogin() (string, bool) {
	if u == nil || !u.githubLogin {
		return "", false
	}
	return u.ID, true
}

// NewServiceUser builds the platform-internal service principal. Exported so
// tests can construct the same principal the middleware does, rather than
// approximating it with a matching ID.
func NewServiceUser() *User {
	return &User{ID: ServiceUserID, Groups: []string{"admins"}, service: true}
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

// jwtIssuer decodes the JWT payload (without signature verification) and returns the "iss" claim.
// Returns empty string if the token is malformed.
func jwtIssuer(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Issuer
}

// ServiceUserID is the identity of the platform-internal service principal
// minted by MCTL_AGENT_SERVICE_TOKEN. Named rather than repeated as a literal
// because handlers distinguish it from a human caller: it is the one
// principal allowed to relay an approver it did not itself authenticate
// (gitops#986).
const ServiceUserID = "mctl-agent"

// IsService reports whether this principal authenticated with the service
// token, rather than being a person who merely shares its name.
func (u *User) IsService() bool { return u.service }

// Surface principals (mctl-api#350). Each surface has its own token and its
// own principal, "surface:<name>". They are not admins, belong to no tenant,
// and are distinct from ServiceUserID: mctl-agent never gains the right to
// relay, and a surface can only ever speak for its own surface.
const SurfacePrincipalPrefix = "surface:"

// surfaceTokenEnv names each surface's token variable.
var surfaceTokenEnv = map[string]string{
	"telegram": "MCTL_SURFACE_TELEGRAM_TOKEN",
	"portal":   "MCTL_SURFACE_PORTAL_TOKEN",
}

// minSurfaceTokenLen refuses a token too short to be a secret.
const minSurfaceTokenLen = 32

// NewSurfaceUser builds the principal for one surface. Exported for tests,
// like NewServiceUser; only the middleware mints it from a token.
func NewSurfaceUser(surface string) *User {
	return &User{ID: SurfacePrincipalPrefix + surface, surface: surface}
}

// Surface reports the surface this principal authenticated as, if it is a
// surface principal.
func (u *User) Surface() (string, bool) {
	if u == nil || u.surface == "" {
		return "", false
	}
	return u.surface, true
}

// NewRelayedUser builds the subject a surface principal relays for, from a
// verified link. The subject is the linked GitHub login with its tenant
// groups; relaying never confers admin, so "admins" is dropped. Returns nil
// unless acting is a surface principal.
func NewRelayedUser(login string, groups []string, acting *User) *User {
	surface, ok := acting.Surface()
	if !ok || login == "" {
		return nil
	}
	kept := make([]string, 0, len(groups))
	for _, g := range groups {
		if g != "admins" {
			kept = append(kept, g)
		}
	}
	return &User{ID: login, Groups: kept, githubLogin: true, actingPrincipal: acting.ID, relaySurface: surface}
}

// ActingPrincipal is the surface principal that carried a relayed request,
// or "" when the caller acted directly.
func (u *User) ActingPrincipal() string {
	if u == nil {
		return ""
	}
	return u.actingPrincipal
}

// RelaySurface is the surface a relayed request came through.
func (u *User) RelaySurface() (string, bool) {
	if u == nil || u.relaySurface == "" {
		return "", false
	}
	return u.relaySurface, true
}

// surfaceTokens reads the configured surface tokens. A token that is short,
// shared by two surfaces, or equal to the mctl-agent service token is
// refused: each must prove exactly one surface and nothing more.
func surfaceTokens() map[string]string {
	service := strings.TrimSpace(os.Getenv("MCTL_AGENT_SERVICE_TOKEN"))
	byToken := map[string]string{}
	refused := map[string]bool{}
	for surface, env := range surfaceTokenEnv {
		token := strings.TrimSpace(os.Getenv(env))
		switch {
		case token == "":
			continue
		case len(token) < minSurfaceTokenLen:
			slog.Error("surface token too short; surface principal disabled", "env", env, "min_length", minSurfaceTokenLen)
			continue
		case service != "" && token == service:
			slog.Error("surface token equals MCTL_AGENT_SERVICE_TOKEN; surface principal disabled", "env", env)
			continue
		}
		if _, dup := byToken[token]; dup || refused[token] {
			slog.Error("two surfaces share one token; both disabled", "env", env)
			delete(byToken, token)
			refused[token] = true
			continue
		}
		byToken[token] = surface
	}
	return byToken
}

// surfaceUserFor matches a bearer token against the surface tokens in
// constant time per candidate.
func surfaceUserFor(tokens map[string]string, token string) *User {
	var match string
	for candidate, surface := range tokens {
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(token)) == 1 {
			match = surface
		}
	}
	if match == "" {
		return nil
	}
	return NewSurfaceUser(match)
}

// staticServiceUser returns a platform-internal service principal when the
// bearer token matches a configured service token. This bypasses GitHub/Dex
// validation for trusted in-cluster automation such as mctl-agent.
func staticServiceUser(token string) *User {
	serviceToken := strings.TrimSpace(os.Getenv("MCTL_AGENT_SERVICE_TOKEN"))
	if serviceToken != "" && token == serviceToken {
		return NewServiceUser()
	}
	return nil
}

// Middleware returns HTTP middleware that validates GitHub tokens or Dex JWTs.
//
// Auth flow:
//  1. No token + AUTH_REQUIRED=false → dev-user admin (local development)
//  2. Bearer <jwt> with iss=localIssuer → validate via OAuthServer (local HMAC-SHA256)
//  3. Bearer <jwt> with other issuer → validate via Dex JWKS → extract username + groups
//  4. Bearer <github_token> → validate via GitHub API → resolve groups from gitops
//
// dex and oauth may be nil; in that case those token types are rejected.
func Middleware(validator *GitHubValidator, resolver TenantResolver, dex *DexVerifier, oauth *OAuthServer) func(http.Handler) http.Handler {
	authRequired := os.Getenv("AUTH_REQUIRED") != "false"
	surfaces := surfaceTokens()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for health checks.
			if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
				next.ServeHTTP(w, r)
				return
			}

			// writeErr writes a 401 with WWW-Authenticate header when OAuth is configured.
			writeErr := func(msg string) {
				if oauth != nil {
					writeUnauthorizedOAuth(w, msg, oauth.BaseURL, r.URL.Path)
				} else {
					writeUnauthorized(w, msg)
				}
			}

			authHeader := r.Header.Get("Authorization")

			// No token: allow in dev mode, reject in production.
			if authHeader == "" {
				if authRequired {
					writeErr("authentication required — set Authorization: Bearer <token>")
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
				writeErr("invalid Authorization header — expected: Bearer <token>")
				return
			}

			var (
				user *User
				err  error
			)

			if svc := staticServiceUser(token); svc != nil {
				user = svc
			} else if su := surfaceUserFor(surfaces, token); su != nil {
				user = su
			} else if isJWT(token) {
				// Peek at the JWT issuer to route to the correct verifier.
				if oauth != nil && jwtIssuer(token) == oauth.BaseURL {
					// Local OAuth JWT: validate with HMAC-SHA256.
					user, err = oauth.ValidateJWT(token)
					if err != nil {
						slog.Warn("local oauth JWT auth failed", "error", err, "path", r.URL.Path)
						writeErr(err.Error())
						return
					}
				} else {
					// Dex JWT path: validate and extract user + groups from claims.
					if dex == nil {
						writeErr("JWT auth not configured on this server")
						return
					}
					user, err = dex.Verify(r.Context(), token)
					if err != nil {
						slog.Warn("dex JWT auth failed", "error", err, "path", r.URL.Path)
						writeErr(err.Error())
						return
					}
				}
			} else {
				// GitHub token path: validate via GitHub API, resolve groups from gitops.
				login, ghErr := validator.Validate(r.Context(), token)
				if ghErr != nil {
					slog.Warn("github auth failed", "error", ghErr, "path", r.URL.Path)
					writeErr(ghErr.Error())
					return
				}
				groups := resolveGroups(login, validator, resolver)
				user = NewGitHubUser(login, groups)
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
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// writeUnauthorizedOAuth writes a 401 with a WWW-Authenticate header
// pointing at this resource's RFC 9728 Protected Resource Metadata document
// — the /mcp-suffixed form for the MCP endpoint itself, the root form for
// every other protected API route, matching how both are registered in
// router.go.
func writeUnauthorizedOAuth(w http.ResponseWriter, msg, baseURL, path string) {
	metadataURL := baseURL + "/.well-known/oauth-protected-resource"
	if path == "/mcp" {
		metadataURL = baseURL + "/.well-known/oauth-protected-resource/mcp"
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="`+baseURL+`", resource_metadata="`+metadataURL+`"`)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
