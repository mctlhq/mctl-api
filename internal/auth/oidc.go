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
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
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

	// usageWriter is set only on the usage-writer principal, authenticated
	// by MCTL_USAGE_WRITER_TOKEN (mctlhq/.github#50). Unexported for the same
	// reason as service.
	usageWriter bool

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

	// How the caller authenticated, for the principal model (mctl-api#373).
	// Unexported for the same reason as service: set only by the code that
	// verified them. githubID is the numeric GitHub user id when the GitHub
	// token path saw it; dexIssuer/dexSubject are a verified Dex token's
	// iss and sub; dev marks the AUTH_REQUIRED=false caller.
	githubID   int64
	dexIssuer  string
	dexSubject string
	dev        bool

	// oidcProviderName, oidcIssuer, oidcSubject, oidcKind record a verified
	// identity from a generic MCTL_OIDC_PROVIDERS entry (mctl-api#374 slice A)
	// that is none of service/surface/usage-writer/dev/dex/github. Unexported
	// for the same reason as the other discriminators: set only by
	// userFromVerified.
	oidcProviderName string
	oidcIssuer       string
	oidcSubject      string
	oidcKind         string

	// principalID is the canonical principal (prn_...) resolved from that
	// identity, and viaPrincipalID the relaying surface's principal. Set
	// only by AttachPrincipal and NewRelayedUser.
	principalID    string
	viaPrincipalID string

	// agent records that this principal authenticated with an agent run
	// token (mctl-api#376): its value is the bare agent name (never
	// "agent:"-prefixed). Deliberately UNEXPORTED, for the same reason as
	// service: it is proof of how the caller authenticated, not a claim
	// anyone can make. Deriving it from ID's spelling instead would let a
	// GitHub login or Dex username spelled "agent:implementer" pass as the
	// agent principal. Only NewAgentUser sets it, and User is never
	// unmarshalled from JSON, so it cannot be forged.
	agent string
	// execID, workItemID and runID are the execution, work item and run
	// token id an agent run token is bound to. Empty unless agent != "".
	execID     string
	workItemID string
	runID      string
	// agentPermissions are the permissions the run token was minted with,
	// checked by HasPermission. Empty for every non-agent principal.
	agentPermissions []string
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
	// issuerURL is remembered (not just handed to the underlying library)
	// so the federation registry's default construction (oidc.go
	// defaultFederationRegistry) can route to this verifier by exact issuer
	// match like every other JWT provider, without re-deriving it.
	issuerURL string
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
	return &DexVerifier{verifier: verifier, issuerURL: issuerURL}, nil
}

// Issuer returns the issuer URL this verifier was constructed with.
func (d *DexVerifier) Issuer() string { return d.issuerURL }

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

	return &User{ID: username, Groups: claims.Groups, dexIssuer: idToken.Issuer, dexSubject: claims.Sub}, nil
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

// AgentPrincipalPrefix labels an agent principal's id, "agent:<name>"
// (mctl-api#376), a sibling of SurfacePrincipalPrefix: distinct per agent
// name, not an admin, belonging to no tenant.
const AgentPrincipalPrefix = "agent:"

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
	return &User{
		ID: login, Groups: kept, githubLogin: true, actingPrincipal: acting.ID, relaySurface: surface,
		viaPrincipalID: acting.principalID,
	}
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

// Usage-writer principal (mctlhq/.github#50, variant B). The model-usage
// producers (investigator, implementer, shepherd) append ledger records with
// their own credential instead of the admin mctl-agent token: a leaked or
// misused producer credential can then only add usage rows, and every row it
// writes is attributed to this principal, not to "some admin".
//
// It holds exactly one permission, PermissionUsageWrite, is not an admin,
// belongs to no tenant, and is confined to POST /api/v1/usage/records by
// the API's usage-writer gate. Human admins keep their existing write
// access to the ledger.
const (
	UsageWriterUserID    = "service:mctl-agents-usage"
	PermissionUsageWrite = "usage:write"
	usageWriterTokenEnv  = "MCTL_USAGE_WRITER_TOKEN" //nolint:gosec // env var name, not a credential
)

// NewUsageWriterUser builds the usage-writer principal. Exported for tests,
// like NewServiceUser; only the middleware mints it from a token.
func NewUsageWriterUser() *User {
	return &User{ID: UsageWriterUserID, usageWriter: true}
}

// IsUsageWriter reports whether this principal authenticated with the
// usage-writer token.
func (u *User) IsUsageWriter() bool { return u != nil && u.usageWriter }

// HasPermission reports whether the caller holds a named permission. An
// agent principal holds exactly the permissions its run token was minted
// with (mctl-api#376) and nothing else -- not PermissionUsageWrite by being
// an admin, because an agent principal is never an admin. Otherwise, only
// PermissionUsageWrite is modelled so far: the usage writer holds it, and an
// admin holds it because the ledger has always been admin-writable.
func (u *User) HasPermission(permission string) bool {
	if u == nil {
		return false
	}
	if u.agent != "" {
		for _, p := range u.agentPermissions {
			if p == permission {
				return true
			}
		}
		return false
	}
	if permission == PermissionUsageWrite {
		return u.usageWriter || u.IsAdmin()
	}
	return false
}

// usageWriterToken reads the usage-writer token. One that is short, or equal
// to the mctl-agent service token or to any surface token, is refused: it
// must prove exactly this principal and nothing more.
//
// The surface tokens are re-read from the environment, not taken from the
// map surfaceTokens returns. That map drops a surface token it refused, and a
// refused token must still not be reusable here.
func usageWriterToken() string {
	token := strings.TrimSpace(os.Getenv(usageWriterTokenEnv))
	service := strings.TrimSpace(os.Getenv("MCTL_AGENT_SERVICE_TOKEN"))
	switch {
	case token == "":
		return ""
	case len(token) < minSurfaceTokenLen:
		slog.Error("usage-writer token too short; usage-writer principal disabled", "env", usageWriterTokenEnv, "min_length", minSurfaceTokenLen)
		return ""
	case service != "" && token == service:
		slog.Error("usage-writer token equals MCTL_AGENT_SERVICE_TOKEN; usage-writer principal disabled", "env", usageWriterTokenEnv)
		return ""
	}
	for _, env := range surfaceTokenEnv {
		if strings.TrimSpace(os.Getenv(env)) == token {
			slog.Error("usage-writer token equals a surface token; usage-writer principal disabled", "env", usageWriterTokenEnv)
			return ""
		}
	}
	return token
}

// usageWriterUserFor matches a bearer token against the usage-writer token
// in constant time.
func usageWriterUserFor(configured, token string) *User {
	if configured == "" || subtle.ConstantTimeCompare([]byte(configured), []byte(token)) != 1 {
		return nil
	}
	return NewUsageWriterUser()
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
	if serviceToken != "" && subtle.ConstantTimeCompare([]byte(serviceToken), []byte(token)) == 1 {
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
//
// Since mctl-api#374 (slice A), steps 2-4 above are dispatched through a
// federation Registry (federation.go) instead of an inline if/else-if chain,
// unless MCTL_FEDERATION_DISABLED is set, in which case the pre-registry
// chain runs exactly as it always has (kept in the tree until slice D).
// WithFederationRegistry supplies a fully-configured Registry (built by
// cmd/api/main.go from MCTL_OIDC_PROVIDERS and the legacy Dex shim); without
// it, Middleware builds a default registry from its own validator, resolver,
// dex and oauth parameters, which is what every existing caller -- including
// every test in this package -- exercises unchanged.
//
// With WithPrincipalResolver, every authenticated caller is also resolved to
// its canonical principal (mctl-api#373, phase 1): a disabled principal is
// refused with 403, and a principal that cannot be resolved leaves the
// request without one (logged and counted by the resolver) rather than
// failing it.
func Middleware(validator *GitHubValidator, resolver TenantResolver, dex *DexVerifier, oauth *OAuthServer, opts ...MiddlewareOption) func(http.Handler) http.Handler {
	authRequired := os.Getenv("AUTH_REQUIRED") != "false"
	surfaces := surfaceTokens()
	usageWriter := usageWriterToken()
	var cfg middlewareConfig
	for _, o := range opts {
		o(&cfg)
	}

	federationDisabled := federationKillSwitchOn(os.Getenv("MCTL_FEDERATION_DISABLED"))
	registry := cfg.federationRegistry
	if !federationDisabled && registry == nil {
		registry = defaultFederationRegistry(validator, resolver, dex, oauth, surfaces, usageWriter)
	}

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
				dev := &User{ID: "dev-user", Groups: []string{"admins"}, dev: true}
				if !attachPrincipal(w, r, cfg.principals, dev, writeErr) {
					return
				}
				ctx := context.WithValue(r.Context(), userContextKey, dev)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")
			if token == authHeader {
				writeErr("invalid Authorization header — expected: Bearer <token>")
				return
			}

			var user *User

			// Agent run tokens (mctl-api#376) are checked ahead of both the
			// legacy chain and the federation registry, and regardless of
			// MCTL_FEDERATION_DISABLED: they are minted and resolved
			// entirely within mctl-api (never a JWT, never a GitHub token,
			// never one of the fixed static secrets a Provider matches), so
			// there is no registry seam for them to join yet, and refusing
			// an unresolvable one here must never fall back to any other
			// principal.
			switch {
			case cfg.agentRuns != nil && strings.HasPrefix(token, AgentRunTokenPrefix):
				run, rerr := cfg.agentRuns.ResolveAgentRun(r.Context(), token)
				if rerr != nil {
					slog.Warn("agent run token auth failed", "error", rerr, "path", r.URL.Path)
					writeErr("invalid, expired, or revoked agent run token")
					return
				}
				user = NewAgentUser(run.Agent, *run)
			case federationDisabled:
				// Pre-registry chain, unchanged (kept in the tree until
				// slice D, and restored wholesale by
				// MCTL_FEDERATION_DISABLED -- including the timing-unsafe
				// service-token compare this proposal otherwise fixes; see
				// requirements.md "Rollback").
				if svc := staticServiceUser(token); svc != nil {
					user = svc
				} else if su := surfaceUserFor(surfaces, token); su != nil {
					user = su
				} else if uw := usageWriterUserFor(usageWriter, token); uw != nil {
					user = uw
				} else if isJWT(token) {
					// Peek at the JWT issuer to route to the correct verifier.
					if oauth != nil && jwtIssuer(token) == oauth.BaseURL {
						// Local OAuth JWT: validate with HMAC-SHA256.
						u, err := oauth.ValidateJWT(token)
						if err != nil {
							slog.Warn("local oauth JWT auth failed", "error", err, "path", r.URL.Path)
							writeErr(err.Error())
							return
						}
						user = u
					} else {
						// Dex JWT path: validate and extract user + groups from claims.
						if dex == nil {
							writeErr("JWT auth not configured on this server")
							return
						}
						u, err := dex.Verify(r.Context(), token)
						if err != nil {
							slog.Warn("dex JWT auth failed", "error", err, "path", r.URL.Path)
							writeErr(err.Error())
							return
						}
						user = u
					}
				} else {
					// GitHub token path: validate via GitHub API, resolve groups from gitops.
					login, githubID, ghErr := validator.ValidateIdentity(r.Context(), token)
					if ghErr != nil {
						slog.Warn("github auth failed", "error", ghErr, "path", r.URL.Path)
						writeErr(ghErr.Error())
						return
					}
					groups := resolveGroups(login, validator, resolver)
					user = NewGitHubUser(login, groups)
					user.githubID = githubID
				}
			default:
				// Federation registry (mctl-api#374): a single lookup
				// replaces the if/else-if chain above.
				if registry == nil {
					writeErr("no identity provider is configured on this server")
					return
				}
				v, verr := registry.Verify(r.Context(), token)
				if verr != nil {
					slog.Warn("federation auth failed", "error", verr, "path", r.URL.Path)
					writeErr(verr.Error())
					return
				}
				user = userFromVerified(v)
			}

			if !attachPrincipal(w, r, cfg.principals, user, writeErr) {
				return
			}

			// Store user and raw token in context for downstream handlers.
			ctx := context.WithValue(r.Context(), userContextKey, user)
			ctx = context.WithValue(ctx, rawTokenKey, token)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// MiddlewareOption configures Middleware.
type MiddlewareOption func(*middlewareConfig)

type middlewareConfig struct {
	principals         PrincipalResolver
	federationRegistry *Registry
	agentRuns          AgentRunResolver
}

// WithPrincipalResolver resolves every authenticated caller to its
// canonical principal. A nil resolver is the same as not passing it.
func WithPrincipalResolver(pr PrincipalResolver) MiddlewareOption {
	return func(c *middlewareConfig) { c.principals = pr }
}

// WithAgentRunResolver authenticates bearer tokens minted by
// POST /api/v1/agent-run-tokens (mctl-api#376) as agent principals. A nil
// resolver is the same as not passing it: every AgentRunTokenPrefix-shaped
// token then falls through to the ordinary provider chain, which refuses it
// as an unrecognized opaque token.
func WithAgentRunResolver(r AgentRunResolver) MiddlewareOption {
	return func(c *middlewareConfig) { c.agentRuns = r }
}

// WithFederationRegistry supplies a fully-configured federation Registry
// (cmd/api/main.go builds one from MCTL_OIDC_PROVIDERS plus the legacy Dex
// shim, federation_config.go) instead of the default Registry Middleware
// would otherwise build from its own validator/resolver/dex/oauth
// parameters. Ignored while MCTL_FEDERATION_DISABLED is set.
func WithFederationRegistry(r *Registry) MiddlewareOption {
	return func(c *middlewareConfig) { c.federationRegistry = r }
}

// federationKillSwitchOn mirrors cmd/api/main.go's killSwitchOn (used for
// PRINCIPALS_DISABLED, WORK_ITEMS_DISABLED, ...): any value except an
// explicit "false"/"f"/"0"/"no"/"off" (or empty) turns the override on, so a
// template that renders the flag as "false" keeps the registry active while
// "yes" or "disabled" never silently fails open. Duplicated here rather than
// imported: cmd/api/main.go already imports this package, so the reverse
// import would cycle.
func federationKillSwitchOn(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "false", "f", "0", "no", "off":
		return false
	}
	return true
}

// defaultFederationRegistry builds the Registry Middleware uses when the
// caller does not supply one via WithFederationRegistry: the same four
// verifiers Middleware has always taken as parameters, wrapped as
// providers. cmd/api/main.go always supplies a fuller registry (built by
// federation_config.go, with audience enforcement); this default is what
// every existing caller of Middleware -- including every test in this
// package -- exercises unchanged.
func defaultFederationRegistry(validator *GitHubValidator, resolver TenantResolver, dex *DexVerifier, oauth *OAuthServer, surfaces map[string]string, usageWriter string) *Registry {
	static := []Provider{
		newServiceTokenProvider(func() string { return strings.TrimSpace(os.Getenv("MCTL_AGENT_SERVICE_TOKEN")) }),
		newSurfaceProvider(func() map[string]string { return surfaces }),
		newUsageWriterProvider(func() string { return usageWriter }),
	}
	var jwtProviders []Provider
	if oauth != nil && oauth.BaseURL != "" {
		jwtProviders = append(jwtProviders, newLocalOAuthProvider(oauth))
	} else if oauth != nil {
		slog.Warn("oauth server has empty BaseURL; local-oauth provider disabled")
	}
	if dex != nil && dex.Issuer() != "" {
		jwtProviders = append(jwtProviders, legacyDexProvider{dex: dex})
	}
	var opaque []Provider
	if validator != nil {
		opaque = append(opaque, newGitHubProvider(validator, legacyGroupSource{validator: validator, resolver: resolver}))
	}
	r, err := NewRegistry(static, jwtProviders, opaque)
	if err != nil {
		// Construction cannot fail here in practice: every input is a fixed
		// built-in shape with distinct names and issuers. Surfaced
		// defensively -- every request then 401s with "no identity
		// provider configured" -- rather than panicking, so a future change
		// to this function's inputs fails closed at request time, not at
		// process start.
		slog.Error("default federation registry refused to construct", "error", err)
		return nil
	}
	return r
}

// legacyDexProvider adapts an already-constructed *DexVerifier (built by
// NewDexVerifier from DEX_ISSUER_URL/DEX_CLIENT_ID) into a federation
// Provider, for defaultFederationRegistry. It delegates entirely to
// DexVerifier.Verify, so its audience behaviour is exactly what
// SkipClientIDCheck already baked in at construction -- the audit/enforce
// distinction is only available through the generic oidcProvider that
// cmd/api/main.go builds via federation_config.go and supplies through
// WithFederationRegistry.
type legacyDexProvider struct{ dex *DexVerifier }

func (p legacyDexProvider) Name() string       { return ProviderDex }
func (p legacyDexProvider) issuerName() string { return p.dex.Issuer() }

func (p legacyDexProvider) Claims(t tokenShape) bool {
	return t.jwt && normalizeIssuer(t.iss) == normalizeIssuer(p.dex.Issuer())
}

func (p legacyDexProvider) Verify(ctx context.Context, raw string) (*Verified, error) {
	u, err := p.dex.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	return &Verified{
		Identity: Identity{Provider: ProviderDex, Issuer: u.dexIssuer, Subject: u.dexSubject, Display: u.ID, Kind: KindHuman},
		Claims:   Claims{Groups: u.Groups},
	}, nil
}

// userFromVerified maps a provider's Verified result to a *User, setting
// the unexported discriminators from the provider's declared namespace and
// the identity it proved -- never from token claims directly. This is the
// only place besides the constructors in this file that builds a *User from
// authentication (design.md "The contract").
func userFromVerified(v *Verified) *User {
	switch {
	case v.Identity.Provider == ProviderService && v.Identity.Subject == ServiceUserID:
		return NewServiceUser()
	case v.Identity.Provider == ProviderService && strings.HasPrefix(v.Identity.Subject, SurfacePrincipalPrefix):
		return NewSurfaceUser(strings.TrimPrefix(v.Identity.Subject, SurfacePrincipalPrefix))
	case v.Identity.Provider == ProviderService && v.Identity.Subject == UsageWriterUserID:
		return NewUsageWriterUser()
	case v.Identity.Provider == ProviderGitHub:
		u := NewGitHubUser(v.Identity.Display, v.Claims.Groups)
		if v.Identity.Subject != "" {
			if id, err := strconv.ParseInt(v.Identity.Subject, 10, 64); err == nil {
				u.githubID = id
			}
		}
		return u
	case v.Identity.Provider == ProviderDex:
		return &User{ID: v.Identity.Display, Groups: v.Claims.Groups, dexIssuer: v.Identity.Issuer, dexSubject: v.Identity.Subject}
	default:
		return &User{
			ID: v.Identity.Display, Groups: v.Claims.Groups,
			oidcProviderName: v.Identity.Provider, oidcIssuer: v.Identity.Issuer,
			oidcSubject: v.Identity.Subject, oidcKind: v.Identity.Kind,
		}
	}
}

// attachPrincipal resolves the caller's principal. It answers false after
// writing the response when the request must be refused: a disabled
// principal (403) or an identity no rule accepts (401). Every other failure
// degrades to a request without a principal id.
func attachPrincipal(w http.ResponseWriter, r *http.Request, pr PrincipalResolver, u *User, writeErr func(string)) bool {
	err := AttachPrincipal(r.Context(), pr, u)
	switch {
	case err == nil:
		return true
	case errors.Is(err, ErrPrincipalDisabled):
		slog.Warn("disabled principal refused", "user", u.ID, "path", r.URL.Path)
		writeForbidden(w, "principal is disabled")
		return false
	case errors.Is(err, ErrIdentityRefused):
		slog.Warn("identity refused", "user", u.ID, "path", r.URL.Path, "error", err)
		writeErr("identity is not accepted")
		return false
	default:
		slog.Warn("principal not resolved; continuing without a principal id", "user", u.ID, "path", r.URL.Path, "error", err)
		return true
	}
}

func writeForbidden(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
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
