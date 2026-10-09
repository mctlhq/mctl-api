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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth/clientstore"
	"github.com/mctlhq/mctl-api/internal/auth/flowstore"
	"github.com/mctlhq/mctl-api/internal/auth/refreshstore"
)

// ErrServerError is returned by OAuth server operations that fail due to a
// transient infrastructure problem (e.g. database unavailability) rather than
// an invalid token or client credential. Token-endpoint handlers must respond
// with HTTP 500 / error:"server_error" when they encounter this sentinel.
var ErrServerError = errors.New("server_error")

// errResolverNotConfigured is returned by resolveGroupsChecked when
// OAuthServer.TenantResolver is nil. It is not a failure: callers treat it as
// "feature off" and keep whatever groups the session already carried, so a
// deployment without a gitops reader behaves exactly as it always has
// (mctl-api#411).
var errResolverNotConfigured = errors.New("tenant resolver not configured")

// errResolverBusy means the resolver could not answer without waiting, because
// the gitops reader is mid-refresh (it holds its write lock across git
// subprocesses). It is transient and expected about once a minute, so it is
// neither negatively cached nor logged above debug. The session keeps its own
// groups until the next attempt.
var errResolverBusy = errors.New("tenant resolver busy (gitops refresh in progress)")

// groupsStaleWarnAfter is the fixed threshold beyond which a present but
// unrefreshed gitops checkout gets a rate-limited warning logged, even though
// the resolution still succeeds from it. Not configurable, and never
// overridden by a *looser* GroupsMaxStaleness -- only a *stricter* one can
// turn staleness into a failure. See resolveGroupsChecked.
const groupsStaleWarnAfter = 15 * time.Minute

// defaultGroupsCacheTTL is used when GroupsCacheTTL is unset.
const defaultGroupsCacheTTL = 30 * time.Second

// resolverFailureTTL is how long a resolver failure is negatively cached,
// capped at the groups cache TTL. It is shorter than the success memo on
// purpose. During an outage it costs one tenant scan per 5s, which is noise.
// After recovery, sessions stay on the fallback (fail-closed, beyond grace)
// for at most this long, because while a failure is cached nothing asks
// the resolver.
const resolverFailureTTL = 5 * time.Second

// busyWaitLimit bounds how long a per-request resolution waits for an
// in-progress gitops refresh once the session is past GroupsDegradedGrace
// (see sessionGroups); busyPollInterval is how often it retries meanwhile.
// Variables so tests can shorten them.
var (
	busyWaitLimit    = 2 * time.Second
	busyPollInterval = 25 * time.Millisecond
)

// groupsCacheEntry is one memoized group-resolution result. It holds tenant
// groups only; "admins" is added on every read by withAdmins, so a cache hit
// still reflects IsAdmin as of that call and each caller gets its own slice.
type groupsCacheEntry struct {
	tenants   []string
	expiresAt time.Time
}

// nonBlockingTenantResolver is satisfied by a TenantResolver that can decline
// to answer instead of waiting on a lock. *gitops.Reader implements it.
// resolveGroupsChecked prefers it, so per-request resolution (ValidateJWT)
// never queues behind a gitops fetch.
type nonBlockingTenantResolver interface {
	TryGetTenantsForUser(login string) (namespaces []string, ok bool, err error)
}

// warnLimiter lets a warning through at most once per interval.
type warnLimiter struct {
	mu   sync.Mutex
	last time.Time
}

func (l *warnLimiter) allow(interval time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if !l.last.IsZero() && now.Sub(l.last) < interval {
		return false
	}
	l.last = now
	return true
}

// groupsWarnInterval rate-limits every group-resolution warning. ValidateJWT
// resolves on each request, so an unlimited warning on a failure path would
// log once per request for the length of an outage.
const groupsWarnInterval = time.Minute

// staleSyncSource is satisfied by a TenantResolver that can also report when
// its backing checkout last synced successfully. *gitops.Reader implements
// it. A resolver that cannot report sync state (test doubles, future
// implementations) simply skips the freshness gate in
// resolveGroupsChecked.
type staleSyncSource interface {
	LastSync() time.Time
}

// OAuthServer implements OAuth 2.0 Authorization Code flow with PKCE (RFC 7636).
// It acts as a public-client OAuth server backed by GitHub for user authentication.
// Access tokens are short-lived JWTs signed with HMAC-SHA256.
type OAuthServer struct {
	// newClientID overrides the random id source for dynamic registrations.
	// Nil in production; tests set it to force a collision with a static id.
	newClientID func() string
	// BaseURL is the public base URL of this server, e.g. "https://api.mctl.ai".
	BaseURL string
	// GitHubClientID / GitHubClientSecret are the GitHub OAuth App credentials.
	GitHubClientID     string
	GitHubClientSecret string
	// JWTSecret is the HMAC-SHA256 signing key for issued access tokens.
	JWTSecret []byte
	// AllowedRedirectURIs is the whitelist of permitted redirect_uri values.
	AllowedRedirectURIs []string
	// AccessTokenTTL is the lifetime of issued access tokens (default: 1h).
	AccessTokenTTL time.Duration
	// RefreshTokenTTL is the lifetime of issued refresh tokens (default: 30d).
	RefreshTokenTTL time.Duration
	// GitHubValidator is used to resolve team memberships for GitHub logins.
	GitHubValidator *GitHubValidator
	// TenantResolver resolves which tenants a GitHub login belongs to.
	TenantResolver TenantResolver

	// GroupsMaxStaleness, when > 0, enables strict mode for group
	// resolution: a TenantResolver checkout whose last successful sync
	// (reported via an optional LastSync() time.Time method) is older than
	// this counts as a failed resolution, same as the resolver returning an
	// error. 0 (the default) disables strict mode: a stale-but-present
	// checkout is then used and only logged/alerted on (see
	// resolveGroupsChecked). Configured from OAUTH_GROUPS_MAX_STALENESS.
	GroupsMaxStaleness time.Duration
	// GroupsDegradedGrace bounds how long the groups stored with a refresh
	// token, or claimed by a JWT, may stand in for a failed group
	// resolution before this server fails closed to admins-only. 0 selects
	// AccessTokenTTL (falling back to 1h if that is also unset), which is
	// the bound requirements.md names.
	GroupsDegradedGrace time.Duration
	// GroupsCacheTTL memoizes a successful group resolution per login, so
	// the per-request re-resolution ValidateJWT performs costs at most one
	// TenantResolver lookup per login per this interval. 0 selects
	// defaultGroupsCacheTTL (30s).
	GroupsCacheTTL time.Duration

	// lastResolveOK is the Unix-nanosecond time of the last successful group
	// resolution anywhere in this process (not per-session, per design.md:
	// the failure being tolerated is a property of the resolver, not of any
	// one session). Seeded to process start by NewOAuthServer, so a pod that
	// boots with a broken gitops checkout still has a bounded grace window
	// rather than an open-ended one.
	lastResolveOK atomic.Int64

	// groupsCacheMu guards groupsCache, the per-login memo of a successful
	// group resolution. Modelled on GitHubValidator.cache.
	groupsCacheMu sync.Mutex
	groupsCache   map[string]groupsCacheEntry

	// resolverFailMu guards resolverFailErr/resolverFailUntil: the negative
	// cache. After a resolver failure, further resolutions return the same
	// error without touching the resolver for resolverFailureTTL (capped at
	// GroupsCacheTTL). Otherwise, during
	// an outage, every authenticated request would re-read and re-parse every
	// tenant file. The cache is process-wide, not per login, because every
	// failure it holds (never-synced checkout, strict-mode staleness,
	// ListTenants error) is a property of the resolver.
	resolverFailMu    sync.Mutex
	resolverFailErr   error
	resolverFailUntil time.Time

	// Rate limiters for the stale-checkout, degraded and fail-closed warnings.
	staleWarn      warnLimiter
	degradedWarn   warnLimiter
	failClosedWarn warnLimiter

	// RefreshStore is an optional persistent store for refresh tokens.
	// When non-nil it replaces the in-memory refreshTokens store, making
	// refresh tokens survive pod restarts. Inject via main.go after construction.
	RefreshStore refreshstore.Store

	// ClientStore is an optional persistent store for RFC 7591 dynamic
	// registrations. When non-nil, RegisterDynamicClient writes to it and
	// GetClient reads from it instead of the in-memory registry, so a client
	// that registered once and cached its client_id -- the Cloudflare MCP
	// portal in automatic mode -- still resolves after a pod restart
	// (mctlhq/mctl-api#395). Registration is then idempotent: the id is
	// derived from the registration metadata, so the same client re-registering
	// gets the same row back instead of adding one. Rows are bounded by
	// MaxRegisteredClients (least recently seen evicted) and by
	// PersistedClientRetention. Inject via main.go after construction.
	ClientStore clientstore.Store

	// FlowStore is an optional shared store for pending authorizations and
	// issued authorization codes. When nil they live in this process's
	// memory, which is correct only while mctl-api runs one replica: the
	// authorize request, the upstream callback and the token exchange can
	// each land on a different pod. Inject via main.go after construction.
	FlowStore flowstore.Store

	// PersistedClientRetention is how long a persisted registration survives
	// without being seen (registered again, or used for a token exchange or
	// refresh). It replaces ClientRegistrationTTL for the persistent store:
	// that TTL runs from registration, which would drop a client that
	// registered once and has been using its tokens ever since. 0 selects
	// defaultPersistedClientRetention; negative disables it.
	PersistedClientRetention time.Duration

	// MaxRegisteredClients caps how many RFC 7591 dynamic registrations are
	// held at once. /oauth/register is unauthenticated, so without a ceiling
	// the map grows for the lifetime of the process — and it grows during
	// ordinary use, not just under attack: an MCP client that fans out across
	// several processes registers a separate client per process on every
	// start. When the cap is reached the oldest entry is evicted. 0 selects
	// defaultMaxRegisteredClients.
	MaxRegisteredClients int

	// ClientRegistrationTTL bounds how long a dynamic registration is kept.
	// The cap above bounds memory; this bounds *staleness*, which the cap
	// cannot: an MCP client that registers once per process on every start
	// leaves entries behind forever, so without an age limit the map fills
	// with dead registrations and eviction starts discarding live ones to
	// make room for them. 0 selects defaultClientRegistrationTTL; negative
	// disables expiry.
	//
	// Expiring a registration is close to harmless here, which is why this is
	// safe to add: /oauth/register only ever accepts redirect URIs that are
	// already on the static allowlist or are RFC 8252 loopback, so an expired
	// client's URIs remain acceptable on their own merits. What it loses is
	// the per-client scoping, and re-registering restores that.
	ClientRegistrationTTL time.Duration

	codes         authCodeStore
	refreshTokens refreshTokenStore
	clientsMu     sync.Mutex
	clients       map[string]RegisteredClient // clientID → client (RFC 7591)
	// static holds pre-registered public clients (OAUTH_PREREGISTERED_CLIENTS).
	// They are outside the dynamic registry on purpose: no TTL, no eviction
	// under MaxRegisteredClients, no dependence on this process having seen a
	// registration. A counterpart that cannot perform RFC 7591 registration
	// -- the Cloudflare MCP portal, whose manual OAuth stores one client id
	// per upstream -- needs an id that is still valid after a pod restart,
	// which the in-memory dynamic registry cannot promise (a ClientStore can,
	// for a counterpart that does register: mctlhq/mctl-api#395).
	static map[string]RegisteredClient
}

// defaultMaxRegisteredClients bounds the dynamic-registration map when
// MaxRegisteredClients is unset. Matches the ceiling mctl-telegram applies to
// the same endpoint.
const defaultMaxRegisteredClients = 1000

// defaultClientRegistrationTTL bounds the age of a dynamic registration when
// ClientRegistrationTTL is unset. 24h matches the ceiling mctl-telegram
// applies to the same endpoint, and comfortably outlasts any single
// authorization flow — a client that still needs its registration a day later
// can re-register, which is one unauthenticated POST.
const defaultClientRegistrationTTL = 24 * time.Hour

// defaultPersistedClientRetention bounds how long a persisted registration is
// kept without being seen. Longer than the 30-day refresh-token lifetime, so a
// client that stays signed in never loses its registration, and a client that
// has been gone for three months is not worth a row.
const defaultPersistedClientRetention = 90 * 24 * time.Hour

// persistedClientRetention resolves the configured value; negative means
// "never expire".
func (s *OAuthServer) persistedClientRetention() time.Duration {
	if s.PersistedClientRetention == 0 {
		return defaultPersistedClientRetention
	}
	return s.PersistedClientRetention
}

// ErrClientIDTaken is returned by RegisterDynamicClient when the id derived
// for a registration is already held by something else: a pre-registered
// client, or (only on a hash collision) a stored client with different
// metadata. Handlers map it to a server error; it is never the caller's fault.
var ErrClientIDTaken = errors.New("derived client_id is already taken")

// dynamicClientIDPrefix marks ids minted by idempotent registration, so an
// operator reading a log line can tell them from the random ids of the
// in-memory registry and from pre-registered ids.
const dynamicClientIDPrefix = "dcr_"

// derivedClientID is the idempotency key of a persisted registration: a hash
// of the client name and the redirect-URI set (deduplicated and sorted, so the
// order a client lists its callbacks in does not matter; each URI byte-exact,
// as IsRedirectURIAllowed compares them). The same client registering again
// gets the same id; a different name or a different callback set is a
// different client. The id is not a secret -- this server is public-client
// only and PKCE is the proof -- so a plain hash is enough.
//
// client_name is optional (RFC 7591 §2), so two unrelated anonymous clients
// that use the same fixed callback -- the MCP Inspector's
// http://localhost:6274/oauth/callback, say -- share one id and one row.
// That is benign for public PKCE clients and is what bounds the rows; a
// client that wants its own record names itself. The name must be valid
// UTF-8 (the handler refuses anything else with invalid_client_metadata):
// json.Marshal would otherwise fold invalid bytes into U+FFFD and derive the
// same id for different names.
func derivedClientID(name string, canonicalURIs []string) string {
	// Marshal cannot fail here: the value is a struct of an int, a string and
	// a []string, none of which has a type json rejects. Were it ever to fail,
	// every client would hash the same nil input -- which the ClientName /
	// RedirectURIs comparison in RegisterDynamicClient would then refuse as a
	// collision rather than share.
	b, _ := json.Marshal(struct {
		V    int      `json:"v"`
		Name string   `json:"client_name"`
		URIs []string `json:"redirect_uris"`
	}{1, name, canonicalURIs})
	sum := sha256.Sum256(b)
	return dynamicClientIDPrefix + hex.EncodeToString(sum[:16])
}

// canonicalRedirectURIs returns uris deduplicated and sorted.
func canonicalRedirectURIs(uris []string) []string {
	out := slices.Clone(uris)
	slices.Sort(out)
	return slices.Compact(out)
}

// clientRegistrationTTL resolves the configured value, honouring a negative
// duration as "never expire".
func (s *OAuthServer) clientRegistrationTTL() time.Duration {
	if s.ClientRegistrationTTL == 0 {
		return defaultClientRegistrationTTL
	}
	return s.ClientRegistrationTTL
}

// clientExpired reports whether c is older than the configured TTL. Callers
// must hold clientsMu.
func (s *OAuthServer) clientExpired(c RegisteredClient, now time.Time) bool {
	ttl := s.clientRegistrationTTL()
	if ttl < 0 {
		return false
	}
	return now.Sub(c.CreatedAt) > ttl
}

// RegisteredClient stores a dynamically registered OAuth client (RFC 7591).
//
// This is the internal record, not the wire type. The registration response
// is assembled field by field in handleOAuthRegister, which is where the RFC
// 7591 §3.2.1 shape is decided — notably client_id_issued_at, which must be
// integer seconds and is emitted as CreatedAt.Unix() there. These struct tags
// are vestigial: nothing marshals this type. They are kept only because the
// field names would otherwise read as unexplained.
type RegisteredClient struct {
	ClientID     string    `json:"client_id"`
	ClientName   string    `json:"client_name,omitempty"`
	RedirectURIs []string  `json:"redirect_uris"`
	CreatedAt    time.Time `json:"client_id_issued_at,omitempty"`
}

// AddPreregisteredClient seeds a static public client. It is the narrower
// counterpart of AllowedRedirectURIs: an exact registration trusts one
// callback for exactly one client_id, where widening the global allowlist
// would loosen redirect acceptance for every dynamically registered client.
//
// The same shape rules IsRedirectURIAllowed relies on apply here, at
// startup, so a misconfiguration is a refused boot rather than a client that
// silently never works: absolute URL, https (or http on a loopback host per
// RFC 8252), no fragment, no userinfo. There is no client_secret: the server
// is public-client only, PKCE is the proof, and no field could change that.
//
// A loopback entry is accepted but matched with its port: a static client
// trusts exactly what it lists and never the port-agnostic loopback rule,
// so a native app that binds an ephemeral port cannot be pre-registered and
// has to use dynamic registration instead.
func (s *OAuthServer) AddPreregisteredClient(clientID, clientName string, redirectURIs []string) error {
	if strings.TrimSpace(clientID) == "" {
		return errors.New("pre-registered client: client_id is required")
	}
	// The id is a map key compared byte for byte at every lookup, so padding
	// would seed a client that only resolves when the counterpart sends the
	// same padding -- one that silently never works.
	if clientID != strings.TrimSpace(clientID) {
		return fmt.Errorf("pre-registered client %q: client_id has leading or trailing whitespace", clientID)
	}
	if len(redirectURIs) == 0 {
		return fmt.Errorf("pre-registered client %q: at least one redirect_uri is required", clientID)
	}
	seen := make(map[string]struct{}, len(redirectURIs))
	for _, raw := range redirectURIs {
		if strings.ContainsRune(raw, '\\') {
			return fmt.Errorf("pre-registered client %q: redirect_uri must not contain a backslash", clientID)
		}
		u, err := url.Parse(raw)
		if err != nil || !u.IsAbs() || u.Host == "" {
			return fmt.Errorf("pre-registered client %q: redirect_uri %q is not an absolute URL", clientID, raw)
		}
		if u.User != nil {
			return fmt.Errorf("pre-registered client %q: redirect_uri must not contain userinfo", clientID)
		}
		if u.Fragment != "" || strings.Contains(raw, "#") {
			return fmt.Errorf("pre-registered client %q: redirect_uri must not contain a fragment", clientID)
		}
		if u.Scheme != "https" && !isLoopbackRedirectURI(raw) {
			return fmt.Errorf("pre-registered client %q: redirect_uri scheme %q is not allowed (https, or http on a loopback host)", clientID, u.Scheme)
		}
		if _, dup := seen[raw]; dup {
			return fmt.Errorf("pre-registered client %q: redirect_uri %q listed twice", clientID, raw)
		}
		seen[raw] = struct{}{}
	}
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	if s.static == nil {
		s.static = make(map[string]RegisteredClient)
	}
	if _, dup := s.static[clientID]; dup {
		return fmt.Errorf("pre-registered client %q: duplicate client_id", clientID)
	}
	// GetClient consults the static registry first, so seeding an id that a
	// dynamic registration already holds would silently re-point that client
	// at a different redirect set. Refused whether or not that can happen in
	// the startup order main uses today; the method is exported.
	if _, taken := s.clients[clientID]; taken {
		return fmt.Errorf("pre-registered client %q: client_id already held by a dynamic registration", clientID)
	}
	s.static[clientID] = RegisteredClient{
		ClientID:     clientID,
		ClientName:   clientName,
		RedirectURIs: append([]string(nil), redirectURIs...),
		// Zero CreatedAt marks the record as static; nothing reads it for
		// expiry because GetClient never subjects static entries to the TTL.
	}
	return nil
}

// PreregisteredClientCount reports how many static clients are seeded.
func (s *OAuthServer) PreregisteredClientCount() int {
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	return len(s.static)
}

// mintClientID returns a fresh dynamic client id: 128 random bits, or
// whatever newClientID yields when a test has set it.
func (s *OAuthServer) mintClientID() string {
	if s.newClientID != nil {
		return s.newClientID()
	}
	b := make([]byte, 16)
	// crypto/rand.Read cannot report failure on the Go version this module
	// requires: since Go 1.24 it is documented never to return an error and
	// panics instead if the system source is broken. Handling the error here
	// would be unreachable code; the discard is deliberate, not an oversight.
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// staticClient returns the pre-registered client with this id, if any.
func (s *OAuthServer) staticClient(clientID string) (RegisteredClient, bool) {
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	c, ok := s.static[clientID]
	return c, ok
}

// isStatic reports whether clientID names a pre-registered client.
func (s *OAuthServer) isStatic(clientID string) bool {
	_, ok := s.staticRedirectURIs(clientID)
	return ok
}

// staticRedirectURIs returns the callbacks a pre-registered client trusts,
// and false when clientID is not a static client.
func (s *OAuthServer) staticRedirectURIs(clientID string) ([]string, bool) {
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	c, ok := s.static[clientID]
	if !ok {
		return nil, false
	}
	return c.RedirectURIs, true
}

// RegisterClient stores a dynamically registered client in the in-memory
// registry under a fresh random id and returns it. It never consults
// ClientStore; RegisterDynamicClient is the entry point that chooses between
// the two.
func (s *OAuthServer) RegisterClient(name string, redirectURIs []string) RegisteredClient {
	clientID := s.mintClientID()
	// A 128-bit random id colliding with a static one is not a realistic
	// event, but the consequence -- a dynamic registration shadowing a
	// pre-registered client -- is bad enough to rule out rather than accept.
	for s.isStatic(clientID) {
		clientID = s.mintClientID()
	}

	client := RegisteredClient{
		ClientID:     clientID,
		ClientName:   name,
		RedirectURIs: redirectURIs,
		CreatedAt:    time.Now(),
	}

	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	if s.clients == nil {
		s.clients = make(map[string]RegisteredClient)
	}
	// Drop expired entries before consulting the cap, so a map full of dead
	// registrations does not force the eviction of live ones.
	now := time.Now()
	for id, c := range s.clients {
		if s.clientExpired(c, now) {
			delete(s.clients, id)
		}
	}

	max := s.MaxRegisteredClients
	if max <= 0 {
		max = defaultMaxRegisteredClients
	}
	for len(s.clients) >= max {
		// Evict by registration time. Anything still in flight was registered
		// seconds ago, so at a cap of this size the victim is always a stale
		// entry unless the map is being deliberately churned — and in that
		// case dropping registrations beats growing without bound.
		var oldestID string
		var oldestAt time.Time
		for id, c := range s.clients {
			if oldestID == "" || c.CreatedAt.Before(oldestAt) {
				oldestID, oldestAt = id, c.CreatedAt
			}
		}
		if oldestID == "" {
			break
		}
		delete(s.clients, oldestID)
	}
	s.clients[clientID] = client
	return client
}

// RegisterDynamicClient is the RFC 7591 registration entry point used by
// POST /oauth/register. Without a ClientStore it is RegisterClient, the
// in-memory registry with a random id, unchanged. With one, the registration
// is persisted and idempotent: the id is derived from the name and the
// redirect-URI set (derivedClientID), so a client that registers again gets
// its existing record back rather than a new row, and the record outlives the
// process. The caller must have validated the redirect URIs already.
func (s *OAuthServer) RegisterDynamicClient(name string, redirectURIs []string) (RegisteredClient, error) {
	if s.ClientStore == nil {
		return s.RegisterClient(name, redirectURIs), nil
	}
	uris := canonicalRedirectURIs(redirectURIs)
	clientID := derivedClientID(name, uris)
	// A derived id can only equal a static one if an operator configured
	// exactly this string, but the consequence -- a dynamic registration
	// answering for a pre-registered client -- is the same one RegisterClient
	// rules out, so it is refused here too rather than trusted not to happen.
	if s.isStatic(clientID) {
		return RegisteredClient{}, fmt.Errorf("register client: %w", ErrClientIDTaken)
	}
	max := s.MaxRegisteredClients
	if max <= 0 {
		max = defaultMaxRegisteredClients
	}
	stored, err := s.ClientStore.Register(clientstore.Client{
		ClientID:     clientID,
		ClientName:   name,
		RedirectURIs: uris,
	}, max)
	if err != nil {
		slog.Error("oauth: client store register failed", "error", err)
		return RegisteredClient{}, fmt.Errorf("register client: %w", ErrServerError)
	}
	// The store returns the first registration's record on a repeat. With a
	// 128-bit hash of the metadata it can only differ on a collision; never
	// hand one client another's callbacks, however unlikely.
	if stored.ClientName != name || !slices.Equal(stored.RedirectURIs, uris) {
		slog.Error("oauth: derived client_id collides with a different registration", "client_id", clientID)
		return RegisteredClient{}, fmt.Errorf("register client: %w", ErrClientIDTaken)
	}
	return fromStored(stored), nil
}

func fromStored(c clientstore.Client) RegisteredClient {
	return RegisteredClient{
		ClientID:     c.ClientID,
		ClientName:   c.ClientName,
		RedirectURIs: c.RedirectURIs,
		CreatedAt:    c.CreatedAt,
	}
}

// touchClient records that clientID used a grant, so the persistent store's
// cap and retention measure activity rather than registration age. A client
// that registered once and then only refreshes -- the portal -- would
// otherwise be the first evicted. Best effort: a failed touch must not fail
// the token exchange it rides on.
func (s *OAuthServer) touchClient(clientID string) {
	if s.ClientStore == nil || clientID == "" || s.isStatic(clientID) {
		return
	}
	if err := s.ClientStore.Touch(clientID); err != nil {
		slog.Warn("oauth: client store touch failed", "error", err)
	}
}

// GCPersistedClients deletes persisted registrations past
// PersistedClientRetention. A no-op without a ClientStore or with retention
// disabled.
func (s *OAuthServer) GCPersistedClients() error {
	r := s.persistedClientRetention()
	if s.ClientStore == nil || r < 0 {
		return nil
	}
	return s.ClientStore.GC(time.Now().Add(-r))
}

// clientLookupTimeout bounds a persistent-store lookup made by GetClient. It
// is reached from unauthenticated endpoints with a caller-chosen client_id
// (/oauth/authorize), so a degraded database must cost those requests a
// fraction of a second, not the store's 5s default, and must not hold pool
// slots long enough for failing traffic to saturate the pool.
const clientLookupTimeout = 500 * time.Millisecond

// isDerivedClientID reports whether id has the exact shape derivedClientID
// produces. Anything else cannot be in the persistent store, so it is
// answered without a query.
func isDerivedClientID(id string) bool {
	rest, ok := strings.CutPrefix(id, dynamicClientIDPrefix)
	if !ok || len(rest) != 32 {
		return false
	}
	_, err := hex.DecodeString(rest)
	return err == nil && rest == strings.ToLower(rest)
}

// GetClient returns a registered client by ID, or false if not found.
// Pre-registered clients are consulted first, then the persistent store when
// one is configured, otherwise the in-memory registry. A store lookup is
// bounded by clientLookupTimeout and is only made for an id of the derived
// shape; a store error reads as "not found".
func (s *OAuthServer) GetClient(clientID string) (RegisteredClient, bool) {
	if clientID == "" {
		return RegisteredClient{}, false
	}
	if s.ClientStore == nil {
		return s.localClient(clientID)
	}
	if c, ok := s.staticClient(clientID); ok {
		return c, true
	}
	if !isDerivedClientID(clientID) {
		return RegisteredClient{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), clientLookupTimeout)
	defer cancel()
	stored, err := s.ClientStore.Get(ctx, clientID)
	if err != nil {
		if !errors.Is(err, clientstore.ErrNotFound) {
			slog.Warn("oauth: client store lookup failed", "error", err)
		}
		return RegisteredClient{}, false
	}
	// Read as absent once past retention, without waiting for the GC
	// ticker, for the same reason the in-memory registry expires on read.
	if r := s.persistedClientRetention(); r > 0 && time.Since(stored.LastSeenAt) > r {
		return RegisteredClient{}, false
	}
	return fromStored(stored), true
}

// ClientForLog resolves clientID for log enrichment only, without ever
// touching the persistent store: the caller is the failure branch of
// unauthenticated /oauth/token, where a database round-trip would add load
// exactly when the database is already failing, for nothing but a name in a
// log line. consulted is false when the answer would have needed the store
// (a derived dcr_ id with a store configured); found is then meaningless.
func (s *OAuthServer) ClientForLog(clientID string) (c RegisteredClient, found, consulted bool) {
	if clientID == "" {
		return RegisteredClient{}, false, true
	}
	if s.ClientStore == nil {
		c, found = s.localClient(clientID)
		return c, found, true
	}
	if c, ok := s.staticClient(clientID); ok {
		return c, true, true
	}
	if isDerivedClientID(clientID) {
		return RegisteredClient{}, false, false
	}
	return RegisteredClient{}, false, true
}

// localClient looks clientID up in the static and in-memory registries.
func (s *OAuthServer) localClient(clientID string) (RegisteredClient, bool) {
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	if c, ok := s.static[clientID]; ok {
		return c, true
	}
	c, ok := s.clients[clientID]
	if !ok {
		return RegisteredClient{}, false
	}
	// An expired registration must read as absent rather than waiting for the
	// next RegisterClient to sweep it: otherwise expiry would depend on
	// unrelated traffic, and a quiet server would honour registrations
	// indefinitely.
	if s.clientExpired(c, time.Now()) {
		delete(s.clients, clientID)
		return RegisteredClient{}, false
	}
	return c, true
}

// RegisteredClientCount reports how many registrations the IN-MEMORY
// registry holds. With a ClientStore configured that registry is unused and
// this is 0; the persisted rows live in oauth_registered_clients. Exported for
// tests and for visibility into the in-memory cap.
func (s *OAuthServer) RegisteredClientCount() int {
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	return len(s.clients)
}

// NewOAuthServer creates a ready-to-use OAuthServer with sensible defaults.
func NewOAuthServer(baseURL, ghClientID, ghClientSecret string, jwtSecret []byte, allowedRedirectURIs []string, ghValidator *GitHubValidator) *OAuthServer {
	s := &OAuthServer{
		BaseURL:             baseURL,
		GitHubClientID:      ghClientID,
		GitHubClientSecret:  ghClientSecret,
		JWTSecret:           jwtSecret,
		AllowedRedirectURIs: allowedRedirectURIs,
		// 1h, was 7*24h. Nothing in production read that 7-day default —
		// main.go overwrites it from OAUTH_TOKEN_TTL, whose own default is 1h,
		// and IssueJWT falls back to 1h when the field is zero. So the
		// constructor was the only place claiming a week, and it claimed it to
		// every caller that did not know to override: tests, and any future
		// wiring. A default that disagrees with both the configured value and
		// the fallback is a trap, and the safe direction for a credential
		// lifetime is the short one.
		AccessTokenTTL:  1 * time.Hour,
		RefreshTokenTTL: 30 * 24 * time.Hour,
		GitHubValidator: ghValidator,
	}
	s.codes.init()
	s.refreshTokens.init()
	// Seeds the degraded-grace window from process start, not from whenever
	// the first resolution happens to run: a pod that boots with a broken
	// gitops checkout still has a bounded window rather than an open-ended
	// one (design.md "A checked resolver").
	s.lastResolveOK.Store(time.Now().UnixNano())
	return s
}

// ResolveGroups resolves the tenant groups for a GitHub login, best-effort.
// It is the exported entry point used at login
// (internal/api/oauth_handlers.go, right after the GitHub OAuth callback
// validates the login) and is reimplemented over resolveGroupsChecked,
// discarding the error: a resolver failure (or none configured) at login
// time still grants "admins" as computed right now, exactly as it did before
// this method existed. Unlike the per-request paths, login waits out an
// in-progress gitops refresh rather than accepting a "busy" decline. Login is
// not a hot path, and the groups resolved here become the refresh-token
// snapshot that later degraded resolutions fall back on.
func (s *OAuthServer) ResolveGroups(login string) []string {
	if groups, err := s.resolveGroups(login, true); err == nil {
		return groups
	}
	return s.withAdmins(login, nil)
}

// resolveGroupsChecked resolves groups for login, reporting failure instead
// of hiding it -- unlike the free function resolveGroups in oidc.go, and
// unlike this method's own predecessor. Rules, in order:
//
//  1. "admins" always comes from GitHubValidator.IsAdmin(login), computed
//     fresh on every call. It is never taken from a stored or claimed value:
//     that is what lets admin status be granted or withdrawn on the same
//     terms as any other group (requirements.md).
//  2. TenantResolver == nil returns errResolverNotConfigured. This is not a
//     failure; it means the feature is off. Callers keep the stored/claimed
//     groups verbatim (groupsForSession), so a deployment without a gitops
//     reader is unaffected.
//  3. A memoized result younger than GroupsCacheTTL is reused without
//     touching the resolver, bounding the added cost of per-request
//     resolution (ValidateJWT) to one lookup per login per TTL. A failure is
//     memoized too, process-wide, for resolverFailureTTL (5s), so an outage
//     costs at most one resolver lookup per 5s rather than one per request. The
//     lookup itself never waits: a resolver that implements
//     nonBlockingTenantResolver (gitops.Reader) and is mid-refresh answers
//     errResolverBusy, which callers treat like a failure but without
//     negative caching or a warning.
//  4. Freshness gate (checkResolverFreshness): if the resolver also reports
//     LastSync() (gitops.Reader does), a checkout that has never synced, or
//     that is stale beyond a configured GroupsMaxStaleness (strict mode), is
//     treated as a failed resolution -- never as "this user has no tenants".
//     A stale-but-present checkout under strict mode's threshold (or with
//     strict mode off) is not a failure; it is used, with a rate-limited
//     warning past the fixed groupsStaleWarnAfter.
//  5. A GetTenantsForUser error is a failure, wrapped with the login for
//     context.
//  6. On success the result is memoized and lastResolveOK is advanced, which
//     is what keeps the degraded-grace window from drifting toward
//     fail-closed while the resolver keeps working (even from a stale
//     checkout).
func (s *OAuthServer) resolveGroupsChecked(login string) ([]string, error) {
	return s.resolveGroups(login, false)
}

// resolveGroups implements resolveGroupsChecked. With wait set, the lookup
// blocks on the resolver instead of declining with errResolverBusy (used at
// login, see ResolveGroups).
func (s *OAuthServer) resolveGroups(login string, wait bool) ([]string, error) {
	if s.TenantResolver == nil {
		return nil, errResolverNotConfigured
	}
	if tenants, ok := s.cachedGroups(login); ok {
		return s.withAdmins(login, tenants), nil
	}
	// Login (wait) pays to get the right answer: it skips the negative
	// cache, since what it resolves becomes the refresh-token snapshot.
	if !wait {
		if err := s.recentResolverFailure(); err != nil {
			return nil, err
		}
	}
	if err := s.checkResolverFreshness(login); err != nil {
		s.noteResolverFailure(err)
		return nil, err
	}
	tenants, err := s.lookupTenants(login, wait)
	if errors.Is(err, errResolverBusy) {
		return nil, err
	}
	if err != nil {
		// No login in the message: this error is memoized process-wide and
		// may be logged against other users; both log sites add "user".
		err = fmt.Errorf("resolve tenant groups: %w", err)
		s.noteResolverFailure(err)
		return nil, err
	}
	tenants = tenantsOnly(tenants)
	s.lastResolveOK.Store(time.Now().UnixNano())
	s.storeGroupsCache(login, tenants)
	return s.withAdmins(login, tenants), nil
}

// lookupTenants asks the resolver for login's tenants. Unless wait is set, it
// does so without waiting when the resolver supports that (see
// nonBlockingTenantResolver), and returns errResolverBusy if it declined.
func (s *OAuthServer) lookupTenants(login string, wait bool) ([]string, error) {
	if nb, ok := s.TenantResolver.(nonBlockingTenantResolver); ok && !wait {
		tenants, answered, err := nb.TryGetTenantsForUser(login)
		if !answered {
			return nil, errResolverBusy
		}
		return tenants, err
	}
	return s.TenantResolver.GetTenantsForUser(login)
}

// recentResolverFailure returns the memoized resolver failure, if one was
// recorded less than resolverFailureTTL (capped at GroupsCacheTTL) ago.
// Recovery after an outage is bounded by that TTL: the memo is not cleared
// early, it simply expires.
func (s *OAuthServer) recentResolverFailure() error {
	s.resolverFailMu.Lock()
	defer s.resolverFailMu.Unlock()
	if s.resolverFailErr == nil || time.Now().After(s.resolverFailUntil) {
		return nil
	}
	return s.resolverFailErr
}

// noteResolverFailure memoizes err as the resolver's current failure for
// min(resolverFailureTTL, GroupsCacheTTL).
func (s *OAuthServer) noteResolverFailure(err error) {
	s.resolverFailMu.Lock()
	defer s.resolverFailMu.Unlock()
	ttl := min(resolverFailureTTL, s.groupsCacheTTL())
	s.resolverFailErr = err
	s.resolverFailUntil = time.Now().Add(ttl)
}

// checkResolverFreshness applies the freshness gate described on
// resolveGroupsChecked. It returns nil when resolution may proceed (fresh,
// stale-but-present with a rate-limited warning already logged, or the
// resolver does not report sync state at all), and a non-nil error only when
// the checkout is definitively too old to trust: never synced, or -- only in
// strict mode -- older than GroupsMaxStaleness.
func (s *OAuthServer) checkResolverFreshness(login string) error {
	src, ok := s.TenantResolver.(staleSyncSource)
	if !ok {
		return nil
	}
	last := src.LastSync()
	if last.IsZero() {
		// A missing tenants directory reads as (nil, nil), not an error
		// (gitops.Reader.ListTenants), which is indistinguishable from "this
		// user has no tenants" unless caught here first.
		return fmt.Errorf("gitops checkout for tenant resolution has never synced")
	}
	age := time.Since(last)
	if s.GroupsMaxStaleness > 0 && age > s.GroupsMaxStaleness {
		return fmt.Errorf("gitops checkout is %s old, beyond OAUTH_GROUPS_MAX_STALENESS (%s)", age.Round(time.Second), s.GroupsMaxStaleness)
	}
	// Independent of the strict-mode check above: the fixed 15m constant
	// never overrides a stricter operator setting, but it still applies (as
	// a warning, not a failure) whether or not strict mode is configured.
	if age > groupsStaleWarnAfter {
		s.warnStaleCheckout(login, age)
	}
	return nil
}

// warnStaleCheckout logs that a stale-but-present checkout is still being
// used to answer group resolution, rate-limited to once per minute so a
// long-lived incident does not flood logs.
func (s *OAuthServer) warnStaleCheckout(login string, age time.Duration) {
	if !s.staleWarn.allow(groupsWarnInterval) {
		return
	}
	slog.Warn("oauth: gitops checkout stale but present; resolving tenant groups from it anyway",
		"user", login, "age", age.Round(time.Second), "warn_after", groupsStaleWarnAfter)
}

// groupsCacheTTL resolves the configured memo TTL.
func (s *OAuthServer) groupsCacheTTL() time.Duration {
	if s.GroupsCacheTTL == 0 {
		return defaultGroupsCacheTTL
	}
	return s.GroupsCacheTTL
}

// cachedGroups returns the memoized tenant groups for login ("admins" not
// included), if an entry exists and has not yet expired.
func (s *OAuthServer) cachedGroups(login string) ([]string, bool) {
	s.groupsCacheMu.Lock()
	defer s.groupsCacheMu.Unlock()
	e, ok := s.groupsCache[login]
	if !ok || time.Now().After(e.expiresAt) {
		return nil, false
	}
	return e.tenants, true
}

// storeGroupsCache memoizes groups for login. Expired entries across the
// whole map are evicted opportunistically on every write (mirroring
// GitHubValidator.cache), so the map cannot grow without bound even though
// nothing ever sweeps it on a timer.
func (s *OAuthServer) storeGroupsCache(login string, tenants []string) {
	s.groupsCacheMu.Lock()
	defer s.groupsCacheMu.Unlock()
	if s.groupsCache == nil {
		s.groupsCache = make(map[string]groupsCacheEntry)
	}
	now := time.Now()
	for k, e := range s.groupsCache {
		if now.After(e.expiresAt) {
			delete(s.groupsCache, k)
		}
	}
	s.groupsCache[login] = groupsCacheEntry{tenants: tenants, expiresAt: now.Add(s.groupsCacheTTL())}
}

// withAdmins returns a new slice holding tenants -- with any incidental
// "admins" entry stripped -- plus a freshly computed "admins" when login is
// currently an admin. The result never aliases tenants, so it is safe to hand
// out from the memo. This
// is the only place group lists are assembled from a fresh IsAdmin check, so
// every caller that wants "admins" reflects live admin status goes through
// here rather than trusting a stored or claimed copy.
func (s *OAuthServer) withAdmins(login string, tenants []string) []string {
	groups := tenantsOnly(tenants)
	if s.GitHubValidator.IsAdmin(login) {
		groups = append([]string{"admins"}, groups...)
	}
	return groups
}

// tenantsOnly strips any "admins" entry from groups. Used to sanitize a
// stored or claimed snapshot before treating it as a fallback: that snapshot
// is never trusted as evidence of admin status, because withAdmins
// recomputes "admins" fresh every time.
func tenantsOnly(groups []string) []string {
	if len(groups) == 0 {
		return nil
	}
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		if g != "admins" {
			out = append(out, g)
		}
	}
	return out
}

// degradedGrace resolves GroupsDegradedGrace, defaulting to AccessTokenTTL
// (the bound requirements.md names), and falling back further to 1h -- the
// same default IssueJWT itself falls back to -- if AccessTokenTTL is also
// unset.
func (s *OAuthServer) degradedGrace() time.Duration {
	if s.GroupsDegradedGrace != 0 {
		return s.GroupsDegradedGrace
	}
	if s.AccessTokenTTL != 0 {
		return s.AccessTokenTTL
	}
	return time.Hour
}

// lastResolveOKTime returns the last time any group resolution in this
// process succeeded.
func (s *OAuthServer) lastResolveOKTime() time.Time {
	return time.Unix(0, s.lastResolveOK.Load())
}

// groupsForSession returns the groups a token should carry for login, given
// the groups previously recorded for that session -- the snapshot stored
// with a refresh token, or the groups a JWT already claims. This is the
// degradation policy described in design.md "A checked resolver" /
// "groupsForSession":
//
//   - resolution succeeded: return the freshly resolved groups.
//   - no TenantResolver configured: return stored unchanged (feature off).
//   - any other failure, within GroupsDegradedGrace of the last successful
//     resolution anywhere in the process: return the stored tenant groups
//     with "admins" recomputed fresh, and log a warning. A resolver outage
//     is tolerated for a bounded window rather than either defeating a
//     removal forever or logging every session out on a single failed
//     git fetch.
//   - any other failure, beyond that grace window: fail closed to
//     admins-only, and log a warning. This is the bound that keeps a
//     resolver outage from defeating a tenant removal for longer than one
//     access-token TTL.
func (s *OAuthServer) groupsForSession(login string, stored []string) []string {
	groups, _ := s.sessionGroups(login, stored)
	return groups
}

// sessionGroups is groupsForSession that also reports whether the result is
// a fresh resolution (true), as opposed to the stored groups passed through
// or a degraded/fail-closed fallback (false).
func (s *OAuthServer) sessionGroups(login string, stored []string) ([]string, bool) {
	groups, err := s.resolveGroupsChecked(login)
	if err == nil {
		return groups, true
	}
	if errors.Is(err, errResolverNotConfigured) {
		return stored, false
	}
	// Busy says nothing about resolver health: we chose not to wait on an
	// in-progress gitops refresh. Within grace the session's groups are used
	// as-is. Beyond grace the snapshot is no longer trustworthy, but a busy
	// resolver can still answer, so wait for it -- boundedly, since a refresh
	// whose git fetch hangs holds the lock for up to gitCommandTimeout. Only
	// if it stays busy does this fall through to the fail-closed branch, so
	// a persistently locked reader cannot defeat a tenant removal (and the
	// first request after an idle spell, landing inside a normal short
	// refresh, is still answered correctly rather than failed closed).
	if errors.Is(err, errResolverBusy) {
		if time.Since(s.lastResolveOKTime()) <= s.degradedGrace() {
			slog.Debug("oauth: gitops refresh in progress; using session's tenant groups", "user", login)
			return s.withAdmins(login, tenantsOnly(stored)), false
		}
		if groups, err = s.awaitBusyResolver(login); err == nil {
			return groups, true
		}
	}
	if time.Since(s.lastResolveOKTime()) <= s.degradedGrace() {
		if s.degradedWarn.allow(groupsWarnInterval) {
			slog.Warn("oauth: group resolution degraded; using stored tenant groups", "user", login, "error", err)
		}
		return s.withAdmins(login, tenantsOnly(stored)), false
	}
	if s.failClosedWarn.allow(groupsWarnInterval) {
		slog.Warn("oauth: group resolution unavailable beyond grace; dropping tenant groups", "user", login, "error", err)
	}
	return s.withAdmins(login, nil), false
}

// awaitBusyResolver retries a non-blocking resolution while the resolver
// reports busy, for at most busyWaitLimit, and returns the last result.
func (s *OAuthServer) awaitBusyResolver(login string) ([]string, error) {
	deadline := time.Now().Add(busyWaitLimit)
	for {
		time.Sleep(busyPollInterval)
		groups, err := s.resolveGroups(login, false)
		if !errors.Is(err, errResolverBusy) || !time.Now().Before(deadline) {
			return groups, err
		}
	}
}

// IsRedirectURIAllowed returns true if uri is in the static whitelist, is a
// loopback callback, or was registered by the client identified by clientID.
// Allowlist entries ending with "/*" are treated as prefix matches
// (e.g. "https://chatgpt.com/connector/oauth/*" matches any path under that prefix).
//
// The clientID scope matters. This used to search every registered client's
// URIs, so any one registration vouched for a URI on behalf of all of them:
// with open dynamic registration, an attacker could register a client pointing
// at their own callback and then start a flow under a privileged client's ID
// with that callback, and the code would be delivered to them. PKCE is no help
// there — whoever starts the flow chooses the challenge. Registrations are now
// only honoured for the client that made them.
func (s *OAuthServer) IsRedirectURIAllowed(clientID, uri string) bool {
	// A pre-registered client trusts the callbacks it lists and nothing else:
	// not the global allowlist, not the loopback rule. That is the property
	// static registration exists to give -- onboarding one counterpart must
	// not let its id be used with a callback it never registered -- so it is
	// decided here, before either general rule can answer for it.
	if uris, ok := s.staticRedirectURIs(clientID); ok {
		return slices.Contains(uris, uri)
	}
	for _, allowed := range s.AllowedRedirectURIs {
		if strings.HasSuffix(allowed, "/*") {
			if strings.HasPrefix(uri, strings.TrimSuffix(allowed, "*")) {
				return true
			}
		} else if allowed == uri {
			return true
		}
	}
	// Loopback redirects (RFC 8252 §7.3). A native app — the mctl CLI, Claude
	// Code — binds an ephemeral port and cannot know it ahead of registration,
	// so the port must not take part in the comparison and no static allowlist
	// entry can cover it. Without this, such a client works only until its
	// registration is gone -- a restart of the in-memory registry, or expiry
	// or eviction in either registry -- while the client keeps its cached
	// client_id and never re-registers, leaving authorize permanently at 400.
	//
	// Safe because the code is useless on its own: ExchangeCode verifies PKCE,
	// so a listener that intercepts a redirect on the user's own machine still
	// cannot redeem it without the verifier.
	if isLoopbackRedirectURI(uri) {
		return true
	}

	// Only this client's own registration counts.
	c, ok := s.GetClient(clientID)
	if !ok {
		return false
	}
	for _, u := range c.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}

// isLoopbackRedirectURI reports whether uri is a loopback redirect as described
// by RFC 8252 §7.3 — an http:// URI whose host is the local machine.
//
// The port is deliberately not examined: the whole point of the loopback flow is
// that the app picks a free port at runtime. The scheme is pinned to http
// because loopback listeners are plain HTTP by design, and https:// on a
// loopback host would be a sign of something other than this flow.
//
// "localhost" is accepted alongside the IP literals for compatibility with
// clients that use the name — RFC 8252 prefers the literals, since "localhost"
// resolves through the host's name resolution and could in principle be
// pointed elsewhere.
func isLoopbackRedirectURI(uri string) bool {
	// A backslash is not a valid URI character. Some user agents treat it as a
	// path separator while others (historically including Go) treated it as
	// userinfo, which is the classic allowlist/browser split that turns a
	// loopback check into an open redirect. Reject before parsing so the two
	// never get a chance to disagree.
	if strings.ContainsRune(uri, '\\') {
		return false
	}
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "http" {
		return false
	}
	// Userinfo has no place in a loopback callback, and accepting it would let
	// http://evil.com@localhost/callback pass the host check (Go's host is
	// localhost; some agents still treat the left of @ as the authority).
	if u.User != nil {
		return false
	}
	// Host names are case-insensitive (RFC 3986 §3.2.2) but url.Parse preserves
	// the case it was given, so "LOCALHOST" would otherwise miss.
	switch strings.ToLower(u.Hostname()) {
	case "127.0.0.1", "::1", "localhost":
		return true
	default:
		return false
	}
}

// GenerateState creates a secure random state value for CSRF protection.
func GenerateState() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Upstream identity providers an authorization can be started for. A
// pending authorization records its upstream, and each callback completes
// only its own (mctl-api#467).
const (
	UpstreamGitHub  = "github"
	UpstreamZitadel = "zitadel"
)

// StorePendingAuth stores a pending authorization keyed by opaque state,
// before the user has authenticated with GitHub.
func (s *OAuthServer) StorePendingAuth(ctx context.Context, state, clientID, redirectURI, codeChallenge string) error {
	return s.storePending(ctx, state, pendingAuth{
		Upstream:      UpstreamGitHub,
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		CodeChallenge: codeChallenge,
		CreatedAt:     time.Now(),
	})
}

// PendingOIDCAuth is an authorization whose user signs in at an OIDC
// upstream. Nonce and Verifier belong to that upstream leg; ClientState is
// the client's own state, returned with the code.
type PendingOIDCAuth struct {
	Upstream      string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	ClientState   string
	Nonce         string
	Verifier      string
}

// StorePendingOIDCAuth stores a pending authorization under the state sent
// to the OIDC upstream.
func (s *OAuthServer) StorePendingOIDCAuth(ctx context.Context, state string, a PendingOIDCAuth) error {
	return s.storePending(ctx, state, pendingAuth{
		Upstream:      a.Upstream,
		ClientID:      a.ClientID,
		RedirectURI:   a.RedirectURI,
		CodeChallenge: a.CodeChallenge,
		ClientState:   a.ClientState,
		Nonce:         a.Nonce,
		Verifier:      a.Verifier,
		CreatedAt:     time.Now(),
	})
}

func (s *OAuthServer) storePending(ctx context.Context, state string, p pendingAuth) error {
	if s.FlowStore == nil {
		s.codes.storePending(state, p)
		return nil
	}
	if err := putFlow(ctx, s.FlowStore, flowstore.KindPending, state, p, p.CreatedAt.Add(pendingAuthTTL)); err != nil {
		slog.Error("oauth: flow store put pending failed", "error", err)
		return fmt.Errorf("store pending authorization: %w", ErrServerError)
	}
	return nil
}

// LoadPendingAuth returns and removes the pending auth entry for a state
// value. ok is false for an unknown or expired state; err is set only when
// the shared store could not be read, which is not the same answer and maps
// to a server error rather than "invalid state".
func (s *OAuthServer) LoadPendingAuth(ctx context.Context, state string) (pendingAuth, bool, error) {
	if s.FlowStore == nil {
		p, ok := s.codes.loadPending(state)
		return p, ok, nil
	}
	var p pendingAuth
	ok, err := takeFlow(ctx, s.FlowStore, flowstore.KindPending, state, &p)
	if err != nil {
		slog.Error("oauth: flow store take pending failed", "error", err)
		return pendingAuth{}, false, fmt.Errorf("load pending authorization: %w", ErrServerError)
	}
	if !ok || time.Since(p.CreatedAt) > pendingAuthTTL {
		return pendingAuth{}, false, nil
	}
	return p, true, nil
}

// IssueCode generates a random authorization code for a GitHub login.
// The code is stored alongside the PKCE challenge for later verification.
func (s *OAuthServer) IssueCode(login, clientID, redirectURI, codeChallenge string, groups []string) (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate code: %w", err)
	}
	code := base64.RawURLEncoding.EncodeToString(b)
	entry := authCodeEntry{
		Login:         login,
		Groups:        groups,
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		CodeChallenge: codeChallenge,
		CreatedAt:     time.Now(),
	}
	if s.FlowStore == nil {
		s.codes.store(code, entry)
		return code, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), flowStoreTimeout)
	defer cancel()
	if err := putFlow(ctx, s.FlowStore, flowstore.KindCode, code, entry, entry.CreatedAt.Add(authCodeTTL)); err != nil {
		slog.Error("oauth: flow store put code failed", "error", err)
		return "", fmt.Errorf("store authorization code: %w", ErrServerError)
	}
	return code, nil
}

// takeCode consumes an authorization code from whichever store holds codes.
func (s *OAuthServer) takeCode(code string) (authCodeEntry, bool, error) {
	if s.FlowStore == nil {
		e, ok := s.codes.loadAndDelete(code)
		return e, ok, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), flowStoreTimeout)
	defer cancel()
	var e authCodeEntry
	ok, err := takeFlow(ctx, s.FlowStore, flowstore.KindCode, code, &e)
	if err != nil {
		slog.Error("oauth: flow store take code failed", "error", err)
		return authCodeEntry{}, false, fmt.Errorf("redeem authorization code: %w", ErrServerError)
	}
	if !ok || time.Since(e.CreatedAt) > authCodeTTL {
		return authCodeEntry{}, false, nil
	}
	return e, true, nil
}

// flowStoreTimeout bounds one shared-store round trip on the sign-in path.
const flowStoreTimeout = 5 * time.Second

func putFlow(ctx context.Context, st flowstore.Store, kind, key string, v any, expiresAt time.Time) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", kind, err)
	}
	return st.Put(ctx, kind, key, payload, expiresAt)
}

// takeFlow decodes a taken entry into v. A payload that does not decode is a
// failed read, not an absent entry.
func takeFlow(ctx context.Context, st flowstore.Store, kind, key string, v any) (bool, error) {
	payload, ok, err := st.Take(ctx, kind, key)
	if err != nil || !ok {
		return false, err
	}
	if err := json.Unmarshal(payload, v); err != nil {
		return false, fmt.Errorf("decode %s: %w", kind, err)
	}
	return true, nil
}

// ExchangeCode validates an authorization code + PKCE verifier and returns a signed JWT.
// The code is consumed (one-time use).
func (s *OAuthServer) ExchangeCode(code, codeVerifier, clientID, redirectURI string) (string, string, error) {
	entry, ok, err := s.takeCode(code)
	if err != nil {
		return "", "", err
	}
	if !ok {
		return "", "", errors.New("invalid or expired authorization code")
	}
	if entry.ClientID != clientID {
		return "", "", errors.New("client_id mismatch")
	}
	if entry.RedirectURI != redirectURI {
		return "", "", errors.New("redirect_uri mismatch")
	}
	if !verifyPKCE(codeVerifier, entry.CodeChallenge) {
		return "", "", errors.New("PKCE verification failed")
	}
	accessToken, err := s.IssueJWT(entry.Login, entry.Groups)
	if err != nil {
		return "", "", err
	}
	refreshToken, err := s.IssueRefreshToken(entry.Login, entry.Groups, clientID)
	if err != nil {
		return "", "", err
	}
	s.touchClient(clientID)
	return accessToken, refreshToken, nil
}

// IssueJWT creates a signed JWT access token for the given user.
func (s *OAuthServer) IssueJWT(login string, groups []string) (string, error) {
	ttl := s.AccessTokenTTL
	if ttl == 0 {
		ttl = time.Hour
	}
	now := time.Now()
	payload := jwtPayload{
		Issuer:    s.BaseURL,
		Subject:   login,
		Groups:    groups,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
	}
	return signJWT(payload, s.JWTSecret)
}

// IssueRefreshToken creates and stores a refresh token for the given user and client.
func (s *OAuthServer) IssueRefreshToken(login string, groups []string, clientID string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate refresh token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	ttl := s.RefreshTokenTTL
	if ttl == 0 {
		ttl = 30 * 24 * time.Hour
	}
	expiresAt := time.Now().Add(ttl)
	if s.RefreshStore != nil {
		if err := s.RefreshStore.Insert(token, login, clientID, groups, expiresAt); err != nil {
			slog.Error("oauth: refresh store insert failed", "error", err)
			return "", fmt.Errorf("store refresh token: %w", ErrServerError)
		}
		return token, nil
	}
	s.refreshTokens.store(token, refreshTokenEntry{
		Login:     login,
		Groups:    groups,
		ClientID:  clientID,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	})
	return token, nil
}

// RefreshAccessToken validates a refresh token, rotates it, and issues a new access token.
func (s *OAuthServer) RefreshAccessToken(refreshToken, clientID string) (string, string, error) {
	if s.RefreshStore != nil {
		newToken := deriveSuccessorRefreshToken(s.JWTSecret, refreshToken)
		ttl := s.RefreshTokenTTL
		if ttl == 0 {
			ttl = 30 * 24 * time.Hour
		}
		login, storedGroups, err := s.RefreshStore.Rotate(refreshToken, newToken, clientID, time.Now().Add(ttl))
		if err != nil {
			// Map store errors to the same string used by the in-memory path so
			// oauth_handlers.go doesn't need to import the refreshstore package.
			if errors.Is(err, refreshstore.ErrInvalidToken) || errors.Is(err, refreshstore.ErrReuseDetected) {
				return "", "", errors.New("invalid or expired refresh token")
			}
			if errors.Is(err, refreshstore.ErrClientMismatch) {
				return "", "", errors.New("client_id mismatch")
			}
			slog.Error("oauth: refresh store unexpected error", "error", err)
			return "", "", fmt.Errorf("oauth: %w", ErrServerError)
		}
		// The row rotate() just wrote still carries storedGroups verbatim --
		// refreshstore.Store.Rotate has no parameter for new groups, and
		// adding one would change the interface, the PostgresStore schema and
		// the in-flight-rotation grace path (design.md "Both refresh paths").
		// That snapshot's staleness is no longer load-bearing because
		// groupsForSession re-resolves it here, bounded by the degraded-grace
		// fallback when resolution fails.
		groups := s.groupsForSession(login, storedGroups)
		accessToken, err := s.IssueJWT(login, groups)
		if err != nil {
			return "", "", err
		}
		s.touchClient(clientID)
		return accessToken, newToken, nil
	}

	entry, ok := s.refreshTokens.loadAndDelete(refreshToken)
	if !ok {
		return "", "", errors.New("invalid or expired refresh token")
	}
	if entry.ClientID != clientID {
		return "", "", errors.New("client_id mismatch")
	}
	// The successor row records the groups only when they are a fresh
	// resolution. A degraded or fail-closed fallback must not overwrite the
	// snapshot: that would leave the next outage nothing to fall back on
	// (the store path never overwrites it, since Rotate carries it forward).
	groups, fresh := s.sessionGroups(entry.Login, entry.Groups)
	accessToken, err := s.IssueJWT(entry.Login, groups)
	if err != nil {
		return "", "", err
	}
	snapshot := entry.Groups
	if fresh {
		snapshot = groups
	}
	newRefreshToken, err := s.IssueRefreshToken(entry.Login, snapshot, clientID)
	if err != nil {
		return "", "", err
	}
	s.touchClient(clientID)
	return accessToken, newRefreshToken, nil
}

// RevokeRefreshToken revokes a stored refresh token (and its whole family when
// the persistent store is active — see refreshstore.Store).
// clientID scopes the revocation to tokens issued for that client; pass ""
// to revoke unconditionally (in-memory fallback, or when client is unknown).
func (s *OAuthServer) RevokeRefreshToken(refreshToken, clientID string) {
	if refreshToken == "" {
		return
	}
	if s.RefreshStore != nil {
		if err := s.RefreshStore.RevokeFamily(refreshToken, clientID, "explicit_revoke"); err != nil {
			slog.Warn("oauth: failed to revoke refresh token family", "error", err)
		}
		return
	}
	s.refreshTokens.delete(refreshToken)
}

// ValidateJWT validates a JWT issued by this server and returns the User.
func (s *OAuthServer) ValidateJWT(token string) (*User, error) {
	payload, err := verifyJWT(token, s.JWTSecret, s.BaseURL)
	if err != nil {
		return nil, err
	}
	// The subject is the GitHub login the OAuth callback validated before
	// IssueCode; this server mints for no other identity provider. The
	// groups claim is retained on the token for compatibility and as the
	// degraded fallback (groupsForSession), not as the authority: it is
	// re-resolved here on every validation, which is what lets a same-session
	// tenant grant or removal reach a live session without waiting for the
	// access token to expire (requirements.md, the reported "karabu" case).
	return NewGitHubUser(payload.Subject, s.groupsForSession(payload.Subject, payload.Groups)), nil
}

// ─── PKCE ─────────────────────────────────────────────────────────────────────

// verifyPKCE checks that SHA256(verifier) == challenge (base64url-encoded).
func verifyPKCE(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	h := sha256.New()
	h.Write([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return hmac.Equal([]byte(computed), []byte(challenge))
}

// ─── Minimal JWT (HMAC-SHA256, no external library) ───────────────────────────

var jwtHeader = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

type jwtPayload struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Groups    []string `json:"groups"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
}

func signJWT(payload jwtPayload, secret []byte) (string, error) {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	sigInput := jwtHeader + "." + payloadB64
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(sigInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return sigInput + "." + sig, nil
}

func verifyJWT(token string, secret []byte, expectedIssuer string) (*jwtPayload, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed JWT")
	}
	sigInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(sigInput))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expectedSig), []byte(parts[2])) {
		return nil, errors.New("invalid JWT signature")
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("malformed JWT payload")
	}
	var payload jwtPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, errors.New("malformed JWT payload")
	}
	if payload.Issuer != expectedIssuer {
		return nil, fmt.Errorf("unexpected JWT issuer: %q", payload.Issuer)
	}
	if time.Now().Unix() > payload.ExpiresAt {
		return nil, errors.New("JWT expired")
	}
	return &payload, nil
}

// ─── Auth code storage ────────────────────────────────────────────────────────

const authCodeTTL = 10 * time.Minute
const pendingAuthTTL = 5 * time.Minute

type authCodeEntry struct {
	Login         string
	Groups        []string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	CreatedAt     time.Time
}

type pendingAuth struct {
	// Upstream is the identity provider this authorization was sent to
	// (UpstreamGitHub, UpstreamZitadel).
	Upstream      string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	// ClientState, Nonce and Verifier are set for an OIDC upstream only.
	ClientState string
	Nonce       string
	Verifier    string
	CreatedAt   time.Time
}

type refreshTokenEntry struct {
	Login     string
	Groups    []string
	ClientID  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type authCodeStore struct {
	codes   sync.Map // code → authCodeEntry
	pending sync.Map // state → pendingAuth
}

type refreshTokenStore struct {
	tokens sync.Map // token → refreshTokenEntry
}

func (s *authCodeStore) init() {
	go s.gcLoop()
}

func (s *authCodeStore) store(code string, e authCodeEntry) {
	s.codes.Store(code, e)
}

func (s *authCodeStore) loadAndDelete(code string) (authCodeEntry, bool) {
	v, ok := s.codes.LoadAndDelete(code)
	if !ok {
		return authCodeEntry{}, false
	}
	e := v.(authCodeEntry)
	if time.Since(e.CreatedAt) > authCodeTTL {
		return authCodeEntry{}, false
	}
	return e, true
}

func (s *authCodeStore) storePending(state string, p pendingAuth) {
	s.pending.Store(state, p)
}

func (s *authCodeStore) loadPending(state string) (pendingAuth, bool) {
	v, ok := s.pending.LoadAndDelete(state)
	if !ok {
		return pendingAuth{}, false
	}
	p := v.(pendingAuth)
	if time.Since(p.CreatedAt) > pendingAuthTTL {
		return pendingAuth{}, false
	}
	return p, true
}

func (s *authCodeStore) gcLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.codes.Range(func(k, v any) bool {
			if time.Since(v.(authCodeEntry).CreatedAt) > authCodeTTL {
				s.codes.Delete(k)
			}
			return true
		})
		s.pending.Range(func(k, v any) bool {
			if time.Since(v.(pendingAuth).CreatedAt) > pendingAuthTTL {
				s.pending.Delete(k)
			}
			return true
		})
	}
}

func (s *refreshTokenStore) init() {
	go s.gcLoop()
}

func (s *refreshTokenStore) store(token string, entry refreshTokenEntry) {
	s.tokens.Store(token, entry)
}

func (s *refreshTokenStore) loadAndDelete(token string) (refreshTokenEntry, bool) {
	v, ok := s.tokens.LoadAndDelete(token)
	if !ok {
		return refreshTokenEntry{}, false
	}
	entry := v.(refreshTokenEntry)
	if time.Now().After(entry.ExpiresAt) {
		return refreshTokenEntry{}, false
	}
	return entry, true
}

func (s *refreshTokenStore) delete(token string) {
	s.tokens.Delete(token)
}

func (s *refreshTokenStore) gcLoop() {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.tokens.Range(func(k, v any) bool {
			if time.Now().After(v.(refreshTokenEntry).ExpiresAt) {
				s.tokens.Delete(k)
			}
			return true
		})
	}
}
