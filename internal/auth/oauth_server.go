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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth/refreshstore"
)

// ErrServerError is returned by OAuth server operations that fail due to a
// transient infrastructure problem (e.g. database unavailability) rather than
// an invalid token or client credential. Token-endpoint handlers must respond
// with HTTP 500 / error:"server_error" when they encounter this sentinel.
var ErrServerError = errors.New("server_error")

// OAuthServer implements OAuth 2.0 Authorization Code flow with PKCE (RFC 7636).
// It acts as a public-client OAuth server backed by GitHub for user authentication.
// Access tokens are short-lived JWTs signed with HMAC-SHA256.
type OAuthServer struct {
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

	// RefreshStore is an optional persistent store for refresh tokens.
	// When non-nil it replaces the in-memory refreshTokens store, making
	// refresh tokens survive pod restarts. Inject via main.go after construction.
	RefreshStore refreshstore.Store

	codes         authCodeStore
	refreshTokens refreshTokenStore
	clients       sync.Map // clientID → RegisteredClient (RFC 7591)
}

// RegisteredClient stores a dynamically registered OAuth client (RFC 7591).
type RegisteredClient struct {
	ClientID     string    `json:"client_id"`
	ClientName   string    `json:"client_name,omitempty"`
	RedirectURIs []string  `json:"redirect_uris"`
	CreatedAt    time.Time `json:"client_id_issued_at,omitempty"`
}

// RegisterClient stores a dynamically registered client and returns the assigned client_id.
func (s *OAuthServer) RegisterClient(name string, redirectURIs []string) RegisteredClient {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	clientID := base64.RawURLEncoding.EncodeToString(b)

	client := RegisteredClient{
		ClientID:     clientID,
		ClientName:   name,
		RedirectURIs: redirectURIs,
		CreatedAt:    time.Now(),
	}
	s.clients.Store(clientID, client)
	return client
}

// GetClient returns a registered client by ID, or false if not found.
func (s *OAuthServer) GetClient(clientID string) (RegisteredClient, bool) {
	v, ok := s.clients.Load(clientID)
	if !ok {
		return RegisteredClient{}, false
	}
	return v.(RegisteredClient), true
}

// NewOAuthServer creates a ready-to-use OAuthServer with sensible defaults.
func NewOAuthServer(baseURL, ghClientID, ghClientSecret string, jwtSecret []byte, allowedRedirectURIs []string, ghValidator *GitHubValidator) *OAuthServer {
	s := &OAuthServer{
		BaseURL:             baseURL,
		GitHubClientID:      ghClientID,
		GitHubClientSecret:  ghClientSecret,
		JWTSecret:           jwtSecret,
		AllowedRedirectURIs: allowedRedirectURIs,
		AccessTokenTTL:      7 * 24 * time.Hour,
		RefreshTokenTTL:     30 * 24 * time.Hour,
		GitHubValidator:     ghValidator,
	}
	s.codes.init()
	s.refreshTokens.init()
	return s
}

// ResolveGroups resolves the tenant groups for a GitHub login.
func (s *OAuthServer) ResolveGroups(login string) []string {
	var groups []string
	if s.GitHubValidator.IsAdmin(login) {
		groups = append(groups, "admins")
	}
	if s.TenantResolver != nil {
		tenants, err := s.TenantResolver.GetTenantsForUser(login)
		if err == nil {
			groups = append(groups, tenants...)
		}
	}
	return groups
}

// IsRedirectURIAllowed returns true if uri is in the static whitelist
// or was registered by a dynamic client (RFC 7591).
// Allowlist entries ending with "/*" are treated as prefix matches
// (e.g. "https://chatgpt.com/connector/oauth/*" matches any path under that prefix).
func (s *OAuthServer) IsRedirectURIAllowed(uri string) bool {
	for _, allowed := range s.AllowedRedirectURIs {
		if strings.HasSuffix(allowed, "/*") {
			if strings.HasPrefix(uri, strings.TrimSuffix(allowed, "*")) {
				return true
			}
		} else if allowed == uri {
			return true
		}
	}
	// Check dynamically registered clients.
	found := false
	s.clients.Range(func(_, v any) bool {
		c := v.(RegisteredClient)
		for _, u := range c.RedirectURIs {
			if u == uri {
				found = true
				return false // stop iteration
			}
		}
		return true
	})
	return found
}

// GenerateState creates a secure random state value for CSRF protection.
func GenerateState() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// StoreAuthCode stores a pending authorization code entry keyed by opaque state,
// before the user has authenticated with GitHub.
func (s *OAuthServer) StorePendingAuth(state, clientID, redirectURI, codeChallenge string) {
	s.codes.storePending(state, pendingAuth{
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		CodeChallenge: codeChallenge,
		CreatedAt:     time.Now(),
	})
}

// LoadPendingAuth returns and removes the pending auth entry for a state value.
func (s *OAuthServer) LoadPendingAuth(state string) (pendingAuth, bool) {
	return s.codes.loadPending(state)
}

// IssueCode generates a random authorization code for a GitHub login.
// The code is stored alongside the PKCE challenge for later verification.
func (s *OAuthServer) IssueCode(login, clientID, redirectURI, codeChallenge string, groups []string) (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate code: %w", err)
	}
	code := base64.RawURLEncoding.EncodeToString(b)
	s.codes.store(code, authCodeEntry{
		Login:         login,
		Groups:        groups,
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		CodeChallenge: codeChallenge,
		CreatedAt:     time.Now(),
	})
	return code, nil
}

// ExchangeCode validates an authorization code + PKCE verifier and returns a signed JWT.
// The code is consumed (one-time use).
func (s *OAuthServer) ExchangeCode(code, codeVerifier, clientID, redirectURI string) (string, string, error) {
	entry, ok := s.codes.loadAndDelete(code)
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
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return "", "", fmt.Errorf("generate refresh token: %w", err)
		}
		newToken := base64.RawURLEncoding.EncodeToString(b)
		ttl := s.RefreshTokenTTL
		if ttl == 0 {
			ttl = 30 * 24 * time.Hour
		}
		login, groups, err := s.RefreshStore.Rotate(refreshToken, newToken, clientID, time.Now().Add(ttl))
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
		accessToken, err := s.IssueJWT(login, groups)
		if err != nil {
			return "", "", err
		}
		return accessToken, newToken, nil
	}

	entry, ok := s.refreshTokens.loadAndDelete(refreshToken)
	if !ok {
		return "", "", errors.New("invalid or expired refresh token")
	}
	if entry.ClientID != clientID {
		return "", "", errors.New("client_id mismatch")
	}
	accessToken, err := s.IssueJWT(entry.Login, entry.Groups)
	if err != nil {
		return "", "", err
	}
	newRefreshToken, err := s.IssueRefreshToken(entry.Login, entry.Groups, clientID)
	if err != nil {
		return "", "", err
	}
	return accessToken, newRefreshToken, nil
}

// RevokeRefreshToken revokes a stored refresh token (and its whole family when
// the persistent store is active — see refreshstore.Store).
func (s *OAuthServer) RevokeRefreshToken(refreshToken string) {
	if refreshToken == "" {
		return
	}
	if s.RefreshStore != nil {
		if err := s.RefreshStore.RevokeFamily(refreshToken, "explicit_revoke"); err != nil {
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
	return &User{
		ID:     payload.Subject,
		Groups: payload.Groups,
	}, nil
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
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	CreatedAt     time.Time
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
