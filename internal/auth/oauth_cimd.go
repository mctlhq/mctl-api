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
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth/cimd"
	"github.com/mctlhq/mctl-api/internal/auth/flowstore"
)

// Client kinds recorded in the oauth.grant_issued audit entry. The kind is
// computed from the client_id and the server's own registries, never from a
// metadata document.
const (
	ClientKindStatic      = "static"
	ClientKindDCR         = "dcr"
	ClientKindCIMD        = "cimd"
	ClientKindAllowlisted = "allowlisted"
)

// consentTTL is how long a consent decision may wait for the human.
const consentTTL = 5 * time.Minute

// CIMDEnabled reports whether Client ID Metadata Documents are resolved.
func (s *OAuthServer) CIMDEnabled() bool { return s != nil && s.CIMD != nil }

// CIMDAdvertised reports whether discovery announces CIMD: only while it is
// resolved and OAUTH_CIMD_ADVERTISE is on.
func (s *OAuthServer) CIMDAdvertised() bool { return s.CIMDEnabled() && s.CIMDAdvertise }

// IsCIMDClient reports whether clientID is handled as a CIMD client.
func (s *OAuthServer) IsCIMDClient(clientID string) bool {
	return s != nil && s.CIMD != nil && cimd.IsCIMDURL(clientID) && !s.isStatic(clientID)
}

// ResolveCIMDClient returns the client a CIMD client_id names, from its
// (cached) metadata document.
func (s *OAuthServer) ResolveCIMDClient(ctx context.Context, clientID string) (RegisteredClient, error) {
	if !s.IsCIMDClient(clientID) {
		return RegisteredClient{}, fmt.Errorf("%w: not a CIMD client", cimd.ErrInvalidDocument)
	}
	doc, err := s.CIMD.Resolve(ctx, clientID)
	if err != nil {
		return RegisteredClient{}, err
	}
	return RegisteredClient{ClientID: doc.ClientID, ClientName: doc.ClientName, RedirectURIs: doc.RedirectURIs}, nil
}

// ClientKind classifies clientID for audit: static, cimd, dcr or
// allowlisted. It never fetches and never reads a document.
func (s *OAuthServer) ClientKind(clientID string) string {
	switch {
	case s.isStatic(clientID):
		return ClientKindStatic
	case s.IsCIMDClient(clientID):
		return ClientKindCIMD
	case isDerivedClientID(clientID):
		return ClientKindDCR
	}
	s.clientsMu.Lock()
	_, ok := s.clients[clientID]
	s.clientsMu.Unlock()
	if ok {
		return ClientKindDCR
	}
	return ClientKindAllowlisted
}

// ConsentEntry is an authorization completed at the upstream and waiting for
// the human's decision. The principal is the upstream's; nothing here comes
// from a client document.
type ConsentEntry struct {
	Login         string
	PrincipalID   string
	Groups        []string
	ClientID      string
	ClientName    string
	RedirectURI   string
	CodeChallenge string
	ClientState   []byte
	Upstream      string
	// BrowserHash is the SHA-256 (hex) of the consent token, held by the
	// browser that signed in as a cookie.
	BrowserHash string
}

type consentMem struct {
	e       ConsentEntry
	expires time.Time
}

// NewConsentToken returns a random 256-bit single-use token.
func NewConsentToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// StoreConsent keeps e under token for consentTTL.
func (s *OAuthServer) StoreConsent(ctx context.Context, token string, e ConsentEntry) error {
	if s.FlowStore == nil {
		now := time.Now()
		s.consents.Range(func(k, v any) bool {
			if now.After(v.(consentMem).expires) {
				s.consents.Delete(k)
			}
			return true
		})
		s.consents.Store(token, consentMem{e: e, expires: now.Add(consentTTL)})
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, flowStoreTimeout)
	defer cancel()
	if err := putFlow(ctx, s.FlowStore, flowstore.KindConsent, token, e, consentTTL); err != nil {
		slog.Error("oauth: flow store put consent failed", "error", err)
		return fmt.Errorf("store consent: %w", ErrServerError)
	}
	return nil
}

// TakeConsent removes and returns the entry for token. ok is false for an
// unknown, replayed or expired token; err only when the store failed.
func (s *OAuthServer) TakeConsent(ctx context.Context, token string) (ConsentEntry, bool, error) {
	if s.FlowStore == nil {
		v, ok := s.consents.LoadAndDelete(token)
		if !ok {
			return ConsentEntry{}, false, nil
		}
		m := v.(consentMem)
		if time.Now().After(m.expires) {
			return ConsentEntry{}, false, nil
		}
		return m.e, true, nil
	}
	ctx, cancel := context.WithTimeout(ctx, flowStoreTimeout)
	defer cancel()
	var e ConsentEntry
	ok, err := takeFlow(ctx, s.FlowStore, flowstore.KindConsent, token, &e)
	if err != nil {
		slog.Error("oauth: flow store take consent failed", "error", err)
		return ConsentEntry{}, false, fmt.Errorf("take consent: %w", ErrServerError)
	}
	return e, ok, nil
}

// ClientAssertionTypeJWT is the only client_assertion_type accepted (RFC 7523
// section 2.2).
const ClientAssertionTypeJWT = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// ClientAssertion is the client authentication a token request carries
// (client_assertion_type and client_assertion). Both empty means none.
type ClientAssertion struct {
	Type      string
	Assertion string
}

func (ca ClientAssertion) present() bool { return ca.Type != "" || ca.Assertion != "" }

// AssertionAudiences are the aud values a client assertion may carry: the
// issuer or the token endpoint URL, compared as exact strings.
func (s *OAuthServer) AssertionAudiences() []string {
	if s.BaseURL == "" {
		return nil
	}
	return []string{s.BaseURL, s.BaseURL + "/oauth/token"}
}

// authenticateClient checks the client authentication of a token request
// and returns the method it satisfied. Every client but a private_key_jwt
// CIMD client is public and must send no assertion; a private_key_jwt client
// must send a valid one, every time. A CIMD client_id is refused while CIMD
// is off: without its document the required method is unknown, and unknown
// is never served as none.
func (s *OAuthServer) authenticateClient(ctx context.Context, clientID string, ca ClientAssertion) (string, error) {
	if !s.IsCIMDClient(clientID) {
		if cimd.IsCIMDURL(clientID) && !s.isStatic(clientID) {
			return "", fmt.Errorf("%w: client metadata documents are not accepted", ErrInvalidClient)
		}
		if ca.present() {
			return "", fmt.Errorf("%w: public client must not send a client assertion", ErrInvalidClient)
		}
		return cimd.AuthMethodNone, nil
	}
	doc, err := s.CIMD.Resolve(ctx, clientID)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidClient, err)
	}
	switch doc.AuthMethod {
	case cimd.AuthMethodNone:
		if ca.present() {
			return "", fmt.Errorf("%w: client declares none and must not send a client assertion", ErrInvalidClient)
		}
		return cimd.AuthMethodNone, nil
	case cimd.AuthMethodPrivateKeyJWT:
		if ca.Type != ClientAssertionTypeJWT || ca.Assertion == "" {
			return "", fmt.Errorf("%w: private_key_jwt client must send client_assertion_type %s and client_assertion", ErrInvalidClient, ClientAssertionTypeJWT)
		}
		auds := s.AssertionAudiences()
		if len(auds) == 0 {
			return "", fmt.Errorf("%w: no issuer configured to check aud against", ErrInvalidClient)
		}
		a, err := s.CIMD.VerifyAssertion(ctx, doc, ca.Assertion, auds)
		if err != nil {
			return "", fmt.Errorf("%w: %w", ErrInvalidClient, err)
		}
		if err := s.consumeJTI(ctx, clientID, a); err != nil {
			return "", err
		}
		return cimd.AuthMethodPrivateKeyJWT, nil
	}
	return "", fmt.Errorf("%w: unsupported token_endpoint_auth_method %q", ErrInvalidClient, doc.AuthMethod)
}

// errJTIReplayed is a client assertion whose jti was already used.
var errJTIReplayed = errors.New("client assertion jti was already used")

// consumeJTI records a's jti for its remaining lifetime, refusing one already
// recorded. The shared store makes that hold across replicas; a store that
// cannot be read or written is a server error, never a pass.
func (s *OAuthServer) consumeJTI(ctx context.Context, clientID string, a cimd.Assertion) error {
	key := clientID + "\x00" + a.JTI
	ttl := max(a.RememberFor, time.Second)
	if s.FlowStore == nil {
		now := time.Now()
		s.jtis.Range(func(k, v any) bool {
			if now.After(v.(time.Time)) {
				s.jtis.Delete(k)
			}
			return true
		})
		if _, loaded := s.jtis.LoadOrStore(key, now.Add(ttl)); loaded {
			return fmt.Errorf("%w: %w", ErrInvalidClient, errJTIReplayed)
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, flowStoreTimeout)
	defer cancel()
	fresh, err := s.FlowStore.PutOnce(ctx, flowstore.KindJTI, key, []byte("{}"), ttl)
	if err != nil {
		slog.Error("oauth: flow store put jti failed", "error", err)
		return fmt.Errorf("record client assertion: %w", ErrServerError)
	}
	if !fresh {
		return fmt.Errorf("%w: %w", ErrInvalidClient, errJTIReplayed)
	}
	return nil
}

// TokenEndpointAuthMethods lists the token endpoint authentication methods
// this server accepts, for discovery.
func (s *OAuthServer) TokenEndpointAuthMethods() []string {
	if s.CIMDEnabled() {
		return []string{cimd.AuthMethodNone, cimd.AuthMethodPrivateKeyJWT}
	}
	return []string{cimd.AuthMethodNone}
}

// TokenEndpointAuthSigningAlgs lists the client assertion algorithms, for
// discovery; nil when no private_key_jwt client can be served.
func (s *OAuthServer) TokenEndpointAuthSigningAlgs() []string {
	if s.CIMDEnabled() {
		return cimd.SigningAlgs()
	}
	return nil
}
