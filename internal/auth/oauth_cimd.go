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
func (s *OAuthServer) CIMDEnabled() bool { return s.CIMD != nil }

// IsCIMDClient reports whether clientID is handled as a CIMD client.
func (s *OAuthServer) IsCIMDClient(clientID string) bool {
	return s.CIMD != nil && cimd.IsCIMDURL(clientID) && !s.isStatic(clientID)
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
