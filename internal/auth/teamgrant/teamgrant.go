// Copyright 2026 MCTL Authors
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

// Package teamgrant stores the server-owned team grants of the Glovo pilot:
// the record that one human, acting through one client, chose one team for
// one resource. A grant is created pending at consent, becomes active only
// inside the code-exchange transaction (ActivateTx), and is revoked together
// with its refresh family. Check accepts only an active, unexpired grant.
//
// The oauth_team_grants table and its indexes are created by the refreshstore
// schema (it shares that database and pool), never by this package.
package teamgrant

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Grant states.
const (
	StatePending = "pending"
	StateActive  = "active"
	StateRevoked = "revoked"
)

// Revocation reasons recorded on a grant.
const (
	ReasonSuperseded = "superseded"
)

// IDPrefix prefixes every grant id.
const IDPrefix = "tgr_"

// Grant is one team grant. RefreshFamilyID is empty until activation.
type Grant struct {
	ID              string
	PrincipalID     string
	Tenant          string
	ClientID        string
	Resource        string
	RefreshFamilyID string
	State           string
	CreatedAt       time.Time
	ExpiresAt       time.Time
}

// ErrGrantInvalid means the grant is unknown, pending, revoked, expired or
// does not match the caller. It is never returned for a store failure: those
// are other errors, so an outage is never read as "no grant".
var ErrGrantInvalid = errors.New("team grant is not valid")

// Store is the grant store the consent step and the resolver use.
type Store interface {
	// Create inserts g as pending and revokes every earlier pending or active
	// grant of the same (principal, client, resource) as superseded, in one
	// step. The id, state and created_at are assigned by the store.
	Create(ctx context.Context, g Grant) (Grant, error)
	// Check returns the grant only when it is active, unexpired and matches
	// the principal, client and resource.
	Check(ctx context.Context, grantID, principalID, clientID, resource string) (Grant, error)
	// Revoke revokes one grant (idempotent).
	Revoke(ctx context.Context, grantID, reason string) error
	// RevokeByFamily revokes the grants bound to a refresh family.
	RevokeByFamily(ctx context.Context, familyID, reason string) error
	// RevokeByPrincipal revokes every live grant of a principal.
	RevokeByPrincipal(ctx context.Context, principalID, reason string) error
}

// Transactional is implemented only by a store on the refresh store's pool.
// The in-memory store does not implement it, so it can never open Glovo.
type Transactional interface {
	Store
	SharesRefreshPool()
}

// NewID returns a fresh grant id.
func NewID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("team grant id: %w", err)
	}
	return IDPrefix + hex.EncodeToString(b), nil
}

// validate checks the fields a new grant must carry.
func validate(g Grant) error {
	switch {
	case g.PrincipalID == "":
		return errors.New("team grant: principal is required")
	case g.Tenant == "":
		return errors.New("team grant: tenant is required")
	case g.Resource == "":
		return errors.New("team grant: resource is required")
	case g.ExpiresAt.IsZero():
		return errors.New("team grant: expiry is required")
	}
	return nil
}

// MemoryStore is an in-memory Store for unit tests. It is not transactional
// with the refresh store, so the Glovo resource stays not ready with it.
type MemoryStore struct {
	mu     sync.Mutex
	grants map[string]*Grant
	now    func() time.Time
	// Err, when set, is returned by every operation (store outage).
	Err error
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{grants: map[string]*Grant{}, now: time.Now}
}

// SetClock replaces the clock (tests).
func (m *MemoryStore) SetClock(now func() time.Time) { m.now = now }

func (m *MemoryStore) Create(_ context.Context, g Grant) (Grant, error) {
	if m.Err != nil {
		return Grant{}, m.Err
	}
	if err := validate(g); err != nil {
		return Grant{}, err
	}
	id, err := NewID()
	if err != nil {
		return Grant{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.grants {
		if e.PrincipalID == g.PrincipalID && e.ClientID == g.ClientID && e.Resource == g.Resource &&
			(e.State == StatePending || e.State == StateActive) {
			e.State = StateRevoked
		}
	}
	g.ID, g.State, g.RefreshFamilyID, g.CreatedAt = id, StatePending, "", m.now()
	cp := g
	m.grants[id] = &cp
	return g, nil
}

// Activate is the in-memory counterpart of ActivateTx, for tests.
func (m *MemoryStore) Activate(grantID, principalID, clientID, resource, familyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.grants[grantID]
	if !ok || e.State != StatePending || !m.now().Before(e.ExpiresAt) ||
		e.PrincipalID != principalID || e.ClientID != clientID || e.Resource != resource {
		return ErrGrantInvalid
	}
	e.State, e.RefreshFamilyID = StateActive, familyID
	return nil
}

func (m *MemoryStore) Check(_ context.Context, grantID, principalID, clientID, resource string) (Grant, error) {
	if m.Err != nil {
		return Grant{}, m.Err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.grants[grantID]
	if !ok || e.State != StateActive || !m.now().Before(e.ExpiresAt) ||
		e.PrincipalID != principalID || e.ClientID != clientID || e.Resource != resource {
		return Grant{}, ErrGrantInvalid
	}
	return *e, nil
}

func (m *MemoryStore) Revoke(_ context.Context, grantID, _ string) error {
	if m.Err != nil {
		return m.Err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.grants[grantID]; ok {
		e.State = StateRevoked
	}
	return nil
}

func (m *MemoryStore) RevokeByFamily(_ context.Context, familyID, _ string) error {
	if m.Err != nil {
		return m.Err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.grants {
		if e.RefreshFamilyID == familyID && familyID != "" {
			e.State = StateRevoked
		}
	}
	return nil
}

func (m *MemoryStore) RevokeByPrincipal(_ context.Context, principalID, _ string) error {
	if m.Err != nil {
		return m.Err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.grants {
		if e.PrincipalID == principalID {
			e.State = StateRevoked
		}
	}
	return nil
}
