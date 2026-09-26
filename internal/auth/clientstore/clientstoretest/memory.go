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

// Package clientstoretest provides an in-memory clientstore.Store for tests.
// It follows the PostgresStore contract (idempotent Register, trim by least
// recent LastSeenAt, throttle-free Touch) so that a test can stand in for "the
// same database seen by a new process" by handing one MemoryStore to two
// OAuthServer instances.
package clientstoretest

import (
	"context"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth/clientstore"
)

// MemoryStore is a clientstore.Store backed by a map.
type MemoryStore struct {
	mu      sync.Mutex
	clients map[string]clientstore.Client
	// Err, when non-nil, is returned by every method.
	Err error
	// Touches counts successful Touch calls per client id.
	Touches map[string]int
	// Registers counts Register calls; LastMax records the cap passed in.
	Registers int
	LastMax   int
	// Gets counts Get calls, to assert when a lookup must not reach the store.
	Gets int
}

// New returns an empty MemoryStore.
func New() *MemoryStore {
	return &MemoryStore{clients: map[string]clientstore.Client{}, Touches: map[string]int{}}
}

// Register implements clientstore.Store.
func (m *MemoryStore) Register(c clientstore.Client, maxClients int) (clientstore.Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Err != nil {
		return clientstore.Client{}, m.Err
	}
	m.Registers++
	m.LastMax = maxClients
	now := time.Now()
	stored, ok := m.clients[c.ClientID]
	if ok {
		stored.LastSeenAt = now
	} else {
		stored = clientstore.Client{
			ClientID:     c.ClientID,
			ClientName:   c.ClientName,
			RedirectURIs: slices.Clone(c.RedirectURIs),
			CreatedAt:    now,
			LastSeenAt:   now,
		}
	}
	m.clients[c.ClientID] = stored
	if maxClients > 0 {
		// Only never-used rows count toward the cap and can be evicted.
		unused := 0
		ids := make([]string, 0, len(m.clients))
		for id := range m.clients {
			if !m.clients[id].UsedAt.IsZero() {
				continue
			}
			unused++
			if id != c.ClientID {
				ids = append(ids, id)
			}
		}
		if unused > maxClients {
			sort.Slice(ids, func(i, j int) bool {
				return m.clients[ids[i]].LastSeenAt.Before(m.clients[ids[j]].LastSeenAt)
			})
			for _, id := range ids[:min(len(ids), unused-maxClients)] {
				delete(m.clients, id)
			}
		}
	}
	return stored, nil
}

// Get implements clientstore.Store.
func (m *MemoryStore) Get(_ context.Context, clientID string) (clientstore.Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Gets++
	if m.Err != nil {
		return clientstore.Client{}, m.Err
	}
	c, ok := m.clients[clientID]
	if !ok {
		return clientstore.Client{}, clientstore.ErrNotFound
	}
	return c, nil
}

// Touch implements clientstore.Store.
func (m *MemoryStore) Touch(clientID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Err != nil {
		return m.Err
	}
	c, ok := m.clients[clientID]
	if !ok {
		return nil
	}
	c.LastSeenAt = time.Now()
	if c.UsedAt.IsZero() {
		c.UsedAt = c.LastSeenAt
	}
	m.clients[clientID] = c
	m.Touches[clientID]++
	return nil
}

// GC implements clientstore.Store.
func (m *MemoryStore) GC(cutoff time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Err != nil {
		return m.Err
	}
	for id := range m.clients {
		if m.clients[id].LastSeenAt.Before(cutoff) {
			delete(m.clients, id)
		}
	}
	return nil
}

// Len reports how many clients are stored.
func (m *MemoryStore) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.clients)
}

// GetCount reports how many times Get was called.
func (m *MemoryStore) GetCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.Gets
}

// Age moves a client's LastSeenAt back by d, to test retention without
// sleeping.
func (m *MemoryStore) Age(clientID string, d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.clients[clientID]; ok {
		c.LastSeenAt = c.LastSeenAt.Add(-d)
		m.clients[clientID] = c
	}
}
