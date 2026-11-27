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

package grant

import (
	"context"
	"sync"
	"time"

	"github.com/mctlhq/mctl-api/internal/glovo"
)

// memStore is the in-memory fake Store of the tests. Consume is a
// compare-and-set under one mutex.
type memStore struct {
	mu       sync.Mutex
	byID     map[string]Grant
	byAppr   map[string]string
	failRead error
}

func newMemStore() *memStore {
	return &memStore{byID: map[string]Grant{}, byAppr: map[string]string{}}
}

func (m *memStore) Insert(_ context.Context, g Grant) (Grant, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id, ok := m.byAppr[g.ApprovalID]; ok {
		return m.byID[id], false, nil
	}
	m.byID[g.ID], m.byAppr[g.ApprovalID] = g, g.ID
	return g, true, nil
}

func (m *memStore) Get(_ context.Context, id string) (Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failRead != nil {
		return Grant{}, m.failRead
	}
	g, ok := m.byID[id]
	if !ok {
		return Grant{}, glovo.ErrNotFound
	}
	return g, nil
}

func (m *memStore) Consume(_ context.Context, id string, at time.Time) (Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.byID[id]
	switch {
	case !ok:
		return Grant{}, glovo.ErrNotFound
	case g.ConsumedAt != nil:
		return Grant{}, glovo.Refuse(glovo.CodeApprovalReplayed)
	case !g.Binding.ExpiresAt.After(at):
		return Grant{}, glovo.Refuse(glovo.CodeApprovalExpired)
	}
	g.ConsumedAt = &at
	m.byID[id] = g
	return g, nil
}

// tamper rewrites a stored grant without going through the service.
func (m *memStore) tamper(id string, f func(*Grant)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.byID[id]
	f(&g)
	m.byID[id] = g
}
