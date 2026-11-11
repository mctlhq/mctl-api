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

package session

import (
	"context"
	"sync"
	"time"
)

// Memory is the in-memory fake Store. It implements the same contract as the
// Postgres store, including the lease and CAS rules, and keeps tokens in the
// clear in process memory: for tests and local development only.
type Memory struct {
	mu   sync.Mutex
	now  func() time.Time
	rows map[Key]*Record
}

// NewMemory returns an empty fake. now defaults to time.Now.
func NewMemory(now func() time.Time) *Memory {
	if now == nil {
		now = time.Now
	}
	return &Memory{now: now, rows: map[Key]*Record{}}
}

func (m *Memory) row(key Key) (*Record, error) {
	if err := key.validate(); err != nil {
		return nil, err
	}
	r, ok := m.rows[key]
	if !ok {
		return nil, ErrNotFound
	}
	return r, nil
}

func (m *Memory) Put(_ context.Context, key Key, t Tokens) (Record, error) {
	if err := key.validate(); err != nil {
		return Record{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for k := range m.rows {
		if k.ConnectionID == key.ConnectionID && k != key {
			return Record{}, ErrNotFound // the connection id belongs to another owner
		}
	}
	gen := int64(1)
	if r, ok := m.rows[key]; ok {
		gen = r.Generation + 1
	}
	m.rows[key] = &Record{Key: key, State: StateActive, Tokens: t, Generation: gen, UpdatedAt: m.now()}
	return *m.rows[key], nil
}

func (m *Memory) Get(_ context.Context, key Key) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := m.row(key)
	if err != nil {
		return Record{}, err
	}
	return *r, nil
}

func (m *Memory) AcquireLease(_ context.Context, key Key, holder string, ttl time.Duration) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := m.row(key)
	if err != nil {
		return Record{}, err
	}
	if r.State != StateActive {
		return *r, nil
	}
	if r.LeaseHolder != "" && r.LeaseHolder != holder && r.LeaseUntil.After(m.now()) {
		return Record{}, ErrLeaseHeld
	}
	prior := r.RefreshIntent
	r.LeaseHolder, r.LeaseUntil, r.RefreshIntent = holder, m.now().Add(ttl), true
	out := *r
	out.RefreshIntent = prior // the caller learns whether an earlier refresh left an unknown outcome
	return out, nil
}

func (m *Memory) Commit(_ context.Context, key Key, holder string, expected int64, t Tokens) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := m.row(key)
	if err != nil {
		return Record{}, err
	}
	if r.State != StateActive || r.Generation != expected {
		return Record{}, ErrStale
	}
	if r.LeaseHolder != holder {
		return Record{}, ErrLeaseLost
	}
	r.Tokens, r.Generation, r.FromRefresh = t, expected+1, true
	r.LeaseHolder, r.LeaseUntil, r.RefreshIntent, r.UpdatedAt = "", time.Time{}, false, m.now()
	return *r, nil
}

func (m *Memory) Release(_ context.Context, key Key, holder string, outcomeKnown bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := m.row(key)
	if err != nil {
		return err
	}
	if r.LeaseHolder == holder {
		r.LeaseHolder, r.LeaseUntil = "", time.Time{}
		if outcomeKnown {
			r.RefreshIntent = false
		}
	}
	return nil
}

func (m *Memory) MarkRelogin(_ context.Context, key Key, expected int64, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := m.row(key)
	if err != nil {
		return err
	}
	if r.State != StateActive || r.Generation != expected {
		return ErrStale
	}
	r.State, r.Tokens, r.ReloginReason, r.Generation = StateReloginRequired, Tokens{}, reason, expected+1
	r.LeaseHolder, r.LeaseUntil, r.RefreshIntent, r.UpdatedAt = "", time.Time{}, false, m.now()
	return nil
}

func (m *Memory) Revoke(_ context.Context, key Key) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := m.row(key)
	if err != nil {
		return err
	}
	r.State, r.Tokens, r.Generation = StateRevoked, Tokens{}, r.Generation+1
	r.LeaseHolder, r.LeaseUntil, r.RefreshIntent, r.UpdatedAt = "", time.Time{}, false, m.now()
	return nil
}

func (m *Memory) Status(ctx context.Context, key Key) (Status, error) {
	r, err := m.Get(ctx, key)
	if err != nil {
		return Status{}, err
	}
	return Status{State: r.State, Generation: r.Generation, AccessExpiresAt: r.Tokens.AccessExpiresAt,
		ReloginReason: r.ReloginReason, UpdatedAt: r.UpdatedAt}, nil
}
