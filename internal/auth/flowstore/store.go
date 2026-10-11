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

// Package flowstore provides shared storage for the short-lived, one-time
// entries of an OAuth authorization in flight: the pending authorization
// keyed by the upstream state, and the issued authorization code.
//
// The in-memory store in OAuthServer is per process. With more than one
// replica, /oauth/authorize, the upstream callback and /oauth/token can land
// on different pods, and a pod that did not write the entry answers "invalid
// or expired". Injecting a Store makes every replica see the same entries.
package flowstore

import (
	"context"
	"time"
)

// Kinds of entry. A key is looked up only within its own kind, so a state
// value can never be redeemed as a code or the other way round.
const (
	KindPending = "pending"
	KindCode    = "code"
)

// Store keeps one-time entries until they are taken or expire.
type Store interface {
	// Put stores payload under (kind, key) for ttl. The key is a bearer
	// secret (a code, a state); the store keeps only its hash. Expiry is
	// measured on the store's clock alone, so replicas whose clocks disagree
	// still agree on whether an entry is live.
	Put(ctx context.Context, kind, key string, payload []byte, ttl time.Duration) error

	// Take atomically removes the entry and returns its payload. found is
	// false when no entry exists or it has expired; err is set only when the
	// store could not be read, which callers must not treat as "not found".
	// An entry is returned at most once across all replicas.
	Take(ctx context.Context, kind, key string) (payload []byte, found bool, err error)

	// GC deletes expired entries. Safe to call on a schedule from every
	// replica.
	GC(ctx context.Context) error
}
