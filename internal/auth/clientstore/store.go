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

// Package clientstore provides persistent storage for RFC 7591 dynamically
// registered OAuth clients.
//
// The in-memory registry in OAuthServer loses every registration on a pod
// restart, while a client that registered keeps its cached client_id and
// never registers again. For a counterpart that registers exactly once -- the
// Cloudflare MCP portal in automatic (DCR) mode -- every rollout would leave it
// holding an id the server no longer knows (mctlhq/mctl-api#395). Injecting a
// Store makes registrations survive restarts.
package clientstore

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned by Get when no client with that id is stored.
var ErrNotFound = errors.New("oauth client not found")

// Client is one persisted dynamic registration.
type Client struct {
	ClientID     string
	ClientName   string
	RedirectURIs []string
	// CreatedAt is when the id was first registered. A repeated, idempotent
	// registration never moves it.
	CreatedAt time.Time
	// LastSeenAt is when the client last registered or used a grant. It is
	// what the row cap evicts by and what retention is measured from, so a
	// client that registers once and then only uses its tokens -- the portal --
	// is not mistaken for a stale one.
	LastSeenAt time.Time
	// UsedAt is when the client first completed a code exchange or refresh
	// (set by Touch); zero for a registration that has never been used.
	UsedAt time.Time
}

// Store is the interface OAuthServer uses to persist dynamic registrations.
// A nil Store means "use the in-memory registry" -- OAuthServer checks for nil
// before calling any method.
type Store interface {
	// Register stores c, or, when c.ClientID is already stored, marks it seen
	// and returns the stored record unchanged (idempotent registration: the
	// caller derives the id from the registration metadata). Afterwards the
	// NEVER-USED rows are trimmed to maxClients by least recent LastSeenAt;
	// the row just registered is never the one trimmed. maxClients <= 0
	// disables the trim.
	//
	// A row that has been used (UsedAt set) is never trimmed: registration is
	// unauthenticated, so letting fresh registrations push out a client that
	// completed a GitHub sign-in would let anonymous traffic evict exactly
	// the record this store exists to keep. Used rows are bounded by
	// retention (GC) and by each one having needed a real sign-in.
	Register(c Client, maxClients int) (Client, error)

	// Get returns the stored client, or ErrNotFound. ctx bounds the lookup;
	// callers on unauthenticated paths pass a short deadline.
	Get(ctx context.Context, clientID string) (Client, error)

	// Touch marks clientID as seen now and as used. last_seen_at is throttled
	// in the store so the hot path (every token exchange and refresh) is not a
	// write per call; the first use is always recorded. Idempotent and silent
	// for an unknown id.
	Touch(clientID string) error

	// GC hard-deletes clients not seen since cutoff.
	GC(cutoff time.Time) error
}
