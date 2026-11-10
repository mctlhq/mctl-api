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

package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ReadKind is a v1alpha2 read command kind (mctl-agents#1059). There is no
// prepare read: prepare is the #957 write.
type ReadKind string

// The three read kinds.
const (
	ReadHistory ReadKind = KindReadHistory
	ReadPreview ReadKind = KindReadPreview
	ReadBasket  ReadKind = KindReadBasket
)

// ReadRequest is what the #957 handlers pass to ReadClient.Read, after their
// own checks. It carries no secret: the refs are opaque and the scopes come
// from the verified subject token.
type ReadRequest struct {
	Kind             ReadKind
	Tenant           string // private
	OwnerPrincipalID string // private
	TenantRef        string // tnr_
	PrincipalRef     string // prr_
	ConnectionRef    string // gcn_
	// InstallRevision is the decimal #959 revision: stored on the result row and
	// compared on fetch.
	InstallRevision string
	// InstallRevisionRef is the irv_ wire ref minted by #957. It is written only
	// to the command's install_revision_ref; Read refuses either one empty.
	InstallRevisionRef string
	Scopes             []string        // for the glovo:read re-check
	Params             json.RawMessage // bounded, validated against the #1059 command schema
	Deadline           time.Time
}

// ReadResult is the verified, typed outcome of a read: the canonical bytes
// whose sha256 is Digest.
type ReadResult struct {
	Kind      ReadKind
	ResultRef string
	Digest    string
	Data      []byte // canonical (RFC 8785) bytes
	ExpiresAt time.Time
}

// LiveConnection is what a ConnectionChecker reports for a live connection:
// its gcn_ id and its decimal install revision.
type LiveConnection struct {
	ConnectionRef   string
	InstallRevision string
}

// NotLiveError is returned by a ConnectionChecker for a connection that is
// absent, revoked or expired. State is the closed M1a state for #957 to map.
type NotLiveError struct{ State string }

func (e *NotLiveError) Error() string { return "connection not live: " + e.State }

// ConnectionChecker answers whether the owner has a live connection right now.
// Any error other than *NotLiveError fails the fetch closed.
type ConnectionChecker interface {
	Live(ctx context.Context, tenant, principalID string) (LiveConnection, error)
}

// DenyConnectionChecker is the default: it fails closed.
type DenyConnectionChecker struct{}

// Live always errors.
func (DenyConnectionChecker) Live(context.Context, string, string) (LiveConnection, error) {
	return LiveConnection{}, errors.New("no connection checker configured")
}

// SetConnectionChecker installs the live connection check. nil restores the
// fail-closed default.
func (s *Store) SetConnectionChecker(c ConnectionChecker) {
	s.mu.Lock()
	s.checker = c
	s.mu.Unlock()
}

func (s *Store) currentChecker() ConnectionChecker {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.checker == nil {
		return DenyConnectionChecker{}
	}
	return s.checker
}

const (
	defaultReadDeadline = 10 * time.Second
	readPollMin         = 25 * time.Millisecond
	readPollMax         = 250 * time.Millisecond
)

// ReadClient is the in-process read transport of #957: it enqueues one read
// command, waits for its result on the store with a bounded deadline and
// fetches the verified bytes. There is no route, tool, workflow or signal.
type ReadClient struct {
	Store *Store
	// ProviderRef is the provider the command is leased to; default "glovo".
	ProviderRef string
	// DefaultDeadline applies when the request has none; default 10 s.
	DefaultDeadline time.Duration
}

// Read runs one read. On deadline it cancels the command and returns
// ErrReadUnavailable; a late result for the cancelled command is refused.
func (c *ReadClient) Read(ctx context.Context, r ReadRequest) (*ReadResult, error) {
	s := c.Store
	provider := c.ProviderRef
	if provider == "" {
		provider = "glovo"
	}
	now := s.now()
	deadline := r.Deadline
	if deadline.IsZero() {
		d := c.DefaultDeadline
		if d <= 0 {
			d = defaultReadDeadline
		}
		deadline = now.Add(d)
	}
	ttl := deadline.Sub(now)
	if ttl < time.Second {
		return nil, fmt.Errorf("%w: deadline too close", ErrReadUnavailable)
	}
	if ttl > MaxReadTTLSeconds*time.Second {
		ttl = MaxReadTTLSeconds * time.Second
		deadline = now.Add(ttl)
	}
	ttl = ttl.Truncate(time.Second)

	tx, err := s.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("bridge: read begin: %w", err)
	}
	commandID, _, err := s.EnqueueRead(ctx, tx, ReadEnqueue{ProviderRef: provider, Request: r, TTL: ttl})
	if err := finish(ctx, tx, err); err != nil {
		return nil, err
	}

	wctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	ref, err := s.awaitRead(wctx, commandID)
	if err != nil {
		if wctx.Err() != nil {
			c.cancelRead(commandID)
			return nil, fmt.Errorf("%w: read deadline passed", ErrReadUnavailable)
		}
		return nil, err
	}
	return s.FetchReadResult(ctx, ReadFetch{
		ResultRef: ref, Tenant: r.Tenant, PrincipalID: r.OwnerPrincipalID, ConnectionRef: r.ConnectionRef,
		InstallRevision: r.InstallRevision, Scopes: r.Scopes,
	})
}

// awaitRead polls the command with backoff until it completes and returns the
// result ref. Any other final state, or a completed command without a stored
// result (a failed outcome), is ErrReadUnavailable.
func (s *Store) awaitRead(ctx context.Context, commandID string) (string, error) {
	wait := readPollMin
	for {
		var status string
		if err := s.pool.QueryRow(ctx, `SELECT status FROM bridge_commands WHERE command_id=$1`, commandID).Scan(&status); err != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			return "", fmt.Errorf("%w: read status: %v", ErrReadUnavailable, err)
		}
		switch status {
		case StatusCompleted:
			var ref string
			err := s.pool.QueryRow(ctx, `SELECT result_ref FROM bridge_read_results WHERE command_id=$1`, commandID).Scan(&ref)
			if errors.Is(err, pgx.ErrNoRows) {
				return "", fmt.Errorf("%w: the provider reported no data", ErrReadUnavailable)
			}
			if err != nil {
				if ctx.Err() != nil {
					return "", ctx.Err()
				}
				return "", fmt.Errorf("%w: read result lookup: %v", ErrReadUnavailable, err)
			}
			return ref, nil
		case StatusCancelled, StatusExpired:
			return "", fmt.Errorf("%w: command %s", ErrReadUnavailable, status)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(wait):
		}
		if wait *= 2; wait > readPollMax {
			wait = readPollMax
		}
	}
}

// cancelRead cancels the command on a fresh context: the request context is
// already done.
func (c *ReadClient) cancelRead(commandID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := c.Store.begin(ctx)
	if err != nil {
		return
	}
	// ErrAlreadyCompleted means the result raced the deadline; the answer to
	// the caller stays ErrReadUnavailable either way.
	_ = finish(ctx, tx, c.Store.Cancel(ctx, tx, commandID, "read-client"))
}
