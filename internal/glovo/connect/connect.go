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

// Package connect is the one in-process code path that creates a synthetic
// Glovo connection (mctl-api#961, design 4a). The facade connect route and the
// join-API adapter of mctl-api#957 both call Service, so the per-tenant limit,
// the hourly limit, the L2a tenant mutex and the single-use handoff reference
// are enforced on every route that creates a connection and no caller has a
// connect path of its own.
package connect

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/glovo"
)

// JoinScope is the verified scope: tenant, principal and install revision come
// from the resolver and the store, never from a request body.
type JoinScope struct {
	Tenant          string
	PrincipalID     string
	InstallRevision int64
}

// ConnectOutcome is the result of Connect. HandoffURL is empty when a replay
// finds the connection no longer waiting for a handoff.
type ConnectOutcome struct {
	Connection       *glovo.Connection
	HandoffURL       string
	HandoffExpiresAt time.Time
	Replayed         bool
}

// Service creates connections. HandoffBaseURL is
// GLOVO_SYNTHETIC_HANDOFF_BASE_URL: synthetic and test-only like the worker
// credential; unset, Connect answers not_ready and never invents a URL.
type Service struct {
	Store          *glovo.Store
	HandoffBaseURL string
	// AfterLimits, when set, runs after the limits on the same transaction of
	// every connect and reconnect that inserts a connection (never on a
	// replay). It is a test seam: production leaves it nil.
	AfterLimits func(ctx context.Context, tx pgx.Tx) error
}

func (s *Service) ready() error {
	if s == nil || s.Store == nil || strings.TrimSpace(s.HandoffBaseURL) == "" {
		return glovo.Refuse(glovo.CodeNotReady)
	}
	return nil
}

func owner(sc JoinScope) glovo.Owner {
	return glovo.Owner{TenantID: sc.Tenant, PrincipalID: sc.PrincipalID}
}

func actor(sc JoinScope) glovo.Actor {
	return glovo.Actor{PrincipalID: sc.PrincipalID, Kind: glovo.ActorUser}
}

func codeOf(err error) (glovo.Code, bool) {
	var ge *glovo.Error
	if errors.As(err, &ge) {
		return ge.Code, true
	}
	return "", false
}

func (s *Service) input(sc JoinScope, key string) glovo.ConnectInput {
	limits := s.Store.ConnectLimits(owner(sc))
	return glovo.ConnectInput{
		Owner: owner(sc), ExpectedInstallRevision: sc.InstallRevision, IdempotencyKey: key, Actor: actor(sc),
		AfterLocks: func(ctx context.Context, tx pgx.Tx) error {
			if err := limits(ctx, tx); err != nil {
				return err
			}
			if s.AfterLimits != nil {
				return s.AfterLimits(ctx, tx)
			}
			return nil
		},
	}
}

// Connect creates the owner's connection, or replays it. A connection that is
// live in storage but past its expires_at is first ended through #959
// Reconnect with TerminalOnly (the unique live index is state-based and would
// otherwise refuse the new row). The replay lookup runs before the limits, so
// a replay moves no counter. A second short transaction then issues the
// single-use handoff reference; the raw value is never stored, so a replay
// returns a fresh one and the older one no longer activates.
func (s *Service) Connect(ctx context.Context, sc JoinScope, idempotencyKey string) (*ConnectOutcome, error) {
	out, err := s.ConnectWithoutHandoff(ctx, sc, idempotencyKey)
	if err != nil {
		return nil, err
	}
	in := s.input(sc, idempotencyKey)
	issue, err := s.Store.IssueHandoff(ctx, in.Owner, out.Connection.ConnectionID, in.Actor)
	if err != nil {
		if code, typed := codeOf(err); typed && out.Replayed && code != glovo.CodeNotFound {
			return out, nil
		}
		return nil, err
	}
	out.HandoffURL = strings.TrimRight(strings.TrimSpace(s.HandoffBaseURL), "/") + "/" + issue.Ref
	out.HandoffExpiresAt = issue.ExpiresAt
	return out, nil
}

// ConnectWithoutHandoff is Connect without issuing a handoff reference. The
// facade uses it: its response carries no reference, so issuing one would
// delete a previously issued unconsumed reference on an idempotent retry and
// discard the new one. The facade /handoff route issues the reference.
func (s *Service) ConnectWithoutHandoff(ctx context.Context, sc JoinScope, idempotencyKey string) (*ConnectOutcome, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	in := s.input(sc, idempotencyKey)
	cur, err := s.Store.LiveConnection(ctx, in.Owner)
	var res *glovo.ConnectResult
	switch code, typed := codeOf(err); {
	case err == nil:
		res, err = s.Store.Connect(ctx, in)
	case typed && code == glovo.CodeConnectionExpired && cur != nil:
		in.TerminalOnly = true
		res, err = s.Store.Reconnect(ctx, in, cur.ConnectionID)
	case typed && (code == glovo.CodeNoConnection || code == glovo.CodeConnectionRevoked):
		res, err = s.Store.Connect(ctx, in)
	default:
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	return &ConnectOutcome{Connection: res.Connection, Replayed: res.Replayed}, nil
}

// Reconnect creates a new connection that supersedes a terminal prior of the
// same owner. A live prior is refused connection_exists: this route never
// supersedes. It issues no handoff reference.
func (s *Service) Reconnect(ctx context.Context, sc JoinScope, idempotencyKey, priorConnectionID string) (*glovo.ConnectResult, error) {
	if s == nil || s.Store == nil {
		return nil, glovo.Refuse(glovo.CodeNotReady)
	}
	in := s.input(sc, idempotencyKey)
	in.TerminalOnly = true
	return s.Store.Reconnect(ctx, in, priorConnectionID)
}

// Current returns the owner's live connection: no_connection when there is
// none, connection_expired once its expires_at has passed (database clock),
// connection_revoked for a revoked one.
func (s *Service) Current(ctx context.Context, sc JoinScope) (*glovo.Connection, error) {
	if s == nil || s.Store == nil {
		return nil, glovo.Refuse(glovo.CodeNotReady)
	}
	c, err := s.Store.LiveConnection(ctx, owner(sc))
	if err != nil {
		return nil, err
	}
	return c, nil
}
