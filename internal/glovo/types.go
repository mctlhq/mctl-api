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

package glovo

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// InstallState is the state of a tenant's Glovo install.
type InstallState string

const (
	InstallInstalled   InstallState = "installed"
	InstallUninstalled InstallState = "uninstalled"
)

// ConnectionState is the state of one connection.
type ConnectionState string

const (
	PendingHandoff  ConnectionState = "pending_handoff"
	PendingProvider ConnectionState = "pending_provider"
	Active          ConnectionState = "active"
	Expired         ConnectionState = "expired"
	Failed          ConnectionState = "failed"
	Revoked         ConnectionState = "revoked"
)

var allStates = []ConnectionState{PendingHandoff, PendingProvider, Active, Expired, Failed, Revoked}

// transitions is the complete edge table. Expired, failed and revoked are
// terminal. PendingProvider -> Active is taken only inside ActivateTx's
// two-step chain: no M1 caller moves a connection that rests in
// pending_provider to active, it leaves that state through Transition to
// failed, expired or revoked.
var transitions = map[ConnectionState][]ConnectionState{
	PendingHandoff:  {PendingProvider, Failed, Expired, Revoked},
	PendingProvider: {Active, Failed, Expired, Revoked},
	Active:          {Expired, Failed, Revoked},
}

// Live reports whether the state counts against the one-live-connection index.
func (s ConnectionState) Live() bool {
	return s == PendingHandoff || s == PendingProvider || s == Active
}

// Terminal reports whether no transition leaves the state.
func (s ConnectionState) Terminal() bool { return s == Expired || s == Failed || s == Revoked }

func (s ConnectionState) valid() bool {
	for _, v := range allStates {
		if v == s {
			return true
		}
	}
	return false
}

// CanTransition reports whether from -> to is an allowed edge.
func CanTransition(from, to ConnectionState) bool {
	for _, t := range transitions[from] {
		if t == to {
			return true
		}
	}
	return false
}

// PrincipalPrefix is the prefix of a canonical principal id.
const PrincipalPrefix = "prn_"

// MaxConnectionTTL bounds ActivateInput.ExpiresIn.
const MaxConnectionTTL = 24 * time.Hour

// Owner is the (tenant, principal) pair that owns a connection. It is a
// required argument of every connection read and write.
type Owner struct{ TenantID, PrincipalID string }

func (o Owner) validate() error {
	if o.TenantID == "" || len(o.TenantID) > 253 || !strings.HasPrefix(o.PrincipalID, PrincipalPrefix) || len(o.PrincipalID) > 128 {
		return refuse(CodeInvalidRequest)
	}
	return nil
}

// ActorKind is the closed set of glovo_audit_events_actor_kind_check.
type ActorKind string

const (
	ActorUser   ActorKind = "user"
	ActorOwner  ActorKind = "owner"
	ActorAdmin  ActorKind = "admin"
	ActorWorker ActorKind = "worker"
	ActorSystem ActorKind = "system"
)

// Actor is the one source of an audit event's actor columns.
type Actor struct {
	PrincipalID string
	Kind        ActorKind
}

// validate: user, owner and admin need a prn_ principal; worker and system use
// the fixed labels "worker" and "system".
func (a Actor) validate() error {
	switch a.Kind {
	case ActorUser, ActorOwner, ActorAdmin:
		if strings.HasPrefix(a.PrincipalID, PrincipalPrefix) && len(a.PrincipalID) <= 128 {
			return nil
		}
	case ActorWorker:
		if a.PrincipalID == "worker" {
			return nil
		}
	case ActorSystem:
		if a.PrincipalID == "system" {
			return nil
		}
	}
	return refuse(CodeInvalidRequest)
}

type actorKey struct{}

// WithActor returns a context carrying the audit actor.
func WithActor(ctx context.Context, a Actor) context.Context {
	return context.WithValue(ctx, actorKey{}, a)
}

// ActorFrom returns the actor set by WithActor. When none is set it derives
// Actor{"worker", worker} from an authenticated Glovo worker principal in ctx
// (the principal's own id is not copied). Any other principal is not an
// actor: there is no default and no system fallback.
func ActorFrom(ctx context.Context) (Actor, bool) {
	if a, ok := ctx.Value(actorKey{}).(Actor); ok {
		return a, true
	}
	if u := auth.UserFromContext(ctx); u.IsGlovoWorker() {
		return Actor{PrincipalID: "worker", Kind: ActorWorker}, true
	}
	return Actor{}, false
}

// RefusalEvent is the input of AppendRefusal. The row's from_state, to_state
// and install_revision are read from the entity.
type RefusalEvent struct {
	TenantID   string
	EntityKind string // "install" or "connection"
	EntityID   string
	Code       Code
	Actor      Actor
}

// Install mirrors glovo_installs.
type Install struct {
	InstallID       string
	TenantID        string
	InstallRevision int64
	State           InstallState
	InstalledBy     string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	Version         int64
}

// Connection mirrors glovo_connections column for column. SecretRef is what
// the row holds (gsr_ or empty). ReleasedSecretRef is set only on a
// connection that the call ended: it is the reference the row held before the
// purge, to be released by the caller after commit, exactly once.
type Connection struct {
	ConnectionID      string
	Owner             Owner
	InstallID         string
	InstallRevision   int64
	State             ConnectionState
	SecretRef         string
	SupersedesID      string
	EndReason         string
	Version           int64
	CreatedAt         time.Time
	UpdatedAt         time.Time
	EndedAt           *time.Time
	ExpiresAt         *time.Time
	ReleasedSecretRef string
}

// AuditEvent mirrors glovo_audit_events.
type AuditEvent struct {
	EventID            string
	TenantID           string
	SubjectPrincipalID string
	ActorPrincipalID   string
	ActorKind          ActorKind
	EntityKind         string
	EntityID           string
	Event              string
	FromState          string
	ToState            string
	InstallRevision    int64
	ReasonCode         string
	RecordedAt         time.Time
}

// ConnectResult is the outcome of Connect and Reconnect.
type ConnectResult struct {
	Connection *Connection
	Replayed   bool
	// Ended lists the connections this call ended (Reconnect superseding or
	// expiring a prior), each with its ReleasedSecretRef.
	Ended []Connection
}

// Reasons recorded in end_reason and audit reason_code.
const (
	ReasonSuperseded         = "superseded"
	ReasonInstallRevoked     = "install_revoked"
	ReasonInstallReinstalled = "install_reinstalled"
	ReasonMembershipRemoved  = "membership_removed"
	ReasonExpired            = "expired"
	maxReasonLen             = 64
	maxIdempotencyKeyLen     = 200
)

var reasonRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func validReason(r string) bool { return reasonRE.MatchString(r) }

// lengthPrefixed encodes fields so no value can alias another (the encoding of
// commerce.lengthPrefixed).
func lengthPrefixed(version string, fields [][2]string) string {
	var b strings.Builder
	b.WriteString(version)
	b.WriteByte('\n')
	for _, f := range fields {
		fmt.Fprintf(&b, "%s:%d:%s\n", f[0], len(f[1]), f[1])
	}
	return b.String()
}
