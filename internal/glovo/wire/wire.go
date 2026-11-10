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

// Package wire holds the versioned JSON bodies of the synthetic Glovo
// connection routes (mctl-api#961): one struct per body with a mandatory
// "schema" constant, a strict bounded decoder, the public connection state,
// and the committed JSON Schemas under schema/. Refusals are not a wire type:
// they are written by glovo.WriteError as {"error","error_description"}.
package wire

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/mctlhq/mctl-api/internal/glovo"
)

// Schema identifiers. Every success body and every request body carries one.
const (
	SchemaConnection       = "glovo-connection/v1alpha1.Connection"
	SchemaContext          = "glovo-connection/v1alpha1.Context"
	SchemaConnectRequest   = "glovo-connection/v1alpha1.ConnectRequest"
	SchemaActionRequest    = "glovo-connection/v1alpha1.ActionRequest"
	SchemaHandoff          = "glovo-connection/v1alpha1.Handoff"
	SchemaWorkerCheckReq   = "glovo-connection/v1alpha1.WorkerCheckRequest"
	SchemaWorkerCheckResp  = "glovo-connection/v1alpha1.WorkerCheckResponse"
	SchemaWorkerActivate   = "glovo-connection/v1alpha1.WorkerActivateRequest"
	SchemaInstallationReq  = "glovo-connection/v1alpha1.InstallationRequest"
	SchemaInstallation     = "glovo-connection/v1alpha1.Installation"
	MaxBodyBytes           = 16 << 10
	publicStateFailedClose = "failed"
)

//go:embed schema/*.json
var schemaFS embed.FS

// SchemaFS returns the committed JSON Schemas, one file per body.
func SchemaFS() embed.FS { return schemaFS }

// Public connection states.
const (
	StatePending = "pending"
	StateActive  = "active"
	StateExpired = "expired"
	StateFailed  = "failed"
	StateRevoked = "revoked"
)

// PublicState maps a store state to the wire state: both pending_* states are
// pending. An unknown state is failed, never a state that could read as usable.
func PublicState(s glovo.ConnectionState) string {
	switch s {
	case glovo.PendingHandoff, glovo.PendingProvider:
		return StatePending
	case glovo.Active:
		return StateActive
	case glovo.Expired:
		return StateExpired
	case glovo.Failed:
		return StateFailed
	case glovo.Revoked:
		return StateRevoked
	}
	return publicStateFailedClose
}

// Connection is one connection as the caller sees it.
type Connection struct {
	Schema          string     `json:"schema"`
	ConnectionID    string     `json:"connection_id"`
	State           string     `json:"state"`
	InstallRevision int64      `json:"install_revision"`
	SupersedesID    string     `json:"supersedes_id,omitempty"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	Replayed        bool       `json:"replayed,omitempty"`
}

// FromConnection builds the wire connection of a view. A live connection whose
// expires_at has passed is expired.
func FromConnection(v glovo.ConnectionView, replayed bool) Connection {
	c := Connection{
		Schema: SchemaConnection, ConnectionID: v.ConnectionID, State: PublicState(v.EffectiveState()),
		InstallRevision: v.InstallRevision, SupersedesID: v.SupersedesID,
		CreatedAt: v.CreatedAt.UTC(), UpdatedAt: v.UpdatedAt.UTC(), Replayed: replayed,
	}
	if v.ExpiresAt != nil {
		t := v.ExpiresAt.UTC()
		c.ExpiresAt = &t
	}
	return c
}

// Context is GET /api/v1/glovo/facade/context.
type Context struct {
	Schema          string       `json:"schema"`
	Tenant          string       `json:"tenant"`
	PrincipalID     string       `json:"principal_id"`
	InstallationID  string       `json:"installation_id"`
	InstallRevision int64        `json:"install_revision"`
	Connections     []Connection `json:"connections"`
}

// Handoff is the one response that carries a raw handoff reference.
type Handoff struct {
	Schema       string    `json:"schema"`
	ConnectionID string    `json:"connection_id"`
	HandoffRef   string    `json:"handoff_ref"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Empty is the body of the routes that take no input but the schema: connect,
// reconnect, handoff, revoke and expire.
type Empty struct {
	Schema string `json:"schema"`
}

// WorkerCheckRequest is POST /api/v1/glovo/worker/check.
type WorkerCheckRequest struct {
	Schema          string `json:"schema"`
	ConnectionID    string `json:"connection_id"`
	InstallRevision int64  `json:"install_revision"`
}

// WorkerCheckResponse is its answer. Allowed is true only for an active,
// unexpired connection whose owner is still a member and on the allowlist.
type WorkerCheckResponse struct {
	Schema           string     `json:"schema"`
	Allowed          bool       `json:"allowed"`
	Tenant           string     `json:"tenant"`
	OwnerPrincipalID string     `json:"owner_principal_id"`
	State            string     `json:"state"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
}

// WorkerActivateRequest is POST /api/v1/glovo/worker/connections/{id}/activate.
type WorkerActivateRequest struct {
	Schema          string `json:"schema"`
	InstallRevision int64  `json:"install_revision"`
	HandoffRef      string `json:"handoff_ref"`
}

// InstallationRequest is PUT /api/v1/glovo/tenants/{tenant}/installation. The
// revision is optional: absent means the current one.
type InstallationRequest struct {
	Schema          string `json:"schema"`
	InstallRevision *int64 `json:"install_revision,omitempty"`
}

// Installation is the answer of the installation routes.
type Installation struct {
	Schema          string `json:"schema"`
	Tenant          string `json:"tenant"`
	InstallationID  string `json:"installation_id"`
	InstallRevision int64  `json:"install_revision"`
	State           string `json:"state"`
}

// versioned is implemented by every request body.
type versioned interface{ schemaValue() string }

func (e *Empty) schemaValue() string                 { return e.Schema }
func (e *WorkerCheckRequest) schemaValue() string    { return e.Schema }
func (e *WorkerActivateRequest) schemaValue() string { return e.Schema }
func (e *InstallationRequest) schemaValue() string   { return e.Schema }

func invalid() *glovo.Error { return glovo.Refuse(glovo.CodeInvalidRequest) }

// Decode reads the request body into dst: at most MaxBodyBytes, no unknown
// field, no trailing data, and the exact schema. Any failure is
// invalid_request. With optional, an empty body is accepted and leaves dst
// zero (the caller must not read it).
func Decode(w http.ResponseWriter, r *http.Request, dst versioned, schema string, optional bool) *glovo.Error {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	if err != nil {
		return invalid()
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		if optional {
			return nil
		}
		return invalid()
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return invalid()
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return invalid()
	}
	if dst.schemaValue() != schema {
		return invalid()
	}
	return nil
}
