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

package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"
)

// The Glovo control worker (mctl-api#985) is the machine identity of the
// DevLoop control activities that dispatch and cancel a Glovo order and read
// its command and approval. It is distinct from the bridge provider, the #961
// Glovo worker, the orchestrator-DevLoop principal and every other principal,
// is not an admin, belongs to no tenant of its own and holds exactly one
// permission (PermissionGlovoControlDispatch). The API confines it to the
// /api/v1/internal/glovo routes (glovoControlWorkerGate).
//
// Its credential is a federated service OIDC token whose issuer, subject,
// audience, exp and nbf are pinned (GlovoControlWorkerConfig.PinClaims).
// There is no production verifier: ZITADEL versus Vault for the Temporal
// workload identity is the issuer decision mctl-gitops#2506, which this
// change must not make. Until a follow-up wires one, nothing in a production
// build can produce this principal, so every route answers 403 to every
// caller; a test builds the principal directly with NewGlovoControlWorkerUser.
const (
	// GlovoControlWorkerUserID is the identity of the control worker.
	GlovoControlWorkerUserID = "service:glovo-control-worker"
	// PermissionGlovoControlDispatch is held only by the control worker.
	PermissionGlovoControlDispatch = "glovo:control-dispatch"
	// GlovoControlAudience is the exact audience a control-worker token carries.
	GlovoControlAudience = "mctl-api-glovo-control"

	glovoControlWorkerEnv = "MCTL_GLOVO_CONTROL_WORKER"
)

// GlovoControlWorkerConfig is MCTL_GLOVO_CONTROL_WORKER. Tenants are a
// required, non-empty upper bound: an order or command outside it is not
// found. The tenant and owner of an order are read from its stored row.
type GlovoControlWorkerConfig struct {
	Issuer   string   `json:"issuer"`
	Subject  string   `json:"subject"`
	Audience string   `json:"audience"`
	Tenants  []string `json:"tenants"`
}

// NewGlovoControlWorkerUser builds the control-worker principal. A production
// build has no caller of it until the verifier of mctl-gitops#2506 lands.
func NewGlovoControlWorkerUser() *User {
	return &User{ID: GlovoControlWorkerUserID, glovoControlWorker: true}
}

// IsGlovoControlWorker reports whether the caller is the control worker. It is
// false for every other principal type: users, admins, the Glovo facade
// (IsGlovoAudience), bridge providers, the #961 Glovo worker, the
// orchestrator-DevLoop principal, agents, CI and surfaces.
func (u *User) IsGlovoControlWorker() bool { return u != nil && u.glovoControlWorker }

// ParseGlovoControlWorker parses MCTL_GLOVO_CONTROL_WORKER strictly: unknown
// fields, trailing data, a non-https issuer, an empty subject, an audience
// other than GlovoControlAudience, an empty tenants list and an empty tenant
// name are all errors. Empty input is no configuration (nil, nil).
func ParseGlovoControlWorker(raw string) (*GlovoControlWorkerConfig, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	var c GlovoControlWorkerConfig
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", glovoControlWorkerEnv, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%s: trailing data after the JSON object", glovoControlWorkerEnv)
	}
	if u, err := url.Parse(c.Issuer); err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("%s: issuer must be an https URL", glovoControlWorkerEnv)
	}
	if strings.TrimSpace(c.Subject) == "" {
		return nil, fmt.Errorf("%s: subject is required", glovoControlWorkerEnv)
	}
	if c.Audience != GlovoControlAudience {
		return nil, fmt.Errorf("%s: audience must be exactly %q", glovoControlWorkerEnv, GlovoControlAudience)
	}
	if len(c.Tenants) == 0 {
		return nil, fmt.Errorf("%s: tenants must not be empty", glovoControlWorkerEnv)
	}
	for i, t := range c.Tenants {
		c.Tenants[i] = strings.TrimSpace(t)
		if c.Tenants[i] == "" {
			return nil, fmt.Errorf("%s: empty tenant name", glovoControlWorkerEnv)
		}
	}
	return &c, nil
}

// LoadGlovoControlWorker reads MCTL_GLOVO_CONTROL_WORKER. A malformed value
// disables the mapping, with an error log: it returns nil.
func LoadGlovoControlWorker() *GlovoControlWorkerConfig {
	c, err := ParseGlovoControlWorker(os.Getenv(glovoControlWorkerEnv))
	if err != nil {
		slog.Error("invalid glovo control worker configuration; the control worker is disabled", "error", err)
		return nil
	}
	return c
}

// PinClaims is the exact-trust check for a verified service JWT: issuer,
// subject and audience must equal the pins, exp must be in the future and nbf,
// when present, must not be. It fails closed on any missing value. The
// signature and JWKS trust are the verifier's job, before this is called.
func (c GlovoControlWorkerConfig) PinClaims(issuer string, audiences []string, subject string, exp, nbf, now time.Time) error {
	if issuer == "" || issuer != c.Issuer {
		return fmt.Errorf("control worker token issuer is not the pinned issuer")
	}
	if subject == "" || subject != c.Subject {
		return fmt.Errorf("control worker token subject is not the pinned subject")
	}
	ok := false
	for _, a := range audiences {
		if a == c.Audience {
			ok = true
		}
	}
	if !ok {
		return fmt.Errorf("control worker token audience is not %q", c.Audience)
	}
	if exp.IsZero() || !exp.After(now) {
		return fmt.Errorf("control worker token is expired or has no exp")
	}
	if !nbf.IsZero() && nbf.After(now) {
		return fmt.Errorf("control worker token is not yet valid")
	}
	return nil
}
