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

package contract

import (
	"strings"
	"time"
)

// Support constraint limits.
const (
	SupportMaxTTL   = 24 * time.Hour
	SupportMaxFires = 3
)

// SupportInputs are the already-resolved facts the Support constraints apply to.
type SupportInputs struct {
	OwnerAuthorized   bool
	TenantBound       bool
	Scope             AgentScope
	TTL               time.Duration
	MaxFires          int
	Capabilities      []string
	DelegatedActor    string
	ImpersonatedOwner string
	AuthRef           string
	AuthRefLive       bool // independent live authorization of AuthRef
}

// CheckSupport enforces the support.diagnostic-followup.v1 constraints; any
// violation is automation_support_constraint. An auth_ref alone never
// authorizes anything.
func CheckSupport(in SupportInputs) error {
	switch {
	case !in.OwnerAuthorized:
		return fail(CodeSupportConstraint, "tenant owner authorization required")
	case !in.TenantBound:
		return fail(CodeSupportConstraint, "must be bound to exactly one tenant")
	case in.Scope != ScopeSupport:
		return fail(CodeSupportConstraint, "support agent scope required")
	case in.TTL <= 0 || in.TTL > SupportMaxTTL:
		return fail(CodeSupportConstraint, "ttl must be within 24h")
	case in.MaxFires < 1 || in.MaxFires > SupportMaxFires:
		return fail(CodeSupportConstraint, "max_fires must be 1..%d", SupportMaxFires)
	case in.DelegatedActor != "":
		return fail(CodeSupportConstraint, "delegated actor not allowed")
	case in.ImpersonatedOwner != "":
		return fail(CodeSupportConstraint, "impersonated owner not allowed")
	case in.AuthRef != "" && !in.AuthRefLive:
		return fail(CodeSupportConstraint, "auth_ref requires live authorization")
	}
	for _, c := range in.Capabilities {
		if !strings.HasPrefix(c, "read.") {
			return fail(CodeSupportConstraint, "write capability %q not allowed", c)
		}
	}
	return nil
}

// supportInputsFromBody derives the body-visible facts. Tenant binding, owner
// authorization and auth_ref liveness are server facts established at the
// authority checkpoints; at body-validation time the tenant comes from the
// authenticated context, and an auth_ref is never live.
func supportInputsFromBody(obj map[string]any, tmpl Template) SupportInputs {
	in := SupportInputs{OwnerAuthorized: true, TenantBound: true, Scope: tmpl.Scope}
	if f, ok := obj["ttl_seconds"].(interface{ Int64() (int64, error) }); ok {
		n, _ := f.Int64()
		in.TTL = time.Duration(n) * time.Second
	}
	if f, ok := obj["max_fires"].(interface{ Int64() (int64, error) }); ok {
		n, _ := f.Int64()
		in.MaxFires = int(n)
	}
	in.DelegatedActor, _ = obj["delegate"].(string)
	in.ImpersonatedOwner, _ = obj["impersonate_owner"].(string)
	in.AuthRef, _ = obj["auth_ref"].(string)
	if caps, ok := obj["requested_capabilities"].([]any); ok {
		for _, c := range caps {
			if s, ok := c.(string); ok {
				in.Capabilities = append(in.Capabilities, s)
			}
		}
	}
	return in
}
