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

package api

import (
	"errors"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// principalMode reports whether tenants are decided by principal.
func (h *Handlers) principalMode() bool { return h.opts.TenantAuthzMode == TenantAuthzPrincipal }

// authorizeSubject decides, in principal mode, the tenants of a subject a
// surface relays for or an agent run delegates to, the same way the
// middleware decides a direct caller's (mctl-api#377 B5): by its principal,
// never by its login, and never admin. An error means the subject cannot
// be decided (no principal, membership unreadable, not configured) and the
// request must be refused with 503. Outside principal mode it does nothing.
func (h *Handlers) authorizeSubject(subject *auth.User) error {
	if !h.principalMode() {
		return nil
	}
	if h.opts.PrincipalAuthz == nil {
		return errors.New("principal authorization is not configured")
	}
	return h.opts.PrincipalAuthz.Apply(subject)
}
