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

package glovo

import "github.com/mctlhq/mctl-api/internal/auth"

// Gate is the Glovo feature gate. It infers no tenant.
type Gate struct{ Open bool }

// Default is closed. It is a constant of the build, not configuration, so
// nothing can open it before the later slices exist.
var Default = Gate{Open: false}

// ControlDefault is the gate of the control-worker routes (mctl-api#985). It
// is backed by an unexported constant of the build (gate_release.go, or
// gate_fixture.go under the glovojoin_fixture tag), so a configuration value
// can never open it.
var ControlDefault = Gate{Open: controlGateOpen}

// Authorize returns nil only for an open gate and a Glovo-audience caller
// with a resolved principal. Closed: not_ready for everyone. Admin status
// grants nothing.
func (g Gate) Authorize(u *auth.User) error {
	if !g.Open {
		return &Error{Code: CodeNotReady, Description: "the glovo facade is not ready"}
	}
	deny := &Error{Code: CodeNotAuthorized, Description: "not authorized for the glovo facade"}
	if u == nil || !u.IsGlovoAudience() || u.PrincipalID() == "" || u.PrincipalUnresolved() {
		return deny
	}
	if u.IsAgent() || u.IsService() || u.IsCI() || u.IsSupportAudience() || u.ViaPrincipalID() != "" {
		return deny
	}
	if _, ok := u.Surface(); ok {
		return deny
	}
	return nil
}
