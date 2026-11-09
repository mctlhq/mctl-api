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

package auth

import (
	"context"
	"errors"
	"fmt"
)

// ErrSignInRefused is the error of UserForSignIn for an identity that may
// not act: its principal is disabled, refused, or could not be decided.
var ErrSignInRefused = errors.New("sign-in identity refused")

// UserForSignIn builds the caller a server-side sign-in proved, as the
// bearer middleware would build it for the same verified human identity:
// the generic federated user, its principal attached, principal mode
// applied (mctl-api#964). The API itself verified the ID token, so there is
// no bearer and no token claims: the user carries no groups, and in
// principal mode its admin bit comes from its principal alone.
//
// Unlike the middleware it fails closed on every principal error, including
// one the middleware would let through without a principal id: a sign-in
// that decides something must know who decided it.
func UserForSignIn(ctx context.Context, id Identity, pr PrincipalResolver, authz *PrincipalAuthz) (*User, error) {
	if id.Kind != KindHuman || id.Provider == "" || id.Issuer == "" || id.Subject == "" ||
		reservedProviderNames[id.Provider] || id.Provider == ProviderDex || id.Customer != nil {
		return nil, fmt.Errorf("%w: not a federated human identity", ErrSignInRefused)
	}
	if IsOrchestratorDevLoopIdentity(id) {
		return nil, fmt.Errorf("%w: the orchestrator machine user is not a person", ErrSignInRefused)
	}
	u := userFromVerified(&Verified{Identity: id})
	if pr == nil {
		return nil, fmt.Errorf("%w: no principal resolver", ErrSignInRefused)
	}
	if err := AttachPrincipal(ctx, pr, u); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignInRefused, err)
	}
	if u.PrincipalID() == "" {
		return nil, fmt.Errorf("%w: principal not resolved", ErrSignInRefused)
	}
	if authz != nil {
		if err := authz.Apply(u); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrSignInRefused, err)
		}
	}
	return u, nil
}
