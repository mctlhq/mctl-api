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
	"strconv"
)

// Canonical principals, phase 1 (mctl-api#373).
//
// Every authenticated caller also carries an opaque, mctl-api-issued
// principal id (prn_<ulid>), resolved from the external identity the caller
// proved: never from a login's spelling. Phase 1 only RECORDS it. Nothing
// authorizes on it yet; User.ID and User.Groups still decide access. The one
// exception is a disabled principal, which is refused at authentication.

// External identity providers.
const (
	// ProviderGitHub: subject is the numeric GitHub user id. The login is
	// display only, because logins can be renamed and then reused.
	ProviderGitHub = "github"
	// ProviderDex: issuer is the token's iss, subject its sub.
	ProviderDex = "dex"
	// ProviderService: subject is "mctl-agent", "surface:<name>" or the
	// usage writer, "service:mctl-agents-usage".
	ProviderService = "service"
	// ProviderDev: the dev-mode caller (AUTH_REQUIRED=false) only.
	ProviderDev = "dev"
)

// Principal kinds.
const (
	KindHuman   = "human"
	KindAgent   = "agent"
	KindService = "service"
)

// Identity is what authentication proved about a caller, in the form the
// principal store keys on.
type Identity struct {
	Provider string
	Issuer   string
	Subject  string
	// Display is informational (a login, a preferred_username). It is never
	// used to decide which principal an identity belongs to, except for the
	// GitHub login-only case below.
	Display string
	Kind    string
}

// GitHubLoginOnly reports an identity whose GitHub login was proven earlier
// (a local OAuth JWT minted after the GitHub callback, or a relayed human),
// but whose numeric id is not at hand. The resolver maps it through the
// login recorded for a known GitHub identity, or asks GitHub for the id.
func (i Identity) GitHubLoginOnly() bool {
	return i.Provider == ProviderGitHub && i.Subject == "" && i.Display != ""
}

// PrincipalResolver maps a proven identity to its canonical principal id,
// provisioning one where the rules allow it.
type PrincipalResolver interface {
	ResolvePrincipal(ctx context.Context, id Identity) (string, error)
}

var (
	// ErrPrincipalDisabled: the identity belongs to a disabled principal.
	// Refused at authentication already in phase 1.
	ErrPrincipalDisabled = errors.New("principal is disabled")
	// ErrIdentityRefused: an identity no rule may provision, such as the
	// dev identity when authentication is required.
	ErrIdentityRefused = errors.New("identity is not accepted")
)

// PrincipalID is the caller's canonical principal id, or "" when it could
// not be resolved (phase 1 degrades rather than refusing; see
// AttachPrincipal).
func (u *User) PrincipalID() string {
	if u == nil {
		return ""
	}
	return u.principalID
}

// ViaPrincipalID is the principal of the surface that relayed this request,
// or "" when the caller acted directly.
func (u *User) ViaPrincipalID() string {
	if u == nil {
		return ""
	}
	return u.viaPrincipalID
}

// Identity is the external identity this caller proved, and false when it
// proved none the principal model records.
func (u *User) Identity() (Identity, bool) {
	switch {
	case u == nil:
		return Identity{}, false
	case u.service:
		return Identity{Provider: ProviderService, Subject: ServiceUserID, Display: ServiceUserID, Kind: KindService}, true
	case u.surface != "":
		return Identity{Provider: ProviderService, Subject: u.ID, Display: u.ID, Kind: KindService}, true
	case u.usageWriter:
		return Identity{Provider: ProviderService, Subject: UsageWriterUserID, Display: UsageWriterUserID, Kind: KindService}, true
	case u.dev:
		return Identity{Provider: ProviderDev, Subject: u.ID, Display: u.ID, Kind: KindHuman}, true
	case u.dexSubject != "":
		return Identity{Provider: ProviderDex, Issuer: u.dexIssuer, Subject: u.dexSubject, Display: u.ID, Kind: KindHuman}, true
	case u.githubLogin && u.githubID > 0:
		return Identity{Provider: ProviderGitHub, Subject: strconv.FormatInt(u.githubID, 10), Display: u.ID, Kind: KindHuman}, true
	case u.githubLogin:
		return Identity{Provider: ProviderGitHub, Display: u.ID, Kind: KindHuman}, true
	}
	return Identity{}, false
}

// AttachPrincipal resolves u's principal and records it on u. A nil resolver
// or a caller with no recordable identity leaves u unchanged.
//
// ErrPrincipalDisabled and ErrIdentityRefused are returned as they are, for
// the caller to refuse the request. Any other error means the principal
// could not be resolved (the store is unavailable, GitHub did not answer):
// the caller proceeds without a principal id, because in phase 1 nothing
// authorizes on it.
func AttachPrincipal(ctx context.Context, pr PrincipalResolver, u *User) error {
	if pr == nil || u == nil {
		return nil
	}
	id, ok := u.Identity()
	if !ok {
		return nil
	}
	principal, err := pr.ResolvePrincipal(ctx, id)
	if err != nil {
		return err
	}
	u.principalID = principal
	return nil
}
