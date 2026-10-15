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
	"errors"
	"fmt"
	"regexp"
)

// Self-service customer accounts (mctl-web docs/plans/site-onboarding-review.md,
// stage C0). A customer signs in to ZITADEL with GitHub and lands in the
// ZITADEL organization `customers`. The identity hook (internal/zitadelhook)
// records the GitHub numeric id the IdP proved and copies it into the
// `mctl:*` claims of the tokens it issues. Such a token is resolved to the
// principal of that GitHub id, never by its login and never by provisioning
// a principal for the ZITADEL subject alone.
//
// The token names its user's organization only when the client asked for
// ScopeResourceOwner. A token from the ZITADEL entry that does not name it
// is refused: an organization that could not be observed is never taken to
// be "not customers".

const (
	// ScopeResourceOwner asks ZITADEL to put the user's organization into
	// the token as ClaimResourceOwnerID.
	ScopeResourceOwner = "urn:zitadel:iam:user:resourceowner"
	// ClaimResourceOwnerID is the id of the organization the user belongs to.
	ClaimResourceOwnerID = "urn:zitadel:iam:user:resourceowner:id"

	// The identity hook's claims; the names match internal/zitadelhook.
	ClaimCustomerOrg         = "mctl:org"
	ClaimCustomerIdP         = "mctl:idp"
	ClaimCustomerGitHubID    = "mctl:github_id"
	ClaimCustomerGitHubLogin = "mctl:github_login"
	ClaimCustomerRefused     = "mctl:refused"

	customerOrgName = "customers"
	customerIdP     = "github"
)

var (
	// ErrResourceOwnerUnknown: a token from an issuer with a customers
	// organization that does not say which organization its user is in.
	ErrResourceOwnerUnknown = errors.New("the ZITADEL token does not name its user's organization")
	// ErrCustomerUnproven: a customers token without a usable GitHub
	// identity: the hook refused it, failed, or did not run for the client.
	ErrCustomerUnproven = errors.New("the customer token carries no proven GitHub identity")
)

var (
	githubIDRE    = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
	githubLoginRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9]|-[A-Za-z0-9])*$`)
)

// maxGitHubLogin is GitHub's login length limit.
const maxGitHubLogin = 39

// ValidGitHubLogin reports whether s follows GitHub's login grammar.
func ValidGitHubLogin(s string) bool {
	return len(s) <= maxGitHubLogin && githubLoginRE.MatchString(s)
}

// CustomerProof is the GitHub identity a customers token carries.
type CustomerProof struct {
	GitHubID    string
	GitHubLogin string
}

// GitHubIdentity is the identity the customer's principal is keyed by.
func (c CustomerProof) GitHubIdentity() Identity {
	return Identity{Provider: ProviderGitHub, Subject: c.GitHubID, Display: c.GitHubLogin, Kind: KindHuman}
}

// ReadCustomerProof reads the customer claims of a verified ZITADEL token.
// It answers (nil, nil) for a user of any other organization. A missing
// organization is ErrResourceOwnerUnknown; a customers token without a
// complete, well-formed GitHub identity is ErrCustomerUnproven.
func ReadCustomerProof(claims map[string]any, customersOrgID string) (*CustomerProof, error) {
	if customersOrgID == "" {
		return nil, errors.New("no customers organization configured")
	}
	owner, ok := claims[ClaimResourceOwnerID].(string)
	if !ok || owner == "" {
		return nil, ErrResourceOwnerUnknown
	}
	if owner != customersOrgID {
		return nil, nil
	}
	if reason, present := claims[ClaimCustomerRefused]; present {
		return nil, fmt.Errorf("%w: the identity hook refused it (%v)", ErrCustomerUnproven, reason)
	}
	org, _ := claims[ClaimCustomerOrg].(string)
	idp, _ := claims[ClaimCustomerIdP].(string)
	id, _ := claims[ClaimCustomerGitHubID].(string)
	login, _ := claims[ClaimCustomerGitHubLogin].(string)
	switch {
	case org != customerOrgName || idp != customerIdP:
		return nil, fmt.Errorf("%w: %s=%q, %s=%q", ErrCustomerUnproven, ClaimCustomerOrg, org, ClaimCustomerIdP, idp)
	case !githubIDRE.MatchString(id):
		return nil, fmt.Errorf("%w: %s is missing or not a GitHub id", ErrCustomerUnproven, ClaimCustomerGitHubID)
	case !ValidGitHubLogin(login):
		return nil, fmt.Errorf("%w: %s is missing or not a GitHub login", ErrCustomerUnproven, ClaimCustomerGitHubLogin)
	}
	return &CustomerProof{GitHubID: id, GitHubLogin: login}, nil
}
