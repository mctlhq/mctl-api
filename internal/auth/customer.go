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
// A customer may instead sign in with Google (mctl-api#1079). The hook then
// proves Google's subject (`mctl:google_sub`) and nothing about GitHub, and
// the token resolves to the principal of that Google subject. Google proofs
// are accepted only where the caller enables them (ReadCustomerProofWith):
// until the customers organization has a Google IdP, a Google token is as
// unproven as any other.
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
	// ScopeOrgIDPrefix, followed by an organization id, makes ZITADEL sign
	// the user in to that organization, under its login policy.
	ScopeOrgIDPrefix = "urn:zitadel:iam:org:id:"
	// ScopeIdPIDPrefix, followed by an IdP id, sends the user straight to
	// that identity provider instead of the login page.
	ScopeIdPIDPrefix = "urn:zitadel:iam:org:idp:id:"

	// The identity hook's claims; the names match internal/zitadelhook.
	ClaimCustomerOrg         = "mctl:org"
	ClaimCustomerIdP         = "mctl:idp"
	ClaimCustomerGitHubID    = "mctl:github_id"
	ClaimCustomerGitHubLogin = "mctl:github_login"
	ClaimCustomerGoogleSub   = "mctl:google_sub"
	ClaimCustomerRefused     = "mctl:refused"

	customerOrgName = "customers"
	customerIdP     = "github"
	customerIdPGoog = "google"
)

var (
	// ErrResourceOwnerUnknown: a token from an issuer with a customers
	// organization that does not say which organization its user is in.
	ErrResourceOwnerUnknown = errors.New("the ZITADEL token does not name its user's organization")
	// ErrCustomerUnproven: a customers token without a usable GitHub
	// identity: the hook refused it, failed, or did not run for the client.
	ErrCustomerUnproven = errors.New("the customer token carries no proven GitHub or Google identity")
)

var (
	githubIDRE    = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
	githubLoginRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9]|-[A-Za-z0-9])*$`)
	// googleSubRE matches the identity hook's rule: Google subjects are
	// decimal, at most 255 characters by OIDC, in practice 21 digits.
	googleSubRE = regexp.MustCompile(`^[0-9]{1,64}$`)
)

// ValidGoogleSubject reports whether s has the shape of a Google subject.
func ValidGoogleSubject(s string) bool { return googleSubRE.MatchString(s) }

// maxGitHubLogin is GitHub's login length limit.
const maxGitHubLogin = 39

// ValidGitHubLogin reports whether s follows GitHub's login grammar.
func ValidGitHubLogin(s string) bool {
	return len(s) <= maxGitHubLogin && githubLoginRE.MatchString(s)
}

// CustomerProof is the external identity a customers token carries:
// Provider ProviderGitHub with GitHubID and GitHubLogin, or ProviderGoogle
// with GoogleSub. The other provider's fields are empty.
type CustomerProof struct {
	Provider    string
	GitHubID    string
	GitHubLogin string
	GoogleSub   string
}

// Identity is the identity the customer's principal is keyed by. A proof of
// any other provider yields an identity with no provider, which the
// principal store refuses as invalid: never a guess.
func (c CustomerProof) Identity() Identity {
	switch c.Provider {
	case ProviderGitHub:
		return Identity{Provider: ProviderGitHub, Subject: c.GitHubID, Display: c.GitHubLogin, Kind: KindHuman}
	case ProviderGoogle:
		// No display: the hook puts no name or email into the token, and
		// the subject is not one.
		return Identity{Provider: ProviderGoogle, Subject: c.GoogleSub, Kind: KindHuman}
	}
	return Identity{Kind: KindHuman}
}

// Subject is the proven subject of the proof's provider, for logs and
// messages.
func (c CustomerProof) Subject() string {
	if c.Provider == ProviderGoogle {
		return c.GoogleSub
	}
	return c.GitHubID
}

// ReadCustomerProof reads the customer claims of a verified ZITADEL token,
// accepting a GitHub identity only. It answers (nil, nil) for a user of any
// other organization. A missing organization is ErrResourceOwnerUnknown; a
// customers token without a complete, well-formed GitHub identity is
// ErrCustomerUnproven.
func ReadCustomerProof(claims map[string]any, customersOrgID string) (*CustomerProof, error) {
	return ReadCustomerProofWith(claims, customersOrgID, false)
}

// ReadCustomerProofWith is ReadCustomerProof that, with acceptGoogle, also
// accepts a Google identity. A token carrying claims of both providers is
// unproven whichever it names: the hook never issues one, so it is not a
// token to pick a side of.
func ReadCustomerProofWith(claims map[string]any, customersOrgID string, acceptGoogle bool) (*CustomerProof, error) {
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
	_, hasGitHubID := claims[ClaimCustomerGitHubID]
	_, hasGitHubLogin := claims[ClaimCustomerGitHubLogin]
	_, hasGoogle := claims[ClaimCustomerGoogleSub]
	if org == customerOrgName && idp == customerIdPGoog && acceptGoogle {
		sub, _ := claims[ClaimCustomerGoogleSub].(string)
		switch {
		case hasGitHubID || hasGitHubLogin:
			return nil, fmt.Errorf("%w: a Google token carries GitHub claims", ErrCustomerUnproven)
		case !googleSubRE.MatchString(sub):
			return nil, fmt.Errorf("%w: %s is missing or not a Google subject", ErrCustomerUnproven, ClaimCustomerGoogleSub)
		}
		return &CustomerProof{Provider: ProviderGoogle, GoogleSub: sub}, nil
	}
	id, _ := claims[ClaimCustomerGitHubID].(string)
	login, _ := claims[ClaimCustomerGitHubLogin].(string)
	switch {
	case org != customerOrgName || idp != customerIdP:
		return nil, fmt.Errorf("%w: %s=%q, %s=%q", ErrCustomerUnproven, ClaimCustomerOrg, org, ClaimCustomerIdP, idp)
	case hasGoogle:
		return nil, fmt.Errorf("%w: a GitHub token carries %s", ErrCustomerUnproven, ClaimCustomerGoogleSub)
	case !githubIDRE.MatchString(id):
		return nil, fmt.Errorf("%w: %s is missing or not a GitHub id", ErrCustomerUnproven, ClaimCustomerGitHubID)
	case !ValidGitHubLogin(login):
		return nil, fmt.Errorf("%w: %s is missing or not a GitHub login", ErrCustomerUnproven, ClaimCustomerGitHubLogin)
	}
	return &CustomerProof{Provider: ProviderGitHub, GitHubID: id, GitHubLogin: login}, nil
}
