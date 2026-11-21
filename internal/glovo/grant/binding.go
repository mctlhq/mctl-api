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

// Package grant is the R2 ApprovalGrant of the Glovo write path
// (mctl-api#1011): a single-use, expiring authorization to change one real
// provider cart, minted from a human basket decision and spent by a
// server-side verify-and-consume call at the point of effect.
//
// This package has no effect path. It does not call a provider, is imported
// by no route, MCP tool or startup code, and ships no Postgres store: the
// Store interface is the seam of the next slice. Two properties are enforced
// by construction and pinned by tests:
//
//   - a grant is minted only from a HumanDecision, a value only
//     DecisionFromApproval can build, and only from an approved, unexpired
//     owner decision of a glovo.basket_approval; nothing the caller supplies
//     can name another tenant, owner, basket or revision;
//   - a grant is spent only by VerifyAndConsume, which refuses a foreign,
//     expired, replayed or drifted grant, and which leaves a grant that
//     merely went stale unconsumed.
//
// "Could not observe" is never "no drift": every live value a consume needs
// is mandatory, and an empty one is an invalid request, not a match.
package grant

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/mctlhq/mctl-api/internal/glovo/basket"
	"github.com/mctlhq/mctl-api/internal/jcs"
)

// FingerprintVersion is the domain tag of a grant fingerprint.
const FingerprintVersion = "mctl-approval-grant/v1"

// IDPrefix prefixes every grant id.
const IDPrefix = "agr_"

// MaxGrantTTL bounds how long a minted grant lives, whatever the approval's
// own expiry is.
const MaxGrantTTL = 15 * time.Minute

var (
	sha256RE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	idRE     = regexp.MustCompile(`^[A-Za-z0-9_.:@-]{1,128}$`)
	basketRE = regexp.MustCompile(`^gbk_[A-Za-z0-9]{26}$`)
	grantRE  = regexp.MustCompile(`^agr_[0-9a-f]{32}$`)
)

// ErrInvalid marks a malformed input, never a refusal of a well-formed one.
var ErrInvalid = errors.New("glovo grant: invalid")

func invalidf(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Binding is everything a grant is bound to. Every field is mandatory and
// immutable once minted.
//
//   - Tenant and OwnerPrincipalID: whose basket, and who decided.
//   - ConnectionID and ConnectionRevision: which provider connection, at
//     which authority revision. Any change of scope, identity, confirmation,
//     disable or revocation must bump the revision, which strands the grant.
//   - BasketID, BasketRevision and BasketFingerprint: the exact frozen
//     revision the human saw (the fingerprint is the canonical-form hash).
//   - ProviderCartVersion: the provider cart version the plan was diffed
//     against.
//   - PriceSnapshotDigest: the digest of the price and fee snapshot read from
//     the provider when the plan was made.
//   - ExpiresAt: when the grant stops being spendable (UTC).
type Binding struct {
	Tenant              string
	OwnerPrincipalID    string
	ConnectionID        string
	ConnectionRevision  int64
	BasketID            string
	BasketRevision      int64
	BasketFingerprint   string
	ProviderCartVersion string
	PriceSnapshotDigest string
	ExpiresAt           time.Time
}

// Validate refuses a binding with a missing or malformed field.
func (b Binding) Validate() error {
	switch {
	case !idRE.MatchString(b.Tenant):
		return invalidf("tenant")
	case len(b.OwnerPrincipalID) <= len("prn_") || b.OwnerPrincipalID[:4] != "prn_" || !idRE.MatchString(b.OwnerPrincipalID):
		return invalidf("owner_principal_id must be a prn_ id")
	case !idRE.MatchString(b.ConnectionID):
		return invalidf("connection_id")
	case b.ConnectionRevision < 1:
		return invalidf("connection_revision must be positive")
	case !basketRE.MatchString(b.BasketID):
		return invalidf("basket_id")
	case b.BasketRevision < 1:
		return invalidf("basket_revision must be positive")
	case !sha256RE.MatchString(b.BasketFingerprint):
		return invalidf("basket_fingerprint")
	case !idRE.MatchString(b.ProviderCartVersion):
		return invalidf("provider_cart_version")
	case !sha256RE.MatchString(b.PriceSnapshotDigest):
		return invalidf("price_snapshot_digest")
	case b.ExpiresAt.IsZero():
		return invalidf("expires_at")
	}
	return nil
}

// Fingerprint is "sha256:" + hex(sha256(JCS(binding))), the construction of
// the basket fingerprint. The expiry enters as UTC unix microseconds, so no
// floating-point or time-zone spelling can change the digest.
func (b Binding) Fingerprint() (string, error) {
	if err := b.Validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(struct {
		V                   string `json:"v"`
		Tenant              string `json:"tenant"`
		OwnerPrincipalID    string `json:"owner_principal_id"`
		ConnectionID        string `json:"connection_id"`
		ConnectionRevision  int64  `json:"connection_revision"`
		BasketID            string `json:"basket_id"`
		BasketRevision      int64  `json:"basket_revision"`
		BasketFingerprint   string `json:"basket_fingerprint"`
		ProviderCartVersion string `json:"provider_cart_version"`
		PriceSnapshotDigest string `json:"price_snapshot_digest"`
		ExpiresAtUnixMicro  int64  `json:"expires_at_unix_micro"`
	}{FingerprintVersion, b.Tenant, b.OwnerPrincipalID, b.ConnectionID, b.ConnectionRevision, b.BasketID,
		b.BasketRevision, b.BasketFingerprint, b.ProviderCartVersion, b.PriceSnapshotDigest, b.ExpiresAt.UTC().UnixMicro()})
	if err != nil {
		return "", fmt.Errorf("glovo grant: marshal: %w", err)
	}
	canonical, err := jcs.Canonicalize(raw)
	if err != nil {
		return "", fmt.Errorf("glovo grant: canonicalize: %w", err)
	}
	return basket.Fingerprint(canonical), nil
}
