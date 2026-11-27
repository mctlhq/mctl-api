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

package grant

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Grant is one minted authorization. A grant is consumed at most once.
type Grant struct {
	ID         string
	ApprovalID string
	Binding    Binding
	// Fingerprint is Binding.Fingerprint() at mint time; it is re-derived at
	// every consume, so a stored row that does not reproduce is refused.
	Fingerprint string
	// IdempotencyKey is generated here, never by a caller, and is the only
	// key the effect may use toward the provider.
	IdempotencyKey string
	MintedAt       time.Time
	ConsumedAt     *time.Time
}

// Store is the grant ledger. Implementations must make Insert unique on
// ApprovalID and Consume an atomic compare-and-set; a failed or partial read
// is an error, never ErrNotFound.
type Store interface {
	// Insert stores g. When a grant of g.ApprovalID exists it is returned with
	// created=false and nothing is written.
	Insert(ctx context.Context, g Grant) (stored Grant, created bool, err error)
	// Get returns the grant or glovo.ErrNotFound.
	Get(ctx context.Context, id string) (Grant, error)
	// Consume marks the grant consumed at "at" if and only if it is not
	// consumed yet and not expired at "at". It returns the grant as consumed,
	// glovo.CodeApprovalReplayed when it was already consumed, or
	// glovo.CodeApprovalExpired when it is past its expiry.
	Consume(ctx context.Context, id string, at time.Time) (Grant, error)
}

// HumanDecision is proof that the bound owner approved one frozen basket
// revision. Its fields are unexported: the only constructor is
// DecisionFromApproval, so a caller cannot invent a decision, widen one, or
// point it at another basket.
type HumanDecision struct {
	valid      bool
	approvalID string
	tenant     string
	owner      string
	basketID   string
	revision   int64
	basketFP   string
	// until is the earliest of the approval's expiry and fresh_until.
	until time.Time
}

// ApprovalID is the aar_ the decision belongs to.
func (d HumanDecision) ApprovalID() string { return d.approvalID }

// DecisionFromApproval builds a HumanDecision from the ledger rows of a
// decided basket approval. It is the human decision path's call only (see
// the architecture test): it accepts nothing but an approved
// glovo.basket_approval whose decider is the bound owner acting as resource
// owner, not yet expired at "now".
func DecisionFromApproval(a *workitems.ActionApprovalRequest, b *workitems.GlovoBasketBinding, now time.Time) (HumanDecision, error) {
	switch {
	case a == nil || b == nil:
		return HumanDecision{}, invalidf("approval and binding are required")
	case a.ActionKind != workitems.ActionKindGlovoBasketApproval || a.ID == "" || a.ID != b.ApprovalID:
		return HumanDecision{}, glovo.Refuse(glovo.CodeApprovalInvalid)
	case a.State != workitems.ApprovalApproved:
		return HumanDecision{}, glovo.Refuse(glovo.CodeApprovalInvalid)
	case b.OwnerPrincipalID == "" || a.DecidedByPrincipalID != b.OwnerPrincipalID || a.AuthorityBasis != workitems.GlovoAuthorityBasis:
		return HumanDecision{}, glovo.Refuse(glovo.CodeApprovalInvalid)
	}
	until := a.ExpiresAt
	if a.FreshUntil != nil && a.FreshUntil.Before(until) {
		until = *a.FreshUntil
	}
	if !until.After(now) {
		return HumanDecision{}, glovo.Refuse(glovo.CodeApprovalExpired)
	}
	return HumanDecision{valid: true, approvalID: a.ID, tenant: b.Tenant, owner: b.OwnerPrincipalID,
		basketID: b.BasketID, revision: b.Revision, basketFP: b.BasketFingerprint, until: until.UTC()}, nil
}

// Service mints and spends grants.
type Service struct {
	Store Store
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// NewID mints a grant id; nil is crypto/rand. It exists for tests.
	NewID func() (string, error)
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func newGrantID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("glovo grant: crypto/rand: %w", err)
	}
	return IDPrefix + hex.EncodeToString(raw[:]), nil
}

// MintInput is what the decision path adds to a HumanDecision: the provider
// connection and the live observations of the plan. The basket identity is
// not an input: it comes from the decision.
type MintInput struct {
	Decision            HumanDecision
	ConnectionID        string
	ConnectionRevision  int64
	ProviderCartVersion string
	PriceSnapshotDigest string
	// TTL is how long the grant lives, 0 < TTL <= MaxGrantTTL; the expiry is
	// also capped by the decision's own.
	TTL time.Duration
}

// Mint stores the grant of one human decision. One approval has one grant: a
// repeat with the same inputs returns it, a repeat that differs is refused
// as replayed.
func (s *Service) Mint(ctx context.Context, in MintInput) (*Grant, error) {
	if s == nil || s.Store == nil {
		return nil, glovo.Refuse(glovo.CodeNotReady)
	}
	d := in.Decision
	if !d.valid {
		return nil, glovo.Refuse(glovo.CodeApprovalInvalid)
	}
	if in.TTL <= 0 || in.TTL > MaxGrantTTL {
		return nil, invalidf("ttl must be positive and at most %s", MaxGrantTTL)
	}
	now := s.now()
	exp := now.Add(in.TTL)
	if d.until.Before(exp) {
		exp = d.until
	}
	if !exp.After(now) {
		return nil, glovo.Refuse(glovo.CodeApprovalExpired)
	}
	b := Binding{Tenant: d.tenant, OwnerPrincipalID: d.owner, ConnectionID: in.ConnectionID,
		ConnectionRevision: in.ConnectionRevision, BasketID: d.basketID, BasketRevision: d.revision,
		BasketFingerprint: d.basketFP, ProviderCartVersion: in.ProviderCartVersion,
		PriceSnapshotDigest: in.PriceSnapshotDigest, ExpiresAt: exp.UTC().Truncate(time.Microsecond)}
	fp, err := b.Fingerprint()
	if err != nil {
		return nil, err
	}
	mint := s.NewID
	if mint == nil {
		mint = newGrantID
	}
	id, err := mint()
	if err != nil {
		return nil, err
	}
	g := Grant{ID: id, ApprovalID: d.approvalID, Binding: b, Fingerprint: fp, IdempotencyKey: "glovo-grant:" + id, MintedAt: now}
	stored, created, err := s.Store.Insert(ctx, g)
	if err != nil {
		return nil, err
	}
	if !created && !sameScope(stored.Binding, b) {
		return nil, glovo.Refuse(glovo.CodeApprovalReplayed)
	}
	return &stored, nil
}

// sameScope compares two bindings on everything but the expiry, which a retry
// at a later clock legitimately moves.
func sameScope(a, b Binding) bool {
	a.ExpiresAt, b.ExpiresAt = time.Time{}, time.Time{}
	return a == b
}

// Live is what the caller just re-read from the provider and the connection
// at the point of effect. Every field is mandatory: an unobserved value is
// not a matching one.
type Live struct {
	ConnectionRevision  int64
	ProviderCartVersion string
	PriceSnapshotDigest string
}

// ConsumeRequest names the grant and the exact scope it is spent in.
type ConsumeRequest struct {
	GrantID           string
	Tenant            string
	OwnerPrincipalID  string
	ConnectionID      string
	BasketID          string
	BasketRevision    int64
	BasketFingerprint string
	Live              Live
}

func (r ConsumeRequest) validate() error {
	switch {
	case !grantRE.MatchString(r.GrantID):
		return invalidf("grant_id")
	case r.Tenant == "" || r.OwnerPrincipalID == "" || r.ConnectionID == "" || r.BasketID == "" || r.BasketRevision < 1 || r.BasketFingerprint == "":
		return invalidf("the consume scope is incomplete")
	case r.Live.ConnectionRevision < 1 || r.Live.ProviderCartVersion == "" || r.Live.PriceSnapshotDigest == "":
		return invalidf("live observations are mandatory")
	}
	return nil
}

// StaleError is approval_stale: the grant was valid but what it was bound to
// moved. The grant is left unconsumed, and a new plan needs a new approval.
type StaleError struct{ Drifted []string }

func (e *StaleError) Error() string { return "approval_stale: " + fmt.Sprint(e.Drifted) }

// IsStale reports an approval_stale refusal.
func IsStale(err error) bool { var se *StaleError; return errors.As(err, &se) }

// Consumed is what a successful VerifyAndConsume returns: the permission to
// perform exactly one effect, under the returned idempotency key.
type Consumed struct {
	GrantID        string
	ApprovalID     string
	Fingerprint    string
	IdempotencyKey string
	Binding        Binding
	ConsumedAt     time.Time
}

// VerifyAndConsume is the point-of-effect check. The order is fixed:
//
//  1. a malformed request is invalid;
//  2. the grant is read; a missing grant and a grant of another tenant,
//     owner, connection, basket, revision or fingerprint are one not_found,
//     so the answer is no oracle and nothing is consumed;
//  3. the stored binding is re-fingerprinted; a row that does not reproduce
//     is fingerprint_changed;
//  4. an already consumed grant is approval_replayed, a past-expiry one
//     approval_expired;
//  5. the live connection revision, cart version and price snapshot are
//     compared; any difference is approval_stale and the grant stays
//     unconsumed;
//  6. only then the grant is consumed by an atomic compare-and-set, whose
//     loss is again replayed or expired.
func (s *Service) VerifyAndConsume(ctx context.Context, req ConsumeRequest) (*Consumed, error) {
	if s == nil || s.Store == nil {
		return nil, glovo.Refuse(glovo.CodeNotReady)
	}
	if err := req.validate(); err != nil {
		return nil, err
	}
	g, err := s.Store.Get(ctx, req.GrantID)
	if err != nil {
		return nil, err
	}
	b := g.Binding
	if b.Tenant != req.Tenant || b.OwnerPrincipalID != req.OwnerPrincipalID || b.ConnectionID != req.ConnectionID ||
		b.BasketID != req.BasketID || b.BasketRevision != req.BasketRevision || b.BasketFingerprint != req.BasketFingerprint {
		return nil, glovo.ErrNotFound
	}
	fp, err := b.Fingerprint()
	if err != nil || fp != g.Fingerprint {
		return nil, glovo.Refuse(glovo.CodeFingerprintChanged)
	}
	now := s.now()
	if g.ConsumedAt != nil {
		return nil, glovo.Refuse(glovo.CodeApprovalReplayed)
	}
	if !b.ExpiresAt.After(now) {
		return nil, glovo.Refuse(glovo.CodeApprovalExpired)
	}
	var drifted []string
	if req.Live.ConnectionRevision != b.ConnectionRevision {
		drifted = append(drifted, "connection_revision")
	}
	if req.Live.ProviderCartVersion != b.ProviderCartVersion {
		drifted = append(drifted, "provider_cart_version")
	}
	if req.Live.PriceSnapshotDigest != b.PriceSnapshotDigest {
		drifted = append(drifted, "price_snapshot")
	}
	if len(drifted) > 0 {
		return nil, &StaleError{Drifted: drifted}
	}
	c, err := s.Store.Consume(ctx, g.ID, now)
	if err != nil {
		return nil, err
	}
	at := now
	if c.ConsumedAt != nil {
		at = *c.ConsumedAt
	}
	return &Consumed{GrantID: c.ID, ApprovalID: c.ApprovalID, Fingerprint: c.Fingerprint,
		IdempotencyKey: c.IdempotencyKey, Binding: c.Binding, ConsumedAt: at}, nil
}
