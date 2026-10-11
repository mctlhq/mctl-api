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

package commerce

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Dispatch is step 9 of ADR 020 sec. 7, the server half of C4
// (mctl-agents#619): the reserved -> dispatching edge persists the dispatch
// intent under a fence, and mctl-api signs the invocation authorization a
// paid provider verifies at its own ingress (sec. 9 requirement 1).
//
// The fence is the deadline itself. The edge writes dispatch_deadline once;
// every authorization for the row carries exactly that deadline, and Ed25519
// signatures are deterministic, so a second dispatcher (a retry, a restarted
// gateway, a concurrent duplicate) can only ever be handed the identical
// authorization. Together with the provider's durable dedupe on the
// operation key and its refusal of a key past its deadline, that is what
// keeps one invocation to one execution: no authorization with a later
// deadline is ever minted for a row that already entered dispatching.

const (
	// DefaultDispatchWindow is how long a provider may accept the key after
	// the dispatch edge (ADR 020 sec. 9 requirement 4).
	DefaultDispatchWindow = 60 * time.Second
	// MaxClockSkew is the margin after the deadline before a provider's
	// not_found is definitive (ADR 020 sec. 9 requirement 4). mctl-api never
	// reads it: the gateway applies it before releasing on not_found
	// (mctl-agents orchestrator/commerce.py MAX_CLOCK_SKEW_S, which must
	// stay equal). It is published here so the two sides share one number.
	MaxClockSkew = 60 * time.Second

	// DispatchAuthorizationVersion names the signed encoding.
	DispatchAuthorizationVersion = "mctl-commerce-dispatch/v1"
	// DispatchSignatureAlgorithm is the only algorithm in the milestone.
	DispatchSignatureAlgorithm = "ed25519"
)

var (
	// ErrDispatchUnavailable: no signing key is configured, so nothing can
	// be dispatched to a paid provider. Accepting and reserving still work;
	// the row stays reserved and the reconciler releases it.
	ErrDispatchUnavailable = errors.New("commerce: dispatch signing is not configured")
	// ErrBadAuthorization: an authorization failed verification.
	ErrBadAuthorization = errors.New("commerce: invocation authorization is not valid")
)

// DispatchSigner holds the Ed25519 key mctl-api signs authorizations with.
// Providers hold only the public key, so a provider can verify an
// authorization but never mint one.
type DispatchSigner struct {
	keyID string
	priv  ed25519.PrivateKey
}

// NewDispatchSigner builds a signer from a key id and a 32-byte seed.
func NewDispatchSigner(keyID string, seed []byte) (*DispatchSigner, error) {
	if err := checkText("key_id", keyID, MaxIDBytes, true); err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("commerce: dispatch signing seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	return &DispatchSigner{keyID: keyID, priv: ed25519.NewKeyFromSeed(seed)}, nil
}

// KeyID names the key in every authorization it signs.
func (s *DispatchSigner) KeyID() string { return s.keyID }

// PublicKey is what a provider is configured with.
func (s *DispatchSigner) PublicKey() ed25519.PublicKey {
	return s.priv.Public().(ed25519.PublicKey)
}

// UseDispatchSigner installs the signer. Without one, Dispatch answers
// ErrDispatchUnavailable.
func (s *Store) UseDispatchSigner(signer *DispatchSigner) { s.signer = signer }

// DispatchKey is the public half of the signing key.
type DispatchKey struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	// PublicKey is base64url without padding.
	PublicKey string `json:"public_key"`
}

// DispatchKeys lists the public keys a provider may verify against.
func (s *Store) DispatchKeys() ([]DispatchKey, error) {
	if s.signer == nil {
		return nil, ErrDispatchUnavailable
	}
	return []DispatchKey{{
		KeyID: s.signer.keyID, Algorithm: DispatchSignatureAlgorithm,
		PublicKey: base64.RawURLEncoding.EncodeToString(s.signer.PublicKey()),
	}}, nil
}

// DispatchAuthorization is the signed statement a paid provider verifies
// before it accepts a dispatch (ADR 020 sec. 9 requirement 1). It binds the
// invocation, the provider operation key, the provider, the exact capability
// version, the argument digest, the tenant and the dispatch deadline. It
// carries no arguments, no result and no money.
type DispatchAuthorization struct {
	SchemaVersion        int    `json:"schema_version"`
	KeyID                string `json:"key_id"`
	InvocationID         string `json:"invocation_id"`
	ProviderOperationKey string `json:"provider_operation_key"`
	ProviderID           string `json:"provider_id"`
	CapabilityID         string `json:"capability_id"`
	InputSchemaHash      string `json:"input_schema_hash"`
	ArgsDigest           string `json:"args_digest"`
	TenantID             string `json:"tenant_id"`
	// DispatchDeadline is in the HashedTime form: UTC, seconds, literal Z.
	DispatchDeadline string `json:"dispatch_deadline"`
	// Signature is base64url without padding over SigningMessage().
	Signature string `json:"signature"`
}

// SigningMessage is the exact byte string the signature covers: the same
// length-prefixed encoding the quote digest and the approval intent hash
// use, under its own version line, so no JSON canonicalization is involved and a
// provider in any language reproduces it byte for byte.
func (a DispatchAuthorization) SigningMessage() []byte {
	return []byte(lengthPrefixed(DispatchAuthorizationVersion, [][2]string{
		{"key_id", a.KeyID},
		{"invocation_id", a.InvocationID},
		{"provider_operation_key", a.ProviderOperationKey},
		{"provider_id", a.ProviderID},
		{"capability_id", a.CapabilityID},
		{"input_schema_hash", a.InputSchemaHash},
		{"args_digest", a.ArgsDigest},
		{"tenant_id", a.TenantID},
		{"dispatch_deadline", a.DispatchDeadline},
	}))
}

func (s *DispatchSigner) sign(a DispatchAuthorization) DispatchAuthorization {
	a.SchemaVersion = SchemaVersion
	a.KeyID = s.keyID
	a.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.priv, a.SigningMessage()))
	return a
}

// VerifyDispatchAuthorization checks the signature and the internal
// consistency of an authorization. It does not check the deadline or the
// provider: those belong to the provider's own ingress, on its own clock.
func VerifyDispatchAuthorization(pub ed25519.PublicKey, a DispatchAuthorization) error {
	if a.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: schema_version %d", ErrBadAuthorization, a.SchemaVersion)
	}
	if a.ProviderOperationKey != ProviderOperationKey(a.InvocationID) {
		return fmt.Errorf("%w: provider_operation_key does not derive from invocation_id", ErrBadAuthorization)
	}
	if _, err := time.Parse("2006-01-02T15:04:05Z", a.DispatchDeadline); err != nil {
		return fmt.Errorf("%w: dispatch_deadline", ErrBadAuthorization)
	}
	sig, err := base64.RawURLEncoding.DecodeString(a.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature encoding", ErrBadAuthorization)
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, a.SigningMessage(), sig) {
		return fmt.Errorf("%w: signature", ErrBadAuthorization)
	}
	return nil
}

// DispatchInput enters dispatching for one invocation.
type DispatchInput struct {
	TenantID     string
	InvocationID string
	Actor        string
	Note         string
}

// DispatchResult is the row and its authorization. Replayed is true when
// the row was already dispatching and the stored fence was re-signed.
type DispatchResult struct {
	Invocation    *Invocation           `json:"invocation"`
	Authorization DispatchAuthorization `json:"authorization"`
	Replayed      bool                  `json:"replayed"`
}

// Dispatch persists the dispatch intent and returns the signed
// authorization. From reserved it writes the fence and moves to
// dispatching; on a row already dispatching it re-signs the stored fence
// and changes nothing. Any other phase is a phase conflict: past
// dispatching the only safe next step is the provider's outcome lookup,
// never a second dispatch.
func (s *Store) Dispatch(ctx context.Context, in DispatchInput) (*DispatchResult, error) {
	if s.signer == nil {
		return nil, ErrDispatchUnavailable
	}
	for _, f := range [][2]string{{"tenant_id", in.TenantID}, {"invocation_id", in.InvocationID}, {"actor", in.Actor}} {
		if err := checkText(f[0], f[1], MaxIDBytes, true); err != nil {
			return nil, err
		}
	}
	if err := checkText("note", in.Note, MaxReasonBytes, false); err != nil {
		return nil, err
	}
	var res DispatchResult
	err := s.withTx(ctx, "commerce:inv:"+in.InvocationID, func(tx pgx.Tx) error {
		cur, err := s.lockInvocation(ctx, tx, in.TenantID, in.InvocationID)
		if err != nil {
			return err
		}
		var schemaHash string
		if err := tx.QueryRow(ctx, `SELECT input_schema_hash FROM commerce_quotes WHERE quote_id = $1`,
			cur.QuoteID).Scan(&schemaHash); err != nil {
			return fmt.Errorf("commerce: load quote of %s: %w", cur.InvocationID, err)
		}
		switch cur.Phase {
		case PhaseDispatching:
			if cur.DispatchDeadline == nil {
				// Only the dispatch edge enters dispatching and it always
				// writes the fence; a row without one was moved behind the
				// API and must not be handed an authorization.
				return fmt.Errorf("%w: %s is dispatching without a dispatch fence", ErrPhaseConflict, cur.InvocationID)
			}
			res = DispatchResult{Invocation: cur, Authorization: s.authorizationFor(cur, schemaHash), Replayed: true}
			return nil
		case PhaseReserved:
		default:
			return fmt.Errorf("%w: phase is %s; only a reserved invocation is dispatched", ErrPhaseConflict, cur.Phase)
		}
		now := s.now()
		if cur.ReservationDeadline != nil && !now.Before(*cur.ReservationDeadline) {
			// The reconciler may release this hold at any moment; dispatching
			// against it would race the release.
			return fmt.Errorf("%w: reservation of %s expired at %s", ErrPhaseConflict, cur.InvocationID,
				HashedTime(*cur.ReservationDeadline))
		}
		next, err := s.applyTransition(ctx, tx, in.TenantID, TransitionInput{
			InvocationID: in.InvocationID, ExpectedPhase: PhaseReserved, ToPhase: PhaseDispatching,
			Actor: in.Actor, Note: in.Note,
		})
		if err != nil {
			return err
		}
		// Truncated to the second because the signed text has second
		// precision: the stored fence and the signed deadline are the same
		// instant, never a sub-second apart.
		deadline := now.Add(DefaultDispatchWindow).UTC().Truncate(time.Second)
		stored, err := scanInvocation(tx.QueryRow(ctx, `UPDATE commerce_invocations SET dispatch_deadline = $3
			WHERE invocation_id = $1 AND tenant_id = $2 AND dispatch_deadline IS NULL
			RETURNING `+invocationColumns, next.InvocationID, in.TenantID, deadline))
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: %s already carries a dispatch fence", ErrPhaseConflict, next.InvocationID)
		}
		if err != nil {
			return fmt.Errorf("commerce: write dispatch fence: %w", err)
		}
		res = DispatchResult{Invocation: stored, Authorization: s.authorizationFor(stored, schemaHash)}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (s *Store) authorizationFor(v *Invocation, inputSchemaHash string) DispatchAuthorization {
	return s.signer.sign(DispatchAuthorization{
		InvocationID:         v.InvocationID,
		ProviderOperationKey: ProviderOperationKey(v.InvocationID),
		ProviderID:           v.ProviderID,
		CapabilityID:         v.CapabilityID,
		InputSchemaHash:      inputSchemaHash,
		ArgsDigest:           v.ArgsDigest,
		TenantID:             v.TenantID,
		DispatchDeadline:     HashedTime(*v.DispatchDeadline),
	})
}
