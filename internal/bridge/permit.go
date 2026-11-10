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

package bridge

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// FenceBinding is everything the #954 final physical-write fence needs to
// decide, read from the stored command row (never from the request).
type FenceBinding struct {
	CommandID        string
	ExecutionID      string
	WorkItemID       string
	Tenant           string
	OwnerPrincipalID string
	ConnectionRef    string
	InstallRevision  string
	IntentHash       string
	ApprovalRef      string
	OperationKey     string
	LeaseEpoch       int64
}

// WriteFence is the transaction-compatible interface to mctl-api#954's single
// canonical reserve/consume/record-outcome fence. Check runs inside the
// permit transaction, locks the aar_ approval row and verifies human
// approval, current tenant membership, owner, connection, install revision,
// basket fingerprint, unexpired/unrevoked state and equal IntentHash. It
// returns an opaque fence reference, or an error wrapping ErrWriteFenceRefused.
// The bridge keeps no second grant or receipt state machine.
//
// PreLock runs first, before the command row is locked (mctl-api#989 design
// section 6): a fence that must take locks on other rows (the glovo order,
// connection and approval levels L1-L4 of the #957 lock order) takes them
// here, so the permit transaction never locks them after the command (L5).
// It reads the command without a lock, applies the same provider and tenant
// scope as lockOwned (an absent or foreign command is ErrCommandNotFound, with
// no lock taken) and returns nil without a lock for a command it does not
// fence. The default fence has nothing to lock.
type WriteFence interface {
	PreLock(ctx context.Context, tx pgx.Tx, c Caller, commandID string) error
	Check(ctx context.Context, tx pgx.Tx, b FenceBinding) (fenceRef string, err error)
}

// refusingFence is the default: #954 is absent, so no permit is ever issued.
type refusingFence struct{}

func (refusingFence) PreLock(context.Context, pgx.Tx, Caller, string) error { return nil }

func (refusingFence) Check(context.Context, pgx.Tx, FenceBinding) (string, error) {
	return "", ErrWriteFenceUnavailable
}

// Permit is a recorded write permit.
type Permit struct {
	CommandID  string    `json:"command_id"`
	FenceRef   string    `json:"fence_ref"`
	LeaseEpoch int64     `json:"lease_epoch"`
	IssuedAt   time.Time `json:"issued_at"`
}

// IssueWritePermit authorizes one synthetic mutation. It locks the command,
// checks the lease and kind, asks the fence, and only then inserts the unique
// permit and marks the effect permitted, all in one transaction. A permit
// proves nothing about provider I/O: the provider must still dedupe by
// command and read back, and an ambiguous outcome stays unknown.
func (s *Store) IssueWritePermit(ctx context.Context, c Caller, commandID, leaseToken string) (*Permit, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("bridge: permit begin: %w", err)
	}
	p, err := s.permitTx(ctx, tx, c, commandID, leaseToken)
	if err := finish(ctx, tx, err); err != nil {
		return nil, err
	}
	return p, nil
}

func (s *Store) permitTx(ctx context.Context, tx pgx.Tx, c Caller, commandID, leaseToken string) (*Permit, error) {
	if err := s.currentFence().PreLock(ctx, tx, c, commandID); err != nil {
		if errors.Is(err, ErrWriteFenceUnavailable) || errors.Is(err, ErrWriteFenceRefused) || errors.Is(err, ErrCommandNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrWriteFenceRefused, err)
	}
	row, err := s.lockOwned(ctx, tx, c, commandID)
	if err != nil {
		return nil, err
	}
	if !tokenEqual(row.LeaseToken, leaseToken) {
		return nil, ErrLeaseStale
	}
	if err := s.leaseLive(row, leaseToken); err != nil {
		return nil, err
	}
	if row.Kind != KindPlaceOrderFake && row.Kind != KindCancelOrder || row.ApprovalRef == "" {
		return nil, ErrNotMutating
	}
	if row.CancelRequested {
		return nil, ErrCommandCancelled
	}
	if row.EffectState != EffectNone {
		return nil, ErrPermitExists
	}
	fenceRef, err := s.currentFence().Check(ctx, tx, FenceBinding{
		CommandID: row.CommandID, ExecutionID: row.ExecutionID, WorkItemID: row.WorkItemID, Tenant: row.Tenant,
		OwnerPrincipalID: row.OwnerPrincipalID, ConnectionRef: row.ConnectionRef, InstallRevision: row.InstallRevision,
		IntentHash: row.IntentHash, ApprovalRef: row.ApprovalRef, OperationKey: row.OperationKey, LeaseEpoch: row.LeaseEpoch,
	})
	if err != nil {
		if errors.Is(err, ErrWriteFenceUnavailable) || errors.Is(err, ErrWriteFenceRefused) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrWriteFenceRefused, err)
	}
	var issued time.Time
	err = tx.QueryRow(ctx, `INSERT INTO bridge_write_permits (command_id, operation_key, approval_ref, fence_ref, lease_epoch)
		VALUES ($1,$2,$3,$4,$5) RETURNING issued_at`,
		row.CommandID, row.OperationKey, row.ApprovalRef, fenceRef, row.LeaseEpoch).Scan(&issued)
	if err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23505" {
			return nil, ErrPermitExists
		}
		return nil, fmt.Errorf("bridge: permit insert: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE bridge_commands SET effect_state='permitted', updated_at=now() WHERE command_id=$1`, row.CommandID); err != nil {
		return nil, fmt.Errorf("bridge: permit effect: %w", err)
	}
	return &Permit{CommandID: row.CommandID, FenceRef: fenceRef, LeaseEpoch: row.LeaseEpoch, IssuedAt: issued}, nil
}
