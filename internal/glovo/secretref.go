// Copyright 2026 MCTL Authors
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

import (
	"context"
	"errors"
)

// ErrSecretBackendUnavailable is returned by the only SecretRefs
// implementation this slice ships.
var ErrSecretBackendUnavailable = errors.New("glovo: secret backend unavailable")

// SecretRef is an opaque reference id ("gsr_<ULID>"). It carries no bytes: no
// provider session, cookie, token or password ever reaches this package.
type SecretRef struct{ ID string }

// SecretRefs reserves and releases opaque references. The store records only
// the reference id and clears it in the transaction that ends a connection;
// the ended Connection's ReleasedSecretRef tells the caller what to release.
//
// Design note, not implemented and not a guarantee: a future backend may
// protect each connection's secret with a random per-connection data key
// wrapped by an independent key. Nothing here claims that destroying such a
// key erases the secret, so this package does not call it crypto-shredding.
type SecretRefs interface {
	Reserve(ctx context.Context, owner Owner, connectionID string) (SecretRef, error)
	Release(ctx context.Context, ref SecretRef) error
}

// RefusingSecretRefs refuses everything.
type RefusingSecretRefs struct{}

func (RefusingSecretRefs) Reserve(context.Context, Owner, string) (SecretRef, error) {
	return SecretRef{}, ErrSecretBackendUnavailable
}

func (RefusingSecretRefs) Release(context.Context, SecretRef) error {
	return ErrSecretBackendUnavailable
}
