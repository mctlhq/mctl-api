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

//go:build glovojoin_fixture

package glovojoin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/mctlhq/mctl-api/internal/bridge"
)

// FixtureBridge is a ReadBridge for tests and the harness, compiled only under
// the glovojoin_fixture tag so it cannot ship in the release image. It serves
// canned canonical #1059 payloads per kind and records every request. It
// never touches a provider, a database or the network.
type FixtureBridge struct {
	mu sync.Mutex
	// Payload holds the canonical payload bytes served per kind.
	Payload map[bridge.ReadKind][]byte
	// Err, when set, is returned by every read.
	Err   error
	calls []bridge.ReadRequest
}

// NewFixtureBridge returns a FixtureBridge serving payload per kind.
func NewFixtureBridge(payload map[bridge.ReadKind][]byte) *FixtureBridge {
	return &FixtureBridge{Payload: payload}
}

var _ ReadBridge = (*FixtureBridge)(nil)

// Read serves the canned payload of r.Kind, or Err.
func (f *FixtureBridge) Read(_ context.Context, r bridge.ReadRequest) (*bridge.ReadResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r)
	if f.Err != nil {
		return nil, f.Err
	}
	data, ok := f.Payload[r.Kind]
	if !ok {
		return nil, fmt.Errorf("%w: no fixture for %s", bridge.ErrReadUnavailable, r.Kind)
	}
	sum := sha256.Sum256(data)
	return &bridge.ReadResult{
		Kind: r.Kind, ResultRef: "rres_fixture", Digest: "sha256:" + hex.EncodeToString(sum[:]),
		Data: append([]byte(nil), data...), ExpiresAt: time.Now().Add(time.Minute),
	}, nil
}

// Calls returns a copy of every request received.
func (f *FixtureBridge) Calls() []bridge.ReadRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]bridge.ReadRequest(nil), f.calls...)
}
