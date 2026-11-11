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

package glovojoin

import (
	"context"
	"errors"
	"regexp"

	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
)

// ReadBridge is the in-process seam of the three provider reads (design 5).
// The production implementation is the #986 bridge.ReadClient; NotReadyBridge
// is the default until it is wired, and FixtureBridge (build tag
// glovojoin_fixture) serves canned #1059 payloads to tests. There is no route,
// tool or workflow between a handler and the bridge, and a ReadBridge never
// writes to the provider.
type ReadBridge interface {
	Read(ctx context.Context, r bridge.ReadRequest) (*bridge.ReadResult, error)
}

var _ ReadBridge = (*bridge.ReadClient)(nil)

// NotReadyBridge is the default ReadBridge: every read is not_ready, so a
// router with no bridge answers 503 not_ready and enqueues nothing.
type NotReadyBridge struct{}

// Read always refuses with not_ready.
func (NotReadyBridge) Read(context.Context, bridge.ReadRequest) (*bridge.ReadResult, error) {
	return nil, glovo.Refuse(glovo.CodeNotReady)
}

var liveStateRE = regexp.MustCompile(`connection ([a-z_]+)$`)

// MapReadError maps a #986 read error to a join refusal (design 4.2): the
// order of the checks is the order of the table. A read that failed, expired
// or could not be matched is unavailable, never an empty answer.
func MapReadError(err error) *Refusal {
	if err == nil {
		return nil
	}
	var ge *glovo.Error
	if errors.As(err, &ge) {
		return &Refusal{Err: ge, Reason: "read:" + string(ge.Code)}
	}
	switch {
	case errors.Is(err, bridge.ErrReadNotAuthorized):
		return refusal(glovo.CodeScopeUnsupported, "insufficient_scope")
	case errors.Is(err, bridge.ErrBindingMismatch):
		if m := liveStateRE.FindStringSubmatch(err.Error()); m != nil {
			switch c := glovo.Code(m[1]); c {
			case glovo.CodeNoConnection, glovo.CodeConnectionRevoked, glovo.CodeConnectionExpired, glovo.CodeStaleInstall:
				return refusal(c, "read_binding:"+m[1])
			}
		}
		return refusal(glovo.CodeUnavailable, "read:binding_mismatch")
	case errors.Is(err, bridge.ErrReadUnavailable):
		return refusal(glovo.CodeUnavailable, "read:read_unavailable")
	case errors.Is(err, bridge.ErrCommandNotFound):
		return refusal(glovo.CodeUnavailable, "read:command_not_found")
	case errors.Is(err, bridge.ErrCommandExpired):
		return refusal(glovo.CodeUnavailable, "read:command_expired")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return refusal(glovo.CodeUnavailable, "read:context")
	}
	return refusal(glovo.CodeUnavailable, "dependency_unavailable:read_bridge")
}
