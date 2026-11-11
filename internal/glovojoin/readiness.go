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
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovojoin/contract"
)

// HeartbeatMaxAge is the bound past which a worker heartbeat is stale.
const HeartbeatMaxAge = 90 * time.Second

// Heartbeat is what a worker heartbeat read reports.
type Heartbeat struct {
	// Recorded is false when no heartbeat was ever written.
	Recorded bool
	// At is the time of the last heartbeat; meaningful only when Recorded.
	At time.Time
}

// HeartbeatProbe turns a heartbeat read into a dependency probe (design 9,
// T15). Only a heartbeat that was read, recorded and fresh is a pass: a nil
// reader (never wired), a read error, a never-recorded heartbeat, a zero or
// future-dated timestamp and a stale one are all not ready.
func HeartbeatProbe(read func(context.Context) (Heartbeat, error), now func() time.Time, maxAge time.Duration) func(context.Context) error {
	if now == nil {
		now = time.Now
	}
	return func(ctx context.Context) error {
		if read == nil {
			return errors.New("heartbeat: no reader")
		}
		hb, err := read(ctx)
		if err != nil {
			return err
		}
		if !hb.Recorded || hb.At.IsZero() {
			return errors.New("heartbeat: never recorded")
		}
		age := now().Sub(hb.At)
		if age < 0 || age > maxAge {
			return errors.New("heartbeat: stale")
		}
		return nil
	}
}

// BridgeProbe is ready only for a ReadBridge that is a real transport:
// NotReadyBridge, a nil bridge (an untyped nil and a typed nil pointer inside
// the interface alike) and a failed readiness check are not ready. A bridge
// that can report its own readiness (a Ready(ctx) error method) is ready only
// when that call returns nil.
func BridgeProbe(b ReadBridge) func(context.Context) error {
	return func(ctx context.Context) error {
		if b == nil {
			return errors.New("read bridge: absent")
		}
		if v := reflect.ValueOf(b); v.Kind() == reflect.Pointer && v.IsNil() {
			return errors.New("read bridge: nil transport")
		}
		if _, ok := b.(NotReadyBridge); ok {
			return glovo.Refuse(glovo.CodeNotReady)
		}
		if _, ok := b.(*NotReadyBridge); ok {
			return glovo.Refuse(glovo.CodeNotReady)
		}
		if rb, ok := b.(interface{ Ready(context.Context) error }); ok {
			return rb.Ready(ctx)
		}
		return nil
	}
}

// Readiness probes each dependency of /compatibility. A nil probe is a
// dependency nobody observes, which is not_ready: never a pass.
type Readiness struct {
	ConnectionRegistry func(context.Context) error
	OrdersStore        func(context.Context) error
	WorkItemsStore     func(context.Context) error
	// ProveOneDB is #985 control.ProveOneDatabase, injected by main so that
	// this package never imports control.
	ProveOneDB     func(context.Context) error
	ReadBridge     func(context.Context) error
	ControlWorker  func(context.Context) error
	ProviderWorker func(context.Context) error
	APIVersion     string
}

// Compatibility is the 200 body of GET /compatibility.
type Compatibility struct {
	ContractVersion string `json:"contract_version"`
	ContractDigest  string `json:"contract_digest"`
	APIVersion      string `json:"api_version"`
	Dependencies    struct {
		ConnectionRegistry string `json:"connection_registry"`
		ProviderOrders     string `json:"provider_orders"`
		ReadBridge         string `json:"read_bridge"`
		ControlWorker      string `json:"control_worker"`
		ProviderWorker     string `json:"provider_worker"`
	} `json:"dependencies"`
	DeployReady bool `json:"deploy_ready"`
}

func probeState(ctx context.Context, probes ...func(context.Context) error) string {
	for _, p := range probes {
		if p == nil || p(ctx) != nil {
			return "not_ready"
		}
	}
	return "ready"
}

// Check runs every probe. deploy_ready is always false in this slice: only a
// later launch decision, with the compatibility matrix, may change that.
func (r Readiness) Check(ctx context.Context) Compatibility {
	var c Compatibility
	c.ContractVersion, c.ContractDigest = contract.Version, contract.Digest
	c.APIVersion = r.APIVersion
	if c.APIVersion == "" {
		c.APIVersion = "v1alpha1"
	}
	c.Dependencies.ConnectionRegistry = probeState(ctx, r.ConnectionRegistry)
	c.Dependencies.ProviderOrders = probeState(ctx, r.OrdersStore, r.WorkItemsStore, r.ProveOneDB)
	c.Dependencies.ReadBridge = probeState(ctx, r.ReadBridge)
	c.Dependencies.ControlWorker = probeState(ctx, r.ControlWorker)
	c.Dependencies.ProviderWorker = probeState(ctx, r.ProviderWorker)
	return c
}

// JSON is the wire body.
func (c Compatibility) JSON() []byte {
	b, _ := json.Marshal(c)
	return b
}
