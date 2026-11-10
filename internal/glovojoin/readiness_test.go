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
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/glovojoin/contract"
)

func ok(context.Context) error { return nil }

func allReady() Readiness {
	return Readiness{ConnectionRegistry: ok, OrdersStore: ok, WorkItemsStore: ok, ProveOneDB: ok, ReadBridge: ok, ControlWorker: ok, ProviderWorker: ok}
}

// T15: the four unobserved heartbeat cases are not_ready for the worker
// dependency, and only a read, recorded, fresh heartbeat is ready.
func TestHeartbeatProbeOnlyAFreshReadIsReady(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	cases := []struct {
		name  string
		read  func(context.Context) (Heartbeat, error)
		ready bool
	}{
		{"unread: no reader wired", nil, false},
		{"unreadable: query error", func(context.Context) (Heartbeat, error) { return Heartbeat{}, errors.New("db down") }, false},
		{"stale", func(context.Context) (Heartbeat, error) {
			return Heartbeat{Recorded: true, At: now.Add(-HeartbeatMaxAge - time.Second)}, nil
		}, false},
		{"never recorded (empty read)", func(context.Context) (Heartbeat, error) { return Heartbeat{}, nil }, false},
		{"recorded with a zero time", func(context.Context) (Heartbeat, error) { return Heartbeat{Recorded: true}, nil }, false},
		{"future-dated", func(context.Context) (Heartbeat, error) {
			return Heartbeat{Recorded: true, At: now.Add(time.Minute)}, nil
		}, false},
		{"fresh", func(context.Context) (Heartbeat, error) {
			return Heartbeat{Recorded: true, At: now.Add(-5 * time.Second)}, nil
		}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := allReady()
			r.ControlWorker = HeartbeatProbe(c.read, clock, HeartbeatMaxAge)
			r.ProviderWorker = HeartbeatProbe(c.read, clock, HeartbeatMaxAge)
			got := r.Check(context.Background())
			want := "not_ready"
			if c.ready {
				want = "ready"
			}
			if got.Dependencies.ControlWorker != want || got.Dependencies.ProviderWorker != want {
				t.Fatalf("workers = %s / %s, want %s", got.Dependencies.ControlWorker, got.Dependencies.ProviderWorker, want)
			}
			var wire Compatibility
			if err := json.Unmarshal(got.JSON(), &wire); err != nil || wire.Dependencies.ControlWorker != want {
				t.Fatalf("wire body: %s (%v)", got.JSON(), err)
			}
		})
	}
}

func TestReadinessUnobservedIsNeverReady(t *testing.T) {
	ctx := context.Background()
	got := Readiness{}.Check(ctx)
	d := got.Dependencies
	for name, v := range map[string]string{"connection_registry": d.ConnectionRegistry, "provider_orders": d.ProviderOrders,
		"read_bridge": d.ReadBridge, "control_worker": d.ControlWorker, "provider_worker": d.ProviderWorker} {
		if v != "not_ready" {
			t.Errorf("%s = %s with no probe wired", name, v)
		}
	}
	if got.DeployReady {
		t.Fatal("deploy_ready must stay false")
	}
	if all := allReady().Check(ctx); all.DeployReady || all.Dependencies.ProviderOrders != "ready" {
		t.Fatalf("all-ready check = %+v", all)
	}
	// provider_orders needs the one-database proof, both stores and nothing less.
	for name, mut := range map[string]func(*Readiness){
		"no proof":   func(r *Readiness) { r.ProveOneDB = nil },
		"proof fail": func(r *Readiness) { r.ProveOneDB = func(context.Context) error { return errors.New("two databases") } },
		"no orders":  func(r *Readiness) { r.OrdersStore = nil },
		"no work":    func(r *Readiness) { r.WorkItemsStore = func(context.Context) error { return errors.New("x") } },
	} {
		r := allReady()
		mut(&r)
		if got := r.Check(ctx).Dependencies.ProviderOrders; got != "not_ready" {
			t.Errorf("%s: provider_orders = %s", name, got)
		}
	}
}

func TestCompatibilityCarriesTheContractIdentity(t *testing.T) {
	c := allReady().Check(context.Background())
	if c.ContractVersion != contract.Version || c.ContractDigest != contract.Digest || c.APIVersion == "" {
		t.Fatalf("identity = %+v", c)
	}
	if got := BridgeProbe(NotReadyBridge{})(context.Background()); got == nil {
		t.Fatal("NotReadyBridge probed ready")
	}
	if got := BridgeProbe(nil)(context.Background()); got == nil {
		t.Fatal("nil bridge probed ready")
	}
}
