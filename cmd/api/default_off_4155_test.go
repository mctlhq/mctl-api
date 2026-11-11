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

package main

import (
	"os"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Every flag introduced between 4.154.0 and 081bd6b7 reads as OFF when unset,
// and a typo in a boolean-ish flag refuses the boot instead of reading as on.
// This is release evidence for 4.155.0 (dark API-only release), not a feature test.

var newFlagEnv = []string{
	"GLOVO_ENABLED", "GLOVO_JOIN_ENABLED", "MCTL_GLOVO_CONTROL_ENABLED", "MCTL_GLOVO_CONTROL_WORKER",
	"MCTL_GLOVO_FACADE_TOKEN", "MCTL_GLOVO_WORKER_TOKEN_FILE", "GLOVO_DB_URL", "GLOVO_DB_RUNTIME_ROLE",
	"GLOVO_DB_MIGRATION_ROLE", "MCTL_BRIDGE_ENABLED", "MCTL_BRIDGE_PROVIDERS", "MCTL_BRIDGE_PROVIDER_TOKENS",
	"MCTL_EXECUTION_REQUEST_QUEUE_WHILE_ACTIVE", "MCTL_ORCHESTRATOR_DEVLOOP_PROVIDER",
	"MCTL_ORCHESTRATOR_DEVLOOP_SUBJECT", "DEVLOOP_DECIDE_CLIENT_ID", "DEVLOOP_DECIDE_CLIENT_SECRET",
}

func clearNewFlags(t *testing.T) func(string) (string, bool) {
	t.Helper()
	for _, k := range newFlagEnv {
		t.Setenv(k, "")
		_ = os.Unsetenv(k)
	}
	return os.LookupEnv
}

func TestNewFlagsDefaultOff4155(t *testing.T) {
	lookup := clearNewFlags(t)

	if on, err := glovoEnabled(lookup); err != nil || on {
		t.Fatalf("GLOVO_ENABLED unset: on=%v err=%v, want off", on, err)
	}
	if r, err := configureGlovoJoin(lookup, true); err != nil || r != nil {
		t.Fatalf("GLOVO_JOIN_ENABLED unset: routes=%v err=%v, want unmounted", r, err)
	}
	if r, err := configureGlovoControl(lookup, &auth.GlovoControlWorkerConfig{Tenants: []string{"x"}}); err != nil || r != nil {
		t.Fatalf("MCTL_GLOVO_CONTROL_ENABLED unset: routes=%v err=%v, want unmounted", r, err)
	}
	if os.Getenv("MCTL_BRIDGE_ENABLED") == "true" {
		t.Fatal("MCTL_BRIDGE_ENABLED must not read as true when unset (main.go gate)")
	}
	if p := auth.LoadBridgeProviders(); len(p) != 0 {
		t.Fatalf("bridge providers configured by default: %d", len(p))
	}
	if w := auth.LoadGlovoControlWorker(); w != nil {
		t.Fatalf("glovo control worker configured by default: %+v", w)
	}
	if auth.GlovoFacadeConfigured() || auth.GlovoWorkerConfigured() {
		t.Fatal("glovo facade/worker credentials configured by default")
	}
	if on, err := workitems.ParseQueueWhileActive(os.Getenv(workitems.QueueWhileActiveEnv)); err != nil || on {
		t.Fatalf("queue-while-active unset: on=%v err=%v, want off", on, err)
	}
}

func TestNewFlagTyposFailClosed4155(t *testing.T) {
	cases := map[string]func(string) error{
		"GLOVO_ENABLED": func(v string) error {
			_, err := glovoEnabled(func(string) (string, bool) { return v, true })
			return err
		},
		"GLOVO_JOIN_ENABLED": func(v string) error {
			_, err := configureGlovoJoin(func(string) (string, bool) { return v, true }, true)
			return err
		},
		"MCTL_GLOVO_CONTROL_ENABLED": func(v string) error {
			_, err := configureGlovoControl(func(string) (string, bool) { return v, true }, nil)
			return err
		},
		"MCTL_EXECUTION_REQUEST_QUEUE_WHILE_ACTIVE": func(v string) error {
			_, err := workitems.ParseQueueWhileActive(v)
			return err
		},
	}
	for name, f := range cases {
		for _, typo := range []string{"yes", "1", "ture", "enabled"} {
			if f(typo) == nil {
				t.Errorf("%s=%q was accepted; a typo must refuse, not pick a mode", name, typo)
			}
		}
	}
}
