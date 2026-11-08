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
	"testing"
	"time"
)

type fakeOutbox struct {
	pending map[string]*Signal
	sent    map[string]bool
	unknown map[string]bool
}

func (f *fakeOutbox) LeaseSignals(_ context.Context, limit int, _ time.Duration) ([]Signal, error) {
	var out []Signal
	for _, s := range f.pending {
		if len(out) < limit {
			out = append(out, *s)
		}
	}
	return out, nil
}
func (f *fakeOutbox) MarkSignalSent(_ context.Context, id string) error {
	f.sent[id] = true
	delete(f.pending, id)
	return nil
}
func (f *fakeOutbox) MarkSignalUnknown(_ context.Context, id, _ string) error {
	f.unknown[id] = true
	delete(f.pending, id)
	return nil
}
func (f *fakeOutbox) RetrySignal(_ context.Context, id, _ string, _ time.Duration) error {
	f.pending[id].Attempts++
	return nil
}

type fakeSignaler struct {
	calls    map[string]int
	delivery map[string]int
	failOnce map[string]bool
	gone     map[string]bool
	ids      []string
}

func (f *fakeSignaler) SignalBridgeResult(_ context.Context, wf, run, id, digest string) error {
	f.calls[id]++
	f.ids = append(f.ids, wf+"/"+run)
	if f.gone[id] {
		return ErrSignalTargetNotFound
	}
	if f.failOnce[id] {
		delete(f.failOnce, id)
		return errors.New("transient")
	}
	f.delivery[id]++
	return nil
}

func TestDispatcherRetriesAndDeliversOnce(t *testing.T) {
	ob := &fakeOutbox{pending: map[string]*Signal{
		"cmd_a": {CommandID: "cmd_a", WorkflowID: "wf-a", RunID: "run-a", ResultDigest: "sha256:a"},
		"cmd_b": {CommandID: "cmd_b", WorkflowID: "wf-b", RunID: "run-b", ResultDigest: "sha256:b"},
	}, sent: map[string]bool{}, unknown: map[string]bool{}}
	sg := &fakeSignaler{calls: map[string]int{}, delivery: map[string]int{}, failOnce: map[string]bool{"cmd_a": true}, gone: map[string]bool{"cmd_b": true}}
	d := &Dispatcher{Outbox: ob, Signaler: sg}
	for i := 0; i < 3; i++ {
		if _, err := d.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if sg.delivery["cmd_a"] != 1 || !ob.sent["cmd_a"] {
		t.Errorf("cmd_a delivery=%d sent=%v, want exactly one after a transient error", sg.delivery["cmd_a"], ob.sent["cmd_a"])
	}
	if sg.calls["cmd_a"] != 2 {
		t.Errorf("cmd_a calls=%d, want 2 (one retry)", sg.calls["cmd_a"])
	}
	if !ob.unknown["cmd_b"] || ob.sent["cmd_b"] {
		t.Error("a missing workflow must end as unknown, not sent")
	}
	for _, id := range sg.ids {
		if id != "wf-a/run-a" && id != "wf-b/run-b" {
			t.Errorf("signalled unexpected target %s", id)
		}
	}
}
