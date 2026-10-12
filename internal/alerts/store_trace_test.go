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

package alerts

import (
	"context"
	"testing"
)

const (
	traceA = "431486061c652efb376a860d9d656f25"
	traceB = "008ad8979d34c0509e74d8062b7f92ca"
)

// assertTrace fails unless a carries the stored trace id and workflow name,
// labelled "reported" exactly when a trace id is present.
func assertTrace(t *testing.T, path string, a *Alert, wantTrace, wantWorkflow string) {
	t.Helper()
	wantSource := ""
	if wantTrace != "" {
		wantSource = "reported"
	}
	if a.TraceID != wantTrace || a.WorkflowName != wantWorkflow || a.TraceSource != wantSource {
		t.Fatalf("%s: trace_id=%q workflow_name=%q trace_source=%q, want %q / %q / %q",
			path, a.TraceID, a.WorkflowName, a.TraceSource, wantTrace, wantWorkflow, wantSource)
	}
}

// mctl-api#585 T1 + T3: every read path returns the stored trace identity.
// A read path that stops selecting trace_id (or a schema that drops it)
// fails here rather than silently serving incidents without their trace.
func TestTraceID_RoundTripsThroughEveryReadPath(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	in := newAlert("argo-wf-trace-1", "workflow_failed:trace:roundtrip")
	in.TraceID = traceA
	in.WorkflowName = "mctl-agents-implement-dae24112"

	created, err := s.Create(ctx, in)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	assertTrace(t, "Create RETURNING", created, traceA, in.WorkflowName)

	got, err := s.Get(ctx, in.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	assertTrace(t, "Get", got, traceA, in.WorkflowName)

	byPrefix, err := s.GetByPrefix(ctx, "argo-wf-trace")
	if err != nil {
		t.Fatalf("get by prefix: %v", err)
	}
	assertTrace(t, "GetByPrefix", byPrefix, traceA, in.WorkflowName)

	list, err := s.List(ctx, ListFilter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("list: %d rows, want 1", len(list))
	}
	assertTrace(t, "List", &list[0], traceA, in.WorkflowName)

	// Ack/resolve round-trip the row they read through Update: the trace
	// must survive that unchanged.
	got.Status = StatusAcknowledged
	if err := s.Update(ctx, got); err != nil {
		t.Fatalf("ack-style update: %v", err)
	}
	after, err := s.Get(ctx, in.ID)
	if err != nil {
		t.Fatalf("get after ack: %v", err)
	}
	assertTrace(t, "Get after ack-style Update", after, traceA, in.WorkflowName)

	// A PATCH carrying a new trace replaces it; workflow_name is immutable.
	after.TraceID = traceB
	after.WorkflowName = "something-else"
	if err := s.Update(ctx, after); err != nil {
		t.Fatalf("trace update: %v", err)
	}
	replaced, err := s.Get(ctx, in.ID)
	if err != nil {
		t.Fatalf("get after trace update: %v", err)
	}
	assertTrace(t, "Get after trace Update", replaced, traceB, in.WorkflowName)
}

// An incident created without a trace reads back with no trace and no
// trace_source, so "reported" is never claimed for an empty value.
func TestTraceID_AbsentStaysAbsent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.Create(ctx, newAlert("argo-wf-notrace", "workflow_failed:trace:none")); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.Get(ctx, "argo-wf-notrace")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	assertTrace(t, "Get", got, "", "")
}

// mctl-api#585 T2: a dedup hit with a new valid trace replaces the stored one,
// a dedup hit without a trace keeps it, and workflow_name stays the original.
func TestTraceID_Dedup(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const fp = "workflow_failed:trace:dedup"

	first := newAlert("argo-dedup-1", fp)
	first.TraceID = traceA
	first.WorkflowName = "wf-first"
	if _, err := s.Create(ctx, first); err != nil {
		t.Fatalf("first create: %v", err)
	}

	second := newAlert("argo-dedup-2", fp)
	second.TraceID = traceB
	second.WorkflowName = "wf-second"
	got, err := s.Create(ctx, second)
	if err != nil {
		t.Fatalf("second create: %v", err)
	}
	if got.ID != first.ID || got.OccurrenceCount != 2 {
		t.Fatalf("second create did not dedup: id=%q count=%d", got.ID, got.OccurrenceCount)
	}
	assertTrace(t, "dedup with new trace", got, traceB, "wf-first")

	third := newAlert("argo-dedup-3", fp)
	got, err = s.Create(ctx, third)
	if err != nil {
		t.Fatalf("third create: %v", err)
	}
	if got.OccurrenceCount != 3 {
		t.Fatalf("third create did not dedup: count=%d", got.OccurrenceCount)
	}
	assertTrace(t, "dedup without trace", got, traceB, "wf-first")
}
