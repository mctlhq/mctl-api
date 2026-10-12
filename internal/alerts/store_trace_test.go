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

// assertTrace fails unless a carries the stored trace id and workflow name.
// trace_source is response-only and set by the handlers, so the store leaves
// it empty.
func assertTrace(t *testing.T, path string, a *Alert, wantTrace, wantWorkflow string) {
	t.Helper()
	if a.TraceID != wantTrace || a.WorkflowName != wantWorkflow || a.TraceSource != "" {
		t.Fatalf("%s: trace_id=%q workflow_name=%q trace_source=%q, want %q / %q / \"\"",
			path, a.TraceID, a.WorkflowName, a.TraceSource, wantTrace, wantWorkflow)
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

	// A PATCH carrying a new trace replaces it. Update does not persist
	// workflow_name, so the changed value below is dropped, not rejected.
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

	// A partial update that does not carry the trace must not blank it.
	replaced.TraceID = ""
	if err := s.Update(ctx, replaced); err != nil {
		t.Fatalf("partial update: %v", err)
	}
	kept, err := s.Get(ctx, in.ID)
	if err != nil {
		t.Fatalf("get after partial update: %v", err)
	}
	assertTrace(t, "Get after Update without trace", kept, traceB, in.WorkflowName)
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

// mctl-api#585 T2: trace_id and workflow_name describe the same run, so a
// dedup hit moves them together. A new valid trace replaces both; a hit
// without a trace keeps both; and while no trace is stored a newer
// workflow_name replaces the older one, so derivation uses the latest run.
func TestTraceID_Dedup(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	occur := func(id, fp, trace, workflow string, wantCount int) *Alert {
		t.Helper()
		a := newAlert(id, fp)
		a.TraceID, a.WorkflowName = trace, workflow
		got, err := s.Create(ctx, a)
		if err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
		if got.OccurrenceCount != wantCount {
			t.Fatalf("create %s: occurrence_count=%d, want %d", id, got.OccurrenceCount, wantCount)
		}
		return got
	}

	const fp = "workflow_failed:trace:dedup"
	occur("argo-dedup-1", fp, traceA, "wf-first", 1)
	assertTrace(t, "new trace replaces the pair", occur("argo-dedup-2", fp, traceB, "wf-second", 2), traceB, "wf-second")
	assertTrace(t, "no trace keeps the pair", occur("argo-dedup-3", fp, "", "wf-third", 3), traceB, "wf-second")
	assertTrace(t, "a trace without a name clears the stale name", occur("argo-dedup-4", fp, traceA, "", 4), traceA, "")

	const fpNoTrace = "workflow_failed:trace:dedup-untraced"
	occur("argo-untraced-1", fpNoTrace, "", "wf-a", 1)
	assertTrace(t, "untraced row takes the newer workflow", occur("argo-untraced-2", fpNoTrace, "", "wf-b", 2), "", "wf-b")
	assertTrace(t, "empty workflow keeps the stored one", occur("argo-untraced-3", fpNoTrace, "", "", 3), "", "wf-b")
}
