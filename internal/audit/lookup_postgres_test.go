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

package audit

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
)

// mctl-api#585 task 2: LookupByWorkflow tells "no such record" ((nil, nil))
// from "could not look" ((nil, err)), which GetByWorkflow cannot.
func TestPostgresLogger_LookupByWorkflow(t *testing.T) {
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed audit test")
	}
	ctx := context.Background()
	p, err := NewPostgresLogger(ctx, connStr)
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.NewString()
	wf := "lookup-" + id[:8]
	t.Cleanup(func() {
		_, _ = p.pool.Exec(ctx, `DELETE FROM audit_events WHERE id=$1`, id)
		p.pool.Close()
	})
	p.Log(Entry{ID: id, UserID: "mctl-agent", Operation: "mctl-agents-implement", WorkflowName: wf,
		Status: "submitted", Parameters: map[string]string{"traceparent": "00-431486061c652efb376a860d9d656f25-7a16c732dc164e9e-01"}})

	e, err := p.LookupByWorkflow(ctx, wf)
	if err != nil || e == nil || e.Parameters["traceparent"] == "" {
		t.Fatalf("found: entry=%+v err=%v", e, err)
	}

	e, err = p.LookupByWorkflow(ctx, "no-such-"+id[:8])
	if err != nil || e != nil {
		t.Fatalf("missing record: entry=%+v err=%v, want (nil, nil)", e, err)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	e, err = p.LookupByWorkflow(cancelled, wf)
	if err == nil || e != nil {
		t.Fatalf("failed read: entry=%+v err=%v, want (nil, error)", e, err)
	}
}
