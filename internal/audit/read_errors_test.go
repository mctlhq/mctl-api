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
	"time"

	"github.com/google/uuid"
)

// fakeRow yields one audit row with the given raw params to scanAuditEntry.
func fakeRow(params []byte) func(dest ...any) error {
	return func(dest ...any) error {
		*dest[0].(*string) = "a-1"
		*dest[1].(*time.Time) = time.Now()
		*dest[2].(*string) = "someone"
		*dest[3].(*string) = "deploy-service"
		*dest[4].(*[]byte) = params
		wf := "wf-x"
		*dest[5].(**string) = &wf
		*dest[6].(*string) = "submitted"
		return nil
	}
}

// mctl-api#586 T8: params that do not decode mark the row rather than
// passing it off as a submission without parameters, and the row survives.
func TestScanAuditEntry_UnreadableParameters(t *testing.T) {
	e, err := scanAuditEntry(fakeRow([]byte(`"not-an-object"`)))
	if err != nil {
		t.Fatalf("scan: %v; an unreadable params value must not drop the row", err)
	}
	if !e.ParametersUnreadable || e.Parameters != nil || e.WorkflowName != "wf-x" {
		t.Fatalf("entry = %+v, want ParametersUnreadable with nil Parameters", e)
	}

	e, err = scanAuditEntry(fakeRow([]byte(`{"tenant_name":"acme"}`)))
	if err != nil || e.ParametersUnreadable || e.Parameters["tenant_name"] != "acme" {
		t.Fatalf("readable params: entry=%+v err=%v", e, err)
	}
}

// mctl-api#586 T9: against Postgres, a corrupt params value comes back marked
// from both read paths, and a failed queue read is an error, not an empty
// page.
func TestPostgresLogger_ReadErrors(t *testing.T) {
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
	wf := "unreadable-" + id[:8]
	t.Cleanup(func() {
		_, _ = p.pool.Exec(ctx, `DELETE FROM audit_events WHERE id=$1`, id)
		p.pool.Close()
	})
	if _, err := p.pool.Exec(ctx,
		`INSERT INTO audit_events (id, timestamp, user_id, operation, params, workflow, status)
		 VALUES ($1, now(), 'someone', 'deploy-service', '"not-an-object"'::jsonb, $2, 'submitted')`,
		id, wf); err != nil {
		t.Fatal(err)
	}

	e, err := p.LookupByWorkflow(ctx, wf)
	if err != nil || e == nil || !e.ParametersUnreadable {
		t.Fatalf("lookup: entry=%+v err=%v, want the row marked ParametersUnreadable", e, err)
	}

	queue, err := p.ListByStatus("submitted", time.Hour, 1000, time.Time{})
	if err != nil {
		t.Fatalf("list by status: %v", err)
	}
	found := false
	for i := range queue {
		if queue[i].WorkflowName == wf {
			found = queue[i].ParametersUnreadable
		}
	}
	if !found {
		t.Fatalf("list by status: the corrupt row is missing or unmarked")
	}

	closed, err := NewPostgresLogger(ctx, connStr)
	if err != nil {
		t.Fatal(err)
	}
	closed.pool.Close()
	queue, err = closed.ListByStatus("submitted", time.Hour, 1000, time.Time{})
	if err == nil || queue != nil {
		t.Fatalf("closed pool: queue=%d rows err=%v, want (nil, error)", len(queue), err)
	}
}
