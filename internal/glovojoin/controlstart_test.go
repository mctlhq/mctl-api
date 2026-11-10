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
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/glovo"
)

func TestControlStartTx(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.insertStart(orderRefA)

	wf, run, err := ControlStartTx(ctx, e.rp, orderRefA)
	if err != nil || wf != workflowID(orderRefA) || run != "" {
		t.Fatalf("before start = %q, %q, %v", wf, run, err)
	}
	mustExec(t, e.rp, `UPDATE glovo.control_starts SET state = 'started', started_run_id = 'run-42', updated_at = now() WHERE order_ref = $1`, orderRefA)
	wf, run, err = ControlStartTx(ctx, e.rp, orderRefA)
	if err != nil || wf != workflowID(orderRefA) || run != "run-42" {
		t.Fatalf("after start = %q, %q, %v", wf, run, err)
	}

	// on the caller's transaction: it sees the caller's uncommitted row, and
	// the rollback removes it, so the read joins the shared transaction.
	tx, err := e.rp.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("{}")
	if _, err := tx.Exec(ctx, `INSERT INTO glovo.control_starts (order_ref, workflow_id, input, input_digest, next_attempt_at, created_at, updated_at) VALUES ($1, $2, $3, $4, now(), now(), now())`, orderRefB, workflowID(orderRefB), input, digestOf(input)); err != nil {
		t.Fatal(err)
	}
	if wf, _, err := ControlStartTx(ctx, tx, orderRefB); err != nil || wf != workflowID(orderRefB) {
		t.Fatalf("on the caller's tx = %q, %v", wf, err)
	}
	if _, _, err := ControlStartTx(ctx, e.rp, orderRefB); !errors.Is(err, glovo.Refuse(glovo.CodeNotFound)) {
		t.Fatalf("an uncommitted row is visible from the pool: %v", err)
	}
	_ = tx.Rollback(ctx)
	if _, _, err := ControlStartTx(ctx, e.rp, orderRefB); !errors.Is(err, glovo.Refuse(glovo.CodeNotFound)) {
		t.Fatalf("after rollback = %v", err)
	}

	// refusals
	if _, _, err := ControlStartTx(ctx, e.rp, "pord_internal"); !errors.Is(err, glovo.Refuse(glovo.CodeInvalidRequest)) {
		t.Fatalf("a malformed ref = %v", err)
	}
	if _, _, err := ControlStartTx(ctx, e.rp, ""); !errors.Is(err, glovo.Refuse(glovo.CodeInvalidRequest)) {
		t.Fatalf("an empty ref = %v", err)
	}
}

// TestControlStartTxFailedReadIsUnavailable: a failed read is never an
// absent row. A dropped table and a closed pool are unavailable, not not_found.
func TestControlStartTxFailedReadIsUnavailable(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.insertStart(orderRefA)
	mustExec(t, e.mp, `DROP TABLE glovo.control_starts`)
	if _, _, err := ControlStartTx(ctx, e.rp, orderRefA); !errors.Is(err, glovo.Refuse(glovo.CodeUnavailable)) {
		t.Fatalf("a missing table = %v", err)
	}
	cctx, cancel := context.WithTimeout(ctx, time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
	if _, _, err := ControlStartTx(cctx, e.rp, orderRefA); !errors.Is(err, glovo.Refuse(glovo.CodeUnavailable)) {
		t.Fatalf("an expired context = %v", err)
	}
}
