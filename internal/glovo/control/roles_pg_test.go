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

package control

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo/receipt"
)

// The receipt Audit and Sweeper run on the shared glovo_runtime pool
// (mctl-api#985 OPEN decision (a)): no role of their own, no test-only grant.
// This runs them as the runtime role with exactly the grants the schemas
// give it, and shows that removing one grant makes them fail loudly instead
// of reporting a clean or empty result.
func TestAuditAndSweeperRunOnTheSharedRuntimeRole(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	f := e.finalized(fixOpt{})
	cmd := e.dispatched(f)
	sw := &receipt.Sweeper{Begin: func(ctx context.Context) (pgx.Tx, error) { return e.rtp.Begin(ctx) }, Approvals: e.st}

	res, err := receipt.Audit(ctx, e.rtp)
	if err != nil {
		t.Fatalf("Audit as the runtime role: %v", err)
	}
	if res.Checked != 1 || res.SweepDue != 0 || len(res.Violations) != 0 {
		t.Fatalf("a live reserved receipt: %+v", res)
	}
	// The command ends with no permit: the receipt is due for the sweeper.
	e.setCommand(cmd, `status='cancelled', effect_state='none'`)
	if res, err = receipt.Audit(ctx, e.rtp); err != nil || res.SweepDue != 1 || len(res.Violations) != 0 {
		t.Fatalf("Audit: %+v %v", res, err)
	}
	moved, err := sw.Sweep(ctx)
	if err != nil || moved != 1 {
		t.Fatalf("Sweep as the runtime role: moved %d err %v", moved, err)
	}
	if got := e.aarState(f); got != "unknown" {
		t.Fatalf("receipt %s", got)
	}
	if res, err = receipt.Audit(ctx, e.rtp); err != nil || res.SweepDue != 0 || len(res.Violations) != 0 || res.Checked != 1 {
		t.Fatalf("Audit after the sweep: %+v %v", res, err)
	}

	// Without a grant the readers fail; they never answer "nothing found".
	g := e.finalized(fixOpt{})
	cmd2 := e.dispatched(g)
	e.setCommand(cmd2, `status='expired', effect_state='none'`)
	e.mustMig(fmt.Sprintf(`REVOKE SELECT ON bridge_write_permits FROM %s`, e.rt))
	if _, err := receipt.Audit(ctx, e.rtp); err == nil {
		t.Fatal("Audit answered without the permit grant")
	}
	if n, err := sw.Sweep(ctx); err == nil || n != 0 {
		t.Fatalf("Sweep answered without the permit grant: %d %v", n, err)
	}
	if got := e.aarState(g); got != "reserved" {
		t.Fatalf("a failed sweep moved a receipt: %s", got)
	}
	// And the runtime role holds exactly what the schemas promise.
	e.mustMig(fmt.Sprintf(`GRANT SELECT ON bridge_write_permits TO %s`, e.rt))
	if err := bridge.VerifyRuntimeGrants(ctx, e.rtp); err != nil {
		t.Fatalf("VerifyRuntimeGrants after restoring the grant: %v", err)
	}
}
