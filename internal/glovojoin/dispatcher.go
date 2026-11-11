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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
)

// Control-start dispatcher bounds (design 6c).
const (
	// MaxStartAttempts is the bound after which a row is failed_terminal.
	MaxStartAttempts = 8
	// StartBatch is the number of due rows one pass claims.
	StartBatch = 10
	// startRowTimeout bounds one workflow start while its row is locked.
	startRowTimeout = 10 * time.Second
)

// ErrAlreadyStarted is returned by a WorkflowStarter, together with the run
// id, when the workflow id is already running: that is success.
var ErrAlreadyStarted = errors.New("glovojoin: workflow already started")

// WorkflowStarter starts the control workflow with the id-reuse policy
// "reject duplicate". It returns the run id; a duplicate is ErrAlreadyStarted
// wrapped with the existing run id.
type WorkflowStarter interface {
	Start(ctx context.Context, workflowID string, input []byte) (runID string, err error)
}

// DispatchPool is the shared glovo_runtime pool.
type DispatchPool interface {
	BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error)
}

// DispatchEvent is an audit event of the dispatcher. It names the order and a
// reason class and never carries the stored input.
type DispatchEvent struct {
	OrderRef string
	Event    string // started | retry | failed_terminal | digest_mismatch
	Reason   string
}

// ControlStartDispatcher drains glovo.control_starts. It reads nothing but
// that table: the stored input is sent verbatim, never rebuilt from the order,
// join-ref or connection stores.
type ControlStartDispatcher struct {
	// Enabled is GLOVO_CONTROL_START_ENABLED. Off: no claim, no start, rows
	// stay pending.
	Enabled bool
	DB      DispatchPool
	Starter WorkflowStarter
	Now     func() time.Time
	Audit   func(DispatchEvent)
}

func (d *ControlStartDispatcher) now() time.Time {
	if d.Now != nil {
		return d.Now().UTC()
	}
	return time.Now().UTC()
}

func (d *ControlStartDispatcher) audit(e DispatchEvent) {
	if d.Audit != nil {
		d.Audit(e)
	}
}

func startBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	sec := 1 << min(attempt, 6)
	return time.Duration(sec) * time.Second
}

// RunOnce claims up to StartBatch due rows and starts their workflows. It
// returns the number of rows it moved to a final state (started or
// failed_terminal) and the first infrastructure error it hit.
func (d *ControlStartDispatcher) RunOnce(ctx context.Context) (int, error) {
	if !d.Enabled || d.DB == nil || d.Starter == nil {
		return 0, nil
	}
	moved := 0
	for i := 0; i < StartBatch; i++ {
		ok, final, err := d.one(ctx)
		if err != nil {
			return moved, err
		}
		if !ok {
			break
		}
		if final {
			moved++
		}
	}
	return moved, nil
}

// one claims the first due row FOR UPDATE SKIP LOCKED and settles it in the
// same transaction, so a concurrent dispatcher skips it and a crash releases
// it untouched.
func (d *ControlStartDispatcher) one(ctx context.Context) (claimed, final bool, err error) {
	tx, err := d.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return false, false, fmt.Errorf("glovojoin: dispatcher begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var (
		orderRef, wf, digest string
		input                []byte
		attempts             int
	)
	err = tx.QueryRow(ctx, `SELECT order_ref, workflow_id, input, input_digest, attempts FROM glovo.control_starts
 WHERE state = 'pending' AND next_attempt_at <= $1 ORDER BY next_attempt_at, order_ref LIMIT 1 FOR UPDATE SKIP LOCKED`, d.now()).
		Scan(&orderRef, &wf, &input, &digest, &attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("glovojoin: dispatcher claim: %w", err)
	}
	set := func(q dbq.Querier, sql string, args ...any) error {
		_, e := q.Exec(ctx, sql, args...)
		return e
	}
	sum := sha256.Sum256(input)
	if "sha256:"+hex.EncodeToString(sum[:]) != digest {
		if err := set(tx, `UPDATE glovo.control_starts SET state='failed_terminal', updated_at=$2 WHERE order_ref=$1`, orderRef, d.now()); err != nil {
			return true, false, fmt.Errorf("glovojoin: dispatcher fail row: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return true, false, fmt.Errorf("glovojoin: dispatcher commit: %w", err)
		}
		d.audit(DispatchEvent{OrderRef: orderRef, Event: "digest_mismatch", Reason: "stored_input_digest"})
		return true, true, nil
	}
	sctx, cancel := context.WithTimeout(ctx, startRowTimeout)
	runID, serr := d.Starter.Start(sctx, wf, input)
	cancel()
	if errors.Is(serr, ErrAlreadyStarted) {
		serr = nil
	}
	if serr == nil && runID == "" {
		serr = errors.New("starter returned no run id")
	}
	now := d.now()
	if serr == nil {
		if err := set(tx, `UPDATE glovo.control_starts SET state='started', started_run_id=$2, attempts=$3, updated_at=$4 WHERE order_ref=$1`,
			orderRef, runID, attempts+1, now); err != nil {
			return true, false, fmt.Errorf("glovojoin: dispatcher mark started: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return true, false, fmt.Errorf("glovojoin: dispatcher commit: %w", err)
		}
		d.audit(DispatchEvent{OrderRef: orderRef, Event: "started"})
		return true, true, nil
	}
	attempts++
	if attempts >= MaxStartAttempts {
		if err := set(tx, `UPDATE glovo.control_starts SET state='failed_terminal', attempts=$2, updated_at=$3 WHERE order_ref=$1`, orderRef, attempts, now); err != nil {
			return true, false, fmt.Errorf("glovojoin: dispatcher fail row: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return true, false, fmt.Errorf("glovojoin: dispatcher commit: %w", err)
		}
		d.audit(DispatchEvent{OrderRef: orderRef, Event: "failed_terminal", Reason: "attempts_exhausted"})
		return true, true, nil
	}
	if err := set(tx, `UPDATE glovo.control_starts SET attempts=$2, next_attempt_at=$3, updated_at=$4 WHERE order_ref=$1`,
		orderRef, attempts, now.Add(startBackoff(attempts)), now); err != nil {
		return true, false, fmt.Errorf("glovojoin: dispatcher back off: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return true, false, fmt.Errorf("glovojoin: dispatcher commit: %w", err)
	}
	d.audit(DispatchEvent{OrderRef: orderRef, Event: "retry", Reason: "start_failed"})
	return true, false, nil
}

// Loop runs RunOnce every interval until ctx ends.
func (d *ControlStartDispatcher) Loop(ctx context.Context, interval time.Duration, onErr func(error)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if _, err := d.RunOnce(ctx); err != nil && onErr != nil {
			onErr(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
