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
	"fmt"
	"log/slog"
	"time"
)

// Signal is one due row of bridge_signal_outbox.
type Signal struct {
	CommandID    string
	WorkflowID   string
	RunID        string
	ResultDigest string
	Attempts     int
}

// BridgeSignaler delivers a recorded result to the workflow that enqueued the
// command. It must signal only the stored workflow and run, and must return an
// error wrapping ErrSignalTargetNotFound when that workflow no longer exists.
type BridgeSignaler interface {
	SignalBridgeResult(ctx context.Context, workflowID, runID, commandID, resultDigest string) error
}

// SignalOutbox is the dispatcher's view of the outbox table.
type SignalOutbox interface {
	// LeaseSignals returns up to limit due signals and hides them from other
	// dispatchers for visibility, so no row lock is held during the network
	// call.
	LeaseSignals(ctx context.Context, limit int, visibility time.Duration) ([]Signal, error)
	MarkSignalSent(ctx context.Context, commandID string) error
	MarkSignalUnknown(ctx context.Context, commandID, code string) error
	RetrySignal(ctx context.Context, commandID, code string, after time.Duration) error
}

// LeaseSignals implements SignalOutbox with FOR UPDATE SKIP LOCKED.
func (s *Store) LeaseSignals(ctx context.Context, limit int, visibility time.Duration) ([]Signal, error) {
	rows, err := s.pool.Query(ctx, `UPDATE bridge_signal_outbox SET next_attempt_at = now() + ($2 * interval '1 second')
		WHERE command_id IN (SELECT command_id FROM bridge_signal_outbox
			WHERE status='pending' AND next_attempt_at <= now()
			ORDER BY next_attempt_at LIMIT $1 FOR UPDATE SKIP LOCKED)
		RETURNING command_id, workflow_id, run_id, result_digest, attempts`, limit, int(visibility/time.Second))
	if err != nil {
		return nil, fmt.Errorf("bridge: lease signals: %w", err)
	}
	defer rows.Close()
	var out []Signal
	for rows.Next() {
		var sg Signal
		if err := rows.Scan(&sg.CommandID, &sg.WorkflowID, &sg.RunID, &sg.ResultDigest, &sg.Attempts); err != nil {
			return nil, fmt.Errorf("bridge: lease signals scan: %w", err)
		}
		out = append(out, sg)
	}
	return out, rows.Err()
}

// MarkSignalSent records delivery. It is guarded on status='pending' so a
// second dispatcher cannot move a terminal row.
func (s *Store) MarkSignalSent(ctx context.Context, commandID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE bridge_signal_outbox SET status='sent', sent_at=now(), attempts=attempts+1, last_error_code=''
		WHERE command_id=$1 AND status='pending'`, commandID)
	return err
}

// MarkSignalUnknown records a terminal "unknown": the target workflow is gone,
// which is not success.
func (s *Store) MarkSignalUnknown(ctx context.Context, commandID, code string) error {
	_, err := s.pool.Exec(ctx, `UPDATE bridge_signal_outbox SET status='unknown', attempts=attempts+1, last_error_code=$2
		WHERE command_id=$1 AND status='pending'`, commandID, code)
	return err
}

// RetrySignal schedules another attempt after a transient failure.
func (s *Store) RetrySignal(ctx context.Context, commandID, code string, after time.Duration) error {
	_, err := s.pool.Exec(ctx, `UPDATE bridge_signal_outbox SET attempts=attempts+1, last_error_code=$2,
			next_attempt_at = now() + ($3 * interval '1 second')
		WHERE command_id=$1 AND status='pending'`, commandID, code, int(after/time.Second))
	return err
}

// Dispatcher drains the signal outbox. Delivery is at least once; the
// workflow dedupes on command_id, so a crash between signal and MarkSignalSent
// re-signals harmlessly.
type Dispatcher struct {
	Outbox   SignalOutbox
	Signaler BridgeSignaler
	Interval time.Duration
	Batch    int
	// Backoff maps the attempt count to the retry delay.
	Backoff func(attempts int) time.Duration
}

func defaultBackoff(attempts int) time.Duration {
	d := 5 * time.Second << min(attempts, 6)
	return min(d, 5*time.Minute)
}

// RunOnce delivers one batch and returns how many signals were sent.
func (d *Dispatcher) RunOnce(ctx context.Context) (int, error) {
	batch := d.Batch
	if batch <= 0 {
		batch = 20
	}
	backoff := d.Backoff
	if backoff == nil {
		backoff = defaultBackoff
	}
	sigs, err := d.Outbox.LeaseSignals(ctx, batch, 2*time.Minute)
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, sg := range sigs {
		err := d.Signaler.SignalBridgeResult(ctx, sg.WorkflowID, sg.RunID, sg.CommandID, sg.ResultDigest)
		switch {
		case err == nil:
			if merr := d.Outbox.MarkSignalSent(ctx, sg.CommandID); merr != nil {
				slog.Error("bridge signal sent but not recorded", "command_id", sg.CommandID, "error", merr)
				continue
			}
			sent++
		case errors.Is(err, ErrSignalTargetNotFound):
			if merr := d.Outbox.MarkSignalUnknown(ctx, sg.CommandID, ErrSignalTargetNotFound.Error()); merr != nil {
				slog.Error("bridge signal unknown not recorded", "command_id", sg.CommandID, "error", merr)
			}
		default:
			slog.Warn("bridge signal failed; will retry", "command_id", sg.CommandID, "attempts", sg.Attempts+1)
			if merr := d.Outbox.RetrySignal(ctx, sg.CommandID, "signal_error", backoff(sg.Attempts)); merr != nil {
				slog.Error("bridge signal retry not recorded", "command_id", sg.CommandID, "error", merr)
			}
		}
	}
	return sent, nil
}

// Run loops until ctx ends.
func (d *Dispatcher) Run(ctx context.Context) {
	interval := d.Interval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if _, err := d.RunOnce(ctx); err != nil && ctx.Err() == nil {
			slog.Error("bridge dispatcher pass failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
