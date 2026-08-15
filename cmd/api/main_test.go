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

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// shrinkStoreInitDelay keeps the retry tests in microseconds instead of the
// ~7.75s a real backoff would take.
func shrinkStoreInitDelay(t *testing.T) {
	t.Helper()
	original := storeInitBaseDelay
	storeInitBaseDelay = time.Microsecond
	t.Cleanup(func() { storeInitBaseDelay = original })
}

func TestInitStore(t *testing.T) {
	errDial := errors.New("connection refused")

	tests := []struct {
		name         string
		failures     int // attempts that fail before one succeeds
		wantAttempts int
		wantErr      bool
	}{
		{name: "succeeds on first attempt", failures: 0, wantAttempts: 1},
		{
			// The case this whole helper exists for: one lost race against pod
			// network readiness used to disable the store for the pod's life.
			name:         "succeeds after one transient failure",
			failures:     1,
			wantAttempts: 2,
		},
		{name: "succeeds on the last allowed attempt", failures: storeInitAttempts - 1, wantAttempts: storeInitAttempts},
		{
			name:         "gives up after the attempt budget",
			failures:     storeInitAttempts,
			wantAttempts: storeInitAttempts,
			wantErr:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			shrinkStoreInitDelay(t)

			attempts := 0
			store, err := initStore(context.Background(), "test", func(context.Context) (string, error) {
				attempts++
				if attempts <= tc.failures {
					return "", errDial
				}
				return "ready", nil
			})

			if attempts != tc.wantAttempts {
				t.Errorf("attempts = %d, want %d", attempts, tc.wantAttempts)
			}
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				if !errors.Is(err, errDial) {
					t.Errorf("error does not wrap the underlying cause: %v", err)
				}
				// The attempt count belongs in the message: "connection refused"
				// alone reads like a single unlucky moment rather than a store
				// that is now off for good.
				if !strings.Contains(err.Error(), "after 6 attempts") {
					t.Errorf("error should report the attempt count, got %q", err)
				}
				if store != "" {
					t.Errorf("expected the zero value on failure, got %q", store)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if store != "ready" {
				t.Errorf("store = %q, want %q", store, "ready")
			}
		})
	}
}

func TestInitStoreStopsOnCancelledContext(t *testing.T) {
	shrinkStoreInitDelay(t)

	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0

	_, err := initStore(ctx, "test", func(context.Context) (string, error) {
		attempts++
		cancel() // cancelled while the first attempt is in flight
		return "", errors.New("connection refused")
	})

	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error should wrap context.Canceled, got %v", err)
	}
	// Shutdown must not be delayed by the remaining backoff budget.
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1 — a cancelled context must not be retried", attempts)
	}
}

func TestInitStoreBackoffDoublesWithinBudget(t *testing.T) {
	// 250ms + 500ms + 1s + 2s + 4s across five waits: the comment on
	// storeInitBaseDelay promises this stays under the readiness probe's 10s
	// initialDelaySeconds, and a pod that starts late is exactly the failure
	// this change is meant to avoid re-introducing.
	total := time.Duration(0)
	delay := storeInitBaseDelay
	for i := 1; i < storeInitAttempts; i++ {
		total += delay
		delay *= 2
	}

	if want := 7750 * time.Millisecond; total != want {
		t.Errorf("total backoff = %v, want %v", total, want)
	}
	if total >= 10*time.Second {
		t.Errorf("total backoff %v must stay under the readiness probe's 10s initial delay", total)
	}
}
