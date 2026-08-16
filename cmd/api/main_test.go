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

func TestStoreInitBudgetBoundsStartup(t *testing.T) {
	// 250ms + 500ms + 1s + 2s + 4s across five waits — one store's full ladder.
	ladder := time.Duration(0)
	delay := storeInitBaseDelay
	for i := 1; i < storeInitAttempts; i++ {
		ladder += delay
		delay *= 2
	}

	if want := 7750 * time.Millisecond; ladder != want {
		t.Errorf("single-store ladder = %v, want %v", ladder, want)
	}
	// A lone store should still get every attempt it is promised.
	if storeInitBudget < ladder {
		t.Errorf("budget %v is shorter than one store's ladder %v", storeInitBudget, ladder)
	}
	// The readiness probe's first check (helm/templates/deployment.yaml:
	// initialDelaySeconds: 10). The budget, not the ladder, is what bounds
	// startup — four stores are initialised in sequence.
	if storeInitBudget >= 10*time.Second {
		t.Errorf("budget %v must stay under the readiness probe's 10s initial delay", storeInitBudget)
	}
}

func TestInitStoreSharedDeadlineStopsLaterStores(t *testing.T) {
	// The regression this guards: with a per-call budget, four stores pointed
	// at the same dead database each ran a full ladder in turn, so the real
	// worst case was four times the one advertised. A shared deadline has to
	// leave the later stores nothing to spend.
	// Deliberately not shrinkStoreInitDelay's microseconds: the deadline has to
	// expire *during* the first store's ladder for the test to mean anything.
	// One ladder here is 1+2+4+8+16 = 31ms, and the budget below is 10ms.
	original := storeInitBaseDelay
	storeInitBaseDelay = time.Millisecond
	t.Cleanup(func() { storeInitBaseDelay = original })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	start := time.Now()
	attempts := 0
	counting := func(context.Context) (string, error) {
		attempts++
		return "", errors.New("connection refused")
	}

	for _, name := range []string{"oauth refresh", "audit log", "alert", "agent registry"} {
		if _, err := initStore(ctx, name, counting); err == nil {
			t.Fatalf("%s: expected an error against a dead database", name)
		}
	}
	elapsed := time.Since(start)

	// Four independent budgets would be four full ladders; one shared deadline
	// is spent by the first store and the rest fail out immediately.
	if elapsed > time.Second {
		t.Errorf("four stores took %v — the deadline is not shared", elapsed)
	}
	if attempts >= 4*storeInitAttempts {
		t.Errorf("attempts = %d — every store ran a full ladder, so each had its own budget", attempts)
	}
}

// TestConfigValidate covers the startup-rejecting behaviour added alongside
// the OAUTH_TOKEN_TTL ceiling. This path can only fail closed, so its
// boundaries need pinning: one minute either side of the ceiling changes
// whether the process starts at all.
func TestConfigValidate(t *testing.T) {
	const (
		ghID   = "gh-client-id"
		secret = "jwt-secret"
	)
	tests := []struct {
		name    string
		cfg     config
		wantErr bool
	}{
		{
			name:    "default 1h is accepted",
			cfg:     config{OAuthGitHubClientID: ghID, OAuthJWTSecret: secret, OAuthTokenTTL: time.Hour},
			wantErr: false,
		},
		{
			name:    "exactly at the ceiling is accepted",
			cfg:     config{OAuthGitHubClientID: ghID, OAuthJWTSecret: secret, OAuthTokenTTL: maxOAuthTokenTTL},
			wantErr: false,
		},
		{
			name:    "one nanosecond over the ceiling is rejected",
			cfg:     config{OAuthGitHubClientID: ghID, OAuthJWTSecret: secret, OAuthTokenTTL: maxOAuthTokenTTL + 1},
			wantErr: true,
		},
		{
			name:    "the year-long value that shipped in the sibling service is rejected",
			cfg:     config{OAuthGitHubClientID: ghID, OAuthJWTSecret: secret, OAuthTokenTTL: 8760 * time.Hour},
			wantErr: true,
		},
		{
			// A leftover env var cannot affect a deployment that issues no
			// tokens; crashing the whole API over it would be out of
			// proportion to the mistake.
			name:    "over the ceiling is ignored when OAuth is disabled",
			cfg:     config{OAuthTokenTTL: 8760 * time.Hour},
			wantErr: false,
		},
		{
			name:    "half-configured OAuth does not enforce the ceiling",
			cfg:     config{OAuthGitHubClientID: ghID, OAuthTokenTTL: 8760 * time.Hour},
			wantErr: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.validate()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validate() accepted OAuthTokenTTL=%v, want an error", tc.cfg.OAuthTokenTTL)
				}
				// A startup failure that does not name the variable is
				// indistinguishable from any other configuration problem.
				if !strings.Contains(err.Error(), "OAUTH_TOKEN_TTL") {
					t.Errorf("error = %q, want it to name OAUTH_TOKEN_TTL", err)
				}
				return
			}
			if err != nil {
				t.Errorf("validate() error = %v, want nil", err)
			}
		})
	}
}
