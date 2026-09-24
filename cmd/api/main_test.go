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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
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
			store, err := initStore(context.Background(), nil, "test", func(context.Context) (string, error) {
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

	_, err := initStore(ctx, nil, "test", func(context.Context) (string, error) {
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
		if _, err := initStore(ctx, nil, name, counting); err == nil {
			t.Fatalf("%s: expected an error against a dead database", name)
		}
	}
	elapsed := time.Since(start)

	// Four independent budgets would be four full ladders; one shared deadline
	// is spent by the first store and each later one gets a single last-chance
	// attempt (mctl-api#387), never a ladder of its own.
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
		// wantVar is the variable the error must name; defaults to OAUTH_TOKEN_TTL.
		wantVar string
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
		{
			// Unlike the TTL ceiling, a malformed client list is refused
			// even when OAuth is off: the README promises the refusal without
			// a caveat, and nothing about the value becomes valid later.
			name:    "malformed OAUTH_PREREGISTERED_CLIENTS is refused with OAuth disabled",
			cfg:     config{OAuthPreregisteredClientsRaw: `[{"client_id":"c","redirect_uris":["https://x/cb"],"client_` + `secret":"s"}]`},
			wantErr: true,
			wantVar: "OAUTH_PREREGISTERED_CLIENTS",
		},
		{
			// Shape rules, not only decoding: the registry's own checks run
			// against a throwaway server so this boot refuses, not the next.
			name:    "OAUTH_PREREGISTERED_CLIENTS with a relative callback is refused with OAuth disabled",
			cfg:     config{OAuthPreregisteredClientsRaw: `[{"client_id":"c","redirect_uris":["/cb"]}]`},
			wantErr: true,
			wantVar: "OAUTH_PREREGISTERED_CLIENTS",
		},
		{
			name:    "well-formed OAUTH_PREREGISTERED_CLIENTS is accepted with OAuth disabled",
			cfg:     config{OAuthPreregisteredClientsRaw: `[{"client_id":"c","redirect_uris":["https://x/cb"]}]`},
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
				want := tc.wantVar
				if want == "" {
					want = "OAUTH_TOKEN_TTL"
				}
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want it to name %s", err, want)
				}
				return
			}
			if err != nil {
				t.Errorf("validate() error = %v, want nil", err)
			}
		})
	}
}

func TestParsePreregisteredClients(t *testing.T) {
	for _, tc := range []struct {
		name    string
		raw     string
		wantN   int
		wantErr string
	}{
		{"unset", "", 0, ""},
		{"blank", "   ", 0, ""},
		{"one client", `[{"client_id":"cloudflare-portal-mcp","client_name":"Portal","redirect_uris":["https://mcp.mctl.ai/servers-callback"]}]`, 1, ""},
		{"not json", `{`, 0, "OAUTH_PREREGISTERED_CLIENTS"},
		{"unknown field is refused, so a secret cannot be smuggled in", `[{"client_id":"c","redirect_uris":["https://x/cb"],"client_` + `secret":"s"}]`, 0, "unknown field"},
		{"missing client_id", `[{"redirect_uris":["https://x/cb"]}]`, 0, "no client_id"},
		{"duplicate client_id", `[{"client_id":"c","redirect_uris":["https://x/cb"]},{"client_id":"c","redirect_uris":["https://y/cb"]}]`, 0, "listed twice"},
		{"trailing data", `[] []`, 0, "trailing data"},
		// dec.More would answer false to a leading "]" and let this through.
		{"trailing data starting with a closing bracket", `[{"client_id":"c","redirect_uris":["https://x/cb"]}] ]`, 0, "trailing data"},
		{"trailing garbage", `[] x`, 0, "trailing data"},
		{"null is refused rather than read as none", `null`, 0, "null is not a client list"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePreregisteredClients(tc.raw)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tc.wantN {
				t.Fatalf("len = %d, want %d", len(got), tc.wantN)
			}
		})
	}
}

// The mctl-api#387 incident, reproduced: a rolling update where the old pod
// still holds the role's connections. Every store's first attempts are
// refused ("too many connections for role"), the shared budget runs out on
// the first store, and later stores used to fail "before attempt 1" and stay
// nil, while /readyz still said ready. Now each later store gets one
// last-chance attempt, every store that still failed is recorded, and the
// real router's /readyz answers 503 naming them.
func TestTransientStoreInitFailureKeepsThePodNotReady(t *testing.T) {
	original := storeInitBaseDelay
	storeInitBaseDelay = time.Millisecond
	t.Cleanup(func() { storeInitBaseDelay = original })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	errTooMany := errors.New("FATAL: too many connections for role \"mctl-api\" (SQLSTATE 53300)")
	refused := func(context.Context) (string, error) { return "", errTooMany }
	failures := &storeInitFailures{}
	for _, name := range []string{"oauth refresh", "surface identities", "event outbox", "agent registry"} {
		if _, err := initStore(ctx, failures, name, refused); err == nil {
			t.Fatalf("%s: expected an error while the connections are exhausted", name)
		}
	}
	want := []string{"oauth refresh", "surface identities", "event outbox", "agent registry"}
	if got := failures.List(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("failures = %v, want %v", got, want)
	}

	router := mctlapi.NewRouter(mctlapi.Options{StoreInitFailures: failures.List})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Status       string   `json:"status"`
		FailedStores []string `json:"failed_stores"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "not ready" || fmt.Sprint(body.FailedStores) != fmt.Sprint(want) {
		t.Errorf("/readyz body = %+v, want not ready naming %v", body, want)
	}

	// Liveness is untouched: a not-ready pod is not a dead one, and must not
	// be restarted into a crash loop while the database recovers.
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("/healthz = %d, want 200", rec.Code)
	}
}

func TestInitStoreRecordsOnlyFailedStores(t *testing.T) {
	shrinkStoreInitDelay(t)
	failures := &storeInitFailures{}
	if _, err := initStore(context.Background(), failures, "alert", func(context.Context) (string, error) {
		return "ok", nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := failures.List(); len(got) != 0 {
		t.Fatalf("a store that initialised was recorded as failed: %v", got)
	}
	if _, err := initStore(context.Background(), failures, "domains", func(context.Context) (string, error) {
		return "", errors.New("connection refused")
	}); err == nil {
		t.Fatal("expected an error")
	}
	if got := failures.List(); fmt.Sprint(got) != "[domains]" {
		t.Fatalf("failures = %v, want [domains]", got)
	}
}

// A store reached after an earlier one spent the shared budget gets one real
// attempt instead of none, and succeeds if its database answers.
func TestInitStoreLastChanceAfterTheBudgetIsSpent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()

	attempts := 0
	store, err := initStore(ctx, nil, "agent registry", func(attemptCtx context.Context) (string, error) {
		attempts++
		if err := attemptCtx.Err(); err != nil {
			return "", err
		}
		return "ready", nil
	})
	if err != nil || store != "ready" {
		t.Fatalf("store = %q err = %v, want a successful last-chance attempt", store, err)
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want exactly one last-chance attempt", attempts)
	}

	// Still exactly one: a failed last chance does not start a ladder.
	attempts = 0
	_, err = initStore(ctx, nil, "domains", func(context.Context) (string, error) {
		attempts++
		return "", errors.New("connection refused")
	})
	if err == nil || !strings.Contains(err.Error(), "last-chance") || attempts != 1 {
		t.Errorf("err = %v attempts = %d, want one failed last-chance attempt", err, attempts)
	}
}

// A cancelled (not expired) context is a shutdown signal: no last chance.
func TestInitStoreCancelledContextGetsNoLastChance(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	attempts := 0
	_, err := initStore(ctx, nil, "alert", func(context.Context) (string, error) {
		attempts++
		return "ok", nil
	})
	if err == nil || attempts != 0 {
		t.Errorf("err = %v attempts = %d, want no attempt after cancellation", err, attempts)
	}
}

// main() itself is not unit-testable, so pin its two wiring points in the
// source: every store main initialises reports into the tracker (a nil there
// would silently exempt that store from readiness), and the tracker reaches
// the router's /readyz.
func TestMainWiresEveryStoreIntoReadiness(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	calls := regexp.MustCompile(`initStore\(([^,]+), ([^,]+), "`).FindAllStringSubmatch(string(src), -1)
	if len(calls) < 14 {
		t.Fatalf("found %d initStore calls in main.go, expected every store (>= 14)", len(calls))
	}
	for _, c := range calls {
		if c[1] != "initCtx" || c[2] != "storeFailures" {
			t.Errorf("initStore(%s, %s, ...) in main.go: every store must report into storeFailures", c[1], c[2])
		}
	}
	if !regexp.MustCompile(`StoreInitFailures:\s+storeFailures\.List,`).Match(src) {
		t.Error("main.go does not pass storeFailures.List to the router: /readyz would never see a failed store")
	}
}
