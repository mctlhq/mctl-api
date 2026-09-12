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

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/lifecycle"
)

// newTestLifecycleStore uses the postgres:16 service the `test` job in
// .github/workflows/validate.yml runs, so these execute on every PR; the skip
// fires only on a developer laptop.
//
// Cleanup is scoped to this test's own key prefix. The job runs
// `go test -p 1 ./...` because packages sharing this database were wiping each
// other's rows, and an unscoped DELETE here would re-create that from a new
// direction.
func newTestLifecycleStore(t *testing.T) (*lifecycle.Store, string) {
	t.Helper()
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed lifecycle handler test")
	}
	ctx := context.Background()
	s, err := lifecycle.NewStore(ctx, connStr)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	prefix := fmt.Sprintf("apitest-%s-%d", t.Name(), time.Now().UnixNano())
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("cleanup pool: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM lifecycle_events WHERE entity_id LIKE $1`, prefix+"%")
		_, _ = pool.Exec(ctx, `DELETE FROM lifecycle_ownership WHERE entity_id LIKE $1`, prefix+"%")
		pool.Close()
		s.Close()
	})
	return s, prefix
}

func lifecyclePost(t *testing.T, h *Handlers, fn http.HandlerFunc, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := adminCtx(httptest.NewRequest("POST", "/api/v1/lifecycle/ownership/acquire", bytes.NewReader(raw)))
	rec := httptest.NewRecorder()
	fn(rec, req)
	return rec
}

func TestLifecycleHandlers_AuthBoundary(t *testing.T) {
	store, _ := newTestLifecycleStore(t)
	h := &Handlers{opts: Options{Lifecycle: store}}

	req := httptest.NewRequest("GET", "/api/v1/lifecycle/ownership", nil)
	rec := httptest.NewRecorder()
	h.GetLifecycleOwnership(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: want 401, got %d", rec.Code)
	}

	req = httptest.NewRequest("GET", "/api/v1/lifecycle/ownership", nil)
	req = req.WithContext(auth.WithUser(req.Context(), &auth.User{ID: "t", Groups: []string{"some-tenant"}}))
	rec = httptest.NewRecorder()
	h.GetLifecycleOwnership(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin: want 403, got %d", rec.Code)
	}

	// A write must be gated identically — an endpoint that decides who may
	// mutate a PR is not a place to have a weaker check than its read.
	rec = lifecyclePost(t, &Handlers{opts: Options{Lifecycle: store}}, func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(auth.WithUser(r.Context(), &auth.User{ID: "t", Groups: []string{"some-tenant"}}))
		h.AcquireLifecycleOwnership(w, r)
	}, map[string]any{"kind": "pull-request", "id": "x", "phase": "review-remediation", "owner_type": "shepherd", "owner_id": "cron"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin write: want 403, got %d", rec.Code)
	}
}

// TestLifecycleHandlers_NilStoreIs503NotEmpty is the one that matters most.
// A store outage answering "no ownership record" would read as "nobody owns
// this", and the caller would act. It must be distinguishable.
func TestLifecycleHandlers_NilStoreIs503NotEmpty(t *testing.T) {
	h := &Handlers{opts: Options{}} // Lifecycle left nil

	for name, fn := range map[string]http.HandlerFunc{
		"get":     h.GetLifecycleOwnership,
		"batch":   h.BatchGetLifecycleOwnership,
		"events":  h.ListLifecycleEvents,
		"acquire": h.AcquireLifecycleOwnership,
		"release": h.ReleaseLifecycleOwnership,
	} {
		req := adminCtx(httptest.NewRequest("GET", "/api/v1/lifecycle/ownership?kind=pull-request&id=x&phase=review-remediation", nil))
		rec := httptest.NewRecorder()
		fn(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s with nil store: want 503, got %d", name, rec.Code)
		}
	}
}

func TestLifecycleHandlers_StatusCodeMapping(t *testing.T) {
	store, prefix := newTestLifecycleStore(t)
	h := &Handlers{opts: Options{Lifecycle: store}}
	id := prefix + "-mapping"

	base := map[string]any{
		"kind": "pull-request", "id": id, "phase": "review-remediation",
		"owner_type": "devloop-workflow", "owner_id": "wf-1",
	}

	// Unknown (kind, phase) is a client error, not a 500.
	bad := map[string]any{"kind": "pull-request", "id": id, "phase": "investigate", "owner_type": "shepherd", "owner_id": "cron"}
	if rec := lifecyclePost(t, h, h.AcquireLifecycleOwnership, bad); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown phase: want 400, got %d: %s", rec.Code, rec.Body.String())
	}

	// Reading a record that does not exist is 404, distinct from the 503 above.
	req := adminCtx(httptest.NewRequest("GET", "/api/v1/lifecycle/ownership?kind=pull-request&id="+id+"&phase=review-remediation", nil))
	rec := httptest.NewRecorder()
	h.GetLifecycleOwnership(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing record: want 404, got %d", rec.Code)
	}

	if rec := lifecyclePost(t, h, h.AcquireLifecycleOwnership, base); rec.Code != http.StatusOK {
		t.Fatalf("acquire: want 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// A competing owner gets 409 AND is told who won — without that, a loser
	// cannot tell a healthy owner from one it should escalate.
	other := map[string]any{"kind": "pull-request", "id": id, "phase": "review-remediation", "owner_type": "shepherd", "owner_id": "cron"}
	rec = lifecyclePost(t, h, h.AcquireLifecycleOwnership, other)
	if rec.Code != http.StatusConflict {
		t.Fatalf("contended acquire: want 409, got %d: %s", rec.Code, rec.Body.String())
	}
	var conflict struct {
		CurrentOwner *lifecycle.Owner `json:"current_owner"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &conflict); err != nil {
		t.Fatalf("conflict body: %v", err)
	}
	if conflict.CurrentOwner == nil || conflict.CurrentOwner.ID != "wf-1" {
		t.Fatalf("409 did not name the winner: %s", rec.Body.String())
	}

	// A stale epoch is 412, not 409: the caller's precondition failed and the
	// correct response is re-read, not retry.
	stale := map[string]any{
		"kind": "pull-request", "id": id, "phase": "review-remediation",
		"owner_type": "devloop-workflow", "owner_id": "wf-1",
		"epoch": 99, "evidence": "x",
	}
	if rec := lifecyclePost(t, h, h.RecordLifecycleProgress, stale); rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale epoch: want 412, got %d: %s", rec.Code, rec.Body.String())
	}

	// Progress without evidence is refused, so "progress" keeps meaning
	// something auditable rather than becoming a heartbeat.
	noEvidence := map[string]any{
		"kind": "pull-request", "id": id, "phase": "review-remediation",
		"owner_type": "devloop-workflow", "owner_id": "wf-1", "epoch": 1,
	}
	if rec := lifecyclePost(t, h, h.RecordLifecycleProgress, noEvidence); rec.Code != http.StatusBadRequest {
		t.Fatalf("progress without evidence: want 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestLifecycleHandlers_BatchOmitsUnknownEntities pins that "we have no
// record" is expressed by ABSENCE, never by a null entry that a caller might
// read as a positive statement that nobody owns it.
func TestLifecycleHandlers_BatchOmitsUnknownEntities(t *testing.T) {
	store, prefix := newTestLifecycleStore(t)
	h := &Handlers{opts: Options{Lifecycle: store}}
	owned := prefix + "-owned"
	unknown := prefix + "-unknown"

	if rec := lifecyclePost(t, h, h.AcquireLifecycleOwnership, map[string]any{
		"kind": "pull-request", "id": owned, "phase": "review-remediation",
		"owner_type": "devloop-workflow", "owner_id": "wf-1",
	}); rec.Code != http.StatusOK {
		t.Fatalf("acquire: %d %s", rec.Code, rec.Body.String())
	}

	url := "/api/v1/lifecycle/ownership/batch?kind=pull-request&phase=review-remediation&id=" + owned + "&id=" + unknown
	req := adminCtx(httptest.NewRequest("GET", url, nil))
	rec := httptest.NewRecorder()
	h.BatchGetLifecycleOwnership(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("batch: %d %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Ownership map[string]json.RawMessage `json:"ownership"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("batch body: %v", err)
	}
	if _, ok := got.Ownership[owned]; !ok {
		t.Fatalf("owned entity missing from batch")
	}
	if _, ok := got.Ownership[unknown]; ok {
		t.Fatalf("unknown entity present in batch; absence is the answer")
	}
}

// TestLifecycleHandlers_ReadModelExposesDerivedState checks that stale and
// healthy are computed server-side, so every caller gets the same answer
// rather than each re-implementing the bound.
func TestLifecycleHandlers_ReadModelExposesDerivedState(t *testing.T) {
	store, prefix := newTestLifecycleStore(t)
	h := &Handlers{opts: Options{Lifecycle: store}}
	id := prefix + "-derived"

	if rec := lifecyclePost(t, h, h.AcquireLifecycleOwnership, map[string]any{
		"kind": "pull-request", "id": id, "phase": "review-remediation",
		"owner_type": "devloop-workflow", "owner_id": "wf-1",
	}); rec.Code != http.StatusOK {
		t.Fatalf("acquire: %d", rec.Code)
	}

	req := adminCtx(httptest.NewRequest("GET", "/api/v1/lifecycle/ownership?kind=pull-request&id="+id+"&phase=review-remediation", nil))
	rec := httptest.NewRecorder()
	h.GetLifecycleOwnership(rec, req)
	var body struct {
		Dead    bool `json:"dead"`
		Stuck   bool `json:"stuck"`
		Healthy bool `json:"healthy"`
		Epoch   int  `json:"epoch"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body: %v", err)
	}
	if body.Dead || body.Stuck {
		t.Fatalf("a just-acquired record must be neither dead nor stuck")
	}
	if !body.Healthy {
		t.Fatalf("a just-acquired record must be healthy")
	}
	if body.Epoch != 1 {
		t.Fatalf("epoch not exposed: %d", body.Epoch)
	}
}

// TestLifecycleHandlers_RecoverTakesADeadRowAndRefusesALiveOne closes the hole
// the first review round found: without this route the API could reach the
// zero-owner state and never leave it.
//
// Acquire refuses an ACTIVE record regardless of liveness — deliberately, on
// the store's own argument that a dead owner's row is not acquirable but
// recoverable — so Recover is the only operation that moves ownership off a
// live record, and it was neither routed nor handled.
func TestLifecycleHandlers_RecoverTakesADeadRowAndRefusesALiveOne(t *testing.T) {
	store, prefix := newTestLifecycleStore(t)
	h := &Handlers{opts: Options{Lifecycle: store}}
	id := prefix + "-recover"
	claim := map[string]any{
		"kind": "pull-request", "id": id, "phase": "review-remediation",
		"owner_type": "devloop-workflow", "owner_id": "wf-1",
	}
	if rec := lifecyclePost(t, h, h.AcquireLifecycleOwnership, claim); rec.Code != http.StatusOK {
		t.Fatalf("acquire: %d %s", rec.Code, rec.Body)
	}

	takeover := map[string]any{
		"kind": "pull-request", "id": id, "phase": "review-remediation",
		"owner_type": "shepherd", "owner_id": "cron",
		"epoch": 1, "evidence": "the workflow stopped being seen",
	}

	// A LIVE owner is not recoverable, whatever the caller believes. The
	// liveness check is the server's, re-derived against the database clock.
	rec := lifecyclePost(t, h, h.RecoverLifecycleOwnership, takeover)
	if rec.Code != http.StatusConflict {
		t.Fatalf("recover from a live owner: want 409, got %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "still") && !strings.Contains(rec.Body.String(), "alive") {
		t.Fatalf("the 409 does not say the owner is alive: %s", rec.Body)
	}

	// Age it past the liveness bound, the only way to simulate a crash.
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx,
		`UPDATE lifecycle_ownership SET last_seen_at = $1
		 WHERE entity_kind = 'pull-request' AND entity_id = $2 AND phase = 'review-remediation'`,
		time.Now().UTC().Add(-11*time.Hour), id,
	); err != nil {
		t.Fatalf("age the row: %v", err)
	}

	rec = lifecyclePost(t, h, h.RecoverLifecycleOwnership, takeover)
	if rec.Code != http.StatusOK {
		t.Fatalf("recover from a dead owner: want 200, got %d %s", rec.Code, rec.Body)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	owner, _ := got["owner"].(map[string]any)
	if owner["id"] != "cron" {
		t.Fatalf("the row was not taken over: %v", got)
	}
	// The epoch moved, or the previous owner is not fenced out.
	if epoch, _ := got["epoch"].(float64); epoch != 2 {
		t.Fatalf("recovery did not move the epoch: %v", got["epoch"])
	}
}

// TestLifecycleHandlers_StaleReadIsRetryableNotAServerError pins the sentinel
// whose whole meaning is "ask again".
//
// It fell through writeLifecycleError's default arm to a 500, which clients
// back off from and which pages an operator — the exact inverse of what the
// store means by it. Reachable from Acquire, RecordProgress, HandoffStart and
// finish under ordinary contention.
func TestLifecycleHandlers_StaleReadIsRetryableNotAServerError(t *testing.T) {
	rec := httptest.NewRecorder()
	writeLifecycleError(rec, fmt.Errorf("%w: it changed while the write was in flight",
		lifecycle.ErrStaleRead), nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("ErrStaleRead: want 409, got %d %s", rec.Code, rec.Body)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["retryable"] != true {
		t.Fatalf("a stale read must be marked retryable: %v", body)
	}

	// The other direction: a 409 that means STAND DOWN must not carry it, or
	// the flag says nothing. ErrNotOwner and ErrOwnedByOther share the status.
	for _, err := range []error{lifecycle.ErrNotOwner, lifecycle.ErrOwnedByOther, lifecycle.ErrOwnerAlive} {
		rec := httptest.NewRecorder()
		writeLifecycleError(rec, err, nil)
		if rec.Code != http.StatusConflict {
			t.Fatalf("%v: want 409, got %d", err, rec.Code)
		}
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if body["retryable"] == true {
			t.Fatalf("%v must not be marked retryable: %v", err, body)
		}
	}
}

// TestLifecycleRoutesAreRegistered pins the ROUTES, not only the handlers.
//
// Every other test in this file calls the handler function directly, so
// deleting a route line left the suite green while the endpoint did not exist.
// That is how `recover` came to be listed in the PR description and absent
// from the router.
func TestLifecycleRoutesAreRegistered(t *testing.T) {
	router, ok := NewRouter(Options{}).(chi.Routes)
	if !ok {
		t.Fatal("the router does not expose its routes")
	}
	found := map[string]bool{}
	if err := chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		found[method+" "+strings.TrimSuffix(route, "/")] = true
		return nil
	}); err != nil {
		t.Fatalf("walk: %v", err)
	}
	for _, want := range []string{
		"POST /api/v1/lifecycle/ownership/acquire",
		"POST /api/v1/lifecycle/ownership/progress",
		"POST /api/v1/lifecycle/ownership/release",
		"POST /api/v1/lifecycle/ownership/terminal",
		"POST /api/v1/lifecycle/ownership/handoff/start",
		"POST /api/v1/lifecycle/ownership/handoff/complete",
		// The one the first review round found missing. Without it a dead
		// owner's row can never be taken over through this API, because
		// Acquire refuses an active record regardless of liveness.
		"POST /api/v1/lifecycle/ownership/recover",
		"GET /api/v1/lifecycle/ownership",
		"GET /api/v1/lifecycle/ownership/batch",
		"GET /api/v1/lifecycle/events",
	} {
		if !found[want] {
			t.Errorf("route not registered: %s", want)
		}
	}
}
