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
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/lifecycle"
)

// recoveryBody builds a well-formed recovery request body for one entity,
// which individual tests then mutate to probe a specific failure.
func recoveryBody(kind, id, phase string, ownerType, ownerID string, epoch int, version, reason string) map[string]any {
	return map[string]any{
		"kind": kind, "id": id, "phase": phase,
		"expected_owner_type": ownerType, "expected_owner_id": ownerID,
		"expected_epoch": epoch, "expected_version": version,
		"reason": reason,
	}
}

func lifecycleRecoveryGet(t *testing.T, h *Handlers, fn http.HandlerFunc, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := adminCtx(httptest.NewRequest("GET", path, nil))
	rec := httptest.NewRecorder()
	fn(rec, req)
	return rec
}

// ageLifecycleLastSeen backdates last_seen_at directly in the table, the way
// internal/lifecycle's own store_test.go does -- the only way to simulate a
// crash without waiting out the phase's 10h liveness bound. It opens its own
// connection rather than reaching into *lifecycle.Store's private pool,
// which this package cannot see.
func ageLifecycleLastSeen(t *testing.T, entity lifecycle.EntityRef, phase string, d time.Duration) {
	t.Helper()
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx,
		`UPDATE lifecycle_ownership SET last_seen_at = $1
		 WHERE entity_kind = $2 AND entity_id = $3 AND phase = $4`,
		time.Now().UTC().Add(d), entity.Kind, entity.ID, phase,
	); err != nil {
		t.Fatalf("age last_seen_at: %v", err)
	}
}

// TestLifecycleRecoveryHandlers_NilStoreIs503 needs no database: a nil store
// must be refused before anything else, on all five endpoints.
func TestLifecycleRecoveryHandlers_NilStoreIs503(t *testing.T) {
	h := &Handlers{opts: Options{}}
	body := recoveryBody("pull-request", "x", "review-remediation", "shepherd", "cron", 1, "", "why")

	for name, fn := range map[string]http.HandlerFunc{
		"reconcile":       h.RequestLifecycleReconcile,
		"fence":           h.FenceLifecycleClaim,
		"handoff/request": h.RequestLifecycleHandoffRecovery,
		"handoff/retry":   h.RetryLifecycleHandoff,
	} {
		rec := lifecyclePost(t, h, fn, body)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s with nil store: want 503, got %d: %s", name, rec.Code, rec.Body.String())
		}
	}

	rec := lifecycleRecoveryGet(t, h, h.GetLifecycleConflict,
		"/api/v1/lifecycle/ownership/conflict?kind=pull-request&id=x&phase=review-remediation")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("conflict with nil store: want 503, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestLifecycleRecoveryHandlers_AuthBoundary requires a configured store to
// get past the nil-store gate, so it needs Postgres like its counterpart in
// handlers_lifecycle_test.go.
func TestLifecycleRecoveryHandlers_AuthBoundary(t *testing.T) {
	store, _ := newTestLifecycleStore(t)
	logger := audit.NewLogger()
	h := &Handlers{opts: Options{Lifecycle: store, AuditLog: logger}}

	raw, _ := json.Marshal(recoveryBody("pull-request", "x", "review-remediation", "shepherd", "cron", 1, "", "why"))

	for name, fn := range map[string]http.HandlerFunc{
		"reconcile":       h.RequestLifecycleReconcile,
		"fence":           h.FenceLifecycleClaim,
		"handoff/request": h.RequestLifecycleHandoffRecovery,
		"handoff/retry":   h.RetryLifecycleHandoff,
	} {
		req := httptest.NewRequest("POST", "/api/v1/lifecycle/ownership/recovery/"+name, bytes.NewReader(raw))
		rec := httptest.NewRecorder()
		fn(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s unauthenticated: want 401, got %d", name, rec.Code)
		}

		req = httptest.NewRequest("POST", "/api/v1/lifecycle/ownership/recovery/"+name, bytes.NewReader(raw))
		req = req.WithContext(auth.WithUser(req.Context(), &auth.User{ID: "t", Groups: []string{"some-tenant"}}))
		rec = httptest.NewRecorder()
		fn(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s non-admin: want 403, got %d", name, rec.Code)
		}
	}

	// The conflict read follows the same admin gate.
	req := httptest.NewRequest("GET", "/api/v1/lifecycle/ownership/conflict?kind=pull-request&id=x&phase=review-remediation", nil)
	rec := httptest.NewRecorder()
	h.GetLifecycleConflict(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("conflict unauthenticated: want 401, got %d", rec.Code)
	}
	req = httptest.NewRequest("GET", "/api/v1/lifecycle/ownership/conflict?kind=pull-request&id=x&phase=review-remediation", nil)
	req = req.WithContext(auth.WithUser(req.Context(), &auth.User{ID: "t", Groups: []string{"some-tenant"}}))
	rec = httptest.NewRecorder()
	h.GetLifecycleConflict(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("conflict non-admin: want 403, got %d", rec.Code)
	}
}

// TestLifecycleRecoveryHandlers_AuditLogRequired pins the EARS criterion that
// a recovery MUTATION must not proceed unaudited: nil AuditLog is 503 on all
// four mutating routes. The conflict READ has nothing to audit -- it changes
// nothing -- so it is deliberately NOT gated on AuditLog; see
// handlers_lifecycle_conflict.go's own doc comment.
func TestLifecycleRecoveryHandlers_AuditLogRequired(t *testing.T) {
	store, prefix := newTestLifecycleStore(t)
	h := &Handlers{opts: Options{Lifecycle: store}} // AuditLog left nil
	id := prefix + "-audit-required"

	body := recoveryBody("pull-request", id, "review-remediation", "shepherd", "cron", 1, "", "why")
	for name, fn := range map[string]http.HandlerFunc{
		"reconcile":       h.RequestLifecycleReconcile,
		"fence":           h.FenceLifecycleClaim,
		"handoff/request": h.RequestLifecycleHandoffRecovery,
		"handoff/retry":   h.RetryLifecycleHandoff,
	} {
		if rec := lifecyclePost(t, h, fn, body); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s without audit log: want 503, got %d: %s", name, rec.Code, rec.Body.String())
		}
	}

	// The conflict read must NOT require an audit log -- it is read-only.
	if rec := lifecycleRecoveryGet(t, h, h.GetLifecycleConflict,
		"/api/v1/lifecycle/ownership/conflict?kind=pull-request&id="+id+"&phase=review-remediation"); rec.Code == http.StatusServiceUnavailable {
		t.Fatalf("conflict read must not require an audit log: got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestLifecycleRecoveryHandlers_Validation checks every EARS-mandated 400:
// missing fields (named specifically, not "invalid request"), an unknown
// field, and that none of these ever reach the store.
func TestLifecycleRecoveryHandlers_Validation(t *testing.T) {
	store, prefix := newTestLifecycleStore(t)
	logger := audit.NewLogger()
	h := &Handlers{opts: Options{Lifecycle: store, AuditLog: logger}}
	id := prefix + "-validation"

	full := recoveryBody("pull-request", id, "review-remediation", "shepherd", "cron", 1, "sha-a", "why")

	missing := func(field string) map[string]any {
		b := map[string]any{}
		for k, v := range full {
			b[k] = v
		}
		delete(b, field)
		return b
	}

	for _, field := range []string{"kind", "id", "phase", "expected_owner_type", "expected_owner_id", "expected_epoch", "expected_version", "reason"} {
		rec := lifecyclePost(t, h, h.RequestLifecycleReconcile, missing(field))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("missing %s: want 400, got %d: %s", field, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), field) {
			t.Errorf("missing %s: error body does not name the field: %s", field, rec.Body.String())
		}
	}

	// Unknown field (e.g. a would-be force_owner) is rejected outright.
	withExtra := map[string]any{}
	for k, v := range full {
		withExtra[k] = v
	}
	withExtra["force_owner"] = "shepherd/cron"
	if rec := lifecyclePost(t, h, h.RequestLifecycleReconcile, withExtra); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: want 400, got %d: %s", rec.Code, rec.Body.String())
	}

	// A zero epoch is a 400, not a 412 -- there is nothing for the store to
	// have moved underneath a caller that never sent a generation.
	zeroEpoch := map[string]any{}
	for k, v := range full {
		zeroEpoch[k] = v
	}
	zeroEpoch["expected_epoch"] = 0
	if rec := lifecyclePost(t, h, h.RequestLifecycleReconcile, zeroEpoch); rec.Code != http.StatusBadRequest {
		t.Fatalf("zero epoch: want 400, got %d: %s", rec.Code, rec.Body.String())
	}

	// None of the above should have reached the store: no ownership row
	// exists for this id.
	if _, err := store.Get(context.Background(), lifecycle.EntityRef{Kind: "pull-request", ID: id}, "review-remediation"); err == nil {
		t.Fatal("a validation failure must not read or mutate the store, but a row now exists")
	}
}

// TestLifecycleRecoveryHandlers_OversizedBodyIsRejected mirrors the existing
// lifecycleMaxBodyBytes cap on the ordinary writes.
func TestLifecycleRecoveryHandlers_OversizedBodyIsRejected(t *testing.T) {
	store, prefix := newTestLifecycleStore(t)
	logger := audit.NewLogger()
	h := &Handlers{opts: Options{Lifecycle: store, AuditLog: logger}}
	id := prefix + "-oversized"

	body := recoveryBody("pull-request", id, "review-remediation", "shepherd", "cron", 1, "sha-a",
		strings.Repeat("x", lifecycleRecoveryMaxBodyBytes+1024))
	req := adminCtx(httptest.NewRequest("POST", "/api/v1/lifecycle/ownership/recovery/reconcile", jsonReader(t, body)))
	rec := httptest.NewRecorder()
	h.RequestLifecycleReconcile(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized body: want 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func jsonReader(t *testing.T, body map[string]any) *bytes.Reader {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return bytes.NewReader(raw)
}

// TestFenceLifecycleClaim_StatusMapping exercises the full status-code
// matrix end to end: 409 on a live owner, 412 on owner/epoch/version
// mismatch, and 200 with exactly one audit entry on success.
func TestFenceLifecycleClaim_StatusMapping(t *testing.T) {
	store, prefix := newTestLifecycleStore(t)
	logger := audit.NewLogger()
	h := &Handlers{opts: Options{Lifecycle: store, AuditLog: logger}}
	id := prefix + "-fence-mapping"
	entity := lifecycle.EntityRef{Kind: "pull-request", ID: id}
	owner := lifecycle.Owner{Type: "devloop-workflow", ID: "wf-1"}

	got, err := store.Acquire(context.Background(), lifecycle.AcquireRequest{
		Entity: entity, Phase: "review-remediation", Owner: owner,
	})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	// Still alive: 409.
	body := recoveryBody("pull-request", id, "review-remediation", "devloop-workflow", "wf-1", got.Epoch, "", "escalate")
	if rec := lifecyclePost(t, h, h.FenceLifecycleClaim, body); rec.Code != http.StatusConflict {
		t.Fatalf("fence a live owner: want 409, got %d: %s", rec.Code, rec.Body.String())
	}
	refused := logger.List(20)
	if len(refused) != 1 {
		t.Fatalf("refused fence: want exactly 1 audit entry, got %d", len(refused))
	}
	if refused[0].Operation != "lifecycle-recovery-fence" || refused[0].Status != "failed" {
		t.Fatalf("unexpected audit entry for refusal: %+v", refused[0])
	}

	// Age it past the liveness bound.
	ageLifecycleLastSeen(t, entity, "review-remediation", -11*time.Hour)

	// Owner mismatch at a matching epoch: 412.
	wrongOwner := recoveryBody("pull-request", id, "review-remediation", "shepherd", "cron", got.Epoch, "", "escalate")
	if rec := lifecyclePost(t, h, h.FenceLifecycleClaim, wrongOwner); rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("owner mismatch: want 412, got %d: %s", rec.Code, rec.Body.String())
	}

	// Epoch mismatch: 412.
	wrongEpoch := recoveryBody("pull-request", id, "review-remediation", "devloop-workflow", "wf-1", got.Epoch+9, "", "escalate")
	if rec := lifecyclePost(t, h, h.FenceLifecycleClaim, wrongEpoch); rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("epoch mismatch: want 412, got %d: %s", rec.Code, rec.Body.String())
	}

	// Version mismatch at the right owner+epoch: 412.
	wrongVersion := recoveryBody("pull-request", id, "review-remediation", "devloop-workflow", "wf-1", got.Epoch, "sha-does-not-exist", "escalate")
	if rec := lifecyclePost(t, h, h.FenceLifecycleClaim, wrongVersion); rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("version mismatch: want 412, got %d: %s", rec.Code, rec.Body.String())
	}

	// Now the real thing: success.
	success := recoveryBody("pull-request", id, "review-remediation", "devloop-workflow", "wf-1", got.Epoch, "", "unseen for 11h")
	if rec := lifecyclePost(t, h, h.FenceLifecycleClaim, success); rec.Code != http.StatusOK {
		t.Fatalf("fence a dead owner: want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var successEntry audit.Entry
	for _, e := range logger.List(20) {
		if e.Operation == "lifecycle-recovery-fence" && e.Status == "succeeded" {
			successEntry = e
		}
	}
	if successEntry.UserID == "" {
		t.Fatal("no successful fence audit entry recorded")
	}
	if successEntry.RiskLevel != "high" {
		t.Errorf("fence audit risk level = %q, want high", successEntry.RiskLevel)
	}
	if len(successEntry.Parameters) == 0 {
		t.Error("fence audit entry carries no parameters")
	}
}

// TestRequestHandoffRecovery_NotStuckIs409 pins the 409 arm for a healthy
// owner, distinct from the 412s above.
func TestRequestHandoffRecovery_NotStuckIs409(t *testing.T) {
	store, prefix := newTestLifecycleStore(t)
	logger := audit.NewLogger()
	h := &Handlers{opts: Options{Lifecycle: store, AuditLog: logger}}
	id := prefix + "-handoff-not-stuck"
	entity := lifecycle.EntityRef{Kind: "pull-request", ID: id}
	owner := lifecycle.Owner{Type: "devloop-workflow", ID: "wf-1"}

	got, err := store.Acquire(context.Background(), lifecycle.AcquireRequest{
		Entity: entity, Phase: "review-remediation", Owner: owner,
	})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	body := recoveryBody("pull-request", id, "review-remediation", "devloop-workflow", "wf-1", got.Epoch, "", "escalate")
	body["to_owner_type"] = "pr-steward"
	body["to_owner_id"] = "steward"
	rec := lifecyclePost(t, h, h.RequestLifecycleHandoffRecovery, body)
	if rec.Code != http.StatusConflict {
		t.Fatalf("healthy owner: want 409, got %d: %s", rec.Code, rec.Body.String())
	}

	// Missing to_owner_* is a 400, not a store round trip.
	noTarget := recoveryBody("pull-request", id, "review-remediation", "devloop-workflow", "wf-1", got.Epoch, "", "escalate")
	rec = lifecyclePost(t, h, h.RequestLifecycleHandoffRecovery, noTarget)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing to_owner: want 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestLifecycleRecoveryHandlers_NoMergeAuthority exercises the five handlers
// against Handlers built with ONLY Lifecycle and AuditLog set -- no GitHub,
// Temporal or Argo client -- and confirms every one of them behaves sanely
// (no nil-pointer panic) and the conflict read still answers (with the
// legacy block reporting unavailable, never "no DevLoop").
func TestLifecycleRecoveryHandlers_NoMergeAuthority(t *testing.T) {
	store, prefix := newTestLifecycleStore(t)
	logger := audit.NewLogger()
	h := &Handlers{opts: Options{Lifecycle: store, AuditLog: logger}}
	id := prefix + "-no-merge-authority"
	entity := lifecycle.EntityRef{Kind: "pull-request", ID: id}
	owner := lifecycle.Owner{Type: "devloop-workflow", ID: "wf-1"}

	got, err := store.Acquire(context.Background(), lifecycle.AcquireRequest{
		Entity: entity, Phase: "review-remediation", Owner: owner,
	})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	// Conflict read: no panic without a TemporalClient, legacy reports
	// unavailable rather than a false "no DevLoop".
	rec := lifecycleRecoveryGet(t, h, h.GetLifecycleConflict,
		"/api/v1/lifecycle/ownership/conflict?kind=pull-request&id="+id+"&phase=review-remediation")
	if rec.Code != http.StatusOK {
		t.Fatalf("conflict read: want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var conflict lifecycleConflictResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &conflict); err != nil {
		t.Fatalf("decode conflict response: %v", err)
	}
	if conflict.Legacy.Available {
		t.Fatal("legacy answer must be unavailable with no Temporal client configured")
	}
	if conflict.Legacy.Answer != legacyAnswerUnknown {
		t.Fatalf("legacy answer = %q, want %q", conflict.Legacy.Answer, legacyAnswerUnknown)
	}
	if conflict.Preconditions.ExpectedOwnerType != owner.Type || conflict.Preconditions.ExpectedOwnerID != owner.ID ||
		conflict.Preconditions.ExpectedEpoch != got.Epoch {
		t.Fatalf("preconditions do not match the row: %+v", conflict.Preconditions)
	}

	// Reconcile: succeeds with no panic.
	reconcileBody := recoveryBody("pull-request", id, "review-remediation", owner.Type, owner.ID, got.Epoch,
		conflict.Preconditions.ExpectedVersion, "please look at this")
	if rec := lifecyclePost(t, h, h.RequestLifecycleReconcile, reconcileBody); rec.Code != http.StatusOK {
		t.Fatalf("reconcile: want 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// The exact preconditions the conflict read returned are what a
	// follow-up fence call accepts, once the owner is actually dead.
	ageLifecycleLastSeen(t, entity, "review-remediation", -11*time.Hour)
	fenceBody := recoveryBody("pull-request", id, "review-remediation",
		conflict.Preconditions.ExpectedOwnerType, conflict.Preconditions.ExpectedOwnerID,
		conflict.Preconditions.ExpectedEpoch, conflict.Preconditions.ExpectedVersion, "unseen for 11h")
	if rec := lifecyclePost(t, h, h.FenceLifecycleClaim, fenceBody); rec.Code != http.StatusOK {
		t.Fatalf("fence with conflict-read preconditions: want 200, got %d: %s", rec.Code, rec.Body.String())
	}
}
