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

package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// newTestStore connects to the Postgres that .github/workflows/validate.yml
// runs as a service for the `test` job (image postgres:16, TEST_DATABASE_URL
// exported). The skip fires on a developer laptop, NOT in CI — the same
// pattern internal/usage/store_test.go and internal/workitems/store_test.go
// use.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed evidence store test")
	}
	ctx := context.Background()
	s, err := NewStore(ctx, connStr)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// uniqueEnvelope builds a distinct, validly-sealed envelope for each call
// (a fresh trace_id keeps the content, and therefore the derived ev- id,
// from colliding across tests and across runs of the same test).
func uniqueEnvelope(t *testing.T, workItemID, runtimeID string) []byte {
	t.Helper()
	exec := map[string]any{
		"execution_id": "we_" + uniqueSuffix(),
		"work_item_id": workItemID,
		"trace_id":     uniqueSuffix(),
	}
	if runtimeID != "" {
		exec["runtime_execution_id"] = runtimeID
	}
	if workItemID == "" {
		delete(exec, "work_item_id")
	}
	return envelopeJSON(t, exec)
}

var uniqueCounter int64
var uniqueMu sync.Mutex

func uniqueSuffix() string {
	uniqueMu.Lock()
	defer uniqueMu.Unlock()
	uniqueCounter++
	return fmt.Sprintf("%d%d", time.Now().UnixNano(), uniqueCounter)
}

func TestStoreIngestCreatesThenReplays(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	env := uniqueEnvelope(t, "wi_test1", "")

	first, created, err := s.Ingest(ctx, IngestInput{EnvelopeBytes: env, IngestedBy: "test:writer"})
	if err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	if !created {
		t.Fatal("first ingest: created=false, want true")
	}

	second, created2, err := s.Ingest(ctx, IngestInput{EnvelopeBytes: env, IngestedBy: "test:other-writer"})
	if err != nil {
		t.Fatalf("second ingest (replay): %v", err)
	}
	if created2 {
		t.Fatal("second ingest: created=true, want false (replay)")
	}
	if second.ID != first.ID || second.IngestedBy != first.IngestedBy {
		t.Errorf("replay returned a different row: first.IngestedBy=%s second.IngestedBy=%s (must keep the FIRST attribution)",
			first.IngestedBy, second.IngestedBy)
	}
}

// A re-seal of identical inputs with a different created_at must be
// recognised as the same evidence (Tier A excludes created_at from the
// hash precisely so this holds) -- never a false 409.
func TestStoreIngestSameContentDifferentCreatedAtIsAReplay(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	execBlock := map[string]any{"execution_id": "we_" + uniqueSuffix(), "trace_id": uniqueSuffix()}
	base := map[string]any{
		"api_version": APIVersionV1Alpha1, "kind": KindV1Alpha1,
		"execution": execBlock, "outcome": map[string]any{"code": "succeeded", "reason_code": "test"},
	}
	seal := func(createdAt string) []byte {
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		m["created_at"] = createdAt
		raw, _ := json.Marshal(m)
		p, err := parseEnvelope(raw)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		canonical, err := CanonicalContentJSON(p)
		if err != nil {
			t.Fatalf("canonical: %v", err)
		}
		hash := ContentHash(canonical)
		m["content_hash"] = hash
		m["evidence_id"] = EvidenceIDFor(hash)
		out, _ := json.Marshal(m)
		return out
	}

	envA := seal("2026-01-01T00:00:00Z")
	envB := seal("2026-06-01T00:00:00Z")

	first, created, err := s.Ingest(ctx, IngestInput{EnvelopeBytes: envA, IngestedBy: "test:writer"})
	if err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	if !created {
		t.Fatal("first ingest: created=false, want true")
	}

	second, created2, err := s.Ingest(ctx, IngestInput{EnvelopeBytes: envB, IngestedBy: "test:writer"})
	if err != nil {
		t.Fatalf("second ingest (re-seal, different created_at): %v", err)
	}
	if created2 {
		t.Fatal("second ingest: created=true, want false (same content, different created_at)")
	}
	if second.ID != first.ID {
		t.Errorf("second.ID = %s, want %s", second.ID, first.ID)
	}
}

// A stored ev- id whose content_hash column disagrees with a freshly
// submitted envelope's recomputed hash is a 64-bit id-prefix collision:
// ErrEvidenceDivergence, and the stored row is untouched. Constructed here
// by inserting a row directly (bypassing Ingest) under the id a distinct,
// valid envelope will legitimately derive.
func TestStoreIngestDivergence(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	env := uniqueEnvelope(t, "wi_test-divergence", "")
	p, contentHash, evidenceID, err := Validate(IngestInput{EnvelopeBytes: env})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	_ = p

	// Plant a different row under the SAME id but a DIFFERENT content_hash
	// -- simulating a collision Ingest's own hashing could never produce
	// from two real envelopes, but which the id column alone cannot rule
	// out.
	fakeHash := "sha256:" + "ab" + contentHash[9:]
	now := time.Now().UTC()
	_, err = s.pool.Exec(ctx, `INSERT INTO execution_evidence (`+evidenceColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		evidenceID, fakeHash, APIVersionV1Alpha1, env, "we_planted", "", "wi_test-divergence", "",
		now, "test:planted", "", now)
	if err != nil {
		t.Fatalf("plant colliding row: %v", err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(ctx, `DELETE FROM execution_evidence WHERE id=$1`, evidenceID) })

	_, _, err = s.Ingest(ctx, IngestInput{EnvelopeBytes: env, IngestedBy: "test:writer"})
	if !errors.Is(err, ErrEvidenceDivergence) {
		t.Fatalf("Ingest() error = %v, want ErrEvidenceDivergence", err)
	}

	// The planted row must be untouched.
	var stillFake string
	if err := s.pool.QueryRow(ctx, `SELECT content_hash FROM execution_evidence WHERE id=$1`, evidenceID).Scan(&stillFake); err != nil {
		t.Fatalf("re-read planted row: %v", err)
	}
	if stillFake != fakeHash {
		t.Errorf("planted row's content_hash changed: got %s, want %s (unchanged)", stillFake, fakeHash)
	}
}

func TestStoreImmutableRowRejectsUpdate(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	env := uniqueEnvelope(t, "wi_test-immutable", "")
	stored, _, err := s.Ingest(ctx, IngestInput{EnvelopeBytes: env, IngestedBy: "test:writer"})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	_, err = s.pool.Exec(ctx, `UPDATE execution_evidence SET ingested_by='someone-else' WHERE id=$1`, stored.ID)
	if err == nil {
		t.Fatal("UPDATE execution_evidence succeeded, want the BEFORE UPDATE trigger to raise")
	}
}

func TestStoreDeleteCascadesToRefs(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	env := uniqueEnvelope(t, "wi_test-cascade", "")
	stored, _, err := s.Ingest(ctx, IngestInput{EnvelopeBytes: env, IngestedBy: "test:writer"})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	var before int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM execution_evidence_refs WHERE evidence_id=$1`, stored.ID).Scan(&before); err != nil {
		t.Fatalf("count refs before delete: %v", err)
	}
	if before != 1 {
		t.Fatalf("expected exactly one ref row after ingest, got %d", before)
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM execution_evidence WHERE id=$1`, stored.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	var after int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM execution_evidence_refs WHERE evidence_id=$1`, stored.ID).Scan(&after); err != nil {
		t.Fatalf("count refs after delete: %v", err)
	}
	if after != 0 {
		t.Errorf("ref row survived deleting its evidence row: count=%d, want 0 (cascade)", after)
	}
}

func TestStoreRefsRuntimeShapeRejectedInWorkColumn(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	env := uniqueEnvelope(t, "wi_test-refshape", "")
	stored, _, err := s.Ingest(ctx, IngestInput{EnvelopeBytes: env, IngestedBy: "test:writer"})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	_, err = s.pool.Exec(ctx, `UPDATE execution_evidence_refs SET work_execution_id='ex-0123456789abcdef' WHERE evidence_id=$1`, stored.ID)
	if err == nil {
		t.Fatal("UPDATE execution_evidence_refs.work_execution_id to an ex- value succeeded, want the CHECK constraint to reject it")
	}
}

// A stored envelope whose bytes no longer hash to its content_hash column
// (tampered out-of-band, or -- as constructed here -- planted directly) is
// refused on read, never served under its old identity.
func TestStoreGetRefusesTamperedBytes(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	env := uniqueEnvelope(t, "wi_test-tamper", "")
	_, contentHash, evidenceID, err := Validate(IngestInput{EnvelopeBytes: env})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	tampered := append([]byte{}, env...)
	tampered = append(tampered, ' ') // any byte change invalidates the hash
	now := time.Now().UTC()
	_, err = s.pool.Exec(ctx, `INSERT INTO execution_evidence (`+evidenceColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		evidenceID, contentHash, APIVersionV1Alpha1, tampered, "we_tampered", "", "wi_test-tamper", "",
		now, "test:planted", "", now)
	if err != nil {
		t.Fatalf("plant tampered row: %v", err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(ctx, `DELETE FROM execution_evidence WHERE id=$1`, evidenceID) })

	_, err = s.Get(ctx, evidenceID)
	if err == nil {
		t.Fatal("Get() succeeded on a row whose bytes no longer hash to content_hash, want an error")
	}
}

func TestStoreListFindsBothIdentityEnvelopeByEitherFilter(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	runtimeID := "ex-" + fmt.Sprintf("%016x", time.Now().UnixNano())[:16]
	env := uniqueEnvelope(t, "wi_test-both", runtimeID)
	stored, _, err := s.Ingest(ctx, IngestInput{EnvelopeBytes: env, IngestedBy: "test:writer"})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}

	byWork, err := s.List(ctx, Filter{ExecutionID: stored.ExecutionID})
	if err != nil {
		t.Fatalf("list by execution_id: %v", err)
	}
	if !containsID(byWork.Evidence, stored.ID) {
		t.Errorf("list by execution_id=%s did not find %s", stored.ExecutionID, stored.ID)
	}

	byRuntime, err := s.List(ctx, Filter{RuntimeExecutionID: runtimeID})
	if err != nil {
		t.Fatalf("list by runtime_execution_id: %v", err)
	}
	if !containsID(byRuntime.Evidence, stored.ID) {
		t.Errorf("list by runtime_execution_id=%s did not find %s", runtimeID, stored.ID)
	}
}

func TestStoreGetUnknownIDIsNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_, err := s.Get(ctx, "ev-0000000000000000")
	if !errors.Is(err, ErrEvidenceNotFound) {
		t.Fatalf("Get() error = %v, want ErrEvidenceNotFound", err)
	}
}

func TestStoreRebuildRefsIsIdempotentAndLeavesEvidenceUnchanged(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	env := uniqueEnvelope(t, "wi_test-rebuild", "")
	stored, _, err := s.Ingest(ctx, IngestInput{EnvelopeBytes: env, IngestedBy: "test:writer"})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if err := s.RebuildRefs(ctx, []string{stored.ID}); err != nil {
		t.Fatalf("first rebuild: %v", err)
	}
	if err := s.RebuildRefs(ctx, []string{stored.ID}); err != nil {
		t.Fatalf("second rebuild: %v", err)
	}
	again, err := s.Get(ctx, stored.ID)
	if err != nil {
		t.Fatalf("get after rebuild: %v", err)
	}
	if again.ContentHash != stored.ContentHash || string(again.Envelope) != string(stored.Envelope) {
		t.Error("RebuildRefs changed the sealed execution_evidence row; it must touch only execution_evidence_refs")
	}
}

func containsID(list []*Evidence, id string) bool {
	for _, e := range list {
		if e.ID == id {
			return true
		}
	}
	return false
}
