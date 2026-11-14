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

package alerts

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// fakeEvidenceRows yields n rows; scanErrAt (1-based, 0 = never) makes that
// row's Scan fail, and streamErr is reported by Err after the last row. Unlike
// real pgx it does not fold a scan error into Err, so each check in
// collectEvidence is exercised on its own.
type fakeEvidenceRows struct {
	n, i, scanErrAt int
	streamErr       error
}

func (r *fakeEvidenceRows) Close()                                       {}
func (r *fakeEvidenceRows) Err() error                                   { return r.streamErr }
func (r *fakeEvidenceRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *fakeEvidenceRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *fakeEvidenceRows) Values() ([]any, error)                       { return nil, nil }
func (r *fakeEvidenceRows) RawValues() [][]byte                          { return nil }
func (r *fakeEvidenceRows) Conn() *pgx.Conn                              { return nil }
func (r *fakeEvidenceRows) Next() bool {
	if r.i >= r.n {
		return false
	}
	r.i++
	return true
}
func (r *fakeEvidenceRows) Scan(dest ...any) error {
	if r.i == r.scanErrAt {
		return errors.New("cannot scan NULL into *string")
	}
	*dest[0].(*int) = r.i
	*dest[1].(*string) = "a1"
	*dest[2].(*string) = "logs"
	*dest[3].(*string) = "content"
	*dest[4].(*time.Time) = time.Unix(int64(r.i), 0)
	return nil
}

func TestCollectEvidence_ScanErrorFailsTheRead(t *testing.T) {
	ev, err := collectEvidence(&fakeEvidenceRows{n: 3, scanErrAt: 2})
	if err == nil {
		t.Fatalf("a row that fails to scan must fail the read, got %d rows and no error", len(ev))
	}
	if ev != nil {
		t.Fatalf("a failed read must return no partial list, got %d rows", len(ev))
	}
}

func TestCollectEvidence_StreamErrorFailsTheRead(t *testing.T) {
	ev, err := collectEvidence(&fakeEvidenceRows{n: 2, streamErr: errors.New("conn reset")})
	if err == nil {
		t.Fatalf("a stream error after the last row must fail the read, got %d rows and no error", len(ev))
	}
}

func TestCollectEvidence_CompleteRead(t *testing.T) {
	ev, err := collectEvidence(&fakeEvidenceRows{n: 3})
	if err != nil || len(ev) != 3 {
		t.Fatalf("got %d rows, err %v; want 3, nil", len(ev), err)
	}
}

// breakEvidenceRow lets one evidence row hold a NULL content, which cannot be
// scanned into Evidence.Content, and restores the constraint afterwards.
func breakEvidenceRow(t *testing.T, s *Store, alertID string) {
	t.Helper()
	ctx := context.Background()
	if _, err := s.pool.Exec(ctx, `ALTER TABLE alert_evidence ALTER COLUMN content DROP NOT NULL`); err != nil {
		t.Fatalf("drop not null: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.pool.Exec(ctx, `DELETE FROM alert_evidence WHERE content IS NULL`)
		_, _ = s.pool.Exec(ctx, `ALTER TABLE alert_evidence ALTER COLUMN content SET NOT NULL`)
	})
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO alert_evidence (alert_id, type, content, collected_at) VALUES ($1, 'logs', NULL, now())`,
		alertID); err != nil {
		t.Fatalf("insert broken evidence: %v", err)
	}
}

// TestGet_UnreadableEvidenceFailsTheRead: Get, GetByPrefix and the dedup path
// of Create used to drop the evidence error and return the incident as if it
// had no (or less) evidence.
func TestGet_UnreadableEvidenceFailsTheRead(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	a := newAlert("evidence-broken-1", "fp-evidence")
	a.Evidence = []Evidence{{Type: "logs", Content: "fine", CollectedAt: time.Now().UTC()}}
	if _, err := s.Create(ctx, a); err != nil {
		t.Fatalf("Create: %v", err)
	}
	breakEvidenceRow(t, s, a.ID)

	if got, err := s.Get(ctx, a.ID); err == nil {
		t.Fatalf("Get: want error, got incident with %d evidence rows", len(got.Evidence))
	}
	if got, err := s.GetByPrefix(ctx, "evidence-broken"); err == nil {
		t.Fatalf("GetByPrefix: want error, got incident with %d evidence rows", len(got.Evidence))
	}
	if got, err := s.Create(ctx, newAlert("evidence-broken-2", "fp-evidence")); err == nil {
		t.Fatalf("Create dedup hit: want error, got incident with %d evidence rows", len(got.Evidence))
	}
}

// TestCreate_EvidenceInsertFailureRollsBack: evidence that Postgres refuses
// (TEXT cannot hold NUL) used to be logged and dropped while the incident was
// stored and reported as created with it.
func TestCreate_EvidenceInsertFailureRollsBack(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	a := newAlert("evidence-nul-1", "")
	a.Evidence = []Evidence{{Type: "logs", Content: "a\x00b", CollectedAt: time.Now().UTC()}}
	if _, err := s.Create(ctx, a); err == nil {
		t.Fatal("Create: want error for evidence Postgres cannot store")
	}
	if _, err := s.Get(ctx, a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed Create must leave no incident behind, Get err = %v", err)
	}
}

func TestUpdate_EvidenceInsertFailureRollsBack(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	a := newAlert("evidence-nul-2", "")
	if _, err := s.Create(ctx, a); err != nil {
		t.Fatalf("Create: %v", err)
	}
	a.Status = StatusFixProposed
	a.Evidence = []Evidence{{Type: "logs", Content: "a\x00b", CollectedAt: time.Now().UTC()}}
	if err := s.Update(ctx, a); err == nil {
		t.Fatal("Update: want error for evidence Postgres cannot store")
	}
	got, err := s.Get(ctx, a.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != StatusOpen {
		t.Fatalf("failed Update must not apply the status change, got %q", got.Status)
	}
}
