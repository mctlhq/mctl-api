package deployplan

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func newStoreForTest(t *testing.T) *Store {
	t.Helper()
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed deploy-plan store test")
	}
	ctx := context.Background()
	s, err := NewStore(ctx, connStr)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	wipe := func() {
		if _, err := s.pool.Exec(ctx, "DELETE FROM deploy_plans WHERE tenant = 'storetest'"); err != nil {
			t.Fatal(err)
		}
	}
	wipe()
	t.Cleanup(func() { wipe(); s.Close() })
	return s
}

func testPlan(digestSeed string) *Plan {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return &Plan{
		Digest: "sha256:" + strings.Repeat(digestSeed, 64), SchemaVersion: SchemaVersion,
		Tenant: "storetest", Service: "web", Environment: EnvironmentPreview,
		Intent: []byte(`{"a":1}`), IntentCanonical: `{"a":1}`, Revision: testRev, GitopsBaseSHA: strings.Repeat("b", 40),
		Action: ActionUpdate, PreviewID: "abc123", ValuesBeforeSHA256: strings.Repeat("e", 64),
		ValuesAfter: "x: 1\n", Diff: "", Host: "web-abc123.mctl.ai", RequiresApproval: true, RequiredRole: "owner",
		ApprovalReason: "r", CreatedBy: "principal:1", Surface: "rest", CreatedAt: now, ExpiresAt: now.Add(30 * time.Minute),
	}
}

// T9: insert then get; the id prefix; no UPDATE; the 24 h CHECK; lazy expiry.
func TestStore_InsertGetImmutable(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()

	p := testPlan("a")
	stored, replayed, err := s.Insert(ctx, p)
	if err != nil || replayed {
		t.Fatalf("Insert: replayed=%v err=%v", replayed, err)
	}
	if !strings.HasPrefix(stored.ID, "dpl_") {
		t.Errorf("id = %q", stored.ID)
	}
	got, err := s.Get(ctx, stored.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Digest != p.Digest || got.IntentCanonical != p.IntentCanonical || got.Action != ActionUpdate || !got.ExpiresAt.Equal(p.ExpiresAt) {
		t.Errorf("round trip lost data: %+v", got)
	}
	if _, err := s.Get(ctx, "dpl_missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get missing = %v", err)
	}

	// The trigger rejects any UPDATE.
	_, err = s.pool.Exec(ctx, "UPDATE deploy_plans SET host = 'x' WHERE id = $1", stored.ID)
	if err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Errorf("UPDATE err = %v, want the immutability trigger", err)
	}

	// The CHECK bounds the lifetime to 24 h.
	long := testPlan("b")
	long.ExpiresAt = long.CreatedAt.Add(25 * time.Hour)
	if _, _, err := s.Insert(ctx, long); err == nil {
		t.Error("expires_at beyond 24 h must fail the CHECK")
	}
	edge := testPlan("c")
	edge.ExpiresAt = edge.CreatedAt.Add(24 * time.Hour)
	if _, _, err := s.Insert(ctx, edge); err != nil {
		t.Errorf("exactly 24 h must pass: %v", err)
	}

	// expired is derived on read; the row is untouched.
	if got.Expired(got.ExpiresAt.Add(-time.Second)) || !got.Expired(got.ExpiresAt.Add(time.Second)) {
		t.Error("lazy expiry")
	}
	again, _ := s.Get(ctx, stored.ID)
	if !again.ExpiresAt.Equal(got.ExpiresAt) {
		t.Error("reading changed the row")
	}
}

func TestStore_Idempotency(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()

	p := testPlan("a")
	p.IdempotencyKey = "key-1"
	first, replayed, err := s.Insert(ctx, p)
	if err != nil || replayed {
		t.Fatalf("first: %v %v", replayed, err)
	}

	same := testPlan("a")
	same.IdempotencyKey = "key-1"
	got, replayed, err := s.Insert(ctx, same)
	if err != nil || !replayed || got.ID != first.ID {
		t.Fatalf("replay: id=%v replayed=%v err=%v", got, replayed, err)
	}

	other := testPlan("d")
	other.IdempotencyKey = "key-1"
	_, _, err = s.Insert(ctx, other)
	var conflict *IdempotencyConflictError
	if !errors.As(err, &conflict) || conflict.PlanID != first.ID || !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflict err = %v", err)
	}

	// Another caller may use the same key, and no key never collides.
	diffCaller := testPlan("a")
	diffCaller.IdempotencyKey, diffCaller.CreatedBy = "key-1", "principal:2"
	if _, replayed, err := s.Insert(ctx, diffCaller); err != nil || replayed {
		t.Fatalf("other caller: %v %v", replayed, err)
	}
	for i := 0; i < 2; i++ {
		if _, replayed, err := s.Insert(ctx, testPlan("a")); err != nil || replayed {
			t.Fatalf("unkeyed %d: %v %v", i, replayed, err)
		}
	}
}
