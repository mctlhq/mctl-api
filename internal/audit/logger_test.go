package audit

import "testing"

func TestLoggerAssignsIDWhenMissing(t *testing.T) {
	logger := NewLogger()

	logger.Log(Entry{
		UserID:       "alice",
		Operation:    "deploy-service",
		WorkflowName: "deploy-service-abc123",
		Status:       "submitted",
	})
	logger.Log(Entry{
		UserID:       "alice",
		Operation:    "retire-service",
		WorkflowName: "retire-service-def456",
		Status:       "submitted",
	})

	entries := logger.List(10)
	if len(entries) != 2 {
		t.Fatalf("expected 2 audit entries, got %d", len(entries))
	}
	if entries[0].ID == "" || entries[1].ID == "" {
		t.Fatalf("expected logger to assign IDs, got entries %#v", entries)
	}
	if entries[0].ID == entries[1].ID {
		t.Fatalf("expected unique IDs, got duplicate %q", entries[0].ID)
	}
}
