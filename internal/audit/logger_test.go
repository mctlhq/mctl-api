package audit

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// A submitted parameter named "code" and the server's refusal code are
// independent: neither overwrites the other, through every in-memory read.
func TestLoggerRefusalCodeIsIndependentOfParameters(t *testing.T) {
	logger := NewLogger()
	logger.Log(Entry{
		UserID: "alice", Operation: "op", Status: "denied", WorkflowName: "wf-1",
		Parameters:  map[string]string{"code": "user-value", "slug": "s"},
		RefusalCode: "validation_failed",
	})
	logger.Log(Entry{UserID: "alice", Operation: "old", Status: "denied", WorkflowName: "wf-2"})

	got := logger.List(10)
	if len(got) != 2 {
		t.Fatalf("entries = %d", len(got))
	}
	if got[0].RefusalCode != "" || got[0].Parameters != nil {
		t.Errorf("row without a refusal code must stay valid and empty: %+v", got[0])
	}
	if got[1].Parameters["code"] != "user-value" || got[1].RefusalCode != "validation_failed" {
		t.Errorf("round trip lost a field: %+v", got[1])
	}
	e, err := logger.LookupByWorkflow(context.Background(), "wf-1")
	if err != nil || e == nil || e.Parameters["code"] != "user-value" || e.RefusalCode != "validation_failed" {
		t.Fatalf("lookup: %+v %v", e, err)
	}

	raw, err := json.Marshal(got[1])
	if err != nil {
		t.Fatal(err)
	}
	var back Entry
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.Parameters["code"] != "user-value" || back.RefusalCode != "validation_failed" {
		t.Errorf("json round trip: %s", raw)
	}
	oldRaw, _ := json.Marshal(got[0])
	if strings.Contains(string(oldRaw), "refusalCode") {
		t.Errorf("empty refusalCode must be omitted: %s", oldRaw)
	}
	// Historical JSON with no refusalCode key decodes cleanly.
	var hist Entry
	if err := json.Unmarshal([]byte(`{"id":"x","operation":"op","parameters":{"code":"c"}}`), &hist); err != nil || hist.RefusalCode != "" || hist.Parameters["code"] != "c" {
		t.Errorf("historical row: %+v %v", hist, err)
	}
}

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
