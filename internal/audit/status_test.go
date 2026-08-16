package audit

import (
	"testing"
	"time"
)

func TestLoggerUpdateStatus(t *testing.T) {
	l := NewLogger()
	l.Log(Entry{Operation: "deploy-service", WorkflowName: "wf-1", Status: "submitted"})

	if !l.UpdateStatus("wf-1", "succeeded", "") {
		t.Fatal("UpdateStatus returned false for a matching non-terminal row")
	}
	if got := l.GetByWorkflow("wf-1"); got.Status != "succeeded" {
		t.Errorf("status = %q, want %q", got.Status, "succeeded")
	}
}

// A terminal row must not be reopened — this is what makes webhook redelivery,
// and a webhook racing the reconciler, safe without any coordination.
func TestLoggerUpdateStatusIgnoresTerminalRows(t *testing.T) {
	l := NewLogger()
	l.Log(Entry{Operation: "deploy-service", WorkflowName: "wf-2", Status: "submitted"})
	l.UpdateStatus("wf-2", "succeeded", "")

	if l.UpdateStatus("wf-2", "failed", "late delivery") {
		t.Error("UpdateStatus overwrote a terminal status")
	}
	if got := l.GetByWorkflow("wf-2"); got.Status != "succeeded" {
		t.Errorf("status = %q, want it to stay %q", got.Status, "succeeded")
	}
}

func TestLoggerUpdateStatusNoMatch(t *testing.T) {
	l := NewLogger()
	if l.UpdateStatus("nonexistent", "succeeded", "") {
		t.Error("UpdateStatus reported a match for an unknown workflow")
	}
	if l.UpdateStatus("", "succeeded", "") {
		t.Error("UpdateStatus matched on an empty workflow name")
	}
}

// An empty message must leave the existing one intact, so a success event does
// not erase detail recorded at submission time.
func TestLoggerUpdateStatusKeepsMessageWhenEmpty(t *testing.T) {
	l := NewLogger()
	l.Log(Entry{WorkflowName: "wf-3", Status: "submitted", Message: "submitted by hand"})

	l.UpdateStatus("wf-3", "succeeded", "")
	if got := l.GetByWorkflow("wf-3"); got.Message != "submitted by hand" {
		t.Errorf("message = %q, want it preserved", got.Message)
	}

	l2 := NewLogger()
	l2.Log(Entry{WorkflowName: "wf-4", Status: "submitted", Message: "original"})
	l2.UpdateStatus("wf-4", "failed", "argo workflow phase Failed")
	if got := l2.GetByWorkflow("wf-4"); got.Message != "argo workflow phase Failed" {
		t.Errorf("message = %q, want it replaced", got.Message)
	}
}

func TestLoggerListByStatus(t *testing.T) {
	l := NewLogger()
	l.Log(Entry{WorkflowName: "wf-open", Status: "submitted"})
	l.Log(Entry{WorkflowName: "wf-done", Status: "succeeded"})

	got := l.ListByStatus("submitted", time.Hour, 10, time.Time{})
	if len(got) != 1 || got[0].WorkflowName != "wf-open" {
		t.Fatalf("ListByStatus = %+v, want just wf-open", got)
	}

	if n := len(l.ListByStatus("submitted", time.Nanosecond, 10, time.Time{})); n != 0 {
		t.Errorf("maxAge ignored: got %d entries, want 0", n)
	}
	if n := len(l.ListByStatus("submitted", time.Hour, 0, time.Time{})); n != 0 {
		t.Errorf("limit ignored: got %d entries, want 0", n)
	}
}

func TestIsTerminal(t *testing.T) {
	for _, s := range TerminalStatuses {
		if !IsTerminal(s) {
			t.Errorf("IsTerminal(%q) = false", s)
		}
	}
	for _, s := range []string{"submitted", "unknown", "denied", ""} {
		if IsTerminal(s) {
			t.Errorf("IsTerminal(%q) = true", s)
		}
	}
}

// The cursor is what lets the reconciler page past rows it cannot resolve yet.
func TestLoggerListByStatusCursor(t *testing.T) {
	l := NewLogger()
	base := time.Now().UTC().Add(-time.Hour)
	for i, name := range []string{"wf-a", "wf-b", "wf-c"} {
		l.Log(Entry{WorkflowName: name, Status: "submitted", Timestamp: base.Add(time.Duration(i) * time.Minute)})
	}

	first := l.ListByStatus("submitted", 2*time.Hour, 1, time.Time{})
	if len(first) != 1 || first[0].WorkflowName != "wf-a" {
		t.Fatalf("first page = %+v, want wf-a", first)
	}

	second := l.ListByStatus("submitted", 2*time.Hour, 1, first[0].Timestamp)
	if len(second) != 1 || second[0].WorkflowName != "wf-b" {
		t.Fatalf("second page = %+v, want wf-b — the cursor did not advance", second)
	}

	last := l.ListByStatus("submitted", 2*time.Hour, 10, second[0].Timestamp)
	if len(last) != 1 || last[0].WorkflowName != "wf-c" {
		t.Fatalf("third page = %+v, want just wf-c", last)
	}
}
