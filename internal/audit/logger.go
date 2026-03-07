package audit

import (
	"log/slog"
	"sync"
	"time"
)

// Entry represents a single audit log entry.
type Entry struct {
	ID           string            `json:"id"`
	Timestamp    time.Time         `json:"timestamp"`
	UserID       string            `json:"userId"`
	Operation    string            `json:"operation"`
	Parameters   map[string]string `json:"parameters"`
	WorkflowName string            `json:"workflowName,omitempty"`
	Status       string            `json:"status"` // submitted, succeeded, failed
	RiskLevel    string            `json:"riskLevel"`
	Message      string            `json:"message,omitempty"`
}

// Log is the interface for recording and querying audit events.
type Log interface {
	Log(entry Entry)
	List(limit int) []Entry
	GetByWorkflow(name string) *Entry
}

// Logger stores audit entries. In production, this writes to PostgreSQL.
// For the PoC, it uses an in-memory store.
type Logger struct {
	mu      sync.RWMutex
	entries []Entry
}

// NewLogger creates a new audit logger.
func NewLogger() *Logger {
	return &Logger{
		entries: make([]Entry, 0, 1000),
	}
}

// Log records an audit entry.
func (l *Logger) Log(entry Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry.Timestamp = time.Now().UTC()
	l.entries = append(l.entries, entry)

	slog.Info("audit",
		"user", entry.UserID,
		"operation", entry.Operation,
		"workflow", entry.WorkflowName,
		"status", entry.Status,
		"riskLevel", entry.RiskLevel,
	)
}

// List returns recent audit entries, most recent first.
func (l *Logger) List(limit int) []Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if limit <= 0 || limit > len(l.entries) {
		limit = len(l.entries)
	}

	// Return in reverse order (most recent first).
	result := make([]Entry, limit)
	for i := 0; i < limit; i++ {
		result[i] = l.entries[len(l.entries)-1-i]
	}
	return result
}

// GetByWorkflow returns the audit entry for a specific workflow.
func (l *Logger) GetByWorkflow(workflowName string) *Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	for i := len(l.entries) - 1; i >= 0; i-- {
		if l.entries[i].WorkflowName == workflowName {
			e := l.entries[i]
			return &e
		}
	}
	return nil
}
