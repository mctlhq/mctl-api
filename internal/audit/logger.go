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

package audit

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Entry represents a single audit log entry.
type Entry struct {
	ID           string            `json:"id"`
	Timestamp    time.Time         `json:"timestamp"`
	UserID       string            `json:"userId"`
	Operation    string            `json:"operation"`
	Parameters   map[string]string `json:"parameters"`
	WorkflowName string            `json:"workflowName,omitempty"`
	// Status is "submitted" on insert and is closed out later by the Argo
	// completion webhook or the reconciler: succeeded, failed, error, or
	// expired when the workflow object was garbage-collected before either
	// could observe its outcome.
	Status    string `json:"status"`
	RiskLevel string `json:"riskLevel"`
	Message   string `json:"message,omitempty"`
	ClientIP  string `json:"clientIp,omitempty"`
	UserAgent string `json:"userAgent,omitempty"`
	RequestID string `json:"requestId,omitempty"`
	// PrincipalID is UserID's canonical principal id (prn_…) and
	// ViaPrincipalID the relaying surface's, when a surface relayed the
	// request (mctl-api#373). Phase 1 records them in the database only; they
	// are not served and nothing authorizes on them.
	PrincipalID    string `json:"-"`
	ViaPrincipalID string `json:"-"`
	// ViaExecutionID is the WorkItemExecution (we_...) an agent run token is
	// bound to (mctl-api#376), recorded next to ViaPrincipalID on a request
	// an agent principal made. "" for every non-agent request. A support
	// row is found by it (ListSupport).
	ViaExecutionID string `json:"-"`
	// Tenant is the tenant a support-scope request was bound to, recorded on
	// support rows only (mctl-api#813).
	Tenant string `json:"tenant,omitempty"`
	// ParametersUnreadable is set when the stored params could not be
	// decoded; Parameters is then nil. It is a marker rather than a read
	// error so the otherwise-good row stays visible to List and ListByStatus.
	// Every caller that authorizes or routes on Parameters (the tenant, the
	// namespace, a traceparent) must refuse explicitly instead of reading nil
	// as "submitted without parameters" (mctl-api#586).
	ParametersUnreadable bool `json:"-"`
}

// OperationSupportRequest is the operation of the one row written for every
// request made with a support-scope run token (mctl-api#813).
const OperationSupportRequest = "support.request"

// OperationSupportTokenMint is the operation of the row written for every
// support-audience token minted for the MCP support tools (mctl-api#852).
const OperationSupportTokenMint = "support.token_mint"

// OperationAgentScopeDenied is the operation of a scope refusal row.
const OperationAgentScopeDenied = "agent_scope.denied"

// SupportFilter selects support rows. At least one of Tenant and
// ExecutionID is expected; Limit is applied as given (the caller bounds it).
type SupportFilter struct {
	Tenant, ExecutionID string
	Limit               int
	Before              time.Time
}

// SupportReader is implemented by logs that can list support rows: the
// support.request rows and the support-scope agent_scope.denied rows.
type SupportReader interface {
	ListSupport(ctx context.Context, f SupportFilter) ([]Entry, error)
}

// Log is the interface for recording and querying audit events.
type Log interface {
	Log(entry Entry)
	List(limit int) []Entry
	// LookupByWorkflow returns the newest entry for the workflow. It tells
	// "no such record" ((nil, nil)) from "could not look" ((nil, err)); a
	// caller must never treat the second as the first (mctl-api#586).
	LookupByWorkflow(ctx context.Context, name string) (*Entry, error)
	// UpdateStatus moves an entry out of a non-terminal status. It is a no-op
	// (returning false) when no row matches or the row is already terminal,
	// which is what makes a redelivered webhook safe.
	UpdateStatus(workflowName, status, message string) bool
	// ListByStatus returns entries in the given status, OLDEST first, limited to
	// those newer than maxAge and strictly newer than after (a cursor; pass the
	// zero time to start from the beginning).
	//
	// Oldest-first because this is a work queue, not a feed: newest-first would
	// let a backlog larger than the caller's limit starve the oldest rows, which
	// are the ones most likely to be stuck. The cursor is what stops that fix
	// from creating the opposite problem — rows that cannot yet be resolved stay
	// oldest forever, so without paging past them they would fill every batch
	// and no newer row would ever be examined.
	//
	// A failed query or iteration returns an error, never a shorter or empty
	// page: a short page is what ends a reconcile pass. A single row that
	// fails to scan is still skipped and logged, so it can shorten a page;
	// with params decode failures now marked (ParametersUnreadable) instead
	// of failing the scan, nothing known reaches that path.
	ListByStatus(status string, maxAge time.Duration, limit int, after time.Time) ([]Entry, error)
}

// TerminalStatuses are the audit statuses that will never change again.
var TerminalStatuses = []string{"succeeded", "failed", "error", "expired"}

// IsTerminal reports whether an audit status is final.
func IsTerminal(status string) bool {
	for _, s := range TerminalStatuses {
		if s == status {
			return true
		}
	}
	return false
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

	if entry.ID == "" {
		entry.ID = uuid.NewString()
	}
	// A caller-supplied timestamp is honoured. Everything in production leaves
	// it zero and gets "now"; tests that exercise age-dependent behaviour
	// (reconcile lookback, GC grace) set it rather than reaching into internals.
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
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

	// Return in reverse order (most recent first). Support rows have their
	// own read, so high-volume reads cannot push operations out of the feed.
	result := make([]Entry, 0, len(l.entries))
	for i := len(l.entries) - 1; i >= 0; i-- {
		if l.entries[i].Operation == OperationSupportRequest {
			continue
		}
		if limit > 0 && len(result) >= limit {
			break
		}
		result = append(result, l.entries[i])
	}
	return result
}

// ListSupport returns support rows, newest first.
func (l *Logger) ListSupport(_ context.Context, f SupportFilter) ([]Entry, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var out []Entry
	for i := len(l.entries) - 1; i >= 0; i-- {
		e := l.entries[i]
		if !isSupportRow(e) {
			continue
		}
		if f.Tenant != "" && e.Tenant != f.Tenant {
			continue
		}
		if f.ExecutionID != "" && e.ViaExecutionID != f.ExecutionID {
			continue
		}
		if !f.Before.IsZero() && !e.Timestamp.Before(f.Before) {
			continue
		}
		if f.Limit > 0 && len(out) >= f.Limit {
			break
		}
		out = append(out, e)
	}
	return out, nil
}

func isSupportRow(e Entry) bool {
	return e.Operation == OperationSupportRequest ||
		(e.Operation == OperationAgentScopeDenied && e.Tenant != "")
}

// LookupByWorkflow returns the newest entry for workflowName, or (nil, nil)
// if none. The in-memory store cannot fail.
func (l *Logger) LookupByWorkflow(_ context.Context, workflowName string) (*Entry, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	for i := len(l.entries) - 1; i >= 0; i-- {
		if l.entries[i].WorkflowName == workflowName {
			e := l.entries[i]
			return &e, nil
		}
	}
	return nil, nil
}

// UpdateStatus closes out the newest non-terminal entry for workflowName.
func (l *Logger) UpdateStatus(workflowName, status, message string) bool {
	if workflowName == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := len(l.entries) - 1; i >= 0; i-- {
		e := &l.entries[i]
		if e.WorkflowName != workflowName || IsTerminal(e.Status) {
			continue
		}
		e.Status = status
		if message != "" {
			e.Message = message
		}
		return true
	}
	return false
}

// ListByStatus returns entries in the given status, oldest first.
func (l *Logger) ListByStatus(status string, maxAge time.Duration, limit int, after time.Time) ([]Entry, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	cutoff := time.Now().UTC().Add(-maxAge)
	out := make([]Entry, 0, limit)
	for i := 0; i < len(l.entries) && len(out) < limit; i++ {
		e := l.entries[i]
		if e.Status != status || e.Timestamp.Before(cutoff) {
			continue
		}
		// Strict comparison. If a page boundary lands mid-tie — several rows
		// sharing the cursor's exact timestamp — the tied remainder is skipped
		// for the rest of this pass, because they are not strictly greater.
		// Accepted: nothing is lost, the next reconcileOnce restarts the cursor
		// at the zero time and re-lists from the beginning, so the cost is one
		// 3-minute cycle. A (timestamp, id) compound cursor would remove even
		// that, at the price of threading a second cursor field through the
		// interface for a delay nobody can observe.
		if !after.IsZero() && !e.Timestamp.After(after) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}
