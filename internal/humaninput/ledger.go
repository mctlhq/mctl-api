package humaninput

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// Delivery states. The ledger records what mctl-api did with a response; it
// is NOT the request's state machine, which only the owning workflow holds.
//
//   - pending_delivery: accepted for delivery, not yet confirmed by the
//     workflow. The response value is retained so any later call can
//     redeliver it: a Temporal outage must never leave an answer recorded
//     but lost.
//   - accepted: the workflow resumed on this response. Terminal.
//   - rejected: the workflow refused it, or the request stopped waiting
//     before it landed. Terminal for this response, but it frees the slot:
//     another submission may claim the request again.
const (
	DeliveryPending  = "pending_delivery"
	DeliveryAccepted = "accepted"
	DeliveryRejected = "rejected"
)

// ErrDeliveryNotPending is returned by Resolve when the row is not the
// pending delivery the caller named (another submission or call resolved or
// replaced it first).
var ErrDeliveryNotPending = errors.New("human-input ledger: delivery is not pending")

// Delivery is one response mctl-api took responsibility for delivering.
// There is at most one row per request_id.
type Delivery struct {
	RequestID   string
	RequestHash string
	WorkflowID  string
	RunID       string
	Respondent  string // actor_type:actor_id, derived from authentication
	Surface     string
	ValueHash   string
	// Value is the JSON of the answer. It is kept only while the delivery
	// is pending and cleared once it is resolved, so the ledger does not
	// become a second store of human answers.
	Value      json.RawMessage
	ReceivedAt time.Time
	// ExpiresAt is the request's expires_at. Past it nothing can be
	// delivered any more, so ClearExpiredValues drops a still-pending value.
	ExpiresAt time.Time
	State     string
	// BaselineResumeCount is the workflow's resume_count just before the
	// first delivery. Only an accepted response increments it, so a later
	// value above the baseline proves the request was answered.
	BaselineResumeCount int
	Attempts            int
	UpdatedAt           time.Time
}

// SameSubmission reports whether d and o are the same answer from the same
// respondent: a duplicate delivery, not a competing response.
func (d Delivery) SameSubmission(o Delivery) bool {
	return d.Respondent == o.Respondent && d.ValueHash == o.ValueHash && d.RequestHash == o.RequestHash
}

// Ledger is the idempotency and delivery record for human-input responses.
type Ledger interface {
	// Get returns the delivery for requestID, or nil when there is none.
	Get(ctx context.Context, requestID string) (*Delivery, error)
	// Claim records d as pending_delivery when no row exists for its
	// request, or when the existing row was rejected. It returns the row
	// that is current afterwards and whether d is it. A pending or accepted
	// row is never replaced.
	Claim(ctx context.Context, d Delivery) (*Delivery, bool, error)
	// NoteAttempt counts one delivery attempt of a pending row.
	NoteAttempt(ctx context.Context, requestID string) error
	// Resolve moves the pending row that is exactly d's submission to state
	// (accepted or rejected) and clears its value.
	Resolve(ctx context.Context, d Delivery, state string) error
	// ClearExpiredValues drops the retained answer of every pending row
	// whose request expired at or before now. The row and its state stay:
	// whether the workflow took the answer before expiry is unknown, so it
	// is neither accepted nor rejected, only no longer deliverable.
	ClearExpiredValues(ctx context.Context, now time.Time) (int, error)
}

// MemoryLedger is an in-process Ledger. It is only correct with a single
// mctl-api replica, so the server wires the Postgres ledger and never this
// one; it exists for tests.
type MemoryLedger struct {
	mu   sync.Mutex
	rows map[string]Delivery
	now  func() time.Time
}

// NewMemoryLedger returns an empty in-process ledger.
func NewMemoryLedger() *MemoryLedger {
	return &MemoryLedger{rows: map[string]Delivery{}, now: time.Now}
}

func (m *MemoryLedger) Get(_ context.Context, requestID string) (*Delivery, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.rows[requestID]
	if !ok {
		return nil, nil
	}
	return &d, nil
}

func (m *MemoryLedger) Claim(_ context.Context, d Delivery) (*Delivery, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cur, ok := m.rows[d.RequestID]; ok && cur.State != DeliveryRejected {
		return &cur, false, nil
	}
	d.State = DeliveryPending
	d.Attempts = 0
	d.UpdatedAt = m.now().UTC()
	m.rows[d.RequestID] = d
	return &d, true, nil
}

func (m *MemoryLedger) NoteAttempt(_ context.Context, requestID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.rows[requestID]
	if !ok || d.State != DeliveryPending {
		return ErrDeliveryNotPending
	}
	d.Attempts++
	d.UpdatedAt = m.now().UTC()
	m.rows[requestID] = d
	return nil
}

func (m *MemoryLedger) ClearExpiredValues(_ context.Context, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for k, d := range m.rows {
		if d.State == DeliveryPending && d.Value != nil && !now.Before(d.ExpiresAt) {
			d.Value = nil
			m.rows[k] = d
			n++
		}
	}
	return n, nil
}

func (m *MemoryLedger) Resolve(_ context.Context, d Delivery, state string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.rows[d.RequestID]
	if !ok || cur.State != DeliveryPending || !cur.SameSubmission(d) {
		return ErrDeliveryNotPending
	}
	cur.State = state
	cur.Value = nil
	cur.UpdatedAt = m.now().UTC()
	m.rows[d.RequestID] = cur
	return nil
}
