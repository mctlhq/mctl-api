package workitems

import (
	"fmt"
	"strings"
)

// QueueWhileActiveEnv is the kill switch for queueing an execution request
// while the work item has an open execution. Off (empty or "off") keeps the
// create refusal 409 execution_active.
const QueueWhileActiveEnv = "MCTL_EXECUTION_REQUEST_QUEUE_WHILE_ACTIVE"

// ParseQueueWhileActive reads the switch value: "" and "off" are off, "on"
// is on, anything else is an error so a typo cannot silently pick a mode.
func ParseQueueWhileActive(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "off":
		return false, nil
	case "on":
		return true, nil
	}
	return false, fmt.Errorf("%s must be \"on\" or \"off\", got %q", QueueWhileActiveEnv, raw)
}

// WithQueueWhileActive turns on queueing of requests behind an open
// execution, the claim guard and (in the API) the orphan reconciler.
func WithQueueWhileActive(on bool) StoreOption {
	return func(s *Store) { s.queueWhileActive = on }
}

// QueueWhileActive reports whether the switch is on.
func (s *Store) QueueWhileActive() bool { return s.queueWhileActive }
