package temporalclient

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"go.temporal.io/sdk/client"
)

// ErrUnavailable marks a client that is configured but has not yet managed to
// dial the Temporal frontend (mctl-api#764).
var ErrUnavailable = errors.New("temporalclient: configured but currently unreachable")

// Backoff and first-attempt bounds. Variables so tests can shrink them.
var (
	redialInitialDelay = time.Second
	redialMaxDelay     = 30 * time.Second
	firstDialTimeout   = 3 * time.Second
)

type dialFunc func(ctx context.Context) (*Client, error)

// Reconnecting is a DevLoopClient that tolerates a failed startup dial: it
// retries in the background with capped exponential backoff and answers
// ErrUnavailable until a dial succeeds. The inner client is swapped atomically.
type Reconnecting struct {
	current atomic.Pointer[Client]
	lastErr atomic.Pointer[error]
	dial    dialFunc
	cancel  context.CancelFunc
	done    chan struct{}
	once    sync.Once
}

// NewReconnecting dials once (bounded) and, on failure, keeps re-dialing in
// the background until success or ctx cancellation / Close.
func NewReconnecting(ctx context.Context, hostPort, namespace string) *Reconnecting {
	return newReconnectingWithDialer(ctx, func(dctx context.Context) (*Client, error) {
		c, err := client.DialContext(dctx, client.Options{HostPort: hostPort, Namespace: namespace})
		if err != nil {
			return nil, fmt.Errorf("temporalclient: dial %s (namespace %s): %w", hostPort, namespace, err)
		}
		return &Client{temporal: c}, nil
	})
}

func newReconnectingWithDialer(ctx context.Context, dial dialFunc) *Reconnecting {
	ctx, cancel := context.WithCancel(ctx)
	r := &Reconnecting{dial: dial, cancel: cancel, done: make(chan struct{})}
	fctx, fcancel := context.WithTimeout(ctx, firstDialTimeout)
	c, err := dial(fctx)
	fcancel()
	if err == nil {
		r.current.Store(c)
		close(r.done)
		return r
	}
	r.lastErr.Store(&err)
	slog.Warn("temporal client dial failed; retrying in background", "error", err)
	go r.loop(ctx)
	return r
}

func (r *Reconnecting) loop(ctx context.Context) {
	defer close(r.done)
	delay := redialInitialDelay
	attempts := 1
	lastLog := time.Now()
	for {
		wait := delay/2 + rand.N(delay/2+1)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		attempts++
		c, err := r.dial(ctx)
		if err == nil {
			if ctx.Err() != nil {
				c.Close()
				return
			}
			r.current.Store(c)
			slog.Info("temporal client connected after retry", "attempts", attempts)
			return
		}
		r.lastErr.Store(&err)
		if time.Since(lastLog) >= redialMaxDelay {
			slog.Warn("temporal client still unreachable", "attempts", attempts, "error", err)
			lastLog = time.Now()
		}
		delay = min(delay*2, redialMaxDelay)
	}
}

// Available returns nil once a dial has succeeded, else an error matching
// ErrUnavailable that wraps the last dial error.
func (r *Reconnecting) Available() error {
	if r.current.Load() != nil {
		return nil
	}
	return r.unavailable()
}

func (r *Reconnecting) unavailable() error {
	if p := r.lastErr.Load(); p != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, *p)
	}
	return ErrUnavailable
}

// Close cancels a pending re-dial and closes the client if it was dialed.
func (r *Reconnecting) Close() {
	r.once.Do(func() {
		r.cancel()
		<-r.done
		if c := r.current.Load(); c != nil {
			c.Close()
		}
	})
}

func (r *Reconnecting) StartDevLoopWorkflow(ctx context.Context, issueURL string) (string, string, error) {
	c := r.current.Load()
	if c == nil {
		return "", "", r.unavailable()
	}
	return c.StartDevLoopWorkflow(ctx, issueURL)
}

func (r *Reconnecting) RestartAbandonedDevLoopWorkflow(ctx context.Context, issueURL string) (string, string, error) {
	c := r.current.Load()
	if c == nil {
		return "", "", r.unavailable()
	}
	return c.RestartAbandonedDevLoopWorkflow(ctx, issueURL)
}

func (r *Reconnecting) DevLoopEnded(ctx context.Context, workflowID, runID string) (DevLoopRunEnd, error) {
	c := r.current.Load()
	if c == nil {
		return DevLoopRunEnd{}, r.unavailable()
	}
	return c.DevLoopEnded(ctx, workflowID, runID)
}

func (r *Reconnecting) SignalApprove(ctx context.Context, workflowID string, payload map[string]string) error {
	c := r.current.Load()
	if c == nil {
		return r.unavailable()
	}
	return c.SignalApprove(ctx, workflowID, payload)
}

func (r *Reconnecting) SignalAbandon(ctx context.Context, workflowID, runID string, payload map[string]string) error {
	c := r.current.Load()
	if c == nil {
		return r.unavailable()
	}
	return c.SignalAbandon(ctx, workflowID, runID, payload)
}

func (r *Reconnecting) DescribeDevLoop(ctx context.Context, workflowID string) (string, error) {
	c := r.current.Load()
	if c == nil {
		return "", r.unavailable()
	}
	return c.DescribeDevLoop(ctx, workflowID)
}

func (r *Reconnecting) DescribeDevLoopExecution(ctx context.Context, workflowID string) (*DevLoopExecution, error) {
	c := r.current.Load()
	if c == nil {
		return nil, r.unavailable()
	}
	return c.DescribeDevLoopExecution(ctx, workflowID)
}

func (r *Reconnecting) QueryShepherdInLoop(ctx context.Context, workflowID string) (bool, error) {
	c := r.current.Load()
	if c == nil {
		return false, r.unavailable()
	}
	return c.QueryShepherdInLoop(ctx, workflowID)
}

func (r *Reconnecting) QueryHumanInputState(ctx context.Context, workflowID, runID string) (*HumanInputState, error) {
	c := r.current.Load()
	if c == nil {
		return nil, r.unavailable()
	}
	return c.QueryHumanInputState(ctx, workflowID, runID)
}

func (r *Reconnecting) SignalHumanInputResponse(ctx context.Context, workflowID, runID string, response map[string]any) error {
	c := r.current.Load()
	if c == nil {
		return r.unavailable()
	}
	return c.SignalHumanInputResponse(ctx, workflowID, runID, response)
}
