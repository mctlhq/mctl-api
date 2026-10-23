package temporalclient

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"go.temporal.io/sdk/mocks"
)

func TestReconnectingRecoversAfterFailedDial(t *testing.T) {
	redialInitialDelay, redialMaxDelay = time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() { redialInitialDelay, redialMaxDelay = time.Second, 30*time.Second })

	var calls atomic.Int32
	dial := func(ctx context.Context) (*Client, error) {
		if calls.Add(1) <= 3 {
			return nil, errors.New("connection refused")
		}
		m := &mocks.Client{}
		m.On("Close").Return()
		return &Client{temporal: m}, nil
	}
	r := newReconnectingWithDialer(context.Background(), dial)
	t.Cleanup(r.Close)

	if err := r.Available(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable before success, got %v", err)
	}
	if _, err := r.DescribeDevLoop(context.Background(), "wf"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable from delegated call, got %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for r.Available() != nil {
		if time.Now().After(deadline) {
			t.Fatal("client never became available")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestReconnectingCloseStopsLoop(t *testing.T) {
	redialInitialDelay, redialMaxDelay = time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() { redialInitialDelay, redialMaxDelay = time.Second, 30*time.Second })
	r := newReconnectingWithDialer(context.Background(), func(context.Context) (*Client, error) {
		return nil, errors.New("down")
	})
	done := make(chan struct{})
	go func() { r.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not stop the re-dial loop")
	}
}
