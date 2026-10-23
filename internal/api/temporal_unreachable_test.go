package api

import (
	"testing"

	"github.com/mctlhq/mctl-api/internal/temporalclient"
)

var _ DevLoopClient = (*temporalclient.Reconnecting)(nil)
var _ TemporalAvailability = (*temporalclient.Reconnecting)(nil)

type unreachableClient struct{ DevLoopClient }

func (unreachableClient) Available() error { return temporalclient.ErrUnavailable }

func TestTemporalStateDistinguishesNotConfiguredFromUnreachable(t *testing.T) {
	h := &Handlers{opts: Options{}}
	if got := h.temporalState(); got != msgTemporalNotConfigured {
		t.Fatalf("nil client: got %q", got)
	}
	h.opts.TemporalClient = unreachableClient{}
	if got := h.temporalState(); got != msgTemporalUnreachable {
		t.Fatalf("unreachable client: got %q", got)
	}
	h.opts.TemporalClient = &fakeDevLoopForState{}
	if got := h.temporalState(); got != "" {
		t.Fatalf("plain client: got %q", got)
	}
}

type fakeDevLoopForState struct{ DevLoopClient }
