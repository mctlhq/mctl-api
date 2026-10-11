package main

import (
	"context"
	"errors"
	"testing"
)

type ctxCheckingReader struct {
	data map[string]string
	err  error
	// sawLiveCtx records that the context handed to ReadKV was neither
	// cancelled nor missing a deadline.
	sawLiveCtx bool
}

func (r *ctxCheckingReader) ReadKV(ctx context.Context, _ string) (map[string]string, error) {
	_, hasDeadline := ctx.Deadline()
	r.sawLiveCtx = ctx.Err() == nil && hasDeadline
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return r.data, r.err
}

func TestNewErpactDeployer_ReadsTokenWithALiveBoundedContext(t *testing.T) {
	r := &ctxCheckingReader{data: map[string]string{"DEPLOYER_API_TOKEN": "tok"}}
	if newErpactDeployer(r, "http://x") == nil {
		t.Fatal("deployer is nil, want a client")
	}
	if !r.sawLiveCtx {
		t.Fatal("ReadKV got a cancelled or unbounded context")
	}
}

func TestNewErpactDeployer_OffWhenTokenUnavailable(t *testing.T) {
	cases := map[string]*ctxCheckingReader{
		"read error":  {err: errors.New("denied")},
		"empty token": {data: map[string]string{"DEPLOYER_API_TOKEN": ""}},
		"no property": {data: map[string]string{"OTHER": "x"}},
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			if newErpactDeployer(r, "http://x") != nil {
				t.Fatal("deployer is set, want nil (feature off)")
			}
		})
	}
	if newErpactDeployer(nil, "http://x") != nil {
		t.Fatal("nil reader must leave the feature off")
	}
}
