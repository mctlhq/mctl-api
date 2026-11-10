package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
)

// configureGlovoControl builds the internal control routes (mctl-api#985).
//
// It is dark by construction. The routes are mounted only when the build gate
// is open (glovo.ControlDefault.Open, a const that is false in every release
// build), MCTL_GLOVO_CONTROL_ENABLED is true, and the control worker's
// server-side tenant bound is configured. Even then no Dispatcher is attached
// here: the orders index, the receipts and the join and execution stores are
// not constructed in this binary yet, so every route answers 503 not_ready.
// A nil result leaves the routes unmounted (404).
func configureGlovoControl(lookup func(string) (string, bool), worker *auth.GlovoControlWorkerConfig) (*api.GlovoControlRoutes, error) {
	v, _ := lookup("MCTL_GLOVO_CONTROL_ENABLED")
	var enabled bool
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "false":
	case "true":
		enabled = true
	default:
		return nil, fmt.Errorf("MCTL_GLOVO_CONTROL_ENABLED %q must be true or false", v)
	}
	if !enabled {
		return nil, nil
	}
	if worker == nil || len(worker.Tenants) == 0 {
		// Without the tenant bound nothing can be served; stay unmounted
		// rather than mount routes that cannot be scoped.
		return nil, nil
	}
	return &api.GlovoControlRoutes{
		Open:    glovo.ControlDefault.Open,
		Enabled: true,
		Tenants: append([]string(nil), worker.Tenants...),
	}, nil
}

// fenceHookReady is write-fence condition 4: the store is ready and its
// revocation hook is bridge.CancelOpenForConnections itself. The synthetic
// no-op hook makes Ready pass, so it cannot satisfy this.
func fenceHookReady(ctx context.Context, s *glovo.Store) bool {
	return s != nil && s.Ready(ctx) == nil && s.RevocationHookIs(bridge.CancelOpenForConnections)
}

// fenceMembershipObserved is write-fence condition 5: a positive signal from
// the membership detector. Until one exists it is false and the fence stays
// refusing (OPEN-985-2).
func fenceMembershipObserved(s *glovo.Store) bool { return s != nil && s.MembershipRevocationWired() }

// glovoFencePreconditions are the six items of the #985 design 7.3. The write
// fence is installed only when every one is true; an item that could not be
// observed is false, never assumed.
type glovoFencePreconditions struct {
	GateOpen             bool // glovo.ControlDefault.Open
	HoldLifted           bool // mctl-gitops#2457, owner decision
	OneDatabaseProof     bool // ProveOneDatabase passed
	RevocationHookReady  bool // #959 Ready() == nil
	MembershipRevocation bool // #959 MembershipRevocationWired()
	ReceiptReady         bool // #989 receipt.Ready() == nil
}

// All reports whether the fence may be installed.
func (p glovoFencePreconditions) All() bool {
	return p.GateOpen && p.HoldLifted && p.OneDatabaseProof &&
		p.RevocationHookReady && p.MembershipRevocation && p.ReceiptReady
}
