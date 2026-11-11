package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/control"
	"github.com/mctlhq/mctl-api/internal/pgshared"
)

// Not-ready reasons of the bridge startup mode decision (mctl-api#985 design 4).
const (
	notReadyBridgeProbe       = "bridge_mode_probe_failed"
	notReadyBridgeNoGlovoPool = "bridge_schema_migrated_glovo_db_url_unset"
)

// bridgeOpenDeps is how the command bridge store is opened. The mode is decided
// once at startup by to_regclass('public.bridge_schema_version'), read on the
// GLOVO_DB_URL pool when there is one and on the legacy bridge DSN otherwise:
//
//   - migrated, with the Glovo pool: bridge.NewRuntimeStore on that pool;
//   - migrated, without it: not_ready, never the legacy store (the legacy role no
//     longer owns the tables and NewStore would run DDL on them);
//   - not migrated: the legacy bridge.NewStore, unchanged;
//   - a probe that fails: not_ready, never a fallback to the legacy store.
type bridgeOpenDeps struct {
	GlovoPool *pgxpool.Pool // nil when the Glovo store is not configured
	LegacyDSN string

	// The functions are the seams of the tests; production uses the defaults.
	ProbePool func(ctx context.Context, p *pgxpool.Pool) (bool, error)
	ProbeDSN  func(ctx context.Context, dsn string) (bool, error)
	Legacy    func(ctx context.Context, dsn string) (*bridge.Store, error)
	Runtime   func(ctx context.Context, p *pgxpool.Pool) (*bridge.Store, error)
}

func (d bridgeOpenDeps) withDefaults() bridgeOpenDeps {
	if d.ProbePool == nil {
		d.ProbePool = func(ctx context.Context, p *pgxpool.Pool) (bool, error) { return bridge.SchemaMigrated(ctx, p) }
	}
	if d.ProbeDSN == nil {
		d.ProbeDSN = func(ctx context.Context, dsn string) (bool, error) {
			p, err := pgshared.Open(ctx, dsn)
			if err != nil {
				return false, err
			}
			defer pgshared.Release(p)
			return bridge.SchemaMigrated(ctx, p)
		}
	}
	if d.Legacy == nil {
		d.Legacy = bridge.NewStore
	}
	if d.Runtime == nil {
		d.Runtime = bridge.NewRuntimeStore
	}
	return d
}

func bridgeNotReady(reason string, cause error) error {
	return &glovo.NotReadyError{Reason: reason, Cause: cause}
}

// openBridgeStore opens the command bridge store in the mode the database is in.
// runtime reports whether it is the runtime-role store on the shared pool.
func openBridgeStore(ctx context.Context, d bridgeOpenDeps) (store *bridge.Store, runtime bool, err error) {
	d = d.withDefaults()
	if d.GlovoPool != nil {
		migrated, perr := d.ProbePool(ctx, d.GlovoPool)
		if perr != nil {
			return nil, false, bridgeNotReady(notReadyBridgeProbe, perr)
		}
		if migrated {
			s, rerr := d.Runtime(ctx, d.GlovoPool)
			return s, true, rerr
		}
	} else {
		if strings.TrimSpace(d.LegacyDSN) == "" {
			return nil, false, errors.New("the command bridge needs COMMERCE_DB_URL (or GLOVO_DB_URL once the schema is migrated)")
		}
		migrated, perr := d.ProbeDSN(ctx, d.LegacyDSN)
		if perr != nil {
			return nil, false, bridgeNotReady(notReadyBridgeProbe, perr)
		}
		if migrated {
			return nil, false, bridgeNotReady(notReadyBridgeNoGlovoPool, nil)
		}
	}
	if strings.TrimSpace(d.LegacyDSN) == "" {
		return nil, false, errors.New("the command bridge needs COMMERCE_DB_URL")
	}
	s, lerr := d.Legacy(ctx, d.LegacyDSN)
	return s, false, lerr
}

// glovoPoolOf is the shared GLOVO_DB_URL pool, or nil without a Glovo store.
func glovoPoolOf(s *glovo.Store) *pgxpool.Pool {
	if s == nil {
		return nil
	}
	return s.Pool()
}

// glovoWriteFenceHoldLifted is fence precondition 2 (mctl-gitops#2457 lifted).
// It has no machine-checkable signal yet (OPEN-985-11), so it is a const false:
// the write fence cannot be installed from this build.
const glovoWriteFenceHoldLifted = false

// controlEnvReady is the explicit-env half of the one-database proof: each of
// the two database variables must be set and none may fall back to another.
func controlEnvReady(lookup func(string) (string, bool)) error {
	for _, k := range []string{"GLOVO_DB_URL", "WORK_ITEMS_DB_URL"} {
		if v, _ := lookup(k); strings.TrimSpace(v) == "" {
			return fmt.Errorf("%s is not set", k)
		}
	}
	return nil
}

// controlProof is fence precondition 3. Anything that cannot be observed is an
// error: a missing variable, a store or pool that is not constructed here, a
// failed nonce read.
func controlProof(ctx context.Context, lookup func(string) (string, bool), bs *bridge.Store, gs *glovo.Store, workItems *pgxpool.Pool) error {
	if err := controlEnvReady(lookup); err != nil {
		return err
	}
	if bs == nil || gs == nil || workItems == nil {
		return errors.New("a store or the work-items pool is not constructed")
	}
	return control.ProveOneDatabase(ctx, bs, gs, workItems)
}

// fenceInstall is everything installWriteFence observes. Nothing is assumed.
type fenceInstall struct {
	Gate       bool
	HoldLifted bool
	Proof      func(ctx context.Context) error
	Glovo      *glovo.Store
	// HookReady and MembershipWired default to the observations of Glovo; they
	// are seams for tests that have no database.
	HookReady       func(ctx context.Context) bool
	MembershipWired func() bool
	// Build returns the complete fence, or an error when a collaborator is
	// missing or receipt.Ready fails.
	Build func(ctx context.Context) (bridge.WriteFence, error)
	Set   func(bridge.WriteFence)
}

// installWriteFence is the single place that calls SetFence. It does so only
// when all six preconditions of the #985 design 7.3 hold, and reports what it
// observed. With any one false the bridge keeps its refusing fence.
func installWriteFence(ctx context.Context, d fenceInstall) (bool, glovoFencePreconditions) {
	pre := glovoFencePreconditions{
		GateOpen:   d.Gate,
		HoldLifted: d.HoldLifted,
		// The proof is evaluated only behind the build gate: a closed-gate
		// release never runs it.
		OneDatabaseProof:     d.Gate && d.Proof != nil && d.Proof(ctx) == nil,
		RevocationHookReady:  fenceHookReady(ctx, d.Glovo),
		MembershipRevocation: fenceMembershipObserved(d.Glovo),
	}
	if d.HookReady != nil {
		pre.RevocationHookReady = d.HookReady(ctx)
	}
	if d.MembershipWired != nil {
		pre.MembershipRevocation = d.MembershipWired()
	}
	var fence bridge.WriteFence
	if d.Build != nil {
		if f, err := d.Build(ctx); err == nil && !glovo.IsNil(f) {
			fence, pre.ReceiptReady = f, true
		}
	}
	if !pre.All() || d.Set == nil {
		return false, pre
	}
	d.Set(fence)
	return true, pre
}
