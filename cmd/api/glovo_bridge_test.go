package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
)

// openBridgeStore decides the bridge mode once, from the schema probe.
func TestOpenBridgeStoreChoosesTheModeFromTheProbe(t *testing.T) {
	pool := &pgxpool.Pool{}
	runtimeStore, legacyStore := &bridge.Store{}, &bridge.Store{}
	boom := errors.New("boom")
	type tc struct {
		name       string
		pool       *pgxpool.Pool
		dsn        string
		migrated   bool
		probeErr   error
		runtimeErr error
		want       *bridge.Store
		wantRT     bool
		wantErr    bool
		notReady   bool
	}
	cases := []tc{
		{name: "migrated with the Glovo pool uses the runtime store", pool: pool, dsn: "d", migrated: true, want: runtimeStore, wantRT: true},
		{name: "migrated with the Glovo pool needs no legacy DSN", pool: pool, migrated: true, want: runtimeStore, wantRT: true},
		{name: "not migrated with the Glovo pool uses the legacy store", pool: pool, dsn: "d", want: legacyStore},
		{name: "probe failure on the pool is not_ready, not legacy", pool: pool, dsn: "d", probeErr: boom, wantErr: true, notReady: true},
		{name: "runtime store failure is its error, not legacy", pool: pool, dsn: "d", migrated: true, runtimeErr: boom, wantErr: true, wantRT: true},
		{name: "migrated without the Glovo pool is not_ready, not legacy", dsn: "d", migrated: true, wantErr: true, notReady: true},
		{name: "not migrated without the Glovo pool uses the legacy store", dsn: "d", want: legacyStore},
		{name: "probe failure on the DSN is not_ready, not legacy", dsn: "d", probeErr: boom, wantErr: true, notReady: true},
		{name: "no pool and no DSN is an error", wantErr: true},
		{name: "not migrated with a pool and no DSN is an error", pool: pool, wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var legacyCalls, runtimeCalls int
			got, rt, err := openBridgeStore(context.Background(), bridgeOpenDeps{
				GlovoPool: c.pool, LegacyDSN: c.dsn,
				ProbePool: func(context.Context, *pgxpool.Pool) (bool, error) { return c.migrated, c.probeErr },
				ProbeDSN:  func(context.Context, string) (bool, error) { return c.migrated, c.probeErr },
				Legacy:    func(context.Context, string) (*bridge.Store, error) { legacyCalls++; return legacyStore, nil },
				Runtime: func(context.Context, *pgxpool.Pool) (*bridge.Store, error) {
					runtimeCalls++
					if c.runtimeErr != nil {
						return nil, c.runtimeErr
					}
					return runtimeStore, nil
				},
			})
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, want error %v", err, c.wantErr)
			}
			if c.notReady && !errors.Is(err, glovo.Refuse(glovo.CodeNotReady)) {
				t.Fatalf("err = %v, want not_ready", err)
			}
			if !c.wantErr && (got != c.want || rt != c.wantRT) {
				t.Fatalf("store/runtime = %p/%v, want %p/%v", got, rt, c.want, c.wantRT)
			}
			if c.wantErr && got != nil {
				t.Fatal("a store came back with the error")
			}
			// A migrated schema never reaches the legacy store, a legacy
			// schema never reaches the runtime store.
			if c.migrated && legacyCalls != 0 {
				t.Fatal("the legacy store (which runs DDL) was opened on a migrated schema")
			}
			if !c.migrated && runtimeCalls != 0 {
				t.Fatal("the runtime store was opened on an unmigrated schema")
			}
			if c.probeErr != nil && (legacyCalls != 0 || runtimeCalls != 0) {
				t.Fatal("a failed probe fell back to a store")
			}
		})
	}
}

func TestControlProofNeedsEveryInput(t *testing.T) {
	full := map[string]string{"GLOVO_DB_URL": "postgres://g", "WORK_ITEMS_DB_URL": "postgres://w"}
	lookup := func(m map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	for _, k := range []string{"GLOVO_DB_URL", "WORK_ITEMS_DB_URL"} {
		m := map[string]string{}
		for a, b := range full {
			if a != k {
				m[a] = b
			}
		}
		if err := controlProof(context.Background(), lookup(m), &bridge.Store{}, &glovo.Store{}, &pgxpool.Pool{}); err == nil || !strings.Contains(err.Error(), k) {
			t.Errorf("%s unset: %v", k, err)
		}
		m[k] = "  "
		if err := controlProof(context.Background(), lookup(m), &bridge.Store{}, &glovo.Store{}, &pgxpool.Pool{}); err == nil {
			t.Errorf("%s blank passed", k)
		}
	}
	// Variables set, but a store or the work-items pool is not constructed:
	// the proof is an error, never a pass, and no URL is in the message.
	for name, args := range map[string][3]any{
		"bridge":     {nil, &glovo.Store{}, &pgxpool.Pool{}},
		"glovo":      {&bridge.Store{}, nil, &pgxpool.Pool{}},
		"work items": {&bridge.Store{}, &glovo.Store{}, nil},
	} {
		bs, _ := args[0].(*bridge.Store)
		gs, _ := args[1].(*glovo.Store)
		wp, _ := args[2].(*pgxpool.Pool)
		err := controlProof(context.Background(), lookup(full), bs, gs, wp)
		if err == nil {
			t.Errorf("%s missing: the proof passed", name)
		} else if strings.Contains(err.Error(), "postgres://") {
			t.Errorf("%s: the error leaks a URL: %v", name, err)
		}
	}
}

// installWriteFence is the only SetFence caller. With any one of the six
// preconditions false it must not install; the hold flag is a const false, so
// the build never installs.
func TestInstallWriteFenceNeedsAllSixPreconditions(t *testing.T) {
	fence := bridge.WriteFence(nil)
	_ = fence
	ok := func(context.Context) error { return nil }
	good := func() fenceInstall {
		return fenceInstall{
			Gate: true, HoldLifted: true, Proof: ok,
			HookReady:       func(context.Context) bool { return true },
			MembershipWired: func() bool { return true },
			Build:           func(context.Context) (bridge.WriteFence, error) { return stubFence{}, nil },
		}
	}
	var installed int
	set := func(bridge.WriteFence) { installed++ }
	d := good()
	d.Set = set
	if got, pre := installWriteFence(context.Background(), d); !got || installed != 1 || !pre.All() {
		t.Fatalf("all six true: installed=%v calls=%d pre=%+v", got, installed, pre)
	}
	breakers := map[string]func(*fenceInstall){
		"gate":          func(d *fenceInstall) { d.Gate = false },
		"hold":          func(d *fenceInstall) { d.HoldLifted = false },
		"proof fails":   func(d *fenceInstall) { d.Proof = func(context.Context) error { return errors.New("x") } },
		"proof missing": func(d *fenceInstall) { d.Proof = nil },
		"hook":          func(d *fenceInstall) { d.HookReady = func(context.Context) bool { return false } },
		"membership":    func(d *fenceInstall) { d.MembershipWired = func() bool { return false } },
		"receipt not ready": func(d *fenceInstall) {
			d.Build = func(context.Context) (bridge.WriteFence, error) { return nil, errors.New("x") }
		},
		"receipt nil":     func(d *fenceInstall) { d.Build = func(context.Context) (bridge.WriteFence, error) { return nil, nil } },
		"receipt missing": func(d *fenceInstall) { d.Build = nil },
	}
	for name, brk := range breakers {
		t.Run(name, func(t *testing.T) {
			installed = 0
			d := good()
			d.Set = set
			brk(&d)
			if got, pre := installWriteFence(context.Background(), d); got || installed != 0 || pre.All() {
				t.Fatalf("installed=%v calls=%d pre=%+v with one condition false", got, installed, pre)
			}
		})
	}
	// The real observations of a store with no database are false.
	installed = 0
	d = good()
	d.HookReady, d.MembershipWired, d.Glovo, d.Set = nil, nil, &glovo.Store{}, set
	if got, _ := installWriteFence(context.Background(), d); got || installed != 0 {
		t.Fatal("a store with no hook and no detector installed the fence")
	}
	// Production wiring: the hold flag is a const false.
	if glovoWriteFenceHoldLifted {
		t.Fatal("glovoWriteFenceHoldLifted must stay false until OPEN-985-11 is decided")
	}
}

type stubFence struct{ bridge.WriteFence }

// The installer is wired, not just defined: main calls it once, and it holds the
// only SetFence reference of the binary.
func TestMainInstallsTheFenceOnlyThroughTheInstaller(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var setFence, installer int
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Clean(e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			if code := strings.TrimSpace(line); !strings.HasPrefix(code, "//") {
				setFence += strings.Count(code, "SetFence")
			}
		}
		if e.Name() == "main.go" {
			installer += strings.Count(string(b), "installWriteFence(")
		}
	}
	if installer != 1 {
		t.Errorf("main.go calls installWriteFence %d times, want 1", installer)
	}
	if setFence != 1 {
		t.Errorf("SetFence is referenced %d times in cmd/api, want exactly 1 (the installer's Set)", setFence)
	}
}

func TestOpenGlovoStoreChoosesTheHook(t *testing.T) {
	env := func(m map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	on, off := env(map[string]string{"MCTL_GLOVO_CONTROL_ENABLED": "true"}), env(nil)
	var proofs, built int
	pass := func(context.Context, dbq.Querier) error { proofs++; return nil }
	fail := func(context.Context, dbq.Querier) error { proofs++; return errors.New("no bridge_commands") }
	newStore := func(opts []glovo.Option) (*glovo.Store, error) { built++; return storeWith(opts), nil }
	open := func(lookup func(string) (string, bool), gate bool, prove func(context.Context, dbq.Querier) error) (*glovo.Store, error) {
		proofs, built = 0, 0
		return openGlovoStore(context.Background(), nil, lookup, gate, prove, newStore)
	}
	synthetic := func(s *glovo.Store) bool {
		return s != nil && s.RevocationHookIs(syntheticRevocationHook) && !s.RevocationHookIs(bridge.CancelOpenForConnections)
	}

	// Flag on, gate closed: no proof, the unchanged synthetic hook.
	for _, p := range []func(context.Context, dbq.Querier) error{pass, fail} {
		s, err := open(on, false, p)
		if err != nil || proofs != 0 || built != 1 || !synthetic(s) {
			t.Fatalf("flag on, gate closed: err=%v proofs=%d built=%d synthetic=%v", err, proofs, built, synthetic(s))
		}
	}
	// Flag off, gate open: no proof, the synthetic hook.
	for _, p := range []func(context.Context, dbq.Querier) error{pass, fail} {
		s, err := open(off, true, p)
		if err != nil || proofs != 0 || built != 1 || !synthetic(s) {
			t.Fatalf("flag off, gate open: err=%v proofs=%d built=%d synthetic=%v", err, proofs, built, synthetic(s))
		}
	}
	// Flag on, gate open, proof fails: the boot is refused, nothing is built.
	if s, err := open(on, true, fail); err == nil || s != nil || built != 0 || proofs != 1 {
		t.Fatalf("a failed proof must refuse the boot: store=%v err=%v built=%d proofs=%d", s, err, built, proofs)
	}
	// Flag on, gate open, proof ok: the real hook.
	if s, err := open(on, true, pass); err != nil || s == nil || proofs != 1 || !s.RevocationHookIs(bridge.CancelOpenForConnections) {
		t.Fatalf("a passing proof must install the real hook: err=%v proofs=%d", err, proofs)
	}
	// A constructor failure is returned, not swallowed.
	boom := errors.New("boom")
	if _, err := openGlovoStore(context.Background(), nil, off, false, pass, func([]glovo.Option) (*glovo.Store, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Fatalf("a store error was lost: %v", err)
	}
}

// With the flag off or the gate closed the store options are exactly the #959
// ones: the synthetic hook, the required end purger, the 5 s lock timeout.
func TestLifecycleOptionsUnchangedWithoutTheRealHook(t *testing.T) {
	s := storeWith(glovoStoreOptions(false))
	if s.RevocationHookIs(bridge.CancelOpenForConnections) {
		t.Fatal("the real hook leaked into the unchanged lifecycle")
	}
	if !s.RevocationHookIs(syntheticRevocationHook) {
		t.Fatal("the unchanged lifecycle lost its synthetic hook")
	}
	if !s.EndPurgerInstalled() {
		t.Fatal("the end purger is not installed")
	}
}

// A closed-gate release never runs the one-database proof: it is not evaluated
// unless the build gate is open.
func TestInstallWriteFenceDoesNotRunTheProofBehindAClosedGate(t *testing.T) {
	var ran int
	d := fenceInstall{
		Gate: false, HoldLifted: true,
		Proof: func(context.Context) error { ran++; return nil },
		Set:   func(bridge.WriteFence) { t.Error("installed behind a closed gate") },
	}
	if got, _ := installWriteFence(context.Background(), d); got || ran != 0 {
		t.Fatalf("gate closed: installed=%v proof ran %d times", got, ran)
	}
	d.Gate = true
	_, _ = installWriteFence(context.Background(), d)
	if ran != 1 {
		t.Fatalf("gate open: the proof ran %d times, want 1", ran)
	}
}
