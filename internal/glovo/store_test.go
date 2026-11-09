// Copyright 2026 MCTL Authors
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

package glovo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestIsolationMatrix: A2 (same tenant), B1 (other tenant) and A1 with a
// never-existing id get the identical not_found for read, transition and
// revoke, and A1's row and audit trail are untouched.
func TestIsolationMatrix(t *testing.T) {
	e := newEnv(t)
	f := newFixture(t)
	ia, ib := e.install(f, f.Alpha), e.install(f, f.Beta)
	c := e.connect(f.A1, ia.InstallRevision, "k")
	e.connect(f.B1, ib.InstallRevision, "kb")
	ghost, _ := newPrefixedID(prefixConnection, time.Now())
	before := e.auditCount(c.ConnectionID)

	type probe struct {
		name  string
		owner Owner
		id    string
	}
	probes := []probe{{"same-tenant", f.A2, c.ConnectionID}, {"other-tenant", f.B1, c.ConnectionID}, {"ghost", f.A1, ghost}}
	var msgs []string
	for _, p := range probes {
		ctx := workerCtx()
		_, err1 := e.store.GetConnection(ctx, p.owner, p.id)
		_, err2 := e.store.Transition(ctx, p.owner, p.id, Failed, 1, "x", nil)
		_, err3 := e.store.Revoke(ctx, p.owner, Actor{PrincipalID: p.owner.PrincipalID, Kind: ActorUser}, p.id, "x")
		for i, err := range []error{err1, err2, err3} {
			if !errors.Is(err, ErrNotFound) {
				t.Fatalf("%s call %d: %v", p.name, i, err)
			}
			msgs = append(msgs, err.Error())
		}
	}
	for _, m := range msgs {
		if m != msgs[0] {
			t.Fatalf("not_found messages differ: %q vs %q", m, msgs[0])
		}
	}
	got, err := e.store.GetConnection(context.Background(), f.A1, c.ConnectionID)
	if err != nil || got.Version != c.Version || got.State != PendingHandoff || e.auditCount(c.ConnectionID) != before {
		t.Fatalf("A1 row changed: %+v %v", got, err)
	}
}

func TestOneLiveConnectionPerOwner(t *testing.T) {
	e := newEnv(t)
	f := newFixture(t)
	ia, ib := e.install(f, f.Alpha), e.install(f, f.Beta)
	e.connect(f.A1, ia.InstallRevision, "k1")
	_, err := e.store.Connect(context.Background(), ConnectInput{Owner: f.A1, ExpectedInstallRevision: ia.InstallRevision,
		IdempotencyKey: "k2", Actor: userActor(f.A1)})
	mustCode(t, err, CodeConnectionExists)
	a2 := e.connect(f.A2, ia.InstallRevision, "k1")
	b1 := e.connect(f.B1, ib.InstallRevision, "k1")
	if a2.ConnectionID == b1.ConnectionID || !strings.HasPrefix(a2.ConnectionID, "gcn_") {
		t.Fatal("ids")
	}
}

func TestIdempotency(t *testing.T) {
	e := newEnv(t)
	f := newFixture(t)
	ia := e.install(f, f.Alpha)
	in := ConnectInput{Owner: f.A1, ExpectedInstallRevision: ia.InstallRevision, IdempotencyKey: "same", Actor: userActor(f.A1)}
	first, err := e.store.Connect(context.Background(), in)
	if err != nil || first.Replayed {
		t.Fatal(first, err)
	}
	in.Actor = f.actorAdmin // a replay by another actor is still a replay
	again, err := e.store.Connect(context.Background(), in)
	if err != nil || !again.Replayed || again.Connection.ConnectionID != first.Connection.ConnectionID {
		t.Fatal(again, err)
	}
	bad := in
	bad.ExpectedInstallRevision = ia.InstallRevision + 1
	_, err = e.store.Connect(context.Background(), bad)
	mustCode(t, err, CodeIdempotencyReused)

	// 20 concurrent connects with one key produce exactly one row.
	owner := f.A2
	cin := ConnectInput{Owner: owner, ExpectedInstallRevision: ia.InstallRevision, IdempotencyKey: "race", Actor: userActor(owner)}
	var wg sync.WaitGroup
	ids := make([]string, 20)
	errs := make([]error, 20)
	for i := range ids {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, err := e.store.Connect(context.Background(), cin)
			errs[i] = err
			if err == nil {
				ids[i] = r.Connection.ConnectionID
			}
		}(i)
	}
	wg.Wait()
	for i := range ids {
		if errs[i] != nil || ids[i] != ids[0] {
			t.Fatalf("%d: %v %q vs %q", i, errs[i], ids[i], ids[0])
		}
	}
	if n := e.count(`SELECT count(*) FROM glovo.glovo_connections WHERE tenant_id=$1 AND principal_id=$2`, owner.TenantID, owner.PrincipalID); n != 1 {
		t.Fatalf("%d rows", n)
	}
}

func TestStaleAndMissingInstall(t *testing.T) {
	e := newEnv(t)
	f := newFixture(t)
	ctx := context.Background()
	cin := func(o Owner, rev int64, key string) ConnectInput {
		return ConnectInput{Owner: o, ExpectedInstallRevision: rev, IdempotencyKey: key, Actor: userActor(o)}
	}
	_, err := e.store.Connect(ctx, cin(f.A1, 1, "k"))
	mustCode(t, err, CodeNoInstall)
	ia := e.install(f, f.Alpha)
	_, err = e.store.Connect(ctx, cin(f.A1, ia.InstallRevision-1, "k2"))
	mustCode(t, err, CodeInvalidRequest) // revision 0 is not a revision
	i2, _, err := e.store.Reinstall(ctx, f.Alpha, f.actorAdmin, ia.InstallRevision)
	if err != nil || i2.InstallRevision != 2 {
		t.Fatal(i2, err)
	}
	_, err = e.store.Connect(ctx, cin(f.A1, 1, "k3"))
	mustCode(t, err, CodeStaleInstall)
	if _, _, err := e.store.RevokeInstall(ctx, f.Alpha, f.actorAdmin, "admin_request", 2); err != nil {
		t.Fatal(err)
	}
	_, err = e.store.Connect(ctx, cin(f.A1, 2, "k4"))
	mustCode(t, err, CodeNoInstall)
	_, err = e.store.GetInstall(ctx, f.Alpha)
	mustCode(t, err, CodeNoInstall)
	// a stale revision on the install calls themselves
	_, _, err = e.store.Reinstall(ctx, f.Alpha, f.actorAdmin, 1)
	mustCode(t, err, CodeStaleInstall)
	// Install on an uninstalled tenant is not a silent resurrection
	_, err = e.store.Install(ctx, f.Alpha, f.actorAdmin)
	mustCode(t, err, CodeInvalidTransition)
	i3, _, err := e.store.Reinstall(ctx, f.Alpha, f.actorAdmin, 2)
	if err != nil || i3.InstallRevision != 3 || i3.State != InstallInstalled {
		t.Fatal(i3, err)
	}
}

func TestReinstallAtomicity(t *testing.T) {
	e := newEnv(t)
	f := newFixture(t)
	ia, ib := e.install(f, f.Alpha), e.install(f, f.Beta)
	a1 := e.connect(f.A1, ia.InstallRevision, "k")
	a2 := e.connect(f.A2, ia.InstallRevision, "k")
	b1 := e.connect(f.B1, ib.InstallRevision, "k")
	e.hookSeen.reset()
	inst, ended, err := e.store.Reinstall(context.Background(), f.Alpha, f.actorAdmin, ia.InstallRevision)
	if err != nil || inst.InstallRevision != ia.InstallRevision+1 || len(ended) != 2 {
		t.Fatal(inst, ended, err)
	}
	for _, c := range ended {
		if c.State != Revoked || c.EndReason != ReasonInstallReinstalled || c.EndedAt == nil {
			t.Fatalf("%+v", c)
		}
	}
	if e.hookSeen.count() != 1 || len(e.hookSeen.calls[0]) != 2 {
		t.Fatalf("hook calls %v", e.hookSeen.calls)
	}
	for _, c := range []*Connection{a1, a2} {
		got, _ := e.store.GetConnection(context.Background(), c.Owner, c.ConnectionID)
		if got.State != Revoked {
			t.Fatal("not revoked")
		}
	}
	if got, _ := e.store.GetConnection(context.Background(), f.B1, b1.ConnectionID); got.State != PendingHandoff {
		t.Fatal("B1 touched")
	}
	n := e.connect(f.A1, inst.InstallRevision, "k-new")
	if n.ConnectionID == a1.ConnectionID || n.InstallRevision != inst.InstallRevision {
		t.Fatal("new connection")
	}
}

// TestRaceConnectVersusRevokers: after both calls commit, no live connection
// is bound below the current revision and an owner has at most one live one.
func TestRaceConnectVersusRevokers(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for _, variant := range []string{"reinstall", "revoke_install", "revoke_prior"} {
		for i := 0; i < 50; i++ {
			f := newFixture(t)
			ia := e.install(f, f.Alpha)
			var prior *Connection
			if variant == "revoke_prior" {
				prior = e.connect(f.A1, ia.InstallRevision, "prior")
			}
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				_, err := e.store.Connect(ctx, ConnectInput{Owner: f.A1, ExpectedInstallRevision: ia.InstallRevision,
					IdempotencyKey: "race", Actor: userActor(f.A1)})
				var ge *Error
				if err != nil && (!errors.As(err, &ge) || (ge.Code != CodeStaleInstall && ge.Code != CodeNoInstall && ge.Code != CodeConnectionExists)) {
					t.Errorf("%s: connect: %v", variant, err)
				}
			}()
			go func() {
				defer wg.Done()
				var err error
				switch variant {
				case "reinstall":
					_, _, err = e.store.Reinstall(ctx, f.Alpha, f.actorAdmin, ia.InstallRevision)
				case "revoke_install":
					_, _, err = e.store.RevokeInstall(ctx, f.Alpha, f.actorAdmin, "admin_request", ia.InstallRevision)
				default:
					_, err = e.store.Revoke(ctx, f.A1, userActor(f.A1), prior.ConnectionID, "owner_request")
				}
				if err != nil {
					t.Errorf("%s: revoker: %v", variant, err)
				}
			}()
			wg.Wait()
			if n := e.count(`SELECT count(*) FROM glovo.glovo_connections c JOIN glovo.glovo_installs i USING (tenant_id)
 WHERE c.tenant_id = $1 AND c.state IN ('pending_handoff','pending_provider','active')
   AND (c.install_revision < i.install_revision OR i.state <> 'installed')`, f.Alpha); n != 0 {
				t.Fatalf("%s iteration %d: %d live connection(s) on a stale install", variant, i, n)
			}
			if n := e.count(`SELECT count(*) FROM glovo.glovo_connections WHERE tenant_id=$1 AND principal_id=$2
 AND state IN ('pending_handoff','pending_provider','active')`, f.A1.TenantID, f.A1.PrincipalID); n > 1 {
				t.Fatalf("%s: %d live connections", variant, n)
			}
		}
	}
}

func TestReconnect(t *testing.T) {
	e := newEnv(t)
	f := newFixture(t)
	ctx := context.Background()
	ia := e.install(f, f.Alpha)
	rin := func(key string, terminalOnly bool) ConnectInput {
		return ConnectInput{Owner: f.A1, ExpectedInstallRevision: ia.InstallRevision, IdempotencyKey: key,
			Actor: userActor(f.A1), TerminalOnly: terminalOnly}
	}

	// live branch
	old := e.connect(f.A1, ia.InstallRevision, "first")
	e.hookSeen.reset()
	r, err := e.store.Reconnect(ctx, rin("rc1", false), old.ConnectionID)
	if err != nil {
		t.Fatal(err)
	}
	if r.Connection.ConnectionID == old.ConnectionID || r.Connection.SupersedesID != old.ConnectionID || r.Connection.State != PendingHandoff {
		t.Fatalf("%+v", r.Connection)
	}
	got, _ := e.store.GetConnection(ctx, f.A1, old.ConnectionID)
	if got.State != Revoked || got.EndReason != ReasonSuperseded {
		t.Fatalf("%+v", got)
	}
	if e.hookSeen.count() != 1 || e.hookSeen.calls[0][0] != old.ConnectionID || len(r.Ended) != 1 {
		t.Fatalf("hook %v ended %v", e.hookSeen.calls, r.Ended)
	}
	// retry with the same key returns the same new id, no third id
	again, err := e.store.Reconnect(ctx, rin("rc1", false), old.ConnectionID)
	if err != nil || !again.Replayed || again.Connection.ConnectionID != r.Connection.ConnectionID {
		t.Fatal(again, err)
	}
	if n := e.count(`SELECT count(*) FROM glovo.glovo_connections WHERE tenant_id=$1 AND principal_id=$2`, f.A1.TenantID, f.A1.PrincipalID); n != 2 {
		t.Fatalf("%d rows", n)
	}
	// TerminalOnly refuses a live prior and ends nothing
	e.hookSeen.reset()
	_, err = e.store.Reconnect(ctx, rin("rc2", true), r.Connection.ConnectionID)
	mustCode(t, err, CodeConnectionExists)
	if e.hookSeen.count() != 0 {
		t.Fatal("hook ran")
	}

	// terminal branch from expired, failed, revoked
	cur := r.Connection
	for _, to := range []ConnectionState{Expired, Failed, Revoked} {
		tc, err := e.store.Transition(workerCtx(), f.A1, cur.ConnectionID, to, cur.Version, "", nil)
		if err != nil {
			t.Fatal(to, err)
		}
		e.hookSeen.reset()
		nr, err := e.store.Reconnect(ctx, rin("from-"+string(to), true), tc.ConnectionID)
		if err != nil || nr.Connection.SupersedesID != tc.ConnectionID || len(nr.Ended) != 0 || e.hookSeen.count() != 0 {
			t.Fatalf("%s: %+v %v hook=%d", to, nr, err, e.hookSeen.count())
		}
		cur = nr.Connection
	}

	// a clock-expired prior: moved to expired first, hook called for it only
	act := e.activate(f.A1, cur, ia.InstallRevision, 50*time.Millisecond)
	time.Sleep(150 * time.Millisecond)
	e.hookSeen.reset()
	nr, err := e.store.Reconnect(ctx, rin("lapsed", true), act.ConnectionID)
	if err != nil || nr.Connection.SupersedesID != act.ConnectionID {
		t.Fatal(nr, err)
	}
	if e.hookSeen.count() != 1 || e.hookSeen.calls[0][0] != act.ConnectionID {
		t.Fatalf("hook %v", e.hookSeen.calls)
	}
	if p, _ := e.store.GetConnection(ctx, f.A1, act.ConnectionID); p.State != Expired {
		t.Fatalf("%s", p.State)
	}

	// a foreign or ghost prior is not_found
	_, err = e.store.Reconnect(ctx, ConnectInput{Owner: f.A2, ExpectedInstallRevision: ia.InstallRevision, IdempotencyKey: "x",
		Actor: userActor(f.A2)}, nr.Connection.ConnectionID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestTransitionsInDB(t *testing.T) {
	e := newEnv(t)
	f := newFixture(t)
	ctx := context.Background()
	ia := e.install(f, f.Alpha)
	rev := ia.InstallRevision

	// happy path: ActivateTx then Transition to revoked
	c := e.connect(f.A1, rev, "k1")
	act := e.activate(f.A1, c, rev, time.Hour)
	if act.State != Active || act.Version != c.Version+2 || act.ExpiresAt == nil {
		t.Fatalf("%+v", act)
	}
	if n := e.auditCount(c.ConnectionID); n != 3 { // connect + two activation steps
		t.Fatalf("%d audit rows", n)
	}
	rv, err := e.store.Transition(workerCtx(), f.A1, c.ConnectionID, Revoked, act.Version, "owner_request", nil)
	if err != nil || rv.State != Revoked || rv.EndedAt == nil {
		t.Fatal(rv, err)
	}

	// the separate edge pending_handoff -> pending_provider through Transition
	c2 := e.connect(f.A1, rev, "k2")
	pp, err := e.store.Transition(workerCtx(), f.A1, c2.ConnectionID, PendingProvider, c2.Version, "", nil)
	if err != nil || pp.State != PendingProvider {
		t.Fatal(pp, err)
	}
	// a stale version
	_, err = e.store.Transition(workerCtx(), f.A1, c2.ConnectionID, Failed, c2.Version, "", nil)
	mustCode(t, err, CodeStaleVersion)
	// pending_provider leaves only to failed/expired/revoked through Transition
	_, err = e.store.Transition(workerCtx(), f.A1, c2.ConnectionID, Active, pp.Version, "", nil)
	mustCode(t, err, CodeInvalidRequest)
	tf, err := e.store.Transition(workerCtx(), f.A1, c2.ConnectionID, Failed, pp.Version, "provider_error", nil)
	if err != nil || tf.State != Failed || tf.EndReason != "provider_error" {
		t.Fatal(tf, err)
	}

	// to = active is invalid_request from every from-state, revoked included
	for _, id := range []string{c.ConnectionID, c2.ConnectionID} {
		_, err := e.store.Transition(workerCtx(), f.A1, id, Active, 1, "", nil)
		mustCode(t, err, CodeInvalidRequest)
	}
	// a forbidden edge with a non-active target
	_, err = e.store.Transition(workerCtx(), f.A1, c.ConnectionID, PendingProvider, rv.Version, "", nil)
	mustCode(t, err, CodeInvalidTransition)
	// an unknown target
	_, err = e.store.Transition(workerCtx(), f.A1, c.ConnectionID, "bogus", rv.Version, "", nil)
	mustCode(t, err, CodeInvalidRequest)

	// ActivateTx refusals: no write, no audit row
	check := func(name string, id string, ver int64, want Code, ttl time.Duration) {
		t.Helper()
		before := e.auditCount(id)
		tx, _ := e.pool.Begin(ctx)
		defer func() { _ = tx.Rollback(ctx) }()
		_, err := e.store.ActivateTx(ctx, tx, ActivateInput{Owner: f.A1, ConnectionID: id, ExpectedVersion: ver,
			ExpectedInstallRevision: rev, ExpiresIn: ttl, Actor: workerActor})
		if want == "" {
			if !errors.Is(err, ErrNotFound) {
				t.Fatalf("%s: %v", name, err)
			}
		} else {
			mustCode(t, err, want)
		}
		if e.auditCount(id) != before {
			t.Fatalf("%s: audit row written", name)
		}
	}
	c3 := e.connect(f.A1, rev, "k3")
	pp3, _ := e.store.Transition(workerCtx(), f.A1, c3.ConnectionID, PendingProvider, c3.Version, "", nil)
	check("pending_provider", c3.ConnectionID, pp3.Version, CodeInvalidTransition, time.Hour)
	if _, err := e.store.Transition(workerCtx(), f.A1, c3.ConnectionID, Expired, pp3.Version, "", nil); err != nil {
		t.Fatal(err)
	}
	check("expired", c3.ConnectionID, 99, CodeConnectionExpired, time.Hour)
	check("revoked, stale version", c.ConnectionID, 1, CodeConnectionRevoked, time.Hour)
	check("failed", c2.ConnectionID, 1, CodeNoConnection, time.Hour)
	ghost, _ := newPrefixedID(prefixConnection, time.Now())
	check("ghost", ghost, 1, "", time.Hour)
	c4 := e.connect(f.A1, rev, "k4")
	a4 := e.activate(f.A1, c4, rev, time.Hour)
	check("unexpired active", c4.ConnectionID, a4.Version, CodeInvalidTransition, time.Hour)
	if _, err := e.store.Transition(workerCtx(), f.A1, c4.ConnectionID, Revoked, a4.Version, "x", nil); err != nil {
		t.Fatal(err)
	}
	c5 := e.connect(f.A1, rev, "k5")
	a5 := e.activate(f.A1, c5, rev, 30*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	check("active past expires_at", c5.ConnectionID, a5.Version, CodeConnectionExpired, time.Hour)
	if _, err := e.store.Transition(workerCtx(), f.A1, c5.ConnectionID, Expired, a5.Version, "", nil); err != nil {
		t.Fatal(err)
	}
	c6 := e.connect(f.A1, rev, "k6")
	check("stale version", c6.ConnectionID, c6.Version+5, CodeStaleVersion, time.Hour)
	check("ttl too small", c6.ConnectionID, c6.Version, CodeInvalidRequest, 0)
	check("ttl too large", c6.ConnectionID, c6.Version, CodeInvalidRequest, MaxConnectionTTL+time.Second)
}

func TestActivateStaleInstallRevision(t *testing.T) {
	e := newEnv(t)
	f := newFixture(t)
	ctx := context.Background()
	ia := e.install(f, f.Alpha)
	c := e.connect(f.A1, ia.InstallRevision, "k")
	tx, _ := e.pool.Begin(ctx)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err := e.store.ActivateTx(ctx, tx, ActivateInput{Owner: f.A1, ConnectionID: c.ConnectionID, ExpectedVersion: c.Version,
		ExpectedInstallRevision: ia.InstallRevision + 1, ExpiresIn: time.Hour, Actor: workerActor})
	mustCode(t, err, CodeStaleInstall)
}

func TestAuditEventsAndImmutability(t *testing.T) {
	e := newEnv(t)
	f := newFixture(t)
	ctx := context.Background()
	ia := e.install(f, f.Alpha)
	c := e.connect(f.A1, ia.InstallRevision, "k")
	if e.auditCount(c.ConnectionID) != 1 || e.auditCount(ia.InstallID) != 1 {
		t.Fatal("connect/install should each write exactly one event")
	}
	if _, err := e.store.Revoke(ctx, f.A1, userActor(f.A1), c.ConnectionID, "owner_request"); err != nil {
		t.Fatal(err)
	}
	if e.auditCount(c.ConnectionID) != 2 {
		t.Fatal("revoke should add exactly one event")
	}
	// revoking again is idempotent and writes nothing
	if _, err := e.store.Revoke(ctx, f.A1, userActor(f.A1), c.ConnectionID, "owner_request"); err != nil {
		t.Fatal(err)
	}
	if e.auditCount(c.ConnectionID) != 2 {
		t.Fatal("idempotent revoke wrote an event")
	}
	evs, err := e.store.ListAudit(ctx, f.Alpha, c.ConnectionID)
	if err != nil || len(evs) != 2 || !strings.HasPrefix(evs[0].EventID, "gae_") || evs[1].ToState != "revoked" || evs[1].SubjectPrincipalID != f.A1.PrincipalID {
		t.Fatalf("%+v %v", evs, err)
	}
	// tenant-bound read
	if other, _ := e.store.ListAudit(ctx, f.Beta, c.ConnectionID); len(other) != 0 {
		t.Fatal("another tenant read the trail")
	}

	// raw SQL as the runtime role: nothing can change or remove history,
	// whatever GUC it forges
	for _, stmt := range []string{
		`UPDATE glovo.glovo_audit_events SET reason_code = 'x'`,
		`DELETE FROM glovo.glovo_audit_events`,
		`TRUNCATE glovo.glovo_audit_events`,
		`DELETE FROM glovo.glovo_connections`,
		`TRUNCATE glovo.glovo_connections`,
	} {
		if _, err := e.pool.Exec(ctx, stmt); err == nil {
			t.Errorf("%s succeeded", stmt)
		}
		tx, _ := e.pool.Begin(ctx)
		_, _ = tx.Exec(ctx, `SET LOCAL glovo.retention_sweep = 'on'`)
		if _, err := tx.Exec(ctx, stmt); err == nil {
			t.Errorf("%s succeeded after SET LOCAL glovo.retention_sweep", stmt)
		}
		_ = tx.Rollback(ctx)
	}
	// even the owner cannot update an audit row or delete a connection: the
	// triggers are unconditional
	mp := e.migPool()
	for _, stmt := range []string{
		`UPDATE glovo.glovo_audit_events SET reason_code = 'x'`,
		`DELETE FROM glovo.glovo_audit_events`,
		`DELETE FROM glovo.glovo_connections`,
	} {
		if _, err := mp.Exec(ctx, stmt); err == nil {
			t.Errorf("owner: %s succeeded", stmt)
		}
	}
}

func TestRollbackLeavesNothing(t *testing.T) {
	e := newEnv(t)
	f := newFixture(t)
	ia := e.install(f, f.Alpha)
	e.store.failAfterWrite = func() error { return errors.New("boom") }
	_, err := e.store.Connect(context.Background(), ConnectInput{Owner: f.A1, ExpectedInstallRevision: ia.InstallRevision,
		IdempotencyKey: "k", Actor: userActor(f.A1)})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatal(err)
	}
	for _, q := range []string{
		`SELECT count(*) FROM glovo.glovo_connections WHERE tenant_id = $1`,
		`SELECT count(*) FROM glovo.glovo_connect_requests WHERE tenant_id = $1`,
		`SELECT count(*) FROM glovo.glovo_audit_events WHERE tenant_id = $1 AND entity_kind = 'connection'`,
	} {
		if n := e.count(q, f.Alpha); n != 0 {
			t.Fatalf("%s: %d", q, n)
		}
	}
}

// TestTerminalPurge: every terminal path clears secret_ref and returns the
// released reference exactly once.
func TestTerminalPurge(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	withRef := func(f fixture, o Owner, rev int64, key string) (*Connection, string) {
		c := e.connect(o, rev, key)
		ref, _ := newPrefixedID(prefixSecretRef, time.Now())
		pp, err := e.store.Transition(workerCtx(), o, c.ConnectionID, PendingProvider, c.Version, "", &SecretRef{ID: ref})
		if err != nil || pp.SecretRef != ref {
			t.Fatal(pp, err)
		}
		return pp, ref
	}
	assertPurged := func(name string, released []Connection, id, ref string) {
		t.Helper()
		n := 0
		for _, c := range released {
			if c.ConnectionID == id {
				n++
				if c.ReleasedSecretRef != ref || c.SecretRef != "" {
					t.Fatalf("%s: %+v", name, c)
				}
			}
		}
		if n != 1 {
			t.Fatalf("%s: released %d times", name, n)
		}
		var s *string
		if err := e.pool.QueryRow(ctx, `SELECT secret_ref FROM glovo.glovo_connections WHERE connection_id=$1`, id).Scan(&s); err != nil || s != nil {
			t.Fatalf("%s: secret_ref %v %v", name, s, err)
		}
	}
	for _, to := range []ConnectionState{Expired, Failed, Revoked} {
		f := newFixture(t)
		ia := e.install(f, f.Alpha)
		c, ref := withRef(f, f.A1, ia.InstallRevision, "k")
		got, err := e.store.Transition(workerCtx(), f.A1, c.ConnectionID, to, c.Version, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		assertPurged(string(to), []Connection{*got}, c.ConnectionID, ref)
	}
	{ // Revoke
		f := newFixture(t)
		ia := e.install(f, f.Alpha)
		c, ref := withRef(f, f.A1, ia.InstallRevision, "k")
		got, err := e.store.Revoke(ctx, f.A1, userActor(f.A1), c.ConnectionID, "owner_request")
		if err != nil {
			t.Fatal(err)
		}
		assertPurged("revoke", []Connection{*got}, c.ConnectionID, ref)
	}
	{ // superseded
		f := newFixture(t)
		ia := e.install(f, f.Alpha)
		c, ref := withRef(f, f.A1, ia.InstallRevision, "k")
		r, err := e.store.Reconnect(ctx, ConnectInput{Owner: f.A1, ExpectedInstallRevision: ia.InstallRevision,
			IdempotencyKey: "rc", Actor: userActor(f.A1)}, c.ConnectionID)
		if err != nil {
			t.Fatal(err)
		}
		assertPurged("superseded", r.Ended, c.ConnectionID, ref)
	}
	{ // install revoked, install reinstalled, membership removed
		f := newFixture(t)
		ia := e.install(f, f.Alpha)
		c1, ref1 := withRef(f, f.A1, ia.InstallRevision, "k")
		c2, ref2 := withRef(f, f.A2, ia.InstallRevision, "k")
		ended, err := e.store.RevokeForMembership(ctx, f.Alpha, f.A2.PrincipalID, f.actorAdmin)
		if err != nil || len(ended) != 1 || ended[0].EndReason != ReasonMembershipRemoved {
			t.Fatal(ended, err)
		}
		assertPurged("membership", ended, c2.ConnectionID, ref2)
		_, ended, err = e.store.Reinstall(ctx, f.Alpha, f.actorAdmin, ia.InstallRevision)
		if err != nil {
			t.Fatal(err)
		}
		assertPurged("reinstall", ended, c1.ConnectionID, ref1)
		c3, ref3 := withRef(f, f.A1, ia.InstallRevision+1, "k3")
		_, ended, err = e.store.RevokeInstall(ctx, f.Alpha, f.actorAdmin, "admin_request", ia.InstallRevision+1)
		if err != nil {
			t.Fatal(err)
		}
		assertPurged("install_revoked", ended, c3.ConnectionID, ref3)
		if ended[0].EndReason != ReasonInstallRevoked {
			t.Fatal(ended[0].EndReason)
		}
	}
}

func TestRevocationHookFencesEveryPath(t *testing.T) {
	e := newEnv(t)
	f := newFixture(t)
	ctx := context.Background()
	ia := e.install(f, f.Alpha)
	rev := ia.InstallRevision
	expectOne := func(name string, ids ...string) {
		t.Helper()
		if e.hookSeen.count() != 1 {
			t.Fatalf("%s: hook called %d times", name, e.hookSeen.count())
		}
		got := e.hookSeen.calls[0]
		if strings.Join(got, ",") != strings.Join(ids, ",") {
			t.Fatalf("%s: hook ids %v want %v", name, got, ids)
		}
		e.hookSeen.reset()
	}
	c := e.connect(f.A1, rev, "a")
	if _, err := e.store.Revoke(ctx, f.A1, userActor(f.A1), c.ConnectionID, "owner_request"); err != nil {
		t.Fatal(err)
	}
	expectOne("revoke", c.ConnectionID)
	c = e.connect(f.A1, rev, "b")
	if _, err := e.store.RevokeForMembership(ctx, f.Alpha, f.A1.PrincipalID, f.actorAdmin); err != nil {
		t.Fatal(err)
	}
	expectOne("membership", c.ConnectionID)
	for _, to := range []ConnectionState{Expired, Failed} {
		c = e.connect(f.A1, rev, "t-"+string(to))
		if _, err := e.store.Transition(workerCtx(), f.A1, c.ConnectionID, to, c.Version, "", nil); err != nil {
			t.Fatal(err)
		}
		expectOne("transition "+string(to), c.ConnectionID)
	}
	// a non-terminal Transition does not call the hook
	c = e.connect(f.A1, rev, "np")
	if _, err := e.store.Transition(workerCtx(), f.A1, c.ConnectionID, PendingProvider, c.Version, "", nil); err != nil {
		t.Fatal(err)
	}
	if e.hookSeen.count() != 0 {
		t.Fatal("hook on non-terminal transition")
	}
	// install revoke ends the connection above with all others
	if _, ended, err := e.store.RevokeInstall(ctx, f.Alpha, f.actorAdmin, "admin_request", rev); err != nil || len(ended) != 1 {
		t.Fatal(ended, err)
	}
	expectOne("revoke_install", c.ConnectionID)

	// a hook error leaves the connection live
	f2 := newFixture(t)
	i2 := e.install(f2, f2.Alpha)
	live := e.connect(f2.A1, i2.InstallRevision, "k")
	e.hookSeen.err = errors.New("hook down")
	_, err := e.store.Revoke(ctx, f2.A1, userActor(f2.A1), live.ConnectionID, "owner_request")
	if err == nil || !strings.Contains(err.Error(), "hook down") {
		t.Fatal(err)
	}
	got, _ := e.store.GetConnection(ctx, f2.A1, live.ConnectionID)
	if got.State != PendingHandoff {
		t.Fatalf("state %s after a failed hook", got.State)
	}
	if e.auditCount(live.ConnectionID) != 1 {
		t.Fatal("audit row survived the rollback")
	}
	e.hookSeen.err = nil
}

// TestLockOrderNoDeadlock: a revoker and a reader that takes the same order
// (L1, L2, the row, then a later lock the hook also takes) never deadlock.
func TestLockOrderNoDeadlock(t *testing.T) {
	const l5 = 424242
	hook := func(ctx context.Context, tx pgx.Tx, _ []string, _ string) error {
		_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, l5)
		return err
	}
	e := newEnv(t, WithRevocationHook(hook))
	ctx := context.Background()
	for i := 0; i < 50; i++ {
		f := newFixture(t)
		ia := e.install(f, f.Alpha)
		c := e.connect(f.A1, ia.InstallRevision, "k")
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, err := e.store.Revoke(ctx, f.A1, userActor(f.A1), c.ConnectionID, "owner_request"); err != nil {
				t.Errorf("revoker: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			tx, err := e.pool.Begin(ctx)
			if err != nil {
				t.Errorf("reader begin: %v", err)
				return
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if err := e.store.LockOwnerShared(ctx, tx, f.Alpha, f.A1.PrincipalID); err != nil {
				t.Errorf("reader lock: %v", err)
				return
			}
			if _, err := tx.Exec(ctx, `SELECT 1 FROM glovo.glovo_connections WHERE connection_id = $1 FOR UPDATE`, c.ConnectionID); err != nil {
				t.Errorf("reader row lock: %v", err)
				return
			}
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, l5); err != nil {
				t.Errorf("reader l5: %v", err)
				return
			}
			_ = tx.Commit(ctx)
		}()
		wg.Wait()
	}
}

func TestPrimitivesAndExpiryFence(t *testing.T) {
	e := newEnv(t)
	f := newFixture(t)
	ctx := context.Background()
	ia := e.install(f, f.Alpha)
	rev := ia.InstallRevision

	// GetConnectionForWorker returns a foreign owner's connection by id
	c := e.connect(f.A1, rev, "k")
	w, err := e.store.GetConnectionForWorker(ctx, c.ConnectionID)
	if err != nil || w.Owner != f.A1 || w.Version != c.Version {
		t.Fatal(w, err)
	}
	ghost, _ := newPrefixedID(prefixConnection, time.Now())
	if _, err := e.store.GetConnectionForWorker(ctx, ghost); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}

	// AfterLocks runs after the locks and an error rolls back everything
	tx, _ := e.pool.Begin(ctx)
	ran := false
	_, err = e.store.ActivateTx(ctx, tx, ActivateInput{Owner: f.A1, ConnectionID: c.ConnectionID, ExpectedVersion: c.Version,
		ExpectedInstallRevision: rev, ExpiresIn: time.Hour, Actor: workerActor,
		AfterLocks: func(context.Context, pgx.Tx) error { ran = true; return refuse(CodeRateLimited) }})
	_ = tx.Rollback(ctx)
	mustCode(t, err, CodeRateLimited)
	if !ran {
		t.Fatal("AfterLocks did not run")
	}
	if got, _ := e.store.GetConnection(ctx, f.A1, c.ConnectionID); got.State != PendingHandoff || got.Version != c.Version {
		t.Fatal("state moved")
	}

	// Connect AfterLocks: runs for a new insert, not for a replay
	calls := 0
	in := ConnectInput{Owner: f.A2, ExpectedInstallRevision: rev, IdempotencyKey: "al", Actor: userActor(f.A2),
		AfterLocks: func(context.Context, pgx.Tx) error { calls++; return nil }}
	for i := 0; i < 2; i++ {
		if _, err := e.store.Connect(ctx, in); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("AfterLocks ran %d times", calls)
	}
	in.IdempotencyKey = "al2" // refused by the unique index: AfterLocks error aborts first
	in.AfterLocks = func(context.Context, pgx.Tx) error { return refuse(CodeRateLimited) }
	_, err = e.store.Connect(ctx, in)
	mustCode(t, err, CodeRateLimited)

	// AppendRefusal writes one row for an existing entity, none for a foreign one
	before := e.auditCount(c.ConnectionID)
	re := RefusalEvent{TenantID: f.Alpha, EntityKind: "connection", EntityID: c.ConnectionID, Code: CodeStaleVersion, Actor: workerActor}
	if err := e.store.AppendRefusal(ctx, re); err != nil || e.auditCount(c.ConnectionID) != before+1 {
		t.Fatal(err)
	}
	re.TenantID = f.Beta
	if err := e.store.AppendRefusal(ctx, re); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	re.TenantID = f.Alpha
	re.Code = "made_up"
	mustCode(t, e.store.AppendRefusal(ctx, re), CodeInvalidRequest)
	re.Code, re.EntityKind, re.EntityID = CodeNoInstall, "install", ia.InstallID
	if err := e.store.AppendRefusal(ctx, re); err != nil {
		t.Fatal(err)
	}

	// expiry fence in a long transaction: the tx begins before expires_at,
	// reads after it, and still sees connection_expired (clock_timestamp()).
	f2 := newFixture(t)
	i2 := e.install(f2, f2.Alpha)
	c2 := e.connect(f2.A1, i2.InstallRevision, "k")
	act := e.activate(f2.A1, c2, i2.InstallRevision, 400*time.Millisecond)
	long, _ := e.pool.Begin(ctx)
	defer func() { _ = long.Rollback(ctx) }()
	if err := e.store.LockOwnerShared(ctx, long, f2.Alpha, f2.A1.PrincipalID); err != nil {
		t.Fatal(err)
	}
	live, err := e.store.LiveConnectionTx(ctx, long, f2.A1)
	if err != nil || live.ConnectionID != act.ConnectionID {
		t.Fatalf("before expiry: %v %v", live, err)
	}
	time.Sleep(600 * time.Millisecond)
	lapsed, err := e.store.LiveConnectionTx(ctx, long, f2.A1)
	mustCode(t, err, CodeConnectionExpired)
	if lapsed == nil || lapsed.ConnectionID != act.ConnectionID {
		t.Fatal("lapsed row missing")
	}
	_, err = e.store.LiveConnection(ctx, f2.A1)
	mustCode(t, err, CodeConnectionExpired)
}

func TestPurgeBothWays(t *testing.T) {
	var purged [][]string
	var purgeErr error
	purger := func(_ context.Context, _ pgx.Tx, ended []string) error {
		if purgeErr != nil {
			return purgeErr
		}
		purged = append(purged, append([]string(nil), ended...))
		return nil
	}
	ctx := context.Background()

	// without a purger: endings still work, Ready asks for one only when required
	e := newEnv(t)
	f := newFixture(t)
	ia := e.install(f, f.Alpha)
	c := e.connect(f.A1, ia.InstallRevision, "k")
	if _, err := e.store.Revoke(ctx, f.A1, userActor(f.A1), c.ConnectionID, "owner_request"); err != nil {
		t.Fatal(err)
	}
	if err := e.store.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	if e.store.EndPurgerInstalled() {
		t.Fatal("purger reported")
	}

	// required but missing
	e2 := newEnv(t, WithEndPurgerRequired(true))
	err := e2.store.Ready(ctx)
	var nr *NotReadyError
	if !errors.As(err, &nr) || nr.Reason != NotReadyPurger || !errors.Is(err, &Error{Code: CodeNotReady}) {
		t.Fatal(err)
	}

	// with a purger: called once with exactly the ended ids, an error rolls back
	e3 := newEnv(t, WithEndPurger(purger))
	f3 := newFixture(t)
	i3 := e3.install(f3, f3.Alpha)
	c3 := e3.connect(f3.A1, i3.InstallRevision, "k")
	purged = nil
	if _, err := e3.store.Revoke(ctx, f3.A1, userActor(f3.A1), c3.ConnectionID, "owner_request"); err != nil {
		t.Fatal(err)
	}
	if len(purged) != 1 || purged[0][0] != c3.ConnectionID {
		t.Fatalf("%v", purged)
	}
	c4 := e3.connect(f3.A1, i3.InstallRevision, "k2")
	purgeErr = errors.New("purge down")
	if _, err := e3.store.Revoke(ctx, f3.A1, userActor(f3.A1), c4.ConnectionID, "owner_request"); err == nil {
		t.Fatal("purger error swallowed")
	}
	if got, _ := e3.store.GetConnection(ctx, f3.A1, c4.ConnectionID); got.State != PendingHandoff {
		t.Fatal("ending survived a purger error")
	}
	purgeErr = nil
	// the purger runs before the hook
	var order []string
	e5 := newEnv(t,
		WithEndPurger(func(context.Context, pgx.Tx, []string) error { order = append(order, "purge"); return nil }),
		WithRevocationHook(func(context.Context, pgx.Tx, []string, string) error { order = append(order, "hook"); return nil }))
	f5 := newFixture(t)
	i5 := e5.install(f5, f5.Alpha)
	c5 := e5.connect(f5.A1, i5.InstallRevision, "k")
	if _, err := e5.store.Revoke(ctx, f5.A1, userActor(f5.A1), c5.ConnectionID, "owner_request"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(order, ",") != "purge,hook" {
		t.Fatal(order)
	}
}

// TestActorSources: every mutating method records the given actor; Transition
// has no default actor.
func TestActorSources(t *testing.T) {
	e := newEnv(t)
	f := newFixture(t)
	ctx := context.Background()
	admin := f.actorAdmin
	owner := Actor{PrincipalID: f.A1.PrincipalID, Kind: ActorOwner}
	actorOf := func(entity, event string) Actor {
		t.Helper()
		var a Actor
		var k string
		err := e.pool.QueryRow(ctx, `SELECT actor_principal_id, actor_kind FROM glovo.glovo_audit_events
 WHERE entity_id = $1 AND event = $2 ORDER BY recorded_at DESC LIMIT 1`, entity, event).Scan(&a.PrincipalID, &k)
		if err != nil {
			t.Fatalf("%s %s: %v", entity, event, err)
		}
		a.Kind = ActorKind(k)
		return a
	}
	ia, err := e.store.Install(ctx, f.Alpha, admin)
	if err != nil || actorOf(ia.InstallID, "install_created") != admin || ia.InstalledBy != admin.PrincipalID {
		t.Fatal(err)
	}
	cr, err := e.store.Connect(ctx, ConnectInput{Owner: f.A1, ExpectedInstallRevision: 1, IdempotencyKey: "k", Actor: owner})
	if err != nil {
		t.Fatal(err)
	}
	c := cr.Connection
	if actorOf(c.ConnectionID, "connection_connected") != owner {
		t.Fatal("connect actor")
	}
	// ActivateTx with a zero Actor and only the worker principal in ctx
	tx, _ := e.pool.Begin(ctx)
	act, err := e.store.ActivateTx(WithActor(ctx, workerActor), tx, ActivateInput{Owner: f.A1, ConnectionID: c.ConnectionID,
		ExpectedVersion: c.Version, ExpectedInstallRevision: 1, ExpiresIn: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	_ = tx.Commit(ctx)
	if actorOf(c.ConnectionID, "connection_active") != workerActor {
		t.Fatal("activate actor")
	}
	// ActivateTx with neither: invalid_request, nothing written
	tx, _ = e.pool.Begin(ctx)
	_, err = e.store.ActivateTx(ctx, tx, ActivateInput{Owner: f.A1, ConnectionID: c.ConnectionID, ExpectedVersion: act.Version,
		ExpectedInstallRevision: 1, ExpiresIn: time.Hour})
	_ = tx.Rollback(ctx)
	mustCode(t, err, CodeInvalidRequest)

	// Transition: no Actor and no worker principal is invalid_request and writes nothing
	n := e.auditCount(c.ConnectionID)
	_, err = e.store.Transition(ctx, f.A1, c.ConnectionID, Failed, act.Version, "x", nil)
	mustCode(t, err, CodeInvalidRequest)
	_, err = e.store.Transition(WithActor(ctx, Actor{PrincipalID: "system", Kind: ActorUser}), f.A1, c.ConnectionID, Failed, act.Version, "x", nil)
	mustCode(t, err, CodeInvalidRequest)
	if e.auditCount(c.ConnectionID) != n {
		t.Fatal("rejected transition wrote")
	}
	tr, err := e.store.Transition(WithActor(ctx, Actor{PrincipalID: "system", Kind: ActorSystem}), f.A1, c.ConnectionID, Expired, act.Version, "", nil)
	if err != nil || actorOf(c.ConnectionID, "connection_expired") != (Actor{PrincipalID: "system", Kind: ActorSystem}) {
		t.Fatal(tr, err)
	}

	// secondary events of RevokeInstall and Reinstall carry the caller's actor
	c2 := e.connect(f.A2, 1, "k")
	if _, _, err := e.store.Reinstall(ctx, f.Alpha, admin, 1); err != nil {
		t.Fatal(err)
	}
	if actorOf(c2.ConnectionID, "connection_revoked") != admin || actorOf(ia.InstallID, "install_reinstalled") != admin {
		t.Fatal("reinstall actors")
	}
	c3 := e.connect(f.A2, 2, "k2")
	if _, _, err := e.store.RevokeInstall(ctx, f.Alpha, owner, "admin_request", 2); err != nil {
		t.Fatal(err)
	}
	if actorOf(c3.ConnectionID, "connection_revoked") != owner || actorOf(ia.InstallID, "install_revoked") != owner {
		t.Fatal("revoke install actors")
	}
	// invalid actors: no write, no audit row
	bad := []Actor{{}, {PrincipalID: "", Kind: ActorUser}, {PrincipalID: "x", Kind: ActorUser}, {PrincipalID: "prn_1", Kind: "root"}}
	total := e.count(`SELECT count(*) FROM glovo.glovo_audit_events`)
	for _, a := range bad {
		_, err := e.store.Install(ctx, "tg959-other-"+randHex(3), a)
		mustCode(t, err, CodeInvalidRequest)
		_, err = e.store.Connect(ctx, ConnectInput{Owner: f.B1, ExpectedInstallRevision: 1, IdempotencyKey: "k", Actor: a})
		mustCode(t, err, CodeInvalidRequest)
		_, err = e.store.Revoke(ctx, f.A1, a, c.ConnectionID, "x")
		mustCode(t, err, CodeInvalidRequest)
		_, err = e.store.RevokeForMembership(ctx, f.Alpha, f.A1.PrincipalID, a)
		mustCode(t, err, CodeInvalidRequest)
		mustCode(t, e.store.AppendRefusal(ctx, RefusalEvent{TenantID: f.Alpha, EntityKind: "install", EntityID: ia.InstallID, Code: CodeNoInstall, Actor: a}), CodeInvalidRequest)
	}
	if e.count(`SELECT count(*) FROM glovo.glovo_audit_events`) != total {
		t.Fatal("invalid actor wrote an audit row")
	}
	// the actor_kind CHECK is the second line
	if _, err := e.pool.Exec(ctx, `INSERT INTO glovo.glovo_audit_events (event_id, tenant_id, actor_principal_id, actor_kind, entity_kind, entity_id, event, to_state, install_revision, recorded_at)
 VALUES ('gae_x', 't', 'a', 'root', 'install', 'i', 'e', 's', 1, now())`); err == nil {
		t.Fatal("actor_kind CHECK missing")
	}
}

// TestTypedNotLiveCodes covers LiveConnection and LiveConnectionTx.
func TestTypedNotLiveCodes(t *testing.T) {
	e := newEnv(t)
	f := newFixture(t)
	ctx := context.Background()
	ia := e.install(f, f.Alpha)
	rev := ia.InstallRevision
	both := func(o Owner, want Code, wantRow bool, wantState ConnectionState) {
		t.Helper()
		tx, _ := e.pool.Begin(ctx)
		defer func() { _ = tx.Rollback(ctx) }()
		for name, fn := range map[string]func() (*Connection, error){
			"pool": func() (*Connection, error) { return e.store.LiveConnection(ctx, o) },
			"tx":   func() (*Connection, error) { return e.store.LiveConnectionTx(ctx, tx, o) },
		} {
			c, err := fn()
			if want == "" {
				if err != nil || c == nil || c.State != wantState {
					t.Fatalf("%s: %+v %v", name, c, err)
				}
				continue
			}
			mustCode(t, err, want)
			if (c != nil) != wantRow || (c != nil && c.State != wantState) {
				t.Fatalf("%s: row %+v", name, c)
			}
		}
	}
	both(f.A1, CodeNoConnection, false, "")

	c := e.connect(f.A1, rev, "k")
	both(f.A1, "", true, PendingHandoff)
	both(f.A2, CodeNoConnection, false, "") // another owner's row is never returned
	both(f.B1, CodeNoConnection, false, "")

	f1, _ := e.store.Transition(workerCtx(), f.A1, c.ConnectionID, Failed, c.Version, "", nil)
	both(f.A1, CodeNoConnection, true, Failed)

	c = e.connect(f.A1, rev, "k2")
	r, _ := e.store.Revoke(ctx, f.A1, userActor(f.A1), c.ConnectionID, "owner_request")
	both(f.A1, CodeConnectionRevoked, true, Revoked)

	// revoked then reconnected: the new live row, not connection_revoked
	rc, err := e.store.Reconnect(ctx, ConnectInput{Owner: f.A1, ExpectedInstallRevision: rev, IdempotencyKey: "rc",
		Actor: userActor(f.A1), TerminalOnly: true}, r.ConnectionID)
	if err != nil {
		t.Fatal(err)
	}
	both(f.A1, "", true, PendingHandoff)
	_ = f1

	// expired by state and by clock
	e.activate(f.A1, rc.Connection, rev, 80*time.Millisecond)
	both(f.A1, "", true, Active)
	time.Sleep(200 * time.Millisecond)
	both(f.A1, CodeConnectionExpired, true, Active)
	if _, err := e.store.Transition(workerCtx(), f.A1, rc.Connection.ConnectionID, Expired, rc.Connection.Version+2, "", nil); err != nil {
		t.Fatal(err)
	}
	both(f.A1, CodeConnectionExpired, true, Expired)
}

// TestLiveReadIsOneStatementAndOrderedByLockOrder: one statement, and the
// two-writer case where created_at is the database wall clock after L2.
func TestLiveReadIsOneStatementAndOrderedByLockOrder(t *testing.T) {
	e := newEnv(t)
	f := newFixture(t)
	ctx := context.Background()
	ia := e.install(f, f.Alpha)
	rev := ia.InstallRevision
	e.connect(f.A1, rev, "k")

	tr := &stmtTracer{}
	pool := tracedPool(t, e, tr)
	st, err := NewStore(ctx, pool, e.rt, e.mig, WithExplicitURL(true))
	if err != nil {
		t.Fatal(err)
	}
	tr.reset()
	if _, err := st.LiveConnection(ctx, f.A1); err != nil {
		t.Fatal(err)
	}
	if n := len(tr.snapshot()); n != 1 {
		t.Fatalf("%d statements: %v", n, tr.snapshot())
	}

	// two writers: A begins first, B connects and revokes and commits, then A
	// takes the locks and inserts. A's row is the most recent.
	f2 := newFixture(t)
	i2 := e.install(f2, f2.Alpha)
	release := make(chan struct{})
	entered := make(chan struct{})
	var once sync.Once
	e.store.beforeL2 = func() {
		once.Do(func() { close(entered); <-release })
	}
	done := make(chan error, 1)
	var aID string
	go func() {
		r, err := e.store.Connect(ctx, ConnectInput{Owner: f2.A1, ExpectedInstallRevision: i2.InstallRevision, IdempotencyKey: "A", Actor: userActor(f2.A1)})
		if err == nil {
			aID = r.Connection.ConnectionID
		}
		done <- err
	}()
	<-entered
	e.store.beforeL2 = nil
	b := e.connect(f2.A1, i2.InstallRevision, "B")
	if _, err := e.store.Revoke(ctx, f2.A1, userActor(f2.A1), b.ConnectionID, "owner_request"); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	live, err := e.store.LiveConnection(ctx, f2.A1)
	if err != nil || live.ConnectionID != aID {
		t.Fatalf("got %v %v want %s", live, err, aID)
	}
}

func TestTxScopedMethodsDoNotBeginOrCommit(t *testing.T) {
	e := newEnv(t)
	f := newFixture(t)
	ctx := context.Background()
	ia := e.install(f, f.Alpha)
	c := e.connect(f.A1, ia.InstallRevision, "k")
	tr := &stmtTracer{}
	pool := tracedPool(t, e, tr)
	st, err := NewStore(ctx, pool, e.rt, e.mig, WithExplicitURL(true))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tr.reset()
	if err := st.LockOwnerShared(ctx, tx, f.Alpha, f.A1.PrincipalID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.LiveConnectionTx(ctx, tx, f.A1); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ActivateTx(ctx, tx, ActivateInput{Owner: f.A1, ConnectionID: c.ConnectionID, ExpectedVersion: c.Version,
		ExpectedInstallRevision: ia.InstallRevision, ExpiresIn: time.Hour, Actor: workerActor}); err != nil {
		t.Fatal(err)
	}
	for _, s := range tr.snapshot() {
		l := strings.ToLower(strings.TrimSpace(s))
		if strings.HasPrefix(l, "begin") || strings.HasPrefix(l, "commit") || strings.HasPrefix(l, "rollback") || strings.HasPrefix(l, "savepoint") {
			t.Fatalf("tx-scoped method issued %q", s)
		}
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
}

// TestNoSecretsOrPIIInRowsOrLogs scans every fixture, connection row and
// audit row for secret-shaped values and emails.
func TestNoSecretsOrPIIInRowsOrLogs(t *testing.T) {
	e := newEnv(t)
	f := newFixture(t)
	ctx := context.Background()
	ia := e.install(f, f.Alpha)
	c := e.connect(f.A1, ia.InstallRevision, "k")
	act := e.activate(f.A1, c, ia.InstallRevision, time.Hour)
	if _, err := e.store.Revoke(ctx, f.A1, userActor(f.A1), act.ConnectionID, "owner_request"); err != nil {
		t.Fatal(err)
	}
	evs, _ := e.store.ListAudit(ctx, f.Alpha, c.ConnectionID)
	rows, _ := e.store.GetConnection(ctx, f.A1, c.ConnectionID)
	insts, _ := e.store.GetInstall(ctx, f.Alpha)
	for _, v := range []any{f, evs, rows, insts, ia} {
		b := fmt.Sprintf("%+v", v)
		if strings.Contains(b, "@") {
			t.Fatalf("email-shaped value in %s", b)
		}
		if p, found := scanSecret([]byte(b)); found {
			t.Fatalf("secret-shaped value (%s) in %s", p, b)
		}
	}
}

func TestInstallIsIdempotentAndMintedServerSide(t *testing.T) {
	e := newEnv(t)
	f := newFixture(t)
	ctx := context.Background()
	a, err := e.store.Install(ctx, f.Alpha, f.actorAdmin)
	if err != nil || !strings.HasPrefix(a.InstallID, "gin_") || a.InstallRevision != 1 {
		t.Fatal(a, err)
	}
	b, err := e.store.Install(ctx, f.Alpha, f.actorAdmin)
	if err != nil || b.InstallID != a.InstallID || e.auditCount(a.InstallID) != 1 {
		t.Fatal(b, err)
	}
	mustCode(t, func() error { _, err := e.store.Install(ctx, "", f.actorAdmin); return err }(), CodeInvalidRequest)
}

// TestGetConnectionForWorkerHasNoOtherCaller: the read by id with no owner
// predicate may be called only from the worker handlers.
func TestGetConnectionForWorkerHasNoOtherCaller(t *testing.T) {
	root := "../.."
	var offenders []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "node_modules" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		slash := filepath.ToSlash(path)
		if strings.HasSuffix(slash, "internal/glovo/connection.go") || strings.HasSuffix(slash, "internal/api/handlers_glovo_worker.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), "GetConnectionForWorker(") {
			offenders = append(offenders, slash)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Fatalf("GetConnectionForWorker called outside handlers_glovo_worker.go: %v", offenders)
	}
}

// TestStoreLogsNothing: the store writes no log line, so no identifier or
// secret-shaped value can reach one.
func TestStoreLogsNothing(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })
	e := newEnv(t)
	f := newFixture(t)
	ia := e.install(f, f.Alpha)
	c := e.connect(f.A1, ia.InstallRevision, "k")
	if _, err := e.store.Revoke(context.Background(), f.A1, userActor(f.A1), c.ConnectionID, "owner_request"); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		if p, found := scanSecret(buf.Bytes()); found {
			t.Fatalf("secret-shaped log output (%s)", p)
		}
		t.Fatalf("the store logged: %s", buf.String())
	}
}
