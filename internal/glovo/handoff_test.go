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
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

func newHandoffEnv(t *testing.T) (*env, fixture, *Install) {
	t.Helper()
	e := newEnv(t, WithEndPurger(PurgeHandoffRefs), WithEndPurgerRequired(true))
	f := newFixture(t)
	return e, f, e.install(f, f.Alpha)
}

// The raw reference is never stored: only its SHA-256 is.
func TestHandoffStoresOnlyTheHash(t *testing.T) {
	e, f, inst := newHandoffEnv(t)
	ctx := context.Background()
	c := e.connect(f.A1, inst.InstallRevision, "k1")
	issue, err := e.store.IssueHandoff(ctx, f.A1, c.ConnectionID, f.actorA1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(issue.Ref, "ghr_") || len(issue.Ref) != 4+64 {
		t.Fatalf("ref shape %q", issue.Ref)
	}
	if n := e.count(`SELECT count(*) FROM glovo.glovo_handoff_refs WHERE ref_hash = $1`, HandoffRefHash(issue.Ref)); n != 1 {
		t.Fatalf("hash row: %d", n)
	}
	// No column of the table, nor any audit row, holds the raw value.
	if n := e.count(`SELECT count(*) FROM glovo.glovo_handoff_refs h WHERE h::text LIKE '%' || $1 || '%'`, issue.Ref); n != 0 {
		t.Fatal("the raw reference is stored")
	}
	if n := e.count(`SELECT count(*) FROM glovo.glovo_audit_events a WHERE a::text LIKE '%' || $1 || '%'`, issue.Ref); n != 0 {
		t.Fatal("the raw reference is audited")
	}
	// A second issue deletes the older unconsumed row.
	if _, err := e.store.IssueHandoff(ctx, f.A1, c.ConnectionID, f.actorA1); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM glovo.glovo_handoff_refs WHERE connection_id = $1`, c.ConnectionID); n != 1 {
		t.Fatalf("rows after reissue: %d", n)
	}
	// A foreign owner cannot issue.
	_, err = e.store.IssueHandoff(ctx, f.A2, c.ConnectionID, userActor(f.A2))
	mustCode(t, err, CodeNotFound)
}

// Two workers consume one reference at once: exactly one activation.
func TestHandoffConcurrentConsumeActivatesOnce(t *testing.T) {
	e, f, inst := newHandoffEnv(t)
	ctx := context.Background()
	for round := 0; round < 5; round++ {
		c := e.connect(f.A1, inst.InstallRevision, "k"+string(rune('a'+round)))
		issue, err := e.store.IssueHandoff(ctx, f.A1, c.ConnectionID, f.actorA1)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		errs := make([]error, 4)
		for i := range errs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = e.store.ActivateWithHandoff(ctx, ActivateInput{Owner: f.A1, ConnectionID: c.ConnectionID, ExpectedVersion: c.Version,
					ExpectedInstallRevision: inst.InstallRevision, ExpiresIn: time.Hour, Actor: workerActor}, issue.Ref)
			}()
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			if err == nil {
				ok++
			}
		}
		if ok != 1 {
			t.Fatalf("round %d: %d activations succeeded: %v", round, ok, errs)
		}
		if n := e.count(`SELECT count(*) FROM glovo.glovo_audit_events WHERE entity_id = $1 AND event = 'connection_active'`, c.ConnectionID); n != 1 {
			t.Fatalf("round %d: %d active events", round, n)
		}
		if _, err := e.store.Revoke(ctx, f.A1, f.actorA1, c.ConnectionID, "user_revoked"); err != nil {
			t.Fatal(err)
		}
	}
}

// Revoking a connection purges its unconsumed references, so a revoke that wins
// leaves nothing to activate with.
func TestHandoffRevokePurgesUnconsumed(t *testing.T) {
	e, f, inst := newHandoffEnv(t)
	ctx := context.Background()
	c := e.connect(f.A1, inst.InstallRevision, "k1")
	issue, err := e.store.IssueHandoff(ctx, f.A1, c.ConnectionID, f.actorA1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.Revoke(ctx, f.A1, f.actorA1, c.ConnectionID, "user_revoked"); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM glovo.glovo_handoff_refs WHERE connection_id = $1`, c.ConnectionID); n != 0 {
		t.Fatalf("%d references survive the revoke", n)
	}
	_, err = e.store.ActivateWithHandoff(ctx, ActivateInput{Owner: f.A1, ConnectionID: c.ConnectionID, ExpectedVersion: c.Version + 1,
		ExpectedInstallRevision: inst.InstallRevision, ExpiresIn: time.Hour, Actor: workerActor}, issue.Ref)
	mustCode(t, err, CodeConnectionRevoked)
	// Reinstall purges too.
	c2 := e.connect(f.A1, inst.InstallRevision, "k2")
	if _, err := e.store.IssueHandoff(ctx, f.A1, c2.ConnectionID, f.actorA1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.store.Reinstall(ctx, f.Alpha, f.actorAdmin, inst.InstallRevision); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM glovo.glovo_handoff_refs WHERE connection_id = $1`, c2.ConnectionID); n != 0 {
		t.Fatalf("%d references survive the reinstall", n)
	}
}

// ConnectLimits creates the mutex row, Sweep never deletes it, and an upsert of
// the hourly counter cannot exceed the budget.
func TestConnectLimitsAndSweep(t *testing.T) {
	e, f, inst := newHandoffEnv(t)
	ctx := context.Background()
	in := func(key string) ConnectInput {
		return ConnectInput{Owner: f.A1, ExpectedInstallRevision: inst.InstallRevision, IdempotencyKey: key, Actor: f.actorA1,
			AfterLocks: e.store.ConnectLimits(f.A1)}
	}
	for i := 0; i < MaxConnectsPerHour; i++ {
		r, err := e.store.Connect(ctx, in("k"+string(rune('a'+i))))
		if err != nil {
			t.Fatalf("connect %d: %v", i, err)
		}
		if _, err := e.store.Revoke(ctx, f.A1, f.actorA1, r.Connection.ConnectionID, "user_revoked"); err != nil {
			t.Fatal(err)
		}
	}
	_, err := e.store.Connect(ctx, in("over"))
	mustCode(t, err, CodeRateLimited)
	if n := e.count(`SELECT count FROM glovo.glovo_rate_counters WHERE scope = 'owner_hour' AND principal_id = $1`, f.A1.PrincipalID); n != MaxConnectsPerHour {
		t.Fatalf("counter %d", n)
	}
	if n := e.count(`SELECT count(*) FROM glovo.glovo_rate_counters WHERE scope = 'tenant_mutex' AND tenant_id = $1`, f.Alpha); n != 1 {
		t.Fatalf("mutex rows %d", n)
	}
	res, err := e.store.Sweep(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if res.Counters != 0 { // the window is the current hour
		t.Fatalf("sweep deleted a current window: %+v", res)
	}
	e.adminExec(`UPDATE glovo.glovo_rate_counters SET window_start = clock_timestamp() - interval '5 hours' WHERE scope = 'owner_hour'`)
	if res, err = e.store.Sweep(ctx, 10); err != nil || res.Counters != 1 {
		t.Fatalf("sweep: %+v %v", res, err)
	}
	if n := e.count(`SELECT count(*) FROM glovo.glovo_rate_counters WHERE scope = 'tenant_mutex' AND tenant_id = $1`, f.Alpha); n != 1 {
		t.Fatal("sweep deleted the tenant mutex row")
	}
	if _, err := e.store.Sweep(ctx, 0); err == nil {
		t.Fatal("a zero limit must be refused")
	}
}

func TestAsErrorMapsToTheClosedSet(t *testing.T) {
	if AsError(refuse(CodeStaleVersion)).Code != CodeStaleVersion {
		t.Fatal("typed refusal changed")
	}
	if AsError(notReady(NotReadyHook)).Code != CodeNotReady {
		t.Fatal("not ready")
	}
	if AsError(context.DeadlineExceeded).Code != CodeUnavailable {
		t.Fatal("a failure must be unavailable")
	}
}
