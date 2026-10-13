// Copyright 2025 MCTL Authors
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

package gitops

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// withinDeadline runs read and fails the test if it does not return
// promptly: a principal-keyed read that waited for the checkout would hang
// here rather than answer.
func withinDeadline(t *testing.T, what string, read func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); read() }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s waited for the checkout", what)
	}
}

// While a refresh holds the checkout, the principal-keyed readers answer
// from the snapshot of the last sync instead of queueing behind git.
func TestPrincipalReadsNeverWaitForARefresh(t *testing.T) {
	dir, r := syncedRepo(t)
	writeTenantYAML(t, dir, "acme", keyedAcmeYAML)
	r.snapshotPrincipals()

	r.mu.Lock() // a refresh in progress
	defer r.mu.Unlock()
	withinDeadline(t, "NamespacesForPrincipal", func() {
		m, err := r.NamespacesForPrincipal(prnBob)
		if err != nil || !reflect.DeepEqual(m.Namespaces, []string{"acme-web"}) {
			t.Errorf("NamespacesForPrincipal = %+v, %v; want [acme-web]", m, err)
		}
	})
	withinDeadline(t, "TryNamespacesForPrincipal", func() {
		m, ok, err := r.TryNamespacesForPrincipal(prnBob)
		if !ok || err != nil || !reflect.DeepEqual(m.Namespaces, []string{"acme-web"}) {
			t.Errorf("TryNamespacesForPrincipal = %+v, %v, %v; want [acme-web]", m, ok, err)
		}
	})
	withinDeadline(t, "MemberRolesForPrincipal", func() {
		roles, err := r.MemberRolesForPrincipal("acme-web", prnBob)
		if err != nil || !reflect.DeepEqual(roles, [][]string{{"developer"}}) {
			t.Errorf("MemberRolesForPrincipal = %q, %v; want [[developer]]", roles, err)
		}
	})
}

// With no snapshot to answer from and the checkout held, nothing was read:
// that is "not observed", never "no tenants" or "not a member".
func TestPrincipalReadsWithoutASnapshotAreNotObserved(t *testing.T) {
	dir, r := syncedRepo(t)
	writeTenantYAML(t, dir, "acme", keyedAcmeYAML)

	r.mu.Lock()
	defer r.mu.Unlock()
	withinDeadline(t, "reads", func() {
		if _, ok, err := r.TryNamespacesForPrincipal(prnBob); ok || err != nil {
			t.Errorf("TryNamespacesForPrincipal answered: %v, %v", ok, err)
		}
		if _, err := r.NamespacesForPrincipal(prnBob); !errors.Is(err, errMembershipNotObserved) {
			t.Errorf("NamespacesForPrincipal: %v, want not observed", err)
		}
		if _, err := r.MemberRolesForPrincipal("acme-web", prnBob); !errors.Is(err, errMembershipNotObserved) {
			t.Errorf("MemberRolesForPrincipal: %v, want not observed", err)
		}
	})
}

// A new sync is read on the next request even if RefreshLoop has not
// rebuilt the snapshot, and an old snapshot is judged by its own sync: one
// that has gone stale does not pass because a later sync happened.
func TestPrincipalSnapshotFollowsTheSync(t *testing.T) {
	dir, r := syncedRepo(t)
	writeTenantYAML(t, dir, "acme", keyedAcmeYAML)
	if m, err := r.NamespacesForPrincipal(prnNone); err != nil || len(m.Namespaces) != 0 {
		t.Fatalf("got %+v, %v; want no namespaces", m, err)
	}
	writeTenantYAML(t, dir, "beta", "tenant:\n  name: beta\n  members:\n    - principalId: "+prnNone+"\n      role: owner\n")
	r.lastSync.Store(time.Now().UnixNano()) // the sync that wrote beta
	if m, err := r.NamespacesForPrincipal(prnNone); err != nil || !reflect.DeepEqual(m.Namespaces, []string{"beta"}) {
		t.Fatalf("a new sync was not read: %+v, %v", m, err)
	}

	r.lastSync.Store(time.Now().Add(-CheckoutMaxAge - time.Minute).UnixNano())
	if _, err := r.NamespacesForPrincipal(prnNone); err == nil {
		t.Fatal("a stale checkout answered")
	}
	// A later sync lands while the checkout is still held: the stale
	// snapshot is all there is, and it must not answer.
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastSync.Store(time.Now().UnixNano())
	withinDeadline(t, "reads", func() {
		if _, err := r.NamespacesForPrincipal(prnNone); err == nil {
			t.Error("a stale snapshot answered for a later sync")
		}
		if _, err := r.MemberRolesForPrincipal("beta", prnNone); err == nil {
			t.Error("a stale snapshot answered roles for a later sync")
		}
	})
}

// RefreshLoop builds the snapshot right after a successful sync, so a
// request arriving during the next refresh still has one to answer from.
func TestRefreshLoopBuildsThePrincipalSnapshot(t *testing.T) {
	root := t.TempDir()
	remote := filepath.Join(root, "remote.git")
	work := filepath.Join(root, "work")
	runGit(t, root, "init", "--bare", remote)
	runGit(t, root, "clone", remote, work)
	runGit(t, work, "checkout", "-b", "main")
	runGit(t, work, "config", "user.email", "test@example.com")
	runGit(t, work, "config", "user.name", "Test User")
	writeTenantYAML(t, work, "acme", keyedAcmeYAML)
	commitAll(t, work, "acme")
	runGit(t, work, "push", "origin", "main")

	r := &Reader{repoURL: remote, branch: "main", localPath: filepath.Join(root, "cache")}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the initial sync only
	r.RefreshLoop(ctx, time.Hour)

	s := r.principals.Load()
	if s == nil || s.syncedAt != r.lastSync.Load() || s.syncedAt == 0 {
		t.Fatalf("no snapshot for the sync: %+v", s)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	withinDeadline(t, "NamespacesForPrincipal", func() {
		if m, err := r.NamespacesForPrincipal(prnBob); err != nil || !reflect.DeepEqual(m.Namespaces, []string{"acme-web"}) {
			t.Errorf("got %+v, %v; want [acme-web]", m, err)
		}
	})
}
