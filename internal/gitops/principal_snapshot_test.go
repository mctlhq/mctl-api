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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// withinDeadline runs read and fails the test if it does not return
// promptly: a principal-keyed read that waited for the checkout would hang
// here rather than answer. read reports through errorf, never t: a read
// still blocked when the test returns must not log afterwards, which the
// testing package turns into a panic that hides this failure.
func withinDeadline(t *testing.T, what string, read func(errorf func(string, ...any))) {
	t.Helper()
	var errs []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		read(func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) })
	}()
	select {
	case <-done:
		for _, e := range errs {
			t.Error(e)
		}
	case <-time.After(2 * time.Second):
		t.Errorf("%s waited for the checkout", what)
	}
}

// While a refresh holds the checkout, the principal-keyed readers answer
// from the snapshot of the last sync instead of queueing behind git.
func TestPrincipalReadsNeverWaitForARefresh(t *testing.T) {
	dir, r := syncedRepo(t)
	writeTenantYAML(t, dir, "acme", keyedAcmeYAML)
	r.principalView() // the snapshot of this sync

	r.mu.Lock() // a refresh in progress
	defer r.mu.Unlock()
	withinDeadline(t, "NamespacesForPrincipal", func(errorf func(string, ...any)) {
		m, err := r.NamespacesForPrincipal(prnBob)
		if err != nil || !reflect.DeepEqual(m.Namespaces, []string{"acme-web"}) {
			errorf("NamespacesForPrincipal = %+v, %v; want [acme-web]", m, err)
		}
	})
	withinDeadline(t, "TryNamespacesForPrincipal", func(errorf func(string, ...any)) {
		m, ok, err := r.TryNamespacesForPrincipal(prnBob)
		if !ok || err != nil || !reflect.DeepEqual(m.Namespaces, []string{"acme-web"}) {
			errorf("TryNamespacesForPrincipal = %+v, %v, %v; want [acme-web]", m, ok, err)
		}
	})
	withinDeadline(t, "MemberRolesForPrincipal", func(errorf func(string, ...any)) {
		roles, err := r.MemberRolesForPrincipal("acme-web", prnBob)
		if err != nil || !reflect.DeepEqual(roles, [][]string{{"developer"}}) {
			errorf("MemberRolesForPrincipal = %q, %v; want [[developer]]", roles, err)
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
	withinDeadline(t, "reads", func(errorf func(string, ...any)) {
		if _, ok, err := r.TryNamespacesForPrincipal(prnBob); ok || err != nil {
			errorf("TryNamespacesForPrincipal answered: %v, %v", ok, err)
		}
		if _, err := r.NamespacesForPrincipal(prnBob); !errors.Is(err, errMembershipNotObserved) {
			errorf("NamespacesForPrincipal: %v, want not observed", err)
		}
		if _, err := r.MemberRolesForPrincipal("acme-web", prnBob); !errors.Is(err, errMembershipNotObserved) {
			errorf("MemberRolesForPrincipal: %v, want not observed", err)
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
	withinDeadline(t, "reads", func(errorf func(string, ...any)) {
		if _, err := r.NamespacesForPrincipal(prnNone); err == nil {
			errorf("a stale snapshot answered for a later sync")
		}
		if _, err := r.MemberRolesForPrincipal("beta", prnNone); err == nil {
			errorf("a stale snapshot answered roles for a later sync")
		}
	})
}

// refresh builds the snapshot of its sync before releasing the checkout,
// so a request arriving during the next refresh still has one to answer
// from, and none has to build one for the new sync.
func TestRefreshBuildsThePrincipalSnapshot(t *testing.T) {
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
	if err := r.refresh(); err != nil {
		t.Fatal(err)
	}

	s := r.principals.Load()
	if s == nil || s.syncedAt != r.lastSync.Load() || s.syncedAt == 0 {
		t.Fatalf("no snapshot for the sync: %+v", s)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	withinDeadline(t, "NamespacesForPrincipal", func(errorf func(string, ...any)) {
		if m, err := r.NamespacesForPrincipal(prnBob); err != nil || !reflect.DeepEqual(m.Namespaces, []string{"acme-web"}) {
			errorf("got %+v, %v; want [acme-web]", m, err)
		}
	})
}

// A read error that may be transient is not kept until the next sync: the
// next read builds again and answers.
func TestPrincipalSnapshotDoesNotKeepAnIOError(t *testing.T) {
	t.Run("listing", func(t *testing.T) {
		dir, r := syncedRepo(t)
		tenants := filepath.Join(dir, "platform-gitops", "tenants")
		if err := os.RemoveAll(tenants); err != nil {
			t.Fatal(err)
		}
		if _, err := r.NamespacesForPrincipal(prnBob); err == nil {
			t.Fatal("an unlistable tenants dir answered")
		}
		writeTenantYAML(t, dir, "acme", keyedAcmeYAML) // same sync
		if m, err := r.NamespacesForPrincipal(prnBob); err != nil || !reflect.DeepEqual(m.Namespaces, []string{"acme-web"}) {
			t.Fatalf("listing error kept: %+v, %v", m, err)
		}
	})
	t.Run("tenant file", func(t *testing.T) {
		dir, r := syncedRepo(t)
		writeTenantYAML(t, dir, "acme", keyedAcmeYAML)
		values := filepath.Join(dir, "platform-gitops", "tenants", "acme", "values.yaml")
		if err := os.Chmod(values, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := r.MemberRolesForPrincipal("acme-web", prnBob); err == nil {
			t.Skip("values.yaml readable at mode 0 (running as root)")
		}
		if err := os.Chmod(values, 0o600); err != nil {
			t.Fatal(err)
		}
		if roles, err := r.MemberRolesForPrincipal("acme-web", prnBob); err != nil || !reflect.DeepEqual(roles, [][]string{{"developer"}}) {
			t.Fatalf("read error kept: %q, %v", roles, err)
		}
	})
	t.Run("parse error is kept", func(t *testing.T) {
		dir, r := syncedRepo(t)
		writeTenantYAML(t, dir, "acme", "tenant: [")
		if _, err := r.MemberRolesForPrincipal("acme-web", prnBob); err == nil {
			t.Fatal("an unparsable tenant answered")
		}
		if s := r.principals.Load(); s == nil || s.syncedAt != r.lastSync.Load() {
			t.Fatal("a snapshot with only a parse error was not kept")
		}
	})
}

// A request-path build never replaces a snapshot stored after the one it
// started from: that one is from a newer sync.
func TestOfferSnapshotKeepsANewerOne(t *testing.T) {
	_, r := syncedRepo(t)
	seen := &principalSnapshot{syncedAt: 1}
	newer := &principalSnapshot{syncedAt: 3}
	r.principals.Store(newer)
	r.offerSnapshot(seen, &principalSnapshot{syncedAt: 2})
	if got := r.principals.Load(); got != newer {
		t.Fatalf("an older snapshot replaced a newer one: %+v", got)
	}
	r.principals.Store(seen)
	fresh := &principalSnapshot{syncedAt: 2}
	r.offerSnapshot(seen, fresh)
	if got := r.principals.Load(); got != fresh {
		t.Fatalf("the snapshot it started from was not replaced: %+v", got)
	}
}

// A sync whose snapshot hit an I/O error does not store it: the snapshot
// of the previous sync stays, and the next read builds again.
func TestRefreshDoesNotKeepAnIOError(t *testing.T) {
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
	if err := r.refresh(); err != nil {
		t.Fatal(err)
	}
	good := r.principals.Load()
	if good == nil {
		t.Fatal("no snapshot for a healthy sync")
	}

	// values.yaml as a directory: reading it fails with an *fs.PathError
	// (EISDIR), the I/O class, on every platform and as root too.
	broken := filepath.Join(work, "platform-gitops", "tenants", "broken", "values.yaml")
	if err := os.MkdirAll(broken, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(broken, "keep"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	commitAll(t, work, "broken")
	runGit(t, work, "push", "origin", "main")
	if err := r.refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if got := r.principals.Load(); got != good {
		t.Fatalf("a snapshot with an I/O error was stored: %+v", got)
	}
	if _, err := r.MemberRolesForPrincipal("acme-web", prnBob); err == nil {
		t.Fatal("an unreadable tenant did not fail the role read")
	}
}
