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
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Principal-keyed membership is read on every request in principal mode
// (mctl-api#377), so it must never queue behind a refresh: refresh() holds
// the write lock across git subprocesses, and a slow or hung fetch would
// otherwise stall every request. The readers answer from an immutable
// snapshot of the parsed tenants instead, built once per successful sync and
// swapped in atomically.

// principalSnapshot is every tenant as one sync left them on disk.
type principalSnapshot struct {
	// syncedAt is the lastSync value of the sync this snapshot was read
	// from (0: never synced). Freshness is judged by it, not by the
	// reader's latest sync, so an old snapshot cannot pass for a new one.
	syncedAt int64
	// listErr is why the tenants directory could not be listed. Every read
	// then fails: "could not list" is never "no tenants".
	listErr error
	tenants []snapshotTenant
}

type snapshotTenant struct {
	dir string
	t   *Tenant
	err error // why values.yaml could not be read or parsed
}

// errMembershipNotObserved: no snapshot exists for the current sync and a
// refresh holds the checkout, so nothing was read. It is "not observed",
// never "not a member".
var errMembershipNotObserved = errors.New("gitops membership not observed: a refresh holds the checkout and no snapshot is loaded")

// snapshotPrincipalsLocked reads every tenant into a new snapshot. The
// caller holds r.mu (read or write).
func (r *Reader) snapshotPrincipalsLocked() *principalSnapshot {
	s := &principalSnapshot{syncedAt: r.lastSync.Load()}
	entries, err := os.ReadDir(filepath.Join(r.localPath, "platform-gitops", "tenants"))
	if err != nil {
		s.listErr = fmt.Errorf("reading tenants dir: %w", err)
		return s
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		t, err := r.readTenant(entry.Name())
		if errors.Is(err, fs.ErrNotExist) {
			// No values.yaml: not a tenant.
			continue
		}
		s.tenants = append(s.tenants, snapshotTenant{dir: entry.Name(), t: t, err: err})
	}
	return s
}

// cacheable reports whether s may be kept until the next sync. A read
// error that may be transient (listing the directory, or reading a file)
// must not be: a kept snapshot answers every read until the next sync, so a
// one-off EIO or EMFILE would fail them all. Left unstored, the next read
// builds again. A parse error is a property of the commit and is kept.
func (s *principalSnapshot) cacheable() bool {
	if s.listErr != nil {
		return false
	}
	for _, st := range s.tenants {
		var pe *fs.PathError
		if st.err != nil && errors.As(st.err, &pe) {
			return false
		}
	}
	return true
}

// offerSnapshot stores fresh in place of seen, the snapshot its builder
// started from, unless another one was stored meanwhile: that one is from
// a sync at least as new (refresh stores under the write lock, which a
// build under the read lock precedes), and replacing it would bring an
// older snapshot back.
func (r *Reader) offerSnapshot(seen, fresh *principalSnapshot) {
	if fresh.cacheable() {
		r.principals.CompareAndSwap(seen, fresh)
	}
}

// principalView is the snapshot for the current sync. refresh() builds it
// under the write lock together with lastSync, so a request normally finds
// it; it is built here only when there is none for the last sync (startup,
// or the last build was not cacheable), and only when the checkout is free.
// While a refresh holds it, the previous snapshot answers; with none at
// all, ok is false. It never waits.
func (r *Reader) principalView() (s *principalSnapshot, ok bool) {
	s = r.principals.Load()
	if s != nil && s.syncedAt == r.lastSync.Load() {
		return s, true
	}
	if !r.mu.TryRLock() {
		return s, s != nil
	}
	fresh := r.snapshotPrincipalsLocked()
	r.mu.RUnlock()
	r.offerSnapshot(s, fresh)
	return fresh, true
}

// check is checkFreshLocked for this snapshot's own sync, and the listing
// error.
func (s *principalSnapshot) check() error {
	if s.syncedAt == 0 {
		return errors.New("gitops checkout has never synced")
	}
	if age := time.Since(time.Unix(0, s.syncedAt)); age > CheckoutMaxAge {
		return fmt.Errorf("gitops checkout last synced %s ago (limit %s)", age.Round(time.Second), CheckoutMaxAge)
	}
	return s.listErr
}

func (s *principalSnapshot) namespacesForPrincipal(principalID string) (PrincipalMembership, error) {
	if err := s.check(); err != nil {
		return PrincipalMembership{}, err
	}
	var out PrincipalMembership
	for _, st := range s.tenants {
		if st.err != nil || st.t.principalErr != nil {
			out.Unreadable = append(out.Unreadable, st.dir)
			continue
		}
		out.Namespaces = append(out.Namespaces, st.t.PrincipalNamespaces(principalID)...)
	}
	sort.Strings(out.Namespaces)
	return out, nil
}

// memberRolesForPrincipal is memberRolesMatching(byPrincipal) over the
// snapshot: a tenant that could not be read may own the namespace, so it
// fails the read rather than being skipped.
func (s *principalSnapshot) memberRolesForPrincipal(namespace, principalID string) ([][]string, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	var roles [][]string
	owner := ""
	for _, st := range s.tenants {
		if st.err != nil {
			return nil, fmt.Errorf("reading tenant %q: %w", st.dir, st.err)
		}
		found, owns := st.t.memberRolesFor(namespace, matchPrincipal(principalID))
		if !owns {
			continue
		}
		if owner != "" {
			return nil, fmt.Errorf("namespace %q is claimed by tenants %q and %q", namespace, owner, st.dir)
		}
		if st.t.principalErr != nil {
			return nil, fmt.Errorf("tenant %q: %w", st.dir, st.t.principalErr)
		}
		owner = st.dir
		roles = found
	}
	return roles, nil
}
