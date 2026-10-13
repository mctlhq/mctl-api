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

package auth

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// RevokePrincipalSessions ends every refresh session of the principal, in
// every client, on both refresh paths, and nobody else's.
func TestRevokePrincipalSessions(t *testing.T) {
	for _, store := range []bool{false, true} {
		t.Run(fmt.Sprintf("store=%v", store), func(t *testing.T) {
			o := tpServer(true)
			if store {
				o.RefreshStore = newFakeRefreshStore()
			}
			issue := func(login, pid, client string) string {
				t.Helper()
				rt, err := o.IssueRefreshToken(login, pid, nil, client)
				if err != nil {
					t.Fatal(err)
				}
				return rt
			}
			a := issue("alice", pzMember, "c1")
			b := issue("", pzMember, "c2")
			other := issue("", pzZitadel, "c1")
			// A rotated session is revoked through its successor.
			_, a, err := o.RefreshAccessToken(a, "c1")
			if err != nil {
				t.Fatal(err)
			}

			// Two sessions, though the store keeps a third row: the rotated
			// predecessor, for reuse detection.
			n, err := o.RevokePrincipalSessions(pzMember, "identity_unlinked")
			if err != nil || n != 2 {
				t.Fatalf("RevokePrincipalSessions = %d, %v; want 2 sessions, nil", n, err)
			}
			if _, _, err := o.RefreshAccessToken(a, "c1"); err == nil {
				t.Error("revoked session still refreshes")
			}
			if _, _, err := o.RefreshAccessToken(b, "c2"); err == nil {
				t.Error("revoked session in another client still refreshes")
			}
			if _, _, err := o.RefreshAccessToken(other, "c1"); err != nil {
				t.Errorf("another principal's session was revoked: %v", err)
			}
			if n, err := o.RevokePrincipalSessions(pzMember, "identity_unlinked"); err != nil || n != 0 {
				t.Errorf("second RevokePrincipalSessions = %d, %v; want 0, nil", n, err)
			}
			for _, bad := range []string{"", "alice", "prn_short"} {
				if _, err := o.RevokePrincipalSessions(bad, "identity_unlinked"); err == nil {
					t.Errorf("RevokePrincipalSessions(%q) accepted", bad)
				}
			}
		})
	}
}

type failingRevokeStore struct{ *fakeRefreshStore }

func (failingRevokeStore) RevokePrincipal(string, string) (int64, error) {
	return 0, errors.New("db down")
}

// A store failure is an error, never "nothing to revoke".
func TestRevokePrincipalSessionsStoreFailure(t *testing.T) {
	o := tpServer(true)
	o.RefreshStore = failingRevokeStore{newFakeRefreshStore()}
	if n, err := o.RevokePrincipalSessions(pzMember, "identity_unlinked"); err == nil {
		t.Fatalf("store failure reported as %d revoked", n)
	}
}

// An in-memory rotation holds the rotation lock from taking the old token
// to storing its successor; the revocation must wait for it, or the
// successor stored after its scan survives.
func TestRevokePrincipalSessionsWaitsForAnInMemoryRotation(t *testing.T) {
	o := tpServer(true)
	rs := &o.refreshTokens
	rs.rotation.RLock() // a rotation in flight, its old token already taken
	done := make(chan int64, 1)
	go func() {
		n, _ := o.RevokePrincipalSessions(pzMember, "identity_unlinked")
		done <- n
	}()
	select {
	case n := <-done:
		rs.rotation.RUnlock()
		t.Fatalf("revocation finished (%d) while a rotation was in flight", n)
	case <-time.After(50 * time.Millisecond):
	}
	rs.store("successor", refreshTokenEntry{PrincipalID: pzMember, ClientID: "c", ExpiresAt: time.Now().Add(time.Hour)})
	rs.rotation.RUnlock()
	if n := <-done; n != 1 {
		t.Errorf("revoked %d, want the successor", n)
	}
	if _, ok := rs.tokens.Load("successor"); ok {
		t.Fatal("successor stored during the revocation survived")
	}
}
