package gitops

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	prnA = "prn_01JABCDEFGHJKMNPQRSTVWXYZ0"
	prnB = "prn_01JZZZZZZZZZZZZZZZZZZZZZZZ"
)

func TestPrincipalReading(t *testing.T) {
	dir, r := syncedRepo(t)
	writeTenantYAML(t, dir, "mctl", `tenant:
  name: mctl
  members:
    - principalId: `+prnA+`
      userId: alice
      role: owner
    - principalId: `+prnB+`
      role: developer
    - userId: legacyonly
      role: viewer
`)
	writeTenantYAML(t, dir, "multi", `tenant:
  name: multi
  teams:
    - name: web
      members:
        - principalId: `+prnA+`
          role: viewer
    - name: api
`)

	got, err := r.NamespacesForPrincipal(prnA)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"mctl", "multi-web"}; !sortedEqual(got, want) {
		t.Errorf("NamespacesForPrincipal(A) = %v, want %v", got, want)
	}
	// ZITADEL-only principal: no userId on the entry.
	got, err = r.NamespacesForPrincipal(prnB)
	if err != nil || !reflect.DeepEqual(got, []string{"mctl"}) {
		t.Errorf("NamespacesForPrincipal(B) = %v, %v", got, err)
	}
	// A login is never a principal key: it is an error, not "no namespaces".
	if _, err = r.NamespacesForPrincipal("alice"); err == nil {
		t.Error("login as principal must be an error")
	}
	if _, ok, err := r.TryNamespacesForPrincipal("alice"); !ok || err == nil {
		t.Errorf("Try with login: ok=%v err=%v", ok, err)
	}
	if _, err = r.MemberRolesForPrincipal("mctl", strings.ToLower(prnA)); err == nil {
		t.Error("lowercased principal must be an error")
	}
	if got, ok, err := r.TryNamespacesForPrincipal(prnB); !ok || err != nil || len(got) != 1 {
		t.Errorf("TryNamespacesForPrincipal = %v %v %v", got, ok, err)
	}

	roles, err := r.MemberRolesForPrincipal("mctl", prnB)
	if err != nil || !reflect.DeepEqual(roles, [][]string{{"developer"}}) {
		t.Errorf("MemberRolesForPrincipal(mctl,B) = %v, %v", roles, err)
	}
	roles, err = r.MemberRolesForPrincipal("multi-web", prnA)
	if err != nil || !reflect.DeepEqual(roles, [][]string{{"viewer"}}) {
		t.Errorf("MemberRolesForPrincipal(multi-web,A) = %v, %v", roles, err)
	}
	if roles, err = r.MemberRolesForPrincipal("multi-api", prnA); err != nil || roles != nil {
		t.Errorf("multi-api = %v, %v", roles, err)
	}
}

func TestPrincipalReading_UnreadableTenant(t *testing.T) {
	cases := map[string]string{
		"malformed": "    - principalId: prn_nope\n      role: owner\n",
		"duplicate": "    - principalId: " + prnA + "\n      role: owner\n    - principalId: " + prnA + "\n      role: viewer\n",
		"unkeyed":   "    - role: owner\n",
	}
	for name, members := range cases {
		t.Run(name, func(t *testing.T) {
			dir, r := syncedRepo(t)
			writeTenantYAML(t, dir, "good", "tenant:\n  name: good\n  members:\n    - principalId: "+prnA+"\n      role: owner\n")
			writeTenantYAML(t, dir, "bad", "tenant:\n  name: bad\n  members:\n"+members)

			if _, err := r.NamespacesForPrincipal(prnA); err == nil || !strings.Contains(err.Error(), "bad") {
				t.Errorf("NamespacesForPrincipal err = %v, want unreadable bad", err)
			}
			if _, err := r.MemberRolesForPrincipal("bad", prnA); err == nil {
				t.Error("MemberRolesForPrincipal(bad) must error, not answer not-a-member")
			}
			// The rest stay readable.
			roles, err := r.MemberRolesForPrincipal("good", prnA)
			if err != nil || !reflect.DeepEqual(roles, [][]string{{"owner"}}) {
				t.Errorf("good = %v, %v", roles, err)
			}
		})
	}
}

func TestPrincipalReading_StaleCheckout(t *testing.T) {
	_, r := setupTempRepo(t) // never synced
	if _, err := r.NamespacesForPrincipal(prnA); err == nil {
		t.Error("never-synced checkout must be an error")
	}
	if _, err := r.MemberRolesForPrincipal("mctl", prnA); err == nil {
		t.Error("never-synced checkout must be an error")
	}
}

func sortedEqual(a, b []string) bool {
	m := map[string]int{}
	for _, s := range a {
		m[s]++
	}
	for _, s := range b {
		m[s]--
	}
	for _, n := range m {
		if n != 0 {
			return false
		}
	}
	return len(a) == len(b)
}

func TestTryNamespacesForPrincipal_WriteLockHeld(t *testing.T) {
	dir, r := syncedRepo(t)
	writeTenantYAML(t, dir, "mctl", "tenant:\n  name: mctl\n  members:\n    - principalId: "+prnA+"\n      role: owner\n")
	r.mu.Lock()
	done := make(chan bool, 1)
	go func() {
		_, ok, _ := r.TryNamespacesForPrincipal(prnA)
		done <- ok
	}()
	select {
	case ok := <-done:
		if ok {
			t.Error("expected ok=false while the write lock is held")
		}
	case <-time.After(2 * time.Second):
		t.Error("TryNamespacesForPrincipal blocked on the refresh write lock")
	}
	r.mu.Unlock()
}

func TestPrincipalReading_UnreadableIsNeverAnAnswer(t *testing.T) {
	owner := "tenant:\n  name: erpact\n  members:\n    - principalId: " + prnA + "\n      role: owner\n"
	both := func(t *testing.T, r *Reader) {
		t.Helper()
		if got, err := r.NamespacesForPrincipal(prnA); err == nil {
			t.Errorf("NamespacesForPrincipal answered %v", got)
		}
		if got, err := r.MemberRolesForPrincipal("erpact", prnA); err == nil {
			t.Errorf("MemberRolesForPrincipal answered %v", got)
		}
	}
	t.Run("stale checkout", func(t *testing.T) {
		dir, r := setupTempRepo(t)
		writeTenantYAML(t, dir, "erpact", owner)
		r.lastSync.Store(time.Now().Add(-CheckoutMaxAge - time.Minute).UnixNano())
		both(t, r)
	})
	t.Run("another tenant unparseable", func(t *testing.T) {
		dir, r := syncedRepo(t)
		writeTenantYAML(t, dir, "erpact", owner)
		writeTenantYAML(t, dir, "broken", "tenant: [not, a, mapping\n")
		both(t, r)
	})
	t.Run("malformed team member", func(t *testing.T) {
		dir, r := syncedRepo(t)
		writeTenantYAML(t, dir, "erpact", "tenant:\n  name: erpact\n  teams:\n    - name: web\n      members:\n        - principalId: prn_nope\n          role: viewer\n")
		if _, err := r.NamespacesForPrincipal(prnA); err == nil {
			t.Error("NamespacesForPrincipal must error")
		}
		if _, err := r.MemberRolesForPrincipal("erpact-web", prnA); err == nil {
			t.Error("MemberRolesForPrincipal must error")
		}
	})
	t.Run("namespace claimed twice", func(t *testing.T) {
		dir, r := syncedRepo(t)
		writeTenantYAML(t, dir, "erpact", owner)
		writeTenantYAML(t, dir, "impostor", "tenant:\n  name: erpact\n  members:\n    - principalId: "+prnB+"\n      role: owner\n")
		got, err := r.MemberRolesForPrincipal("erpact", prnB)
		if err == nil {
			t.Fatalf("an ambiguous namespace answered %v", got)
		}
		if !strings.Contains(err.Error(), "erpact") || !strings.Contains(err.Error(), "impostor") {
			t.Errorf("error does not tell the tenants apart: %v", err)
		}
	})
}
