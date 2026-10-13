package gitops

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

const (
	prnAlice = "prn_01JAAAAAAAAAAAAAAAAAAAAAAA"
	prnBob   = "prn_01JBBBBBBBBBBBBBBBBBBBBBBB"
	prnZed   = "prn_01JZZZZZZZZZZZZZZZZZZZZZZZ" // ZITADEL-only: no userId anywhere
	prnNone  = "prn_01JNNNNNNNNNNNNNNNNNNNNNNN"
)

// The same fixture keyed both ways: every principal decision must equal the
// login decision for the same person, which is what shadow mode measures.
const keyedAcmeYAML = `tenant:
  name: acme
  members:
    - userId: boss
      principalId: prn_01JAAAAAAAAAAAAAAAAAAAAAAA
      role: owner
  teams:
    - name: web
      members:
        - userId: dev
          principalId: prn_01JBBBBBBBBBBBBBBBBBBBBBBB
          role: developer
        - principalId: prn_01JZZZZZZZZZZZZZZZZZZZZZZZ
          role: viewer
    - name: data
      members:
        - userId: analyst
          role: viewer
`

func TestPrincipalMembershipParity(t *testing.T) {
	dir, r := syncedRepo(t)
	writeTenantYAML(t, dir, "acme", keyedAcmeYAML)
	writeTenantYAML(t, dir, "solo", "tenant:\n  name: solo\n  members:\n    - userId: dev\n      principalId: "+prnBob+"\n      role: owner\n")

	pairs := []struct{ login, prn string }{{"boss", prnAlice}, {"dev", prnBob}}
	for _, p := range pairs {
		legacy, err := r.GetTenantsForUser(p.login)
		if err != nil {
			t.Fatal(err)
		}
		got, err := r.NamespacesForPrincipal(p.prn)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Unreadable) != 0 {
			t.Fatalf("unreadable = %v", got.Unreadable)
		}
		want := append([]string(nil), legacy...)
		sortStrings(want)
		if !reflect.DeepEqual(got.Namespaces, want) {
			t.Errorf("%s: principal namespaces %v, login namespaces %v", p.login, got.Namespaces, want)
		}
		for _, ns := range []string{"acme-web", "acme-data", "solo"} {
			lr, err := r.MemberRoles(ns, p.login)
			if err != nil {
				t.Fatal(err)
			}
			pr, err := r.MemberRolesForPrincipal(ns, p.prn)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(lr, pr) {
				t.Errorf("%s on %s: principal roles %q, login roles %q", p.login, ns, pr, lr)
			}
		}
	}
}

// Q5: a principal with no GitHub login at all is a member by principalId.
func TestPrincipalMembershipWithoutUserID(t *testing.T) {
	dir, r := syncedRepo(t)
	writeTenantYAML(t, dir, "acme", keyedAcmeYAML)

	got, err := r.NamespacesForPrincipal(prnZed)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Namespaces, []string{"acme-web"}) {
		t.Fatalf("namespaces = %v, want [acme-web]", got.Namespaces)
	}
	roles, err := r.MemberRolesForPrincipal("acme-web", prnZed)
	if err != nil || !reflect.DeepEqual(roles, [][]string{{"viewer"}}) {
		t.Fatalf("roles = %q, %v; want [[viewer]]", roles, err)
	}
	// An entry with only a userId grants nothing by principal.
	if roles, err := r.MemberRolesForPrincipal("acme-data", prnNone); err != nil || roles != nil {
		t.Fatalf("unkeyed entry answered %q, %v", roles, err)
	}
	// The login path never sees a principal-only entry.
	if ns, _ := r.GetTenantsForUser(""); len(ns) != 0 {
		t.Fatalf("an empty login matched %v", ns)
	}
}

// A bad principal key makes that tenant unknown for principal reads, and
// changes nothing on the login path.
func TestPrincipalKeysInvalid(t *testing.T) {
	cases := map[string]string{
		"malformed": "tenant:\n  name: bad\n  members:\n    - userId: dev\n      principalId: prn_nope\n      role: owner\n",
		"duplicate": "tenant:\n  name: bad\n  members:\n    - userId: dev\n      principalId: " + prnBob + "\n      role: owner\n    - userId: dev2\n      principalId: " + prnBob + "\n      role: viewer\n",
		"nobody":    "tenant:\n  name: bad\n  members:\n    - userId: dev\n      principalId: " + prnBob + "\n      role: owner\n    - role: viewer\n",
		"team":      "tenant:\n  name: bad\n  teams:\n    - name: web\n      members:\n        - userId: dev\n          principalId: lowercase\n          role: owner\n",
	}
	for name, yaml := range cases {
		t.Run(name, func(t *testing.T) {
			dir, r := syncedRepo(t)
			writeTenantYAML(t, dir, "bad", yaml)
			writeTenantYAML(t, dir, "good", "tenant:\n  name: good\n  members:\n    - userId: dev\n      principalId: "+prnBob+"\n      role: developer\n")

			got, err := r.NamespacesForPrincipal(prnBob)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.Unreadable, []string{"bad"}) {
				t.Fatalf("unreadable = %v, want [bad]", got.Unreadable)
			}
			if !reflect.DeepEqual(got.Namespaces, []string{"good"}) {
				t.Fatalf("namespaces = %v, want [good] (what was read stays usable)", got.Namespaces)
			}
			ns := "bad"
			if name == "team" {
				ns = "bad-web"
			}
			if _, err := r.MemberRolesForPrincipal(ns, prnBob); err == nil {
				t.Fatal("roles on a tenant with invalid principal keys came back as an answer")
			}
			// Legacy is untouched by principal keys.
			if roles, err := r.MemberRoles(ns, "dev"); err != nil || len(roles) == 0 {
				t.Fatalf("login roles changed: %q, %v", roles, err)
			}
		})
	}
}

func TestNamespacesForPrincipalRefusesWhatItCannotRead(t *testing.T) {
	dir, r := setupTempRepo(t) // never synced
	writeTenantYAML(t, dir, "acme", keyedAcmeYAML)
	if _, err := r.NamespacesForPrincipal(prnBob); err == nil {
		t.Fatal("a never-synced checkout answered")
	}
	r.lastSync.Store(time.Now().Add(-CheckoutMaxAge - time.Minute).UnixNano())
	if _, err := r.NamespacesForPrincipal(prnBob); err == nil {
		t.Fatal("a stale checkout answered")
	}
	_, r = syncedRepo(t) // synced, but no tenants directory
	if _, err := r.NamespacesForPrincipal(prnBob); err == nil {
		t.Fatal("a missing tenants directory read as no memberships")
	}
	dir, r = syncedRepo(t)
	writeTenantYAML(t, dir, "broken", "tenant: [unclosed\n")
	got, err := r.NamespacesForPrincipal(prnBob)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Unreadable, []string{"broken"}) {
		t.Fatalf("an unparsable tenant was dropped instead of reported: %+v", got)
	}
	if _, err := r.NamespacesForPrincipal("github:dev"); err == nil || !strings.Contains(err.Error(), "invalid principal id") {
		t.Fatalf("a non-principal key was accepted: %v", err)
	}
}

func TestPrincipalKeyMetrics(t *testing.T) {
	dir, r := syncedRepo(t)
	writeTenantYAML(t, dir, "acme", keyedAcmeYAML)
	writeTenantYAML(t, dir, "bad", "tenant:\n  name: bad\n  members:\n    - userId: x\n      principalId: prn_bad\n")
	writeTenantYAML(t, dir, "broken", "tenant: [unclosed\n")
	r.recordPrincipalKeyMetrics()
	if got := testutil.ToFloat64(tenantPrincipalKeysInvalid.WithLabelValues("broken")); got != 1 {
		t.Errorf("invalid broken = %v, want 1: unread keys are not valid keys", got)
	}
	if got := testutil.ToFloat64(tenantMemberEntryUnkeyed.WithLabelValues("acme")); got != 1 {
		t.Errorf("unkeyed acme = %v, want 1 (analyst)", got)
	}
	if got := testutil.ToFloat64(tenantPrincipalKeysInvalid.WithLabelValues("acme")); got != 0 {
		t.Errorf("invalid acme = %v, want 0", got)
	}
	if got := testutil.ToFloat64(tenantPrincipalKeysInvalid.WithLabelValues("bad")); got != 1 {
		t.Errorf("invalid bad = %v, want 1", got)
	}
	if got := testutil.ToFloat64(tenantPrincipalKeysScanOK); got != 1 {
		t.Errorf("scan ok = %v, want 1", got)
	}

	// A scan that cannot list the tenants must not leave the last good
	// numbers standing as if they were current.
	_, empty := syncedRepo(t)
	empty.recordPrincipalKeyMetrics()
	if got := testutil.ToFloat64(tenantPrincipalKeysScanOK); got != 0 {
		t.Errorf("scan ok after a failed scan = %v, want 0", got)
	}
	if n := testutil.CollectAndCount(tenantMemberEntryUnkeyed); n != 0 {
		t.Errorf("a failed scan left %d stale unkeyed series", n)
	}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func TestTryNamespacesForPrincipal(t *testing.T) {
	dir, r := syncedRepo(t)
	writeTenantYAML(t, dir, "acme", keyedAcmeYAML)
	got, ok, err := r.TryNamespacesForPrincipal(prnBob)
	if err != nil || !ok || !reflect.DeepEqual(got.Namespaces, []string{"acme-web"}) {
		t.Fatalf("got %+v, %v, %v; want [acme-web]", got, ok, err)
	}
	// A held checkout is covered in principal_snapshot_test.go: it answers
	// from the snapshot, or is not observed when there is none.
}

func TestAllMemberEntries(t *testing.T) {
	dir, r := syncedRepo(t)
	writeTenantYAML(t, dir, "acme", keyedAcmeYAML)
	writeTenantYAML(t, dir, "bad", "tenant:\n  name: bad\n  members:\n    - userId: x\n      principalId: prn_bad\n")
	writeTenantYAML(t, dir, "broken", "tenant: [unclosed\n")
	got, err := r.AllMemberEntries()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 5 { // acme: boss, dev, zed, analyst; bad: x
		t.Fatalf("entries = %+v, want 5", got.Entries)
	}
	if e := got.Entries[2]; e.Tenant != "acme" || e.Team != "web" || e.Index != 1 || e.UserID != "" || e.PrincipalID != prnZed {
		t.Errorf("third entry = %+v, want acme/web #1, principal-only", e)
	}
	if !reflect.DeepEqual(got.Unreadable, []string{"broken"}) {
		t.Errorf("unreadable = %v, want [broken]", got.Unreadable)
	}
	if _, ok := got.KeyErrors["bad"]; !ok || len(got.KeyErrors) != 1 {
		t.Errorf("key errors = %v, want bad only", got.KeyErrors)
	}

	staleDir, stale := setupTempRepo(t)
	writeTenantYAML(t, staleDir, "acme", keyedAcmeYAML)
	if _, err := stale.AllMemberEntries(); err == nil {
		t.Error("a never-synced checkout answered")
	}
	_, empty := syncedRepo(t)
	if _, err := empty.AllMemberEntries(); err == nil {
		t.Error("a missing tenants directory read as no entries")
	}
}

// Entries and key errors name the tenant directory, as Unreadable does,
// even when tenant.name says otherwise.
func TestAllMemberEntries_KeyedOnDirectory(t *testing.T) {
	dir, r := syncedRepo(t)
	writeTenantYAML(t, dir, "folder", "tenant:\n  name: declared\n  members:\n    - userId: x\n      principalId: prn_bad\n")
	got, err := r.AllMemberEntries()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 1 || got.Entries[0].Tenant != "folder" {
		t.Fatalf("entries = %+v, want tenant \"folder\"", got.Entries)
	}
	if _, ok := got.KeyErrors["folder"]; !ok {
		t.Fatalf("key errors = %v, want them under \"folder\"", got.KeyErrors)
	}
}
