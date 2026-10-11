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

package api_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// listingFixture is three tenants: labs uses the catalogue, acme deploys
// through its own ArgoCD project, admins owns a catalogue service that runs
// in a namespace of its own.
func listingFixture() (*fakeGitReader, *fakeArgoCD) {
	git := &fakeGitReader{
		tenants: []gitops.Tenant{{Name: "admins"}, {Name: "labs"}, {Name: "acme"}},
		services: []gitops.Service{
			{Team: "admins", Name: "api", ImageTag: "4.0.0"},
			{Team: "labs", Name: "tg", ImageTag: "1.2.3"},
			{Team: "labs", Name: "ghost", ImageTag: "0.1.0"},
		},
	}
	argo := &fakeArgoCD{workloads: []argocd.Workload{
		{Name: "labs-tg", Project: "apps", DestNamespace: "labs", Health: "Healthy", SyncStatus: "Synced",
			Hosts: []string{"tg.example.test"}, SourceRepo: "https://git.example.test/platform", SourcePath: "services/labs/tg"},
		{Name: "admins-api", Project: "platform", DestNamespace: "mctl-api", Health: "Healthy", SyncStatus: "Synced"},
		{Name: "acme-shared", Project: "acme", DestNamespace: "acme", Health: "Degraded", SyncStatus: "OutOfSync",
			Hosts: []string{"a.example.test", "b.example.test"}, Images: []string{"registry.example.test/bench:15"},
			SourceRepo: "https://git.example.test/acme/apps", SourcePath: "shared"},
		{Name: "tenant-acme", Project: "platform", DestNamespace: "acme", Health: "Healthy", SyncStatus: "Synced",
			SourceRepo: "https://git.example.test/platform", SourcePath: "tenants/acme"},
		// acme names an application after a labs catalogue service that is not deployed.
		{Name: "labs-ghost", Project: "acme", DestNamespace: "acme", Health: "Healthy", SyncStatus: "Synced",
			Hosts: []string{"spoof.example.test"}},
		{Name: "kube-prometheus", Project: "platform", DestNamespace: "monitoring", Health: "Healthy", SyncStatus: "Synced"},
		{Name: "preview-labs-tg-42", Project: "apps", DestNamespace: "labs", Health: "Healthy", SyncStatus: "Synced"},
	}}
	return git, argo
}

func listingRouter(t *testing.T, git *fakeGitReader, argo mctlapi.ArgoStatusClient) http.Handler {
	t.Helper()
	t.Setenv("AUTH_REQUIRED", "false")
	return mctlapi.NewRouter(mctlapi.Options{
		Registry:  operations.NewRegistry(),
		GitReader: git,
		ArgoCD:    argo,
		AuditLog:  audit.NewLogger(),
		Executor:  &fakeExecutor{},
	})
}

// rowsByKey indexes a listing by "team/name".
func rowsByKey(t *testing.T, items interface{}) map[string]map[string]interface{} {
	t.Helper()
	list, ok := items.([]interface{})
	if !ok {
		t.Fatalf("items is %T, want a list", items)
	}
	out := make(map[string]map[string]interface{}, len(list))
	for _, it := range list {
		row := it.(map[string]interface{})
		key := row["team"].(string) + "/" + row["name"].(string)
		if _, dup := out[key]; dup {
			t.Fatalf("duplicate row %s", key)
		}
		out[key] = row
	}
	return out
}

func TestListServices_MergesCatalogueAndArgoCD(t *testing.T) {
	git, argo := listingFixture()
	w := getAs(t, listingRouter(t, git, argo), "/api/v1/services", adminUser)
	assertStatus(t, w, http.StatusOK)
	body := decodeJSON(t, w)

	if body["complete"] != true || body["argocd"] != "ok" {
		t.Fatalf("complete=%v argocd=%v, want true/ok", body["complete"], body["argocd"])
	}
	if _, ok := body["warning"]; ok {
		t.Errorf("unexpected warning on a complete listing: %v", body["warning"])
	}
	rows := rowsByKey(t, body["items"])

	want := map[string]struct {
		managed  string
		deployed bool
		argoApp  string
	}{
		"admins/api":       {"catalogue", true, "admins-api"},
		"labs/tg":          {"catalogue", true, "labs-tg"},
		"labs/ghost":       {"catalogue", false, ""},
		"acme/shared":      {"external", true, "acme-shared"},
		"acme/labs-ghost":  {"external", true, "labs-ghost"},
		"acme/tenant-acme": {"platform", true, "tenant-acme"},
	}
	if len(rows) != len(want) {
		t.Errorf("got %d rows %v, want %d", len(rows), keysOf(rows), len(want))
	}
	for key, exp := range want {
		row, ok := rows[key]
		if !ok {
			t.Errorf("missing row %s (have %v)", key, keysOf(rows))
			continue
		}
		if row["managed"] != exp.managed {
			t.Errorf("%s managed=%v, want %s", key, row["managed"], exp.managed)
		}
		if row["deployed"] != exp.deployed {
			t.Errorf("%s deployed=%v, want %v", key, row["deployed"], exp.deployed)
		}
		if got, _ := row["argoApp"].(string); got != exp.argoApp {
			t.Errorf("%s argoApp=%q, want %q", key, got, exp.argoApp)
		}
	}

	shared := rows["acme/shared"]
	if shared["health"] != "Degraded" || shared["syncStatus"] != "OutOfSync" {
		t.Errorf("acme/shared health=%v sync=%v", shared["health"], shared["syncStatus"])
	}
	if hosts, _ := shared["hosts"].([]interface{}); len(hosts) != 2 {
		t.Errorf("acme/shared hosts=%v, want 2", shared["hosts"])
	}
	if rows["labs/tg"]["imageTag"] != "1.2.3" {
		t.Errorf("catalogue fields lost on merge: %v", rows["labs/tg"])
	}
}

// An application in another tenant's own project must not be merged into a
// catalogue service just because it carries that service's ArgoCD name.
func TestListServices_NameDoesNotAttribute(t *testing.T) {
	git, argo := listingFixture()
	w := getAs(t, listingRouter(t, git, argo), "/api/v1/services?team=labs", adminUser)
	assertStatus(t, w, http.StatusOK)
	rows := rowsByKey(t, decodeJSON(t, w)["items"])

	ghost, ok := rows["labs/ghost"]
	if !ok {
		t.Fatalf("labs/ghost missing: %v", keysOf(rows))
	}
	if ghost["deployed"] != false {
		t.Errorf("labs/ghost deployed=%v, want false", ghost["deployed"])
	}
	if _, has := ghost["hosts"]; has {
		t.Errorf("labs/ghost took the hosts of another tenant's application: %v", ghost["hosts"])
	}
	if len(rows) != 2 {
		t.Errorf("team=labs returned %v, want only labs/tg and labs/ghost", keysOf(rows))
	}
}

// The guard must not depend on a tenant's AppProject carrying the tenant's
// name: the namespace an application lands in decides, whatever the project.
func TestListServices_NameDoesNotAttributeUnderAnyProjectName(t *testing.T) {
	git, argo := listingFixture()
	for i := range argo.workloads {
		if argo.workloads[i].Name == "labs-ghost" {
			argo.workloads[i].Project = "acme-apps"
		}
	}
	w := getAs(t, listingRouter(t, git, argo), "/api/v1/services", adminUser)
	assertStatus(t, w, http.StatusOK)
	rows := rowsByKey(t, decodeJSON(t, w)["items"])

	ghost := rows["labs/ghost"]
	if ghost == nil {
		t.Fatalf("labs/ghost missing: %v", keysOf(rows))
	}
	if ghost["deployed"] != false {
		t.Errorf("labs/ghost deployed=%v, want false", ghost["deployed"])
	}
	if _, has := ghost["hosts"]; has {
		t.Errorf("labs/ghost took the hosts of an application in namespace acme: %v", ghost["hosts"])
	}
	if row := rows["acme/labs-ghost"]; row == nil || row["argoApp"] != "labs-ghost" {
		t.Errorf("the application is not listed under the tenant it deploys into: %v", keysOf(rows))
	}
}

// {team}/{name} is the key clients address a service by, so two rows must
// never share one. rowsByKey fails the test on a duplicate.
func TestListServices_RowKeysStayUnique(t *testing.T) {
	git, argo := listingFixture()
	git.services = append(git.services, gitops.Service{Team: "acme", Name: "web"})
	argo.workloads = append(argo.workloads,
		// Shares the short name of the undeployed catalogue service acme/web.
		argocd.Workload{Name: "web", Project: "acme", DestNamespace: "acme", Health: "Healthy", SyncStatus: "Synced"},
		// Both of these shorten to "site".
		argocd.Workload{Name: "acme-site", Project: "acme", DestNamespace: "acme", Health: "Healthy", SyncStatus: "Synced"},
		argocd.Workload{Name: "site", Project: "acme", DestNamespace: "acme", Health: "Healthy", SyncStatus: "Synced"},
	)
	w := getAs(t, listingRouter(t, git, argo), "/api/v1/services?team=acme", adminUser)
	assertStatus(t, w, http.StatusOK)
	body := decodeJSON(t, w)
	rows := rowsByKey(t, body["items"])

	apps := map[string]bool{}
	for _, row := range rows {
		if app, ok := row["argoApp"].(string); ok {
			apps[app] = true
		}
	}
	for _, app := range []string{"web", "acme-site", "site", "acme-shared", "tenant-acme", "labs-ghost"} {
		if !apps[app] {
			t.Errorf("application %s is missing from the listing: %v", app, keysOf(rows))
		}
	}
	if web := rows["acme/web"]; web == nil || web["managed"] != "catalogue" || web["deployed"] != false {
		t.Errorf("acme/web = %v, want the undeployed catalogue row", web)
	}
	for key, app := range map[string]string{"acme/web@argocd": "web", "acme/site": "site", "acme/acme-site": "acme-site", "acme/shared": "acme-shared"} {
		if row := rows[key]; row == nil || row["argoApp"] != app {
			t.Errorf("%s = %v, want application %s", key, row, app)
		}
	}
	if got, want := int(body["count"].(float64)), 7; got != want {
		t.Errorf("count=%d, want %d: %v", got, want, keysOf(rows))
	}
}

// labs-a/b and labs/a-b both resolve to the application name labs-a-b. The
// row of the tenant the application deploys into is the one that is running.
func TestListServices_SharedApplicationNamePicksByNamespace(t *testing.T) {
	for _, order := range [][]gitops.Service{
		{{Team: "labs-a", Name: "b"}, {Team: "labs", Name: "a-b"}},
		{{Team: "labs", Name: "a-b"}, {Team: "labs-a", Name: "b"}},
	} {
		git := &fakeGitReader{
			tenants:  []gitops.Tenant{{Name: "labs"}, {Name: "labs-a"}},
			services: order,
		}
		argo := &fakeArgoCD{workloads: []argocd.Workload{
			{Name: "labs-a-b", Project: "apps", DestNamespace: "labs", Health: "Healthy", SyncStatus: "Synced"},
		}}
		w := getAs(t, listingRouter(t, git, argo), "/api/v1/services", adminUser)
		assertStatus(t, w, http.StatusOK)
		rows := rowsByKey(t, decodeJSON(t, w)["items"])
		if rows["labs/a-b"]["deployed"] != true {
			t.Errorf("catalogue order %v: labs/a-b deployed=%v, want true", order, rows["labs/a-b"]["deployed"])
		}
		if rows["labs-a/b"]["deployed"] != false {
			t.Errorf("catalogue order %v: labs-a/b deployed=%v, want false", order, rows["labs-a/b"]["deployed"])
		}
	}
}

func TestListServices_MemberSeesOnlyOwnTenant(t *testing.T) {
	git, argo := listingFixture()
	member := &auth.User{ID: "acme-dev", Groups: []string{"acme"}}
	w := getAs(t, listingRouter(t, git, argo), "/api/v1/services", member)
	assertStatus(t, w, http.StatusOK)
	raw := w.Body.String()
	rows := rowsByKey(t, decodeJSON(t, w)["items"])

	for key, row := range rows {
		if row["team"] != "acme" {
			t.Errorf("member of acme sees %s", key)
		}
	}
	if len(rows) != 3 {
		t.Errorf("got %v, want the three acme rows", keysOf(rows))
	}
	for _, leak := range []string{"labs-tg", "tg.example.test", "admins-api", "kube-prometheus"} {
		if strings.Contains(raw, leak) {
			t.Errorf("response leaks %q to a member of another tenant", leak)
		}
	}

	// The tenant's own source is theirs to see; the platform's is not.
	if src, _ := rows["acme/shared"]["source"].(map[string]interface{}); src["path"] != "shared" {
		t.Errorf("acme/shared source=%v, want the tenant's own source", rows["acme/shared"]["source"])
	}
	if src, has := rows["acme/tenant-acme"]["source"]; has {
		t.Errorf("platform row exposes its source to a member: %v", src)
	}
}

func TestListServices_AdminSeesPlatformSource(t *testing.T) {
	git, argo := listingFixture()
	w := getAs(t, listingRouter(t, git, argo), "/api/v1/services?team=acme", adminUser)
	assertStatus(t, w, http.StatusOK)
	rows := rowsByKey(t, decodeJSON(t, w)["items"])
	if src, _ := rows["acme/tenant-acme"]["source"].(map[string]interface{}); src["path"] != "tenants/acme" {
		t.Errorf("admin does not see the platform row's source: %v", rows["acme/tenant-acme"])
	}
}

func TestListServices_NonMemberGetsNothing(t *testing.T) {
	git, argo := listingFixture()
	outsider := &auth.User{ID: "nobody", Groups: []string{"elsewhere"}}
	w := getAs(t, listingRouter(t, git, argo), "/api/v1/services?team=acme", outsider)
	assertStatus(t, w, http.StatusOK)
	body := decodeJSON(t, w)
	if body["count"].(float64) != 0 {
		t.Errorf("outsider sees %v rows", body["count"])
	}
	if strings.Contains(w.Body.String(), "acme-shared") {
		t.Error("response leaks an application name to a non-member")
	}
}

// A failed ArgoCD read must be visible as such. For a tenant with nothing in
// the catalogue the row count is 0 either way, so "complete" and the warning
// are the only things that tell "could not look" from "nothing there".
func TestListServices_ArgoCDUnreadIsNotEmpty(t *testing.T) {
	git, argo := listingFixture()
	argo.workloads, argo.workloadsErr = nil, errors.New("argocd returned 502")
	router := listingRouter(t, git, argo)

	member := &auth.User{ID: "acme-dev", Groups: []string{"acme"}}
	w := getAs(t, router, "/api/v1/services?team=acme", member)
	assertStatus(t, w, http.StatusOK)
	body := decodeJSON(t, w)
	if body["complete"] != false || body["argocd"] != "unavailable" {
		t.Fatalf("complete=%v argocd=%v, want false/unavailable", body["complete"], body["argocd"])
	}
	if warning, _ := body["warning"].(string); !strings.Contains(warning, "incomplete") {
		t.Errorf("warning=%q, want it to say the result is incomplete", warning)
	}

	// The catalogue is still served, with deployment state unknown rather than false.
	w = getAs(t, router, "/api/v1/services?team=labs", adminUser)
	assertStatus(t, w, http.StatusOK)
	rows := rowsByKey(t, decodeJSON(t, w)["items"])
	if len(rows) != 2 {
		t.Fatalf("catalogue rows lost on an ArgoCD failure: %v", keysOf(rows))
	}
	for key, row := range rows {
		if _, has := row["deployed"]; has {
			t.Errorf("%s reports deployed=%v without an ArgoCD read", key, row["deployed"])
		}
	}
}

func TestListServices_NoArgoCDClientIsNotEmpty(t *testing.T) {
	git, _ := listingFixture()
	w := getAs(t, listingRouter(t, git, nil), "/api/v1/services?team=acme", adminUser)
	assertStatus(t, w, http.StatusOK)
	body := decodeJSON(t, w)
	if body["complete"] != false || body["argocd"] != "not_configured" {
		t.Errorf("complete=%v argocd=%v, want false/not_configured", body["complete"], body["argocd"])
	}
	if _, ok := body["warning"]; !ok {
		t.Error("no warning without an ArgoCD client")
	}
}

// Without the tenant list an application cannot be attributed, so the listing
// fails instead of returning the subset it happens to be sure about.
func TestListServices_TenantListFailureIsAnError(t *testing.T) {
	git, argo := listingFixture()
	git.listTenantsErr = errors.New("gitops checkout unreadable")
	w := getAs(t, listingRouter(t, git, argo), "/api/v1/services", adminUser)
	assertStatus(t, w, http.StatusInternalServerError)
	if !strings.Contains(w.Body.String(), "tenant list") {
		t.Errorf("the error does not name the read that failed: %s", w.Body.String())
	}
}

// A catalogue service the platform deploys from its own repository into a
// namespace of its own is still a catalogue row, and its source is still not
// the tenant's to read.
func TestListServices_PlatformDeployedCatalogueRowHidesSource(t *testing.T) {
	git, argo := listingFixture()
	git.services = append(git.services, gitops.Service{Team: "labs", Name: "mon"})
	argo.workloads = append(argo.workloads, argocd.Workload{
		Name: "labs-mon", Project: "platform", DestNamespace: "monitoring", Health: "Healthy", SyncStatus: "Synced",
		SourceRepo: "https://git.example.test/platform", SourcePath: "infra/monitoring",
	})
	router := listingRouter(t, git, argo)

	member := &auth.User{ID: "labs-dev", Groups: []string{"labs"}}
	w := getAs(t, router, "/api/v1/services", member)
	assertStatus(t, w, http.StatusOK)
	rows := rowsByKey(t, decodeJSON(t, w)["items"])
	if rows["labs/mon"]["deployed"] != true {
		t.Fatalf("labs/mon = %v, want the merged row", rows["labs/mon"])
	}
	if _, has := rows["labs/mon"]["source"]; has {
		t.Errorf("a member sees the platform's source on labs/mon: %v", rows["labs/mon"]["source"])
	}
	// The tenant's own catalogue deployment keeps its source.
	if src, _ := rows["labs/tg"]["source"].(map[string]interface{}); src["path"] != "services/labs/tg" {
		t.Errorf("labs/tg lost its source: %v", rows["labs/tg"])
	}

	w = getAs(t, router, "/api/v1/services?team=labs", adminUser)
	assertStatus(t, w, http.StatusOK)
	rows = rowsByKey(t, decodeJSON(t, w)["items"])
	if src, _ := rows["labs/mon"]["source"].(map[string]interface{}); src["path"] != "infra/monitoring" {
		t.Errorf("an admin does not see the source on labs/mon: %v", rows["labs/mon"])
	}
}

func TestListServices_CatalogueOnlyTenantUnchanged(t *testing.T) {
	git, argo := listingFixture()
	member := &auth.User{ID: "labs-dev", Groups: []string{"labs"}}
	w := getAs(t, listingRouter(t, git, argo), "/api/v1/services", member)
	assertStatus(t, w, http.StatusOK)
	rows := rowsByKey(t, decodeJSON(t, w)["items"])
	if len(rows) != 2 {
		t.Fatalf("got %v, want labs/tg and labs/ghost", keysOf(rows))
	}
	for key, row := range rows {
		if row["managed"] != "catalogue" {
			t.Errorf("%s managed=%v, want catalogue", key, row["managed"])
		}
	}
}

func TestGetTenant_ListsServicesOutsideCatalogue(t *testing.T) {
	git, argo := listingFixture()
	router := listingRouter(t, git, argo)

	member := &auth.User{ID: "acme-dev", Groups: []string{"acme"}}
	w := getAs(t, router, "/api/v1/tenants/acme", member)
	assertStatus(t, w, http.StatusOK)
	body := decodeJSON(t, w)
	if body["servicesComplete"] != true {
		t.Errorf("servicesComplete=%v, want true", body["servicesComplete"])
	}
	if rows := rowsByKey(t, body["services"]); len(rows) != 3 {
		t.Errorf("tenant services=%v, want the three acme rows", keysOf(rows))
	}

	argo.workloadsErr = errors.New("argocd returned 502")
	w = getAs(t, router, "/api/v1/tenants/acme", member)
	assertStatus(t, w, http.StatusOK)
	body = decodeJSON(t, w)
	if body["servicesComplete"] != false {
		t.Errorf("servicesComplete=%v after an ArgoCD failure, want false", body["servicesComplete"])
	}
	if _, ok := body["servicesWarning"]; !ok {
		t.Error("no servicesWarning after an ArgoCD failure")
	}
}

// Members and quotas do not depend on the services read: when it fails the
// tenant is still served and the services are reported as unknown.
func TestGetTenant_ServiceReadFailureKeepsTheTenant(t *testing.T) {
	for name, breakIt := range map[string]func(*fakeGitReader){
		"catalogue":   func(g *fakeGitReader) { g.listServicesErr = errors.New("gitops checkout unreadable") },
		"tenant list": func(g *fakeGitReader) { g.listTenantsErr = errors.New("gitops checkout unreadable") },
	} {
		git, argo := listingFixture()
		breakIt(git)
		member := &auth.User{ID: "acme-dev", Groups: []string{"acme"}}
		w := getAs(t, listingRouter(t, git, argo), "/api/v1/tenants/acme", member)
		assertStatus(t, w, http.StatusOK)
		body := decodeJSON(t, w)
		if tenant, _ := body["tenant"].(map[string]interface{}); tenant["name"] != "acme" {
			t.Errorf("%s unreadable: tenant=%v, want acme", name, body["tenant"])
		}
		if body["servicesComplete"] != false || body["servicesArgocd"] != "unknown" {
			t.Errorf("%s unreadable: servicesComplete=%v servicesArgocd=%v, want false and unknown",
				name, body["servicesComplete"], body["servicesArgocd"])
		}
		if warning, _ := body["servicesWarning"].(string); !strings.Contains(warning, "not an empty one") {
			t.Errorf("%s unreadable: servicesWarning=%q", name, warning)
		}
		if list, ok := body["services"].([]interface{}); !ok || len(list) != 0 {
			t.Errorf("%s unreadable: services=%v, want an empty list", name, body["services"])
		}
	}
}

func keysOf(rows map[string]map[string]interface{}) []string {
	keys := make([]string, 0, len(rows))
	for k := range rows {
		keys = append(keys, k)
	}
	return keys
}
