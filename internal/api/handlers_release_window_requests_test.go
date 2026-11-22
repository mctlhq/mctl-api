package api_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

const rwTestBase = "0123456789abcdef0123456789abcdef01234567"

type fakeWindowHead struct {
	sha   string
	err   error
	calls int
}

func (f *fakeWindowHead) Head(context.Context) (string, error) {
	f.calls++
	return f.sha, f.err
}

// windowArgo answers GetAppSyncWindows the way Argo does: 404 for an
// Application that is unknown or lives in another project.
type windowArgo struct {
	fakeArgoCD
	known map[string]bool // "<project>/<app>"
	err   error
	calls []string
}

func (a *windowArgo) GetProjectSyncWindows(string) (*argocd.ProjectSyncWindows, error) {
	return nil, errors.New("not used")
}

func (a *windowArgo) GetAppSyncWindows(project, app string) (*argocd.AppSyncWindows, error) {
	a.calls = append(a.calls, project+"/"+app)
	if a.err != nil {
		return nil, a.err
	}
	if !a.known[project+"/"+app] {
		return nil, argocd.ErrNotFound
	}
	return &argocd.AppSyncWindows{Application: app, CanSync: true}, nil
}

type windowFixture struct {
	router http.Handler
	head   *fakeWindowHead
	argo   *windowArgo
	wi     *workitems.Store
}

func newWindowFixture(t *testing.T, enabled bool) *windowFixture {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL is unset in CI: the release window tests must run, not skip")
		}
		t.Skip("TEST_DATABASE_URL not set")
	}
	t.Setenv("AUTH_REQUIRED", "false")
	ctx := context.Background()
	wi, err := workitems.NewStore(ctx, dsn)
	if err != nil {
		t.Fatalf("workitems.NewStore: %v", err)
	}
	clean := func() {
		if pool, err := pgxpool.New(ctx, dsn); err == nil {
			_, _ = pool.Exec(ctx, `DELETE FROM action_approval_requests WHERE action_kind = $1`, workitems.ActionKindReleaseWindow)
			pool.Close()
		}
	}
	clean()
	t.Cleanup(func() { clean(); wi.Close() })
	f := &windowFixture{wi: wi, head: &fakeWindowHead{sha: rwTestBase}, argo: &windowArgo{known: map[string]bool{
		"apps/labs-mctl-web": true, "apps/labs-mctl-telegram": true, "platform/admins-mctl-api": true,
	}}}
	opts := mctlapi.Options{
		Registry: operations.NewRegistry(), GitReader: &fakeGitReader{}, ArgoCD: f.argo,
		AuditLog: audit.NewLogger(), Executor: &fakeExecutor{}, WorkItems: wi,
	}
	if enabled {
		opts.ReleaseWindows = &mctlapi.ReleaseWindowOptions{Head: f.head}
	}
	f.router = mctlapi.NewRouter(opts)
	return f
}

func goodWindowBody() map[string]any {
	return map[string]any{"project": "apps", "applications": []string{"labs-mctl-web", "labs-mctl-telegram"},
		"schedule": "0 22 * * 5", "duration": "48h"}
}

const windowsRoute = "/api/v1/release/windows"

func TestReleaseWindowRoutesAreDarkByDefault(t *testing.T) {
	f := newWindowFixture(t, false)
	w := postAsRaw(t, f.router, windowsRoute, goodWindowBody(), adminUser)
	if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST with the feature off: %d %s, want 404", w.Code, w.Body)
	}
	if f.head.calls != 0 {
		t.Fatalf("a dark route read GitHub")
	}
}

func TestRequestReleaseWindowRefusals(t *testing.T) {
	with := func(k string, v any) map[string]any {
		b := goodWindowBody()
		b[k] = v
		return b
	}
	cases := []struct {
		name string
		user *auth.User
		body any
		want int
		code string
		// headCalls/argoCalls: how far a refused request got.
		prep func(*windowFixture)
	}{
		{"non-admin human", ownerUser, goodWindowBody(), http.StatusForbidden, "release_window_forbidden", nil},
		{"gitops CI principal", gitopsCI(gitopsMainWorkflow), goodWindowBody(), http.StatusForbidden, "", nil},
		{"unknown field", adminUser, with("kind", "allow"), http.StatusBadRequest, "release_window_invalid_input", nil},
		{"default project", adminUser, with("project", "default"), http.StatusBadRequest, "release_window_invalid_input", nil},
		{"glob application", adminUser, with("applications", []string{"labs-*"}), http.StatusBadRequest, "release_window_invalid_input", nil},
		{"no applications", adminUser, with("applications", []string{}), http.StatusBadRequest, "release_window_invalid_input", nil},
		{"duplicate application", adminUser, with("applications", []string{"labs-mctl-web", "labs-mctl-web"}), http.StatusBadRequest, "release_window_invalid_input", nil},
		{"named weekday", adminUser, with("schedule", "0 22 * * FRI"), http.StatusBadRequest, "release_window_invalid_input", nil},
		{"bad duration", adminUser, with("duration", "2d"), http.StatusBadRequest, "release_window_invalid_input", nil},
		{"application of another project", adminUser, with("applications", []string{"admins-mctl-api"}), http.StatusUnprocessableEntity, "release_window_unknown_application", nil},
		{"unknown application", adminUser, with("applications", []string{"labs-nope"}), http.StatusUnprocessableEntity, "release_window_unknown_application", nil},
		{"github unreadable", adminUser, goodWindowBody(), http.StatusServiceUnavailable, "release_window_unavailable",
			func(f *windowFixture) { f.head.err = errors.New("github down") }},
		{"argo unreadable", adminUser, goodWindowBody(), http.StatusServiceUnavailable, "release_window_unavailable",
			func(f *windowFixture) { f.argo.err = errors.New("argo down") }},
		{"argo refuses the read", adminUser, goodWindowBody(), http.StatusServiceUnavailable, "release_window_unavailable",
			func(f *windowFixture) { f.argo.err = argocd.ErrForbidden }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newWindowFixture(t, true)
			if c.prep != nil {
				c.prep(f)
			}
			w := postAsRaw(t, f.router, windowsRoute, c.body, c.user)
			if w.Code != c.want {
				t.Fatalf("status %d %s, want %d", w.Code, w.Body, c.want)
			}
			if c.code != "" && !strings.Contains(w.Body.String(), c.code) {
				t.Errorf("body %s, want code %s", w.Body, c.code)
			}
			var n int
			pool, perr := pgxpool.New(context.Background(), os.Getenv("TEST_DATABASE_URL"))
			if perr != nil {
				t.Fatal(perr)
			}
			defer pool.Close()
			if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM action_approval_requests WHERE action_kind=$1`,
				workitems.ActionKindReleaseWindow).Scan(&n); err != nil || n != 0 {
				t.Fatalf("a refused request stored %d rows (%v)", n, err)
			}
		})
	}
}

// A malformed request must not cost a GitHub or Argo call.
func TestRequestReleaseWindowShapeIsCheckedBeforeAnyRead(t *testing.T) {
	f := newWindowFixture(t, true)
	b := goodWindowBody()
	b["project"] = "default"
	if w := postAsRaw(t, f.router, windowsRoute, b, adminUser); w.Code != http.StatusBadRequest {
		t.Fatalf("status %d %s", w.Code, w.Body)
	}
	if f.head.calls != 0 || len(f.argo.calls) != 0 {
		t.Fatalf("a malformed request read GitHub %d times and Argo %v", f.head.calls, f.argo.calls)
	}
}

func TestRequestAndListReleaseWindow(t *testing.T) {
	f := newWindowFixture(t, true)
	w := postAsRaw(t, f.router, windowsRoute, goodWindowBody(), adminUser)
	assertStatus(t, w, http.StatusCreated)
	got := decodeJSON(t, w)
	view := got["window"].(map[string]any)
	approval := view["approval"].(map[string]any)

	win := workitems.ReleaseWindow{Project: "apps", Applications: []string{"labs-mctl-telegram", "labs-mctl-web"},
		Schedule: "0 22 * * 5", Duration: "48h", BaseSHA: rwTestBase}
	wantHash, _ := win.WindowSHA256()
	wantID, _ := win.ReleaseWindowID()
	wantIn, _ := workitems.ReleaseWindowIntent(win)
	if approval["state"] != workitems.ApprovalPending || approval["action_kind"] != workitems.ActionKindReleaseWindow ||
		approval["execution_id"] != rwTestBase || approval["artifact_hash"] != "sha256:"+wantHash ||
		approval["args_digest"] != wantIn.ArgsDigest || approval["target"] != wantIn.Target {
		t.Fatalf("approval does not bind the window: %v", approval)
	}
	if view["window_id"] != wantID || view["window_sha256"] != wantHash {
		t.Fatalf("window id/hash %v %v, want %s %s", view["window_id"], view["window_sha256"], wantID, wantHash)
	}
	// The server sorted the applications: the hash covers the list as given.
	apps := view["window"].(map[string]any)["applications"].([]any)
	if len(apps) != 2 || apps[0] != "labs-mctl-telegram" {
		t.Fatalf("applications not in canonical order: %v", apps)
	}
	if _, ok := got["decide_unavailable"]; !ok {
		t.Errorf("response does not say the request cannot be decided yet: %v", got)
	}
	if len(f.argo.calls) != 2 {
		t.Errorf("argo consulted %v, want one read per application", f.argo.calls)
	}

	// A repeat, even with the applications in the other order, is the stored request.
	b := goodWindowBody()
	b["applications"] = []string{"labs-mctl-telegram", "labs-mctl-web"}
	w = postAsRaw(t, f.router, windowsRoute, b, adminUser)
	assertStatus(t, w, http.StatusOK)
	if decodeJSON(t, w)["window"].(map[string]any)["approval"].(map[string]any)["id"] != approval["id"] {
		t.Fatalf("replay returned another request")
	}
	// The same window on a later main is a new request.
	f.head.sha = strings.Repeat("e", 40)
	w = postAsRaw(t, f.router, windowsRoute, goodWindowBody(), adminUser)
	assertStatus(t, w, http.StatusCreated)

	list := func(user *auth.User, id string, want int) map[string]any {
		t.Helper()
		w := getAs(t, f.router, windowsRoute+"?project=apps&window_id="+id, user)
		if w.Code != want {
			t.Fatalf("GET as %s: %d %s, want %d", user.ID, w.Code, w.Body, want)
		}
		if want != http.StatusOK {
			return nil
		}
		return decodeJSON(t, w)
	}
	if out := list(adminUser, wantID, http.StatusOK); len(out["windows"].([]any)) != 2 {
		t.Fatalf("list: %v", out)
	}
	if out := list(adminUser, "w-ffffffffffff", http.StatusOK); len(out["windows"].([]any)) != 0 {
		t.Fatalf("another id listed windows: %v", out)
	}
	list(adminUser, "w-%", http.StatusBadRequest)
	list(ownerUser, wantID, http.StatusForbidden)
	list(gitopsCI(gitopsMainWorkflow), wantID, http.StatusForbidden)
	// A CI principal still reaches no window route.
	if w := postAsRaw(t, f.router, windowsRoute, goodWindowBody(), gitopsCI(gitopsMainWorkflow)); w.Code != http.StatusForbidden {
		t.Fatalf("CI principal POST: %d", w.Code)
	}
}

// A row edited so that its columns no longer reproduce its digests is an
// error for the reader, never skipped.
func TestListReleaseWindowsRefusesInconsistentRecord(t *testing.T) {
	f := newWindowFixture(t, true)
	w := postAsRaw(t, f.router, windowsRoute, goodWindowBody(), adminUser)
	assertStatus(t, w, http.StatusCreated)
	id := decodeJSON(t, w)["window"].(map[string]any)["window_id"].(string)
	pool, err := pgxpool.New(context.Background(), os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(context.Background(), `UPDATE action_approval_requests SET artifact_hash = $1 WHERE action_kind = $2`,
		"sha256:"+strings.Repeat("c", 64), workitems.ActionKindReleaseWindow); err != nil {
		t.Fatal(err)
	}
	if w := getAs(t, f.router, windowsRoute+"?project=apps&window_id="+id, adminUser); w.Code != http.StatusInternalServerError ||
		!strings.Contains(w.Body.String(), "release_window_record_inconsistent") {
		t.Fatalf("inconsistent row: %d %s", w.Code, w.Body)
	}
}
