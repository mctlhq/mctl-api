package api_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/ghactions"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Sync-window removal: the mirror of the release window routes for lifting ONE
// deny window. A separate kind, so what the addition tests pin for additions is
// pinned here for removals, plus the cross-kind refusals.

const removalsRoute = "/api/v1/release/window-removals"

func removalExecutePath(id string) string { return removalsRoute + "/" + id + "/execute" }

func goodRemovalBody() map[string]any {
	return map[string]any{"project": "apps", "applications": []string{"labs-portfolio"}, "schedule": "0 3 * * 0", "duration": "1h"}
}

// withPortfolioWindow has Argo report the window that goodRemovalBody names.
func (f *windowFixture) withPortfolioWindow() *windowFixture {
	f.argo.assigned = map[string][]argocd.AppSyncWindow{
		"apps/labs-portfolio": {{Kind: "deny", Schedule: "0 3 * * 0", Duration: "1h"}},
	}
	return f
}

func (f *windowFixture) requestRemoval(t *testing.T) string {
	t.Helper()
	w := postAsRaw(t, f.router, removalsRoute, goodRemovalBody(), adminUser)
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("request removal: %d %s", w.Code, w.Body)
	}
	return decodeJSON(t, w)["removal"].(map[string]any)["approval"].(map[string]any)["id"].(string)
}

// approveRemoval stands in for the owner's decide page, with the removal path.
func (f *windowFixture) approveRemoval(t *testing.T, id string) {
	t.Helper()
	a, err := f.wi.ActionApproval(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.wi.DecideReleaseWindowRemovalApproval(context.Background(), workitems.ReleaseWindowDecisionInput{
		ID: id, DecidedBy: "oidc:owner", DecidedByPrincipalID: "prn_owner", Approve: true,
		Evidence: workitems.ReleaseEvidence{Schema: workitems.ReleaseEvidenceSchema, ArgsDigest: a.ArgsDigest,
			Issuer: "https://auth.example", Subject: "3001", ClientID: "release-page", AuthTime: 1_800_000_000, AMR: []string{"mfa"}},
	})
	if err != nil {
		t.Fatalf("approve removal: %v", err)
	}
}

func (f *windowFixture) countKind(t *testing.T, kind string) int {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM action_approval_requests WHERE action_kind=$1`, kind).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestReleaseWindowRemovalRoutesAreDarkByDefault(t *testing.T) {
	f := newWindowFixture(t, false)
	for _, path := range []string{removalsRoute, removalExecutePath("aar_0123456789abcdef0123456789abcdef")} {
		w := postAsRaw(t, f.router, path, goodRemovalBody(), adminUser)
		if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST %s with the feature off: %d %s, want 404", path, w.Code, w.Body)
		}
	}
	if f.head.calls != 0 {
		t.Fatalf("a dark route read GitHub")
	}
}

func TestRequestReleaseWindowRemovalRefusals(t *testing.T) {
	with := func(k string, v any) map[string]any {
		b := goodRemovalBody()
		b[k] = v
		return b
	}
	cases := []struct {
		name string
		user *auth.User
		body any
		want int
		code string
		prep func(*windowFixture)
	}{
		{"non-admin human", ownerUser, goodRemovalBody(), http.StatusForbidden, "release_window_forbidden", nil},
		{"gitops CI principal", gitopsCI(gitopsMainWorkflow), goodRemovalBody(), http.StatusForbidden, "", nil},
		{"unknown field", adminUser, with("kind", "allow"), http.StatusBadRequest, "release_window_invalid_input", nil},
		{"default project", adminUser, with("project", "default"), http.StatusBadRequest, "release_window_invalid_input", nil},
		{"glob application", adminUser, with("applications", []string{"labs-*"}), http.StatusBadRequest, "release_window_invalid_input", nil},
		{"no applications", adminUser, with("applications", []string{}), http.StatusBadRequest, "release_window_invalid_input", nil},
		{"bad duration", adminUser, with("duration", "2d"), http.StatusBadRequest, "release_window_invalid_input", nil},
		{"a schedule Argo does not hold", adminUser, with("schedule", "0 4 * * 0"), http.StatusUnprocessableEntity, "release_window_not_assigned", nil},
		{"a duration Argo does not hold", adminUser, with("duration", "2h"), http.StatusUnprocessableEntity, "release_window_not_assigned", nil},
		{"no window assigned at all", adminUser, goodRemovalBody(), http.StatusUnprocessableEntity, "release_window_not_assigned",
			func(f *windowFixture) { f.argo.assigned = nil }},
		{"an allow window is not a deny window", adminUser, goodRemovalBody(), http.StatusUnprocessableEntity, "release_window_not_assigned",
			func(f *windowFixture) {
				f.argo.assigned["apps/labs-portfolio"][0].Kind = "allow"
			}},
		{"github unreadable", adminUser, goodRemovalBody(), http.StatusServiceUnavailable, "release_window_unavailable",
			func(f *windowFixture) { f.head.err = errors.New("github down") }},
		{"argo unreadable", adminUser, goodRemovalBody(), http.StatusServiceUnavailable, "release_window_unavailable",
			func(f *windowFixture) { f.argo.err = errors.New("argo down") }},
		{"argo refuses the read", adminUser, goodRemovalBody(), http.StatusServiceUnavailable, "release_window_unavailable",
			func(f *windowFixture) { f.argo.err = argocd.ErrForbidden }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newWindowFixture(t, true).withPortfolioWindow()
			if c.prep != nil {
				c.prep(f)
			}
			w := postAsRaw(t, f.router, removalsRoute, c.body, c.user)
			if w.Code != c.want {
				t.Fatalf("status %d %s, want %d", w.Code, w.Body, c.want)
			}
			if c.code != "" && !strings.Contains(w.Body.String(), c.code) {
				t.Errorf("body %s, want code %s", w.Body, c.code)
			}
			if n := f.countKind(t, workitems.ActionKindReleaseWindowRemoval); n != 0 {
				t.Fatalf("a refused request stored %d rows", n)
			}
		})
	}
}

// A malformed request must not cost a GitHub or Argo call.
func TestRequestReleaseWindowRemovalShapeIsCheckedBeforeAnyRead(t *testing.T) {
	f := newWindowFixture(t, true).withPortfolioWindow()
	b := goodRemovalBody()
	b["project"] = "default"
	if w := postAsRaw(t, f.router, removalsRoute, b, adminUser); w.Code != http.StatusBadRequest {
		t.Fatalf("status %d %s", w.Code, w.Body)
	}
	if f.head.calls != 0 || len(f.argo.calls) != 0 {
		t.Fatalf("a malformed request read GitHub %d times and Argo %v", f.head.calls, f.argo.calls)
	}
}

func TestRequestReleaseWindowRemovalCreatesAndReplays(t *testing.T) {
	f := newWindowFixture(t, true).withPortfolioWindow()
	w := postAsRaw(t, f.router, removalsRoute, goodRemovalBody(), adminUser)
	assertStatus(t, w, http.StatusCreated)
	got := decodeJSON(t, w)
	rem := got["removal"].(map[string]any)
	approval := rem["approval"].(map[string]any)
	win := workitems.ReleaseWindow{Project: "apps", Applications: []string{"labs-portfolio"}, Schedule: "0 3 * * 0", Duration: "1h", BaseSHA: rwTestBase}
	wantHash, _ := win.RemovalSHA256()
	wantID, _ := win.ReleaseWindowRemovalID()
	if approval["action_kind"] != workitems.ActionKindReleaseWindowRemoval || approval["state"] != "pending" ||
		rem["removal_sha256"] != wantHash || rem["window_id"] != wantID || !strings.HasPrefix(wantID, "r-") {
		t.Fatalf("request: %v", got)
	}
	if f.countKind(t, workitems.ActionKindReleaseWindow) != 0 || f.countKind(t, workitems.ActionKindReleaseWindowRemoval) != 1 {
		t.Fatal("a removal request must store a removal row and no addition row")
	}
	// The same request again is the same approval.
	w = postAsRaw(t, f.router, removalsRoute, goodRemovalBody(), adminUser)
	assertStatus(t, w, http.StatusOK)
	if decodeJSON(t, w)["removal"].(map[string]any)["approval"].(map[string]any)["id"] != approval["id"] {
		t.Fatal("a repeated request made another approval")
	}
}

// An Application Argo no longer knows (404) does not stop its window from being
// lifted: the workflow checks the window against main.
func TestRequestReleaseWindowRemovalOfADeletedApplicationIsAllowed(t *testing.T) {
	f := newWindowFixture(t, true)
	delete(f.argo.known, "apps/labs-portfolio")
	w := postAsRaw(t, f.router, removalsRoute, goodRemovalBody(), adminUser)
	assertStatus(t, w, http.StatusCreated)
}

func TestExecuteReleaseWindowRemovalDispatchesTheRemovalWorkflowOnce(t *testing.T) {
	f := newWindowFixture(t, true).withPortfolioWindow()
	id := f.requestRemoval(t)
	f.approveRemoval(t, id)

	w := postAsRaw(t, f.router, removalExecutePath(id), nil, adminUser)
	assertStatus(t, w, http.StatusOK)
	got := decodeJSON(t, w)
	win := workitems.ReleaseWindow{Project: "apps", Applications: []string{"labs-portfolio"}, Schedule: "0 3 * * 0", Duration: "1h", BaseSHA: rwTestBase}
	wantHash, _ := win.RemovalSHA256()
	wantID, _ := win.ReleaseWindowRemovalID()

	if f.dispatch.count() != 1 {
		t.Fatalf("%d dispatches, want 1", f.dispatch.count())
	}
	c := f.dispatch.calls[0]
	if c.owner != "mctlhq" || c.repo != "mctl-gitops" || c.workflow != "release-window-removal-pr.yml" || c.ref != "main" {
		t.Fatalf("dispatched to %s/%s %s@%s", c.owner, c.repo, c.workflow, c.ref)
	}
	wantInputs := map[string]string{"window_id": wantID, "project": "apps", "applications": "labs-portfolio",
		"schedule": "0 3 * * 0", "duration": "1h", "base_sha": rwTestBase, "window_sha256": wantHash}
	if len(c.inputs) != len(wantInputs) {
		t.Fatalf("inputs %v", c.inputs)
	}
	for k, v := range wantInputs {
		if c.inputs[k] != v {
			t.Errorf("input %s = %q, want %q", k, c.inputs[k], v)
		}
	}
	if got["status"] != "dispatched" || got["branch"] != "release-window-removal/"+wantID ||
		got["workflow_runs_url"] != "https://github.com/mctlhq/mctl-gitops/actions/workflows/release-window-removal-pr.yml" {
		t.Fatalf("response %v", got)
	}
	if n := got["next"].(string); !strings.Contains(n, "merged and synced nothing") || !strings.Contains(n, "queues it for merge") ||
		!strings.Contains(n, "deletes the window") {
		t.Errorf("the response overclaims or misdescribes: %v", got["next"])
	}
	if f.state(t, id) != workitems.ApprovalExecuted {
		t.Fatalf("approval is %s after a dispatch, want executed", f.state(t, id))
	}
	// Spent once.
	w = postAsRaw(t, f.router, removalExecutePath(id), nil, adminUser)
	if w.Code != http.StatusConflict || f.dispatch.count() != 1 {
		t.Fatalf("second execute: %d %s (dispatches %d)", w.Code, w.Body, f.dispatch.count())
	}
}

// The two kinds are not interchangeable at the execute routes, in either
// direction, and a refusal leaves the approval as it was.
func TestExecuteRoutesRefuseTheOtherKind(t *testing.T) {
	f := newWindowFixture(t, true).withPortfolioWindow()
	remID := f.requestRemoval(t)
	f.approveRemoval(t, remID)
	addID := f.request(t)
	f.approve(t, addID)

	if w := postAsRaw(t, f.router, executePath(remID), nil, adminUser); w.Code != http.StatusNotFound {
		t.Fatalf("the addition route on a removal approval: %d %s", w.Code, w.Body)
	}
	if w := postAsRaw(t, f.router, removalExecutePath(addID), nil, adminUser); w.Code != http.StatusNotFound {
		t.Fatalf("the removal route on an addition approval: %d %s", w.Code, w.Body)
	}
	if f.dispatch.count() != 0 {
		t.Fatalf("a cross-kind execute dispatched %d times", f.dispatch.count())
	}
	for _, id := range []string{remID, addID} {
		if f.state(t, id) != workitems.ApprovalApproved {
			t.Errorf("a refused execute moved %s to %s", id, f.state(t, id))
		}
	}
}

func TestExecuteReleaseWindowRemovalRefusesWhatIsNotApproved(t *testing.T) {
	f := newWindowFixture(t, true).withPortfolioWindow()
	id := f.requestRemoval(t)
	w := postAsRaw(t, f.router, removalExecutePath(id), nil, adminUser)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "release_window_not_decided") {
		t.Fatalf("pending: %d %s", w.Code, w.Body)
	}
	if f.dispatch.count() != 0 {
		t.Fatal("a pending removal was dispatched")
	}
}

func TestExecuteReleaseWindowRemovalWhoMayExecute(t *testing.T) {
	f := newWindowFixture(t, true).withPortfolioWindow()
	id := f.requestRemoval(t)
	f.approveRemoval(t, id)
	for name, u := range map[string]*auth.User{"another admin": otherAdmin, "a non-admin": ownerUser, "gitops CI": gitopsCI(gitopsMainWorkflow)} {
		w := postAsRaw(t, f.router, removalExecutePath(id), nil, u)
		if w.Code != http.StatusNotFound && w.Code != http.StatusForbidden {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	if f.dispatch.count() != 0 || f.state(t, id) != workitems.ApprovalApproved {
		t.Fatalf("a refused caller dispatched %d times, state %s", f.dispatch.count(), f.state(t, id))
	}
}

func TestExecuteReleaseWindowRemovalFailedDispatchIsRetryable(t *testing.T) {
	f := newWindowFixture(t, true).withPortfolioWindow()
	id := f.requestRemoval(t)
	f.approveRemoval(t, id)
	f.dispatch.setErr(errors.New("github 500"))
	if w := postAsRaw(t, f.router, removalExecutePath(id), nil, adminUser); w.Code != http.StatusBadGateway {
		t.Fatalf("failed dispatch: %d %s", w.Code, w.Body)
	}
	if f.state(t, id) != workitems.ApprovalApproved {
		t.Fatalf("a failed dispatch left the approval %s, want approved", f.state(t, id))
	}
	f.dispatch.setErr(nil)
	if w := postAsRaw(t, f.router, removalExecutePath(id), nil, adminUser); w.Code != http.StatusOK {
		t.Fatalf("retry: %d %s", w.Code, w.Body)
	}
	if f.state(t, id) != workitems.ApprovalExecuted {
		t.Fatalf("approval is %s after the retry", f.state(t, id))
	}
	f.dispatch.setErr(ghactions.ErrNotConfigured)
}

func TestExecuteReleaseWindowRemovalWithoutADispatcherLeavesTheApproval(t *testing.T) {
	f := newWindowFixtureWith(t, windowFixtureOpts{enabled: true, noDispatcher: true}).withPortfolioWindow()
	id := f.requestRemoval(t)
	f.approveRemoval(t, id)
	if w := postAsRaw(t, f.router, removalExecutePath(id), nil, adminUser); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("no dispatcher: %d %s", w.Code, w.Body)
	}
	if f.state(t, id) != workitems.ApprovalApproved {
		t.Fatalf("a refusal burned the approval: %s", f.state(t, id))
	}
}

// An Argo that cannot be read, or an Application that has gone, must not stop
// an approved removal: the window is lifted by what main holds.
func TestExecuteReleaseWindowRemovalDoesNotNeedArgo(t *testing.T) {
	f := newWindowFixture(t, true).withPortfolioWindow()
	id := f.requestRemoval(t)
	f.approveRemoval(t, id)
	f.argo.err = errors.New("argo down")
	if w := postAsRaw(t, f.router, removalExecutePath(id), nil, adminUser); w.Code != http.StatusOK {
		t.Fatalf("execute with Argo down: %d %s", w.Code, w.Body)
	}
	if f.dispatch.count() != 1 {
		t.Fatalf("%d dispatches", f.dispatch.count())
	}
}
