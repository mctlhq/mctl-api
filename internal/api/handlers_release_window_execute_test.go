package api_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/ghactions"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Sync-window write path, S3: an approved release.window is spent by ONE
// dispatch of release-window-pr.yml, by the requester, addressed by the
// approval id, and never burned by a refusal or a failed dispatch.

var otherAdmin = &auth.User{ID: "other-admin", Groups: []string{"admins"}}

func executePath(id string) string { return windowsRoute + "/" + id + "/execute" }

// request opens a window request as adminUser and returns the approval id.
func (f *windowFixture) request(t *testing.T) string {
	t.Helper()
	w := postAsRaw(t, f.router, windowsRoute, goodWindowBody(), adminUser)
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("request: %d %s", w.Code, w.Body)
	}
	return decodeJSON(t, w)["window"].(map[string]any)["approval"].(map[string]any)["id"].(string)
}

// approve stands in for the owner's decide page: the same store call, with the
// evidence a fresh sign-in with a second factor produces.
func (f *windowFixture) approve(t *testing.T, id string) {
	t.Helper()
	a, err := f.wi.ActionApproval(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.wi.DecideReleaseWindowApproval(context.Background(), workitems.ReleaseWindowDecisionInput{
		ID: id, DecidedBy: "oidc:owner", DecidedByPrincipalID: "prn_owner", Approve: true,
		Evidence: workitems.ReleaseEvidence{Schema: workitems.ReleaseEvidenceSchema, ArgsDigest: a.ArgsDigest,
			Issuer: "https://auth.example", Subject: "3001", ClientID: "release-page", AuthTime: 1_800_000_000, AMR: []string{"mfa"}},
	})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
}

func (f *windowFixture) state(t *testing.T, id string) string {
	t.Helper()
	a, err := f.wi.ActionApproval(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return a.State
}

func (f *windowFixture) sql(t *testing.T, q string, args ...any) {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(context.Background(), q, args...); err != nil {
		t.Fatal(err)
	}
}

func TestExecuteReleaseWindowDispatchesOnce(t *testing.T) {
	f := newWindowFixture(t, true)
	id := f.request(t)
	f.approve(t, id)

	w := postAsRaw(t, f.router, executePath(id), nil, adminUser)
	assertStatus(t, w, http.StatusOK)
	got := decodeJSON(t, w)

	win := workitems.ReleaseWindow{Project: "apps", Applications: []string{"labs-mctl-telegram", "labs-mctl-web"},
		Schedule: "0 22 * * 5", Duration: "48h", BaseSHA: rwTestBase}
	wantHash, _ := win.WindowSHA256()
	wantID, _ := win.ReleaseWindowID()

	if f.dispatch.count() != 1 {
		t.Fatalf("%d dispatches, want 1", f.dispatch.count())
	}
	c := f.dispatch.calls[0]
	if c.owner != "mctlhq" || c.repo != "mctl-gitops" || c.workflow != "release-window-pr.yml" || c.ref != "main" {
		t.Fatalf("dispatched to %s/%s %s@%s", c.owner, c.repo, c.workflow, c.ref)
	}
	wantInputs := map[string]string{"window_id": wantID, "project": "apps", "applications": "labs-mctl-telegram,labs-mctl-web",
		"schedule": "0 22 * * 5", "duration": "48h", "base_sha": rwTestBase, "window_sha256": wantHash}
	if len(c.inputs) != len(wantInputs) {
		t.Fatalf("inputs %v", c.inputs)
	}
	for k, v := range wantInputs {
		if c.inputs[k] != v {
			t.Errorf("input %s = %q, want %q", k, c.inputs[k], v)
		}
	}
	if got["status"] != "dispatched" || got["branch"] != "release-window/"+wantID ||
		got["workflow_runs_url"] != "https://github.com/mctlhq/mctl-gitops/actions/workflows/release-window-pr.yml" {
		t.Fatalf("response %v", got)
	}
	if !strings.Contains(got["next"].(string), "merged and synced nothing") {
		t.Errorf("the response overclaims: %v", got["next"])
	}
	if f.state(t, id) != workitems.ApprovalExecuted {
		t.Fatalf("approval is %s after a dispatch, want executed", f.state(t, id))
	}

	// Spent once.
	w = postAsRaw(t, f.router, executePath(id), nil, adminUser)
	if w.Code != http.StatusConflict {
		t.Fatalf("second execute: %d %s", w.Code, w.Body)
	}
	if f.dispatch.count() != 1 {
		t.Fatalf("a second execute dispatched again (%d)", f.dispatch.count())
	}
}

func TestExecuteReleaseWindowRefusesWhatIsNotApproved(t *testing.T) {
	f := newWindowFixture(t, true)
	id := f.request(t)

	// Pending: say where the owner decides.
	w := postAsRaw(t, f.router, executePath(id), nil, adminUser)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "release_window_not_decided") {
		t.Fatalf("pending: %d %s", w.Code, w.Body)
	}
	f.approve(t, id)

	// Expired after approval.
	f.sql(t, `UPDATE action_approval_requests SET expires_at = now() - interval '1 minute' WHERE id = $1`, id)
	w = postAsRaw(t, f.router, executePath(id), nil, adminUser)
	if w.Code != http.StatusConflict {
		t.Fatalf("expired: %d %s", w.Code, w.Body)
	}
	if f.dispatch.count() != 0 {
		t.Fatalf("a refused execute dispatched (%d)", f.dispatch.count())
	}
}

func TestExecuteReleaseWindowRefusesAnUnreproducibleDecision(t *testing.T) {
	f := newWindowFixture(t, true)
	id := f.request(t)
	f.approve(t, id)
	// The state still says approved; the evidence no longer reproduces the row.
	f.sql(t, `UPDATE action_approval_requests SET decided_context_digest = $2 WHERE id = $1`, id, "sha256:"+strings.Repeat("0", 64))
	w := postAsRaw(t, f.router, executePath(id), nil, adminUser)
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "release_window_record_inconsistent") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	// And a row that was approved some other way is not a decision either.
	id2 := func() string {
		f2 := f
		f2.head.sha = strings.Repeat("c", 40)
		return f2.request(t)
	}()
	f.sql(t, `UPDATE action_approval_requests SET state = 'approved' WHERE id = $1`, id2)
	if w := postAsRaw(t, f.router, executePath(id2), nil, adminUser); w.Code != http.StatusInternalServerError {
		t.Fatalf("approved with no evidence: %d %s", w.Code, w.Body)
	}
	if f.dispatch.count() != 0 {
		t.Fatalf("dispatched on an unreproducible decision (%d)", f.dispatch.count())
	}
}

// A refusal that can be made without side effects never burns the decision.
func TestExecuteReleaseWindowRefusalsLeaveTheApprovalIntact(t *testing.T) {
	cases := []struct {
		name string
		prep func(*windowFixture)
		want int
		code string
	}{
		{"application gone", func(f *windowFixture) { delete(f.argo.known, "apps/labs-mctl-web") }, http.StatusUnprocessableEntity, "release_window_unknown_application"},
		{"argo down", func(f *windowFixture) { f.argo.err = errors.New("argo down") }, http.StatusServiceUnavailable, "release_window_unavailable"},
		{"argo forbidden", func(f *windowFixture) { f.argo.err = argocd.ErrForbidden }, http.StatusServiceUnavailable, "release_window_unavailable"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newWindowFixture(t, true)
			id := f.request(t)
			f.approve(t, id)
			c.prep(f)
			w := postAsRaw(t, f.router, executePath(id), nil, adminUser)
			if w.Code != c.want || !strings.Contains(w.Body.String(), c.code) {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			if f.dispatch.count() != 0 || f.state(t, id) != workitems.ApprovalApproved {
				t.Fatalf("a refused execute left %d dispatches and state %s", f.dispatch.count(), f.state(t, id))
			}
		})
	}
	t.Run("no dispatcher configured", func(t *testing.T) {
		f := newWindowFixtureWith(t, windowFixtureOpts{enabled: true, noDispatcher: true})
		id := f.request(t)
		f.approve(t, id)
		w := postAsRaw(t, f.router, executePath(id), nil, adminUser)
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "release_window_dispatch_unavailable") {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		// Refused before the claim: the decision is untouched.
		if f.state(t, id) != workitems.ApprovalApproved {
			t.Fatalf("state %s, want approved", f.state(t, id))
		}
	})
}

// A dispatch GitHub did not accept hands the decision back; the retry needs no
// second human decision.
func TestExecuteReleaseWindowFailedDispatchIsRetryable(t *testing.T) {
	for name, c := range map[string]struct {
		err  error
		want int
	}{
		"github refused":      {errors.New("github: 422"), http.StatusBadGateway},
		"no credential":       {ghactions.ErrCredentialUnavailable, http.StatusServiceUnavailable},
		"dispatch not set up": {ghactions.ErrNotConfigured, http.StatusServiceUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			f := newWindowFixture(t, true)
			id := f.request(t)
			f.approve(t, id)
			f.dispatch.setErr(c.err)
			w := postAsRaw(t, f.router, executePath(id), nil, adminUser)
			if w.Code != c.want || !strings.Contains(w.Body.String(), "release_window_dispatch_failed") ||
				!strings.Contains(w.Body.String(), "the approval is intact") {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			if f.state(t, id) != workitems.ApprovalApproved {
				t.Fatalf("state %s after a failed dispatch, want approved", f.state(t, id))
			}
			f.dispatch.setErr(nil)
			if w := postAsRaw(t, f.router, executePath(id), nil, adminUser); w.Code != http.StatusOK {
				t.Fatalf("retry: %d %s", w.Code, w.Body)
			}
			if f.dispatch.count() != 2 || f.state(t, id) != workitems.ApprovalExecuted {
				t.Fatalf("after the retry: %d dispatches, state %s", f.dispatch.count(), f.state(t, id))
			}
		})
	}
}

func TestExecuteReleaseWindowWhoMayExecute(t *testing.T) {
	f := newWindowFixture(t, true)
	id := f.request(t)
	f.approve(t, id)
	cases := []struct {
		name string
		user *auth.User
		path string
		want int
		code string
	}{
		{"non-admin human", ownerUser, executePath(id), http.StatusForbidden, "release_window_forbidden"},
		{"gitops CI principal", gitopsCI(gitopsMainWorkflow), executePath(id), http.StatusForbidden, ""},
		{"another admin", otherAdmin, executePath(id), http.StatusNotFound, "release_window_forbidden"},
		{"malformed id", adminUser, windowsRoute + "/not-an-id/execute", http.StatusBadRequest, "release_window_invalid_input"},
		{"unknown id", adminUser, executePath("aar_00000000000000000000000000000000"), http.StatusNotFound, "release_window_forbidden"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := postAsRaw(t, f.router, c.path, nil, c.user)
			if w.Code != c.want || (c.code != "" && !strings.Contains(w.Body.String(), c.code)) {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
		})
	}
	if f.dispatch.count() != 0 || f.state(t, id) != workitems.ApprovalApproved {
		t.Fatalf("a refused caller left %d dispatches and state %s", f.dispatch.count(), f.state(t, id))
	}
	// A release grant is not a window, even for its own requester.
	art := workitems.ReleaseArtifact{Repository: "mctlhq/mctl-api", Version: "7.7.7",
		TagCommit: strings.Repeat("a", 40), ImageDigest: "sha256:" + strings.Repeat("b", 64)}
	pol := workitems.ReleaseGrantPolicyRuleID
	// The grant is the caller's own, so only the kind check can refuse it.
	mine, err := f.wi.ActionApproval(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	g, _, err := f.wi.CreateReleaseApproval(context.Background(), art, workitems.ActionApprovalInput{
		ActionIntent: workitems.ReleaseIntent(art), RequestedBy: mine.RequestedBy, RequestedByPrincipalID: mine.RequestedByPrincipalID,
		IdempotencyKey: workitems.ReleaseIdempotencyKey(art), ExpiresAt: time.Now().Add(time.Hour), RiskLevel: "high",
		IntentSource: "release:x", SideEffect: "write", PolicyDecision: "require_approval", PolicyReasons: []string{pol},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.sql(t, `DELETE FROM action_approval_requests WHERE id = $1`, g.ID)
	})
	if w := postAsRaw(t, f.router, executePath(g.ID), nil, adminUser); w.Code != http.StatusNotFound {
		t.Fatalf("a grant id at the execute route: %d %s", w.Code, w.Body)
	}
}

// However many callers race, one dispatch is made.
func TestExecuteReleaseWindowRacingCallersDispatchOnce(t *testing.T) {
	f := newWindowFixture(t, true)
	f.dispatch.delay = 150 * time.Millisecond
	id := f.request(t)
	f.approve(t, id)

	const n = 6
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = postAsRaw(t, f.router, executePath(id), nil, adminUser).Code
		}(i)
	}
	wg.Wait()
	ok := 0
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			ok++
		case http.StatusConflict:
		default:
			t.Errorf("unexpected status %d in %v", c, codes)
		}
	}
	if ok != 1 || f.dispatch.count() != 1 {
		t.Fatalf("%d callers succeeded and %d dispatches were made (%v), want exactly one of each", ok, f.dispatch.count(), codes)
	}
}

func TestExecuteReleaseWindowDispatchesToTheConfiguredRepository(t *testing.T) {
	f := newWindowFixtureWith(t, windowFixtureOpts{enabled: true, repository: "acme/gitops"})
	id := f.request(t)
	f.approve(t, id)
	if w := postAsRaw(t, f.router, executePath(id), nil, adminUser); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if c := f.dispatch.calls[0]; c.owner != "acme" || c.repo != "gitops" {
		t.Fatalf("dispatched to %s/%s, want acme/gitops", c.owner, c.repo)
	}
}

func TestExecuteReleaseWindowRouteIsDarkByDefault(t *testing.T) {
	f := newWindowFixture(t, false)
	w := postAsRaw(t, f.router, executePath("aar_00000000000000000000000000000000"), nil, adminUser)
	if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("execute with the feature off: %d %s, want 404", w.Code, w.Body)
	}
	if f.dispatch.count() != 0 {
		t.Fatal("a dark route dispatched")
	}
}
