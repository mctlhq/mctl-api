package api_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/releaseartifact"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// fakeReleaseResolver answers from a map of version -> artifact or error.
type fakeReleaseResolver struct {
	calls int
	out   map[string]workitems.ReleaseArtifact
	errs  map[string]error
}

func (f *fakeReleaseResolver) Resolve(_ context.Context, repo, version string) (workitems.ReleaseArtifact, error) {
	f.calls++
	if err := f.errs[version]; err != nil {
		return workitems.ReleaseArtifact{}, err
	}
	a, ok := f.out[version]
	if !ok || a.Repository != repo {
		return workitems.ReleaseArtifact{}, releaseartifact.ErrNotFound
	}
	return a, nil
}

func releaseArt(version string) workitems.ReleaseArtifact {
	return workitems.ReleaseArtifact{Repository: "mctlhq/mctl-api", Version: version,
		TagCommit: strings.Repeat("a", 40), ImageDigest: "sha256:" + strings.Repeat("b", 64)}
}

type releaseFixture struct {
	router   http.Handler
	resolver *fakeReleaseResolver
	wi       *workitems.Store
}

func newReleaseFixture(t *testing.T, enabled bool) *releaseFixture {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL is unset in CI: the release grant tests must run, not skip")
		}
		t.Skip("TEST_DATABASE_URL not set")
	}
	t.Setenv("AUTH_REQUIRED", "false")
	ctx := context.Background()
	wi, err := workitems.NewStore(ctx, dsn)
	if err != nil {
		t.Fatalf("workitems.NewStore: %v", err)
	}
	t.Cleanup(func() {
		if pool, err := pgxpool.New(ctx, dsn); err == nil {
			_, _ = pool.Exec(ctx, `DELETE FROM action_approval_requests WHERE action_kind = $1`, workitems.ActionKindReleaseGrant)
			pool.Close()
		}
		wi.Close()
	})
	f := &releaseFixture{wi: wi, resolver: &fakeReleaseResolver{
		out:  map[string]workitems.ReleaseArtifact{"7.0.0": releaseArt("7.0.0"), "7.0.1": releaseArt("7.0.1")},
		errs: map[string]error{},
	}}
	opts := mctlapi.Options{
		Registry: operations.NewRegistry(), GitReader: &fakeGitReader{}, ArgoCD: &fakeArgoCD{},
		AuditLog: audit.NewLogger(), Executor: &fakeExecutor{}, WorkItems: wi,
	}
	if enabled {
		opts.ReleaseGrants = &mctlapi.ReleaseGrantOptions{Resolver: f.resolver,
			Repositories: []string{"mctlhq/mctl-api"}, ReaderRepository: "mctlhq/mctl-gitops"}
	}
	f.router = mctlapi.NewRouter(opts)
	return f
}

func gitopsCI(ref string) *auth.User {
	return auth.NewCIJobUser("mctlhq/mctl-gitops", "1", ref)
}

const gitopsMainWorkflow = "mctlhq/mctl-gitops/.github/workflows/release-deploy.yaml@refs/heads/main"

func TestReleaseGrantRoutesAreDarkByDefault(t *testing.T) {
	f := newReleaseFixture(t, false)
	w := postAsRaw(t, f.router, "/api/v1/release/grants", map[string]string{"repository": "mctlhq/mctl-api", "version": "7.0.0"}, adminUser)
	if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST with the feature off: %d %s, want 404", w.Code, w.Body)
	}
}

func TestRequestReleaseGrantRefusals(t *testing.T) {
	f := newReleaseFixture(t, true)
	f.resolver.errs["7.0.2"] = fmt.Errorf("wrapped: %w", releaseartifact.ErrMismatch)
	f.resolver.errs["7.0.3"] = fmt.Errorf("wrapped: %w", releaseartifact.ErrUnavailable)
	body := func(repo, version string) map[string]string {
		return map[string]string{"repository": repo, "version": version}
	}
	cases := []struct {
		name string
		user *auth.User
		body any
		want int
		code string
	}{
		{"non-admin human", ownerUser, body("mctlhq/mctl-api", "7.0.0"), http.StatusForbidden, "release_grant_forbidden"},
		{"gitops CI principal", gitopsCI(gitopsMainWorkflow), body("mctlhq/mctl-api", "7.0.0"), http.StatusForbidden, ""},
		{"repository not enabled", adminUser, body("mctlhq/mctl-web", "7.0.0"), http.StatusForbidden, "release_grant_forbidden"},
		{"unknown field", adminUser, map[string]string{"repository": "mctlhq/mctl-api", "version": "7.0.0", "image_digest": "sha256:x"}, http.StatusBadRequest, "release_grant_invalid_input"},
		{"tag missing", adminUser, body("mctlhq/mctl-api", "7.9.9"), http.StatusNotFound, "release_artifact_not_found"},
		{"image from another commit", adminUser, body("mctlhq/mctl-api", "7.0.2"), http.StatusConflict, "release_artifact_mismatch"},
		{"registry unreadable", adminUser, body("mctlhq/mctl-api", "7.0.3"), http.StatusServiceUnavailable, "release_artifact_unavailable"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := postAsRaw(t, f.router, "/api/v1/release/grants", c.body, c.user)
			if w.Code != c.want {
				t.Fatalf("status %d %s, want %d", w.Code, w.Body, c.want)
			}
			if c.code != "" && !strings.Contains(w.Body.String(), c.code) {
				t.Errorf("body %s, want code %s", w.Body, c.code)
			}
		})
	}
	if rows, err := f.wi.ReleaseApprovals(context.Background(), "mctlhq/mctl-api", "7.0.0", 0); err != nil || len(rows) != 0 {
		t.Fatalf("a refused request stored a row: %v %v", rows, err)
	}
}

func TestRequestAndListReleaseGrant(t *testing.T) {
	f := newReleaseFixture(t, true)
	req := map[string]string{"repository": "mctlhq/mctl-api", "version": "7.0.0"}
	w := postAsRaw(t, f.router, "/api/v1/release/grants", req, adminUser)
	assertStatus(t, w, http.StatusCreated)
	got := decodeJSON(t, w)
	grant := got["grant"].(map[string]any)
	approval := grant["approval"].(map[string]any)
	art := releaseArt("7.0.0")
	if approval["state"] != workitems.ApprovalPending || approval["action_kind"] != workitems.ActionKindReleaseGrant ||
		approval["execution_id"] != art.TagCommit || approval["artifact_hash"] != art.ImageDigest ||
		approval["args_digest"] != workitems.ReleaseArgsDigest(art) || approval["target"] != "mctlhq/mctl-api@7.0.0" {
		t.Fatalf("approval does not bind the artifact: %v", approval)
	}
	if _, ok := got["decide_unavailable"]; !ok {
		t.Errorf("response does not say the grant cannot be decided yet: %v", got)
	}

	// A repeat returns the stored request.
	w = postAsRaw(t, f.router, "/api/v1/release/grants", req, adminUser)
	assertStatus(t, w, http.StatusOK)
	if decodeJSON(t, w)["grant"].(map[string]any)["approval"].(map[string]any)["id"] != approval["id"] {
		t.Fatalf("replay returned another request")
	}

	list := func(user *auth.User, version string, want int) map[string]any {
		t.Helper()
		w := getAs(t, f.router, "/api/v1/release/grants?repository=mctlhq/mctl-api&version="+version, user)
		if w.Code != want {
			t.Fatalf("GET as %s: %d %s, want %d", user.ID, w.Code, w.Body, want)
		}
		if want != http.StatusOK {
			return nil
		}
		return decodeJSON(t, w)
	}
	for _, reader := range []*auth.User{adminUser, gitopsCI(gitopsMainWorkflow)} {
		out := list(reader, "7.0.0", http.StatusOK)
		grants := out["grants"].([]any)
		if len(grants) != 1 || grants[0].(map[string]any)["artifact"].(map[string]any)["image_digest"] != art.ImageDigest {
			t.Fatalf("list as %s: %v", reader.ID, out)
		}
	}
	if out := list(adminUser, "7.0.1", http.StatusOK); len(out["grants"].([]any)) != 0 {
		t.Fatalf("another version listed grants: %v", out)
	}

	// Who may not read.
	list(ownerUser, "7.0.0", http.StatusForbidden)
	list(gitopsCI("mctlhq/mctl-gitops/.github/workflows/release-deploy.yaml@refs/heads/feature"), "7.0.0", http.StatusForbidden)
	// A branch named "x@refs/heads/main": the workflow ref ends like main's.
	list(gitopsCI("mctlhq/mctl-gitops/.github/workflows/release-deploy.yaml@refs/heads/x@refs/heads/main"), "7.0.0", http.StatusForbidden)
	list(gitopsCI("mctlhq/mctl-gitops/.github/workflows/sub/x.yaml@refs/heads/main"), "7.0.0", http.StatusForbidden)
	list(gitopsCI("mctlhq/mctl-gitops/.github/workflows/@refs/heads/main"), "7.0.0", http.StatusForbidden)
	list(gitopsCI("mctlhq/other/.github/workflows/x.yaml@refs/heads/main"), "7.0.0", http.StatusForbidden)
	// Another repository calling a reusable workflow of mctl-gitops on main:
	// job_workflow_ref names mctl-gitops, the token's repository does not.
	list(auth.NewCIJobUser("mctlhq/other", "3", gitopsMainWorkflow), "7.0.0", http.StatusForbidden)
	list(auth.NewCIJobUser("mctlhq/mctl-api", "2", "mctlhq/mctl-api/.github/workflows/x.yaml@refs/heads/main"), "7.0.0", http.StatusForbidden)
	// A CI principal still reaches no other route.
	if w := getAs(t, f.router, "/api/v1/tenants", gitopsCI(gitopsMainWorkflow)); w.Code != http.StatusForbidden {
		t.Fatalf("CI principal on another route: %d", w.Code)
	}
}

// A row edited so that its columns no longer reproduce its args digest is an
// error for the reader, never a grant and never silently skipped.
func TestListReleaseGrantsRefusesInconsistentRecord(t *testing.T) {
	f := newReleaseFixture(t, true)
	w := postAsRaw(t, f.router, "/api/v1/release/grants", map[string]string{"repository": "mctlhq/mctl-api", "version": "7.0.1"}, adminUser)
	assertStatus(t, w, http.StatusCreated)
	pool, err := pgxpool.New(context.Background(), os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(context.Background(), `UPDATE action_approval_requests SET artifact_hash = $1 WHERE target = $2`,
		"sha256:"+strings.Repeat("c", 64), "mctlhq/mctl-api@7.0.1"); err != nil {
		t.Fatal(err)
	}
	if w := getAs(t, f.router, "/api/v1/release/grants?repository=mctlhq/mctl-api&version=7.0.1", adminUser); w.Code != http.StatusInternalServerError ||
		!strings.Contains(w.Body.String(), "release_grant_record_inconsistent") {
		t.Fatalf("inconsistent row: %d %s", w.Code, w.Body)
	}
}
