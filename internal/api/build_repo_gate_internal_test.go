package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// The operation's parameter pattern refuses malformed repositories before
// the gate runs, so through the router the gate's own name check is never
// reached. It stays as defence in depth for any caller that skips parameter
// validation, and is exercised here directly.
func TestCheckBuildRepos_RefusesMalformedNameBeforeAnyLookup(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"team":"tests","repo":"x/y","bound":true}`))
	}))
	t.Cleanup(srv.Close)

	op, ok := operations.NewRegistry().Get("deploy-service")
	if !ok {
		t.Fatal("deploy-service operation not registered")
	}
	h := &Handlers{opts: Options{
		BackstageInternalURL:           srv.URL,
		BackstageGithubAppConnectToken: "gac-token",
		GitHubAPIBaseURL:               srv.URL,
	}}
	user := auth.NewGitHubUser("test-owner", []string{"tests"})

	for _, repo := range []string{"../etc", "owner", "a/b/c", "owner/..", "../..", "./x", " myorg/my-app", "myorg/my-app ", "myorg/my-app\n"} {
		t.Run(repo, func(t *testing.T) {
			hits.Store(0)
			err := h.checkBuildRepos(context.Background(), op, map[string]string{"dockerfile_repo": repo}, user, "tests")
			if !errors.Is(err, errBuildRepoRefused) {
				t.Fatalf("expected a build-repository refusal, got %v", err)
			}
			if hits.Load() != 0 {
				t.Error("a malformed repository must be refused before any lookup")
			}
		})
	}
}
