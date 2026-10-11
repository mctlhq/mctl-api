package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
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

// nilPolicyReader answers ImageNamePolicy with neither a policy nor an
// error; nothing else is called on it.
type nilPolicyReader struct{ GitReader }

func (nilPolicyReader) ImageNamePolicy() (*gitops.ImageNamePolicy, error) { return nil, nil }

func TestCheckImageName_NilPolicyIsUnavailableNotAPanic(t *testing.T) {
	op, ok := operations.NewRegistry().Get("deploy-service")
	if !ok {
		t.Fatal("deploy-service operation not registered")
	}
	h := &Handlers{opts: Options{GitReader: nilPolicyReader{}}}
	user := auth.NewGitHubUser("test-owner", []string{"tests"})
	err := h.checkImageName(op, map[string]string{"action": "onboard", "component_name": "my-app", "dockerfile_repo": "myorg/my-app"}, user, "tests")
	if !errors.Is(err, errBuildCheckUnavailable) {
		t.Fatalf("expected an unavailable check, got %v", err)
	}
}
