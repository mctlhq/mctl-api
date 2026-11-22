package main

import (
	"log/slog"
	"os"
	"strings"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/ghtoken"
	"github.com/mctlhq/mctl-api/internal/gitopshead"
)

// Release windows (sync-window write path, S1). Dark unless
// RELEASE_WINDOWS_ENABLED=true.
//
//	RELEASE_WINDOWS_REPOSITORY  the repository whose main a window is approved on,
//	                            default mctlhq/mctl-gitops
//	RELEASE_WINDOWS_BRANCH      default main
//
// The base commit is read with the GitOps GitHub credential. Without a
// working one every request answers 503, never a pass.
type releaseWindowEnv struct {
	Enabled    bool
	Repository string
	Branch     string
}

func releaseWindowEnvFromOS() releaseWindowEnv {
	return releaseWindowEnv{
		Enabled:    os.Getenv("RELEASE_WINDOWS_ENABLED") == "true",
		Repository: os.Getenv("RELEASE_WINDOWS_REPOSITORY"),
		Branch:     os.Getenv("RELEASE_WINDOWS_BRANCH"),
	}
}

func releaseWindowOptions(env releaseWindowEnv, token ghtoken.Source, haveLedger bool) *mctlapi.ReleaseWindowOptions {
	if !env.Enabled {
		return nil
	}
	if !haveLedger {
		slog.Error("release windows disabled: the work-items store is not configured")
		return nil
	}
	repo := strings.ToLower(envDefault(env.Repository, "mctlhq/mctl-gitops"))
	return &mctlapi.ReleaseWindowOptions{Repository: repo, Head: &gitopshead.Resolver{
		Token:      token,
		Repository: repo,
		Branch:     envDefault(env.Branch, "main"),
	}}
}
