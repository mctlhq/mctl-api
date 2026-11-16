package main

import (
	"log/slog"
	"os"
	"strings"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/ghtoken"
	"github.com/mctlhq/mctl-api/internal/releaseartifact"
)

// Release grants (mctl-api#1022, slice S1). Dark unless
// RELEASE_GRANTS_ENABLED=true.
//
//	RELEASE_GRANTS_REPOSITORIES       comma-separated owner/name, default mctlhq/mctl-api
//	RELEASE_GRANTS_READER_REPOSITORY  the release gate's repository, default mctlhq/mctl-gitops
//	RELEASE_GRANTS_REGISTRY_TOKEN_FILE a file holding a GHCR credential with
//	                                  read:packages, read per use; unset asks
//	                                  GHCR for an anonymous pull token
//
// Tags are read with the GitOps GitHub credential. GHCR accepts neither that
// GitHub App installation token nor fine-grained tokens, so a private
// package needs its own credential. Without a working one every request
// answers 503, never a pass.
type releaseGrantEnv struct {
	Enabled      bool
	Repositories string
	Reader       string
	RegistryFile string
}

func releaseGrantEnvFromOS() releaseGrantEnv {
	return releaseGrantEnv{
		Enabled:      os.Getenv("RELEASE_GRANTS_ENABLED") == "true",
		Repositories: os.Getenv("RELEASE_GRANTS_REPOSITORIES"),
		Reader:       os.Getenv("RELEASE_GRANTS_READER_REPOSITORY"),
		RegistryFile: os.Getenv("RELEASE_GRANTS_REGISTRY_TOKEN_FILE"),
	}
}

func releaseGrantOptions(env releaseGrantEnv, token ghtoken.Source, haveLedger bool) *mctlapi.ReleaseGrantOptions {
	if !env.Enabled {
		return nil
	}
	if !haveLedger {
		slog.Error("release grants disabled: the work-items store is not configured")
		return nil
	}
	repos := []string{}
	for _, r := range strings.Split(envDefault(env.Repositories, "mctlhq/mctl-api"), ",") {
		if r = strings.ToLower(strings.TrimSpace(r)); r != "" {
			repos = append(repos, r)
		}
	}
	return &mctlapi.ReleaseGrantOptions{
		Resolver:         &releaseartifact.Resolver{Token: token, RegistryToken: ghtoken.File(env.RegistryFile)},
		Repositories:     repos,
		ReaderRepository: strings.ToLower(envDefault(env.Reader, "mctlhq/mctl-gitops")),
	}
}

func envDefault(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return v
}
