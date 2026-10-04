package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// buildRepoParameters are operation parameters naming a GitHub repository the
// platform builds. The build workflow checks a repository out with a GitHub
// App token minted for whatever owner/name it is given, so a team may only
// build repositories connected to it in the portal, or public ones.
var buildRepoParameters = map[string]bool{"dockerfile_repo": true}

// Same shape as the portal's REPO_FULL_NAME_RE: owner/name, no dot-only
// segment (which URL normalization would collapse into a path change).
var repoFullNameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

func isDotOnly(s string) bool { return strings.Trim(s, ".") == "" }

const defaultGitHubAPIBaseURL = "https://api.github.com"

var buildRepoClient = &http.Client{Timeout: 10 * time.Second}

// errBuildRepoRefused is wrapped by every refusal, with the reason.
var errBuildRepoRefused = errors.New("build repository refused")

// checkBuildRepos refuses an operation whose build repository the caller's
// team may not use. Admins (which include the platform service principal)
// are not checked. Every failed or unreadable answer refuses: a binding
// lookup error is not "not connected", and only GitHub's own 200 with
// `private: false` makes a repository public.
func (h *Handlers) checkBuildRepos(ctx context.Context, op operations.Operation, input map[string]string, user *auth.User, team string) error {
	if user.IsAdmin() {
		return nil
	}
	for _, p := range op.Parameters {
		if !buildRepoParameters[p.Name] {
			continue
		}
		repo := strings.TrimSpace(input[p.Name])
		if repo == "" {
			continue
		}
		owner, name, _ := strings.Cut(repo, "/")
		if !repoFullNameRE.MatchString(repo) || isDotOnly(owner) || isDotOnly(name) {
			return fmt.Errorf("%w: %q is not a GitHub repository name (owner/name)", errBuildRepoRefused, repo)
		}
		bound, err := h.repoBoundToTeam(ctx, team, repo)
		if err != nil {
			return fmt.Errorf("%w: could not confirm that %q is connected to team %q: %v", errBuildRepoRefused, repo, team, err)
		}
		if bound {
			continue
		}
		public, err := h.repoIsPublic(ctx, repo)
		if err != nil || !public {
			return fmt.Errorf("%w: repository %q is not connected to team %q and is not public; connect it in the portal first", errBuildRepoRefused, repo, team)
		}
	}
	return nil
}

// checkBuildInputs applies every build-input check: the build repository
// (checkBuildRepos) and the image name (checkImageName).
func (h *Handlers) checkBuildInputs(ctx context.Context, op operations.Operation, input map[string]string, user *auth.User, team string) error {
	if err := h.checkImageName(op, input, user, team); err != nil {
		return err
	}
	return h.checkBuildRepos(ctx, op, input, user, team)
}

// imageParameters mark an operation whose component_name is an image name:
// it builds gitops.ImageRegistry/<component_name> (dockerfile_repo) or runs
// a pre-built tag of it (image_tag).
var imageParameters = []string{"dockerfile_repo", "image_tag"}

// checkImageName refuses an operation whose component_name is an image name
// the caller's team does not own, by the reviewed list in mctl-gitops
// (gitops.ImageNamesFile) and the services already there. Admins are not
// checked. An unreadable or malformed policy refuses.
func (h *Handlers) checkImageName(op operations.Operation, input map[string]string, user *auth.User, team string) error {
	if user.IsAdmin() {
		return nil
	}
	declared := map[string]bool{}
	for _, p := range op.Parameters {
		declared[p.Name] = true
	}
	usesImage := false
	for _, name := range imageParameters {
		usesImage = usesImage || declared[name]
	}
	if !usesImage || !declared["component_name"] {
		return nil
	}
	if h.opts.GitReader == nil {
		return fmt.Errorf("%w: image name policy unavailable", errBuildRepoRefused)
	}
	policy, err := h.opts.GitReader.ImageNamePolicy()
	if err != nil {
		return fmt.Errorf("%w: could not read the image name policy: %v", errBuildRepoRefused, err)
	}
	name := strings.TrimSpace(input["component_name"])
	if err := policy.Allowed(team, name, buildsImage(op, input, policy, team, name)); err != nil {
		return fmt.Errorf("%w: %v", errBuildRepoRefused, err)
	}
	return nil
}

// buildsImage reports whether the operation will push to
// <registry>/<component_name>, mirroring the workflows' own decision:
// preview-deploy builds when git_ref is set; deploy-service as
// ImageNamePolicy.DeployServiceBuilds says. Any other operation is taken to
// build, the stricter answer.
func buildsImage(op operations.Operation, input map[string]string, policy *gitops.ImageNamePolicy, team, name string) bool {
	switch op.Name {
	case "preview-deploy":
		return input["git_ref"] != ""
	case "deploy-service":
		return policy.DeployServiceBuilds(input["action"], input["dockerfile_repo"], input["service_template"], team, name)
	}
	return true
}

// repoBoundToTeam asks the portal's github-app-connect plugin, the system of
// record for repository connections.
func (h *Handlers) repoBoundToTeam(ctx context.Context, team, repo string) (bool, error) {
	if h.opts.BackstageInternalURL == "" || h.opts.BackstageGithubAppConnectToken == "" {
		return false, errors.New("repository binding check is not configured")
	}
	q := url.Values{"team": {team}, "repo": {repo}}
	u := strings.TrimRight(h.opts.BackstageInternalURL, "/") + "/api/github-app-connect/repo-binding?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+h.opts.BackstageGithubAppConnectToken)
	resp, err := buildRepoClient.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("binding check answered %d", resp.StatusCode)
	}
	var body struct {
		Team  string `json:"team"`
		Repo  string `json:"repo"`
		Bound *bool  `json:"bound"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body); err != nil {
		return false, fmt.Errorf("malformed binding answer: %w", err)
	}
	if body.Bound == nil || body.Team != team || !strings.EqualFold(body.Repo, repo) {
		return false, errors.New("malformed binding answer")
	}
	return *body.Bound, nil
}

// repoIsPublic asks GitHub without credentials. Only 200 with
// `private: false` is public; anything else (404, rate limit, error,
// malformed body) is reported as an error or false.
func (h *Handlers) repoIsPublic(ctx context.Context, repo string) (bool, error) {
	base := h.opts.GitHubAPIBaseURL
	if base == "" {
		base = defaultGitHubAPIBaseURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/repos/"+repo, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := buildRepoClient.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("github answered %d", resp.StatusCode)
	}
	var body struct {
		Private *bool `json:"private"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return false, fmt.Errorf("malformed github answer: %w", err)
	}
	if body.Private == nil {
		return false, errors.New("github answer has no private flag")
	}
	return !*body.Private, nil
}
