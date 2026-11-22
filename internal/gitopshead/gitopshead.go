// Package gitopshead reads the commit a branch of one repository points at.
//
// A release window approval is given on a base commit of mctl-gitops main
// (execution_id of the request), and release-window-pr.yml refuses it unless
// that commit is an ancestor of main and the target template has not changed
// since. The server reads the commit itself, so a caller cannot choose the base
// it asks the owner to approve.
//
// Every failure is ErrUnavailable: a transport error, any status but 200 (a
// 404 included, because a missing main is not a fact this caller may act on), a
// malformed body, a ref that is not a commit, a SHA that is not 40 lower-case
// hex, a missing credential. There is no "empty" or "unchanged" answer.
package gitopshead

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

	"github.com/mctlhq/mctl-api/internal/ghtoken"
)

// ErrUnavailable: the commit could not be read or checked.
var ErrUnavailable = errors.New("branch head could not be read")

const (
	defaultGitHubAPI = "https://api.github.com"
	maxBody          = 1 << 20
)

var (
	shaRe    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	repoRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*/[a-z0-9][a-z0-9_.-]*$`)
	branchRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,100}$`)
)

// Resolver reads refs/heads/<Branch> of Repository.
type Resolver struct {
	Token      ghtoken.Source
	Repository string // lower-case owner/name
	Branch     string
	GitHubAPI  string // default https://api.github.com
	HTTP       *http.Client
}

func unavailable(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUnavailable, fmt.Sprintf(format, args...))
}

// Head returns the commit SHA the branch points at.
func (r *Resolver) Head(ctx context.Context) (string, error) {
	if !repoRe.MatchString(r.Repository) || !branchRe.MatchString(r.Branch) || strings.Contains(r.Branch, "..") {
		return "", unavailable("repository %q or branch %q is not configured", r.Repository, r.Branch)
	}
	token, err := ghtoken.Resolve(r.Token)
	if err != nil || token == "" {
		return "", unavailable("the GitHub credential could not be read")
	}
	base := r.GitHubAPI
	if base == "" {
		base = defaultGitHubAPI
	}
	// url.PathEscape would turn the '/' of a branch like release/x into %2F,
	// which this endpoint does not accept; escape per segment.
	segs := strings.Split(r.Branch, "/")
	for i := range segs {
		segs[i] = url.PathEscape(segs[i])
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		base+"/repos/"+r.Repository+"/git/ref/heads/"+strings.Join(segs, "/"), nil)
	if err != nil {
		return "", unavailable("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	hc := r.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", unavailable("GET %s: %v", req.URL.Redacted(), err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		return "", unavailable("read %s: body unreadable or over %d bytes", req.URL.Redacted(), maxBody)
	}
	if resp.StatusCode != http.StatusOK {
		return "", unavailable("%s: GitHub answered %d", req.URL.Redacted(), resp.StatusCode)
	}
	var ref struct {
		Object struct {
			Type string `json:"type"`
			SHA  string `json:"sha"`
		} `json:"object"`
	}
	if err := json.Unmarshal(body, &ref); err != nil {
		return "", unavailable("malformed ref: %v", err)
	}
	if ref.Object.Type != "commit" || !shaRe.MatchString(ref.Object.SHA) {
		return "", unavailable("ref is not a commit with a full lower-case SHA (type %q)", ref.Object.Type)
	}
	return ref.Object.SHA, nil
}
