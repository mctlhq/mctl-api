// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package ghactions dispatches GitHub Actions workflows.
//
// It exists so that mctl-api can ask a workflow to run without holding the
// credential that workflow uses. The first caller is the Cloudflare MCP
// portal's server-auth apply (mctl-gitops portal-server-auth-apply.yml): the
// Cloudflare write token is an environment secret on that repository's
// `cloudflare-apply` environment, issued only to a job that requests the
// environment and only after a human reviewer approves it. mctl-api holds a
// GitHub token that can start the run and nothing else, so the approval — and
// the Cloudflare credential — stay on the far side of a boundary this process
// cannot cross.
package ghactions

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ErrNotConfigured is returned when no token is set. Callers turn it into a
// 503 rather than a 500: an unconfigured optional dependency is a deployment
// fact, not a request that went wrong.
var ErrNotConfigured = errors.New("github actions dispatch not configured")

// DefaultBaseURL is github.com's REST API. Overridable so tests can point at
// an httptest server without a network.
const DefaultBaseURL = "https://api.github.com"

// Dispatcher starts workflow_dispatch runs.
type Dispatcher struct {
	Token   string
	BaseURL string
	HTTP    *http.Client
}

// New returns a Dispatcher with a bounded client. A dispatch is a single
// small POST; 15s is generous for it and short enough that a GitHub outage
// does not hold an API request open to the caller's own timeout.
func New(token string) *Dispatcher {
	return &Dispatcher{
		Token:   token,
		BaseURL: DefaultBaseURL,
		HTTP:    &http.Client{Timeout: 15 * time.Second},
	}
}

// Dispatch starts workflowFile on ref in owner/repo.
//
// The API answers 204 with an empty body and no run id — there is no way to
// learn which run this call created, because at 204 the run does not exist
// yet. That is why this returns no identifier and callers hand back a link to
// the workflow's run list instead of pretending to a specific run. Polling for
// "the newest run" would be a guess: a scheduled run or a second dispatcher
// can land between the POST and the poll.
func (d *Dispatcher) Dispatch(ctx context.Context, owner, repo, workflowFile, ref string, inputs map[string]string) error {
	if d == nil || d.Token == "" {
		return ErrNotConfigured
	}
	// Every segment goes into a path. None of them is caller-supplied today
	// (the handler pins all four as constants), but a later caller that
	// forwards user input must not be able to walk out of the path or inject
	// a query, so the check lives here rather than in the one caller.
	for _, seg := range []struct{ name, value string }{
		{"owner", owner}, {"repo", repo}, {"workflow", workflowFile}, {"ref", ref},
	} {
		if seg.value == "" || strings.ContainsAny(seg.value, "/?#%") {
			return fmt.Errorf("invalid %s %q", seg.name, seg.value)
		}
	}

	body := map[string]interface{}{"ref": ref}
	if len(inputs) > 0 {
		body["inputs"] = inputs
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/repos/%s/%s/actions/workflows/%s/dispatches",
		strings.TrimRight(d.BaseURL, "/"), owner, repo, workflowFile)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+d.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	client := d.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("dispatch request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	// Capped: GitHub's error bodies are small, and an unbounded read of an
	// error response is an unbounded allocation driven by the far side.
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	// The token is never in the URL or the body, so the status and GitHub's
	// own message are safe to pass back. 404 is the one worth naming: for a
	// token without `actions: write` GitHub answers 404 rather than 403, so
	// "the workflow does not exist" and "this token may not start it" are the
	// same response and an operator reading only the status will chase the
	// wrong one.
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("github answered 404 for %s/%s %s@%s: the workflow file is missing on that ref, or the token lacks actions:write on the repository (GitHub returns 404, not 403, for both): %s",
			owner, repo, workflowFile, ref, strings.TrimSpace(string(msg)))
	}
	return fmt.Errorf("github answered %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
}
