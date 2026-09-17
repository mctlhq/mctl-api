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

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/mctlhq/mctl-api/internal/events"
)

type fakeGitHubOutbox struct {
	mu   sync.Mutex
	envs map[string]events.Envelope
	err  error
}

func (f *fakeGitHubOutbox) Enqueue(_ context.Context, env events.Envelope, stream string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return false, f.err
	}
	if stream != events.DefaultStream {
		return false, errors.New("wrong stream " + stream)
	}
	if _, seen := f.envs[env.ID]; seen {
		return false, nil
	}
	f.envs[env.ID] = env
	return true, nil
}

const ghSecret = "gh-s3cret"

const prSynchronize = `{
  "action": "synchronize",
  "number": 90,
  "pull_request": {
    "number": 90,
    "title": "SECRET TITLE",
    "body": "SECRET BODY with a diff",
    "updated_at": "2026-09-17T08:05:12Z",
    "head": {"sha": "3e737a5d7c1f0f8f5c9a2b64a1e0d9c2b7f41a0e", "ref": "feat/x"}
  },
  "repository": {"full_name": "mctlhq/.github", "owner": {"login": "mctlhq"}},
  "sender": {"login": "someone"}
}`

func postGitHub(router http.Handler, event, delivery, body, sig string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/github", strings.NewReader(body))
	req.Header.Set("X-GitHub-Event", event)
	req.Header.Set("X-GitHub-Delivery", delivery)
	if sig != "" {
		req.Header.Set("X-Hub-Signature-256", sig)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func githubRouter(outbox GitHubEventOutbox, notify func()) http.Handler {
	return NewRouter(Options{
		GitHubWebhookSecret: ghSecret,
		GitHubWebhookOwners: []string{"mctlhq"},
		GitHubEventOutbox:   outbox,
		GitHubEventNotify:   notify,
	})
}

func TestGitHubWebhook_FailClosedAndSignature(t *testing.T) {
	if rec := postGitHub(NewRouter(Options{}), "pull_request", "d1", prSynchronize, argoSig(ghSecret, prSynchronize)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no secret: status %d, want 401", rec.Code)
	}
	router := githubRouter(&fakeGitHubOutbox{envs: map[string]events.Envelope{}}, nil)
	for name, sig := range map[string]string{"missing": "", "wrong": argoSig("other", prSynchronize), "garbage": "sha256=zz"} {
		if rec := postGitHub(router, "pull_request", "d1", prSynchronize, sig); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s signature: status %d, want 401", name, rec.Code)
		}
	}
	big := strings.Repeat(" ", maxGitHubWebhookBytes+1)
	if rec := postGitHub(router, "pull_request", "d1", big, argoSig(ghSecret, big)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize: status %d, want 413", rec.Code)
	}
}

func TestGitHubWebhook_QueuesReferenceOnlyEnvelopeOnce(t *testing.T) {
	outbox := &fakeGitHubOutbox{envs: map[string]events.Envelope{}}
	notified := 0
	router := githubRouter(outbox, func() { notified++ })
	const delivery = "5b2f7a40-9384-11f1-8a0e-2c6d1a7f0b11"

	rec := postGitHub(router, "pull_request", delivery, prSynchronize, argoSig(ghSecret, prSynchronize))
	if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"queued"`) {
		t.Fatalf("status %d body %s, want 202 queued", rec.Code, rec.Body.String())
	}
	env, ok := outbox.envs["github:"+delivery]
	if !ok {
		t.Fatalf("no envelope queued: %v", outbox.envs)
	}
	raw, _ := json.Marshal(env)
	for _, leaked := range []string{"SECRET", "diff", "someone", "feat/x"} {
		if strings.Contains(string(raw), leaked) {
			t.Fatalf("envelope leaks %q: %s", leaked, raw)
		}
	}
	want := map[string]string{"kind": "github.pull_request", "repository": "mctlhq/.github",
		"number": "90", "head_sha": "3e737a5d7c1f0f8f5c9a2b64a1e0d9c2b7f41a0e"}
	if env.Type != "github.pull_request.synchronize" || env.OccurredAt != "2026-09-17T08:05:12Z" ||
		env.CorrelationID != env.ID || len(env.Subject) != len(want) {
		t.Fatalf("envelope = %+v", env)
	}
	for k, v := range want {
		if env.Subject[k] != v {
			t.Fatalf("subject[%s] = %q, want %q", k, env.Subject[k], v)
		}
	}

	// GitHub redelivery of the same delivery id: accepted, not queued twice.
	rec = postGitHub(router, "pull_request", delivery, prSynchronize, argoSig(ghSecret, prSynchronize))
	if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"duplicate"`) {
		t.Fatalf("redelivery: status %d body %s", rec.Code, rec.Body.String())
	}
	if len(outbox.envs) != 1 || notified != 1 {
		t.Fatalf("queued %d, notified %d; want 1 and 1", len(outbox.envs), notified)
	}
}

func TestGitHubWebhook_IgnoresWhatIsNotPublished(t *testing.T) {
	outbox := &fakeGitHubOutbox{envs: map[string]events.Envelope{}}
	router := githubRouter(outbox, nil)
	labeled := strings.Replace(prSynchronize, `"synchronize"`, `"labeled"`, 1)
	foreign := strings.Replace(strings.Replace(prSynchronize, `"login": "mctlhq"`, `"login": "evil"`, 1), "mctlhq/.github", "evil/repo", 1)
	cases := []struct{ event, body string }{
		{"issues", prSynchronize},
		{"pull_request", labeled},
		{"pull_request", foreign},
		{"pull_request_review", prSynchronize}, // action synchronize is not "submitted"
	}
	for _, c := range cases {
		rec := postGitHub(router, c.event, "d-ignored", c.body, argoSig(ghSecret, c.body))
		if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), "ignored") {
			t.Fatalf("%s: status %d body %s, want 202 ignored", c.event, rec.Code, rec.Body.String())
		}
	}
	if rec := postGitHub(router, "ping", "d-ping", `{}`, argoSig(ghSecret, `{}`)); rec.Code != http.StatusOK {
		t.Fatalf("ping: status %d", rec.Code)
	}
	if len(outbox.envs) != 0 {
		t.Fatalf("ignored deliveries were queued: %v", outbox.envs)
	}
}

func TestGitHubWebhook_ReviewSubmitted(t *testing.T) {
	outbox := &fakeGitHubOutbox{envs: map[string]events.Envelope{}}
	router := githubRouter(outbox, nil)
	body := strings.Replace(prSynchronize, `"synchronize"`, `"submitted"`, 1)
	body = strings.Replace(body, `"sender"`, `"review": {"submitted_at": "2026-09-17T09:00:00Z", "body": "SECRET REVIEW"}, "sender"`, 1)
	rec := postGitHub(router, "pull_request_review", "d-review", body, argoSig(ghSecret, body))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	env := outbox.envs["github:d-review"]
	if env.Type != "github.pull_request_review.submitted" || env.OccurredAt != "2026-09-17T09:00:00Z" {
		t.Fatalf("envelope = %+v", env)
	}
}

func TestGitHubWebhook_OutboxUnavailableIs503NotAccepted(t *testing.T) {
	for name, outbox := range map[string]GitHubEventOutbox{
		"not configured": nil,
		"failing":        &fakeGitHubOutbox{envs: map[string]events.Envelope{}, err: errors.New("db down")},
	} {
		router := githubRouter(outbox, nil)
		rec := postGitHub(router, "pull_request", "d-503", prSynchronize, argoSig(ghSecret, prSynchronize))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: status %d, want 503 so the failed delivery stays visible in GitHub", name, rec.Code)
		}
	}
}

func TestGitHubWebhook_RejectsMalformedReferences(t *testing.T) {
	router := githubRouter(&fakeGitHubOutbox{envs: map[string]events.Envelope{}}, nil)
	noPR := `{"action":"opened","repository":{"full_name":"mctlhq/x","owner":{"login":"mctlhq"}}}`
	if rec := postGitHub(router, "pull_request", "d-x", noPR, argoSig(ghSecret, noPR)); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing pull_request: status %d, want 400", rec.Code)
	}
	if rec := postGitHub(router, "pull_request", "bad id with spaces", prSynchronize, argoSig(ghSecret, prSynchronize)); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid delivery id: status %d, want 400", rec.Code)
	}
}
