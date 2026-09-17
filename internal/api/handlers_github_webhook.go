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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/mctlhq/mctl-api/internal/events"
)

// githubEnqueueTimeout bounds the outbox insert of one webhook delivery.
const githubEnqueueTimeout = 5 * time.Second

// GitHubEventOutbox durably accepts an envelope before the webhook is answered.
type GitHubEventOutbox interface {
	Enqueue(ctx context.Context, env events.Envelope, stream string) (inserted bool, err error)
}

const maxGitHubWebhookBytes = 1 << 20 // 1 MiB

// githubWebhookPayload lists the only fields read. Titles, bodies, diffs and
// review text are never decoded into anything that outlives this request.
type githubWebhookPayload struct {
	Action      string `json:"action"`
	PullRequest *struct {
		Number    int       `json:"number"`
		UpdatedAt time.Time `json:"updated_at"`
		Head      struct {
			SHA string `json:"sha"`
		} `json:"head"`
	} `json:"pull_request"`
	Review *struct {
		SubmittedAt time.Time `json:"submitted_at"`
	} `json:"review"`
	Repository *struct {
		FullName string `json:"full_name"`
		Owner    struct {
			Login string `json:"login"`
		} `json:"owner"`
	} `json:"repository"`
}

// HandleGitHubWebhook turns pull request activity into reference-only
// mctl.events/v1 envelopes for running Claude sessions (mctlhq/.github#87).
//
// Authenticated with X-Hub-Signature-256 over the raw body; fail-closed when
// the secret or the outbox is not configured. 202 is returned only once the
// envelope is committed to the outbox, because GitHub never retries a failed
// delivery by itself: a 5xx is visible in the hook's delivery log and can be
// redelivered, while a 202 for an event that was then lost could not.
func (h *Handlers) HandleGitHubWebhook(w http.ResponseWriter, r *http.Request) {
	secret := h.opts.GitHubWebhookSecret
	if secret == "" {
		writeError(w, http.StatusUnauthorized, "webhook secret not configured")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxGitHubWebhookBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read body")
		return
	}
	if len(body) > maxGitHubWebhookBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "payload too large")
		return
	}
	if !validGitHubSignature(secret, body, r.Header.Get("X-Hub-Signature-256")) {
		writeError(w, http.StatusUnauthorized, "invalid signature")
		return
	}

	event := r.Header.Get("X-GitHub-Event")
	delivery := r.Header.Get("X-GitHub-Delivery")
	if event == "ping" {
		writeJSON(w, http.StatusOK, map[string]string{"status": "pong"})
		return
	}
	if event != "pull_request" && event != "pull_request_review" {
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "ignored", "reason": "event not published"})
		return
	}

	var payload githubWebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json payload")
		return
	}
	if payload.Repository == nil || payload.PullRequest == nil {
		writeError(w, http.StatusBadRequest, "repository and pull_request are required")
		return
	}
	if !h.githubOwnerAllowed(payload.Repository.Owner.Login) {
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "ignored", "reason": "repository owner not allowed"})
		return
	}
	facts := events.PullRequestFacts{
		Event:      event,
		Action:     payload.Action,
		DeliveryID: delivery,
		Repository: payload.Repository.FullName,
		Number:     payload.PullRequest.Number,
		HeadSHA:    payload.PullRequest.Head.SHA,
		OccurredAt: payload.PullRequest.UpdatedAt,
	}
	if (event == "pull_request" && !events.PullRequestActions[payload.Action]) ||
		(event == "pull_request_review" && payload.Action != "submitted") {
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "ignored", "reason": "action not published"})
		return
	}
	if event == "pull_request_review" {
		// The event is the review, so its time is the submission time; a
		// submitted review without one is malformed, not a PR update.
		if payload.Review == nil || payload.Review.SubmittedAt.IsZero() {
			writeError(w, http.StatusBadRequest, "review.submitted_at is required")
			return
		}
		facts.OccurredAt = payload.Review.SubmittedAt
	}
	env, err := events.BuildEnvelope(facts)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if h.opts.GitHubEventOutbox == nil {
		writeError(w, http.StatusServiceUnavailable, "event outbox not configured")
		return
	}
	// This route sits outside the timeout middleware; bound the database call
	// so an unreachable outbox answers 503 instead of holding the delivery.
	enqueueCtx, cancel := context.WithTimeout(r.Context(), githubEnqueueTimeout)
	defer cancel()
	inserted, err := h.opts.GitHubEventOutbox.Enqueue(enqueueCtx, env, events.DefaultStream)
	if err != nil {
		slog.Error("github webhook: event outbox enqueue failed", "event_id", env.ID, "error", err)
		writeError(w, http.StatusServiceUnavailable, "event outbox unavailable")
		return
	}
	if inserted && h.opts.GitHubEventNotify != nil {
		h.opts.GitHubEventNotify()
	}
	status := "queued"
	if !inserted {
		status = "duplicate"
	}
	slog.Info("github webhook accepted", "event_id", env.ID, "type", env.Type,
		"repository", facts.Repository, "number", facts.Number, "status", status)
	writeJSON(w, http.StatusAccepted, map[string]string{"status": status, "event_id": env.ID})
}

func (h *Handlers) githubOwnerAllowed(owner string) bool {
	for _, allowed := range h.opts.GitHubWebhookOwners {
		if strings.EqualFold(owner, allowed) {
			return true
		}
	}
	return false
}

func validGitHubSignature(secret string, body []byte, header string) bool {
	const prefix = "sha256="
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	got, err := hex.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return hmac.Equal(mac.Sum(nil), got)
}
