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

// Package events publishes reference-only mctl.events/v1 envelopes for GitHub
// pull request activity to platform Valkey Streams (mctlhq/.github#87).
//
// An envelope says which pull request changed and at which head, never what it
// contains: the consumer reads canonical state with its own GitHub tools. The
// webhook payload itself is discarded after the identifiers are extracted.
package events

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

const (
	// SpecVersion is the envelope contract (mctlhq/.github events/schemas).
	SpecVersion = "mctl.events/v1"
	// Source identifies this producer.
	Source = "mctl-api"
	// DefaultStream is the stream the github-producer ACL user may XADD to.
	DefaultStream = "mctl:events:github"
	// AuditStream receives one entry per stage of an event's life.
	AuditStream = "mctl:events:audit"
)

// Envelope mirrors the closed v1 schema; subject values are strings.
type Envelope struct {
	SpecVersion   string            `json:"specversion"`
	ID            string            `json:"id"`
	Type          string            `json:"type"`
	Source        string            `json:"source"`
	OccurredAt    string            `json:"occurred_at"`
	CorrelationID string            `json:"correlation_id"`
	Subject       map[string]string `json:"subject"`
}

// PullRequestActions are the pull_request actions that are published. Label,
// assignment and edit churn would wake a session without changing anything a
// reviewer acts on.
var PullRequestActions = map[string]bool{
	"opened": true, "reopened": true, "synchronize": true,
	"ready_for_review": true, "closed": true,
}

var (
	deliveryID = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	repoName   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)
	sha        = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// PullRequestFacts are the only fields read from a webhook payload.
type PullRequestFacts struct {
	Event      string // pull_request | pull_request_review
	Action     string
	DeliveryID string
	Repository string
	Number     int
	HeadSHA    string
	OccurredAt time.Time
}

// BuildEnvelope derives the envelope. The id is the GitHub delivery id, so a
// redelivery of the same webhook deduplicates at the outbox and the consumer.
func BuildEnvelope(f PullRequestFacts) (Envelope, error) {
	if !deliveryID.MatchString(f.DeliveryID) {
		return Envelope{}, fmt.Errorf("invalid delivery id %q", f.DeliveryID)
	}
	if !repoName.MatchString(f.Repository) || f.Number <= 0 {
		return Envelope{}, fmt.Errorf("invalid pull request reference %q#%d", f.Repository, f.Number)
	}
	var typ string
	switch f.Event {
	case "pull_request":
		if !PullRequestActions[f.Action] {
			return Envelope{}, fmt.Errorf("pull_request action %q is not published", f.Action)
		}
		typ = "github.pull_request." + f.Action
	case "pull_request_review":
		if f.Action != "submitted" {
			return Envelope{}, fmt.Errorf("pull_request_review action %q is not published", f.Action)
		}
		typ = "github.pull_request_review.submitted"
	default:
		return Envelope{}, fmt.Errorf("event %q is not published", f.Event)
	}
	id := "github:" + f.DeliveryID
	subject := map[string]string{
		"kind":       "github.pull_request",
		"repository": f.Repository,
		"number":     strconv.Itoa(f.Number),
	}
	if !sha.MatchString(f.HeadSHA) {
		// The head is what identifies the revision the event is about; an
		// event without it would be accepted but not actionable.
		return Envelope{}, fmt.Errorf("invalid head sha %q", f.HeadSHA)
	}
	subject["head_sha"] = f.HeadSHA
	occurred := f.OccurredAt
	if occurred.IsZero() {
		occurred = time.Now()
	}
	return Envelope{
		SpecVersion:   SpecVersion,
		ID:            id,
		Type:          typ,
		Source:        Source,
		OccurredAt:    occurred.UTC().Format(time.RFC3339),
		CorrelationID: id,
		Subject:       subject,
	}, nil
}

// Marshal renders compact JSON and enforces the 4 KiB envelope cap.
func (e Envelope) Marshal() (string, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	if len(b) > 4096 {
		return "", fmt.Errorf("envelope %s exceeds 4096 bytes", e.ID)
	}
	return string(b), nil
}
