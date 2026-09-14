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

package temporalclient

import (
	"errors"
	"testing"
)

func TestWorkflowIDForIssueURL(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		want    string
		wantErr bool
	}{
		{
			name: "well-formed mctlhq issue URL",
			url:  "https://github.com/mctlhq/mctl-telegram/issues/296",
			want: "dev-loop-mctlhq-mctl-telegram-296",
		},
		{
			name: "repo with dots and dashes",
			url:  "https://github.com/mctlhq/mctl-openclaw/issues/1",
			want: "dev-loop-mctlhq-mctl-openclaw-1",
		},
		{name: "wrong org", url: "https://github.com/other-org/repo/issues/1", wantErr: true},
		{name: "not an issue URL", url: "https://github.com/mctlhq/mctl-telegram/pull/296", wantErr: true},
		{name: "missing issue number", url: "https://github.com/mctlhq/mctl-telegram/issues/", wantErr: true},
		{name: "empty string", url: "", wantErr: true},
		{name: "garbage", url: "not a url at all", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := WorkflowIDForIssueURL(tc.url)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %q, got workflow ID %q", tc.url, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.url, err)
			}
			if got != tc.want {
				t.Fatalf("WorkflowIDForIssueURL(%q) = %q, want %q", tc.url, got, tc.want)
			}
		})
	}
}

func TestWorkflowIDForProposalRef(t *testing.T) {
	// The two sentinels are NOT interchangeable, and the `wantErr` column says
	// which one: ErrNoDevLoopForProposalRef is an ANSWER ("this proposal never
	// had one") while ErrMalformedProposalRef is an ABSENCE ("this ref could
	// not be read"). A caller comparing mechanisms records `free` for the
	// first and `unknown` for the second, so conflating them fails in the
	// direction that reports a driven entity as unowned.
	for _, tc := range []struct {
		name    string
		in      string
		want    string
		wantErr error
	}{
		{name: "the shape DevLoopWorkflow writes", in: "mctl-web/issue-7-add-a-thing", want: "dev-loop-mctlhq-mctl-web-7"},
		{name: "multi-digit issue", in: "mctl-telegram/issue-296-x", want: "dev-loop-mctlhq-mctl-telegram-296"},
		{name: "a dotted service name", in: ".github/issue-57-epic", want: "dev-loop-mctlhq-.github-57"},
		// A PREFIX match, trailing hyphen included -- exactly what
		// run_shepherd.py's re.match(r"issue-(\d+)-", slug) accepts, so the two
		// sides cannot disagree about which proposals ever had a DevLoop.
		{name: "issue number with no trailing hyphen", in: "mctl-web/issue-7", wantErr: ErrNoDevLoopForProposalRef},
		{name: "an incident slug never had a DevLoop", in: "mctl-web/incident-2026-09-01", wantErr: ErrNoDevLoopForProposalRef},
		{name: "no service part", in: "issue-7-a-thing", wantErr: ErrMalformedProposalRef},
		{name: "empty slug", in: "mctl-web/", wantErr: ErrMalformedProposalRef},
		{name: "empty service", in: "/issue-7-a-thing", wantErr: ErrMalformedProposalRef},
		{name: "empty ref", in: "", wantErr: ErrMalformedProposalRef},
		// The prefix is anchored: a slug that merely CONTAINS issue-<N>- must
		// not resolve, or a proposal named after another one would silently
		// answer about that other one's workflow.
		{name: "prefix is anchored", in: "mctl-web/reverts-issue-7-a-thing", wantErr: ErrNoDevLoopForProposalRef},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := WorkflowIDForProposalRef(tc.in)
			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("expected an error, got %q", got)
				}
				if !errors.Is(err, tc.wantErr) {
					t.Errorf("error does not wrap %v: %v", tc.wantErr, err)
				}
				// The two must stay distinguishable: a single sentinel wrapping
				// both is the collapse this split exists to prevent.
				other := ErrMalformedProposalRef
				if tc.wantErr == ErrMalformedProposalRef {
					other = ErrNoDevLoopForProposalRef
				}
				if errors.Is(err, other) {
					t.Errorf("error wraps both sentinels: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
