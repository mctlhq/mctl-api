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

import "testing"

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
