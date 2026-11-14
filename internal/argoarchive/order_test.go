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

package argoarchive

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func entry(key, modified string) string {
	return fmt.Sprintf("<Contents><Key>%s</Key><Size>1</Size><LastModified>%s</LastModified></Contents>", key, modified)
}

// TestListStepsOrdersOldestFirst: S3 lists in key order, which for a
// workflow is alphabetical by step name. The steps must come back in the
// order they were archived, ties broken by key, across pages.
func TestListStepsOrdersOldestFirst(t *testing.T) {
	pages := []string{
		`<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>p2</NextContinuationToken>` +
			entry("wf/wf-a-clone-1/main.log", "2026-07-30T08:00:10.000Z") +
			entry("wf/wf-b-notify-2/main.log", "2026-07-30T08:05:00.000Z") +
			entry("wf/wf-c-tie-y-3/main.log", "2026-07-30T08:02:00.000Z") +
			`</ListBucketResult>`,
		`<ListBucketResult><IsTruncated>false</IsTruncated>` +
			entry("wf/wf-c-tie-x-4/main.log", "2026-07-30T08:02:00.000Z") +
			entry("wf/wf-d-setup-5/main.log", "2026-07-30T08:00:00.000Z") +
			`</ListBucketResult>`,
	}
	page := 0
	c := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, pages[page])
		page++
	})
	steps, err := c.ListSteps(context.Background(), "wf")
	if err != nil {
		t.Fatalf("ListSteps: %v", err)
	}
	var got []string
	for _, s := range steps {
		got = append(got, s.Step)
	}
	want := []string{"d-setup-5", "a-clone-1", "c-tie-x-4", "c-tie-y-3", "b-notify-2"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("order = %v, want %v (archive time, then key)", got, want)
	}
}

// TestListStepsPartialListingIsAnError: a listing that cannot be read to
// its end is a failed read, never a shorter list.
func TestListStepsPartialListingIsAnError(t *testing.T) {
	cases := map[string]func(page int) string{
		"truncated page without a continuation token": func(int) string {
			return `<ListBucketResult><IsTruncated>true</IsTruncated>` +
				entry("wf/wf-a-1/main.log", "2026-07-30T08:00:00.000Z") + `</ListBucketResult>`
		},
		"more pages than the cap": func(page int) string {
			return fmt.Sprintf(`<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>t%d</NextContinuationToken>`, page) +
				entry(fmt.Sprintf("wf/wf-s%d-1/main.log", page), "2026-07-30T08:00:00.000Z") + `</ListBucketResult>`
		},
		"entry without LastModified": func(int) string {
			return `<ListBucketResult><IsTruncated>false</IsTruncated>` +
				entry("wf/wf-a-1/main.log", "2026-07-30T08:00:00.000Z") +
				`<Contents><Key>wf/wf-b-2/main.log</Key><Size>1</Size></Contents></ListBucketResult>`
		},
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			page := 0
			c := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprint(w, body(page))
				page++
			})
			steps, err := c.ListSteps(context.Background(), "wf")
			if err == nil {
				t.Fatalf("want an error, got %d steps and no error", len(steps))
			}
			if steps != nil {
				t.Errorf("a failed read must return no steps, got %d", len(steps))
			}
		})
	}
}
