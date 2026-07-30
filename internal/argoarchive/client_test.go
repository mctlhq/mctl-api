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
	"net/http/httptest"
	"strings"
	"testing"
)

func testClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, "argo-workflows-logs", "access", "secret")
}

func TestListStepsParsesArchive(t *testing.T) {
	// Mirrors the real layout of a failed issue-poll run: the run-poller
	// step is absent because its pod never started.
	body := `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>wf-1/wf-1-clone-gitops-733206375/main.log</Key>
    <Size>333</Size>
    <LastModified>2026-07-30T08:16:00.000Z</LastModified>
  </Contents>
  <Contents>
    <Key>wf-1/wf-1-notify-telegram-4116628385/main.log</Key>
    <Size>36</Size>
    <LastModified>2026-07-30T09:16:00.000Z</LastModified>
  </Contents>
</ListBucketResult>`

	var gotQuery string
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		if auth := r.Header.Get("Authorization"); !strings.HasPrefix(auth, signAlgorithm) {
			t.Errorf("request was not signed: %q", auth)
		}
		_, _ = fmt.Fprint(w, body)
	})

	steps, err := c.ListSteps(context.Background(), "wf-1")
	if err != nil {
		t.Fatalf("ListSteps: %v", err)
	}
	if len(steps) != 2 {
		t.Fatalf("got %d steps, want 2", len(steps))
	}

	if !strings.Contains(gotQuery, "list-type=2") || !strings.Contains(gotQuery, "prefix=wf-1%2F") {
		t.Errorf("unexpected listing query: %s", gotQuery)
	}

	if steps[0].Step != "clone-gitops-733206375" {
		t.Errorf("Step = %q, want workflow prefix stripped", steps[0].Step)
	}
	if steps[0].Pod != "wf-1-clone-gitops-733206375" {
		t.Errorf("Pod = %q", steps[0].Pod)
	}
	if steps[0].Size != 333 {
		t.Errorf("Size = %d, want 333", steps[0].Size)
	}
	if steps[0].LastModified.IsZero() {
		t.Error("LastModified was not parsed")
	}
	for _, s := range steps {
		if strings.Contains(s.Step, "run-poller") {
			t.Errorf("unexpected run-poller step in fixture: %v", s)
		}
	}
}

func TestListStepsFollowsPagination(t *testing.T) {
	page := 0
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		page++
		if page == 1 {
			if strings.Contains(r.URL.RawQuery, "continuation-token") {
				t.Error("first page must not send a continuation token")
			}
			_, _ = fmt.Fprint(w, `<ListBucketResult>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>tok2</NextContinuationToken>
  <Contents><Key>wf/wf-a-1/main.log</Key><Size>1</Size></Contents>
</ListBucketResult>`)
			return
		}
		if !strings.Contains(r.URL.RawQuery, "continuation-token=tok2") {
			t.Errorf("continuation token not forwarded: %s", r.URL.RawQuery)
		}
		_, _ = fmt.Fprint(w, `<ListBucketResult>
  <IsTruncated>false</IsTruncated>
  <Contents><Key>wf/wf-b-2/main.log</Key><Size>2</Size></Contents>
</ListBucketResult>`)
	})

	steps, err := c.ListSteps(context.Background(), "wf")
	if err != nil {
		t.Fatalf("ListSteps: %v", err)
	}
	if len(steps) != 2 {
		t.Fatalf("got %d steps across pages, want 2", len(steps))
	}
}

func TestListStepsEmptyIsNotAnError(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>`)
	})

	steps, err := c.ListSteps(context.Background(), "missing-wf")
	if err != nil {
		t.Fatalf("ListSteps: %v", err)
	}
	if len(steps) != 0 {
		t.Errorf("got %d steps, want none", len(steps))
	}
}

func TestListStepsRequiresWorkflow(t *testing.T) {
	c := NewClient("https://example.invalid", "b", "a", "s")
	if _, err := c.ListSteps(context.Background(), ""); err == nil {
		t.Error("expected an error for an empty workflow name")
	}
}

func TestListStepsSurfacesHTTPError(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `<Error><Code>SignatureDoesNotMatch</Code></Error>`)
	})

	_, err := c.ListSteps(context.Background(), "wf")
	if err == nil {
		t.Fatal("expected an error on HTTP 403")
	}
	// A credentials problem must be obvious rather than look like "no logs".
	if !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "SignatureDoesNotMatch") {
		t.Errorf("unhelpful error: %v", err)
	}
}

func TestGetStepDropsPartialFirstLineOnRangedRead(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") == "" {
			t.Error("expected a Range request for the log tail")
		}
		w.Header().Set("Content-Range", "bytes 4096-4120/8192")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = fmt.Fprint(w, "ncated line\nsecond\nthird\n")
	})

	got, err := c.GetStep(context.Background(), "wf/pod/main.log", 10)
	if err != nil {
		t.Fatalf("GetStep: %v", err)
	}
	if got != "second\nthird" {
		t.Errorf("GetStep = %q, want the partial first line dropped", got)
	}
}

// Regression: a suffix range wider than the object returns 206 covering the
// WHOLE object. Keying the drop off the status alone silently ate the first
// line — the live archive reproduced this on a 36-byte notify-telegram log,
// hiding its "telegram http=200" line.
func TestGetStepKeepsFirstLineWhenRangeCoversWholeObject(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Range", "bytes 0-35/36")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = fmt.Fprint(w, "telegram http=200\nincident http=401\n")
	})

	got, err := c.GetStep(context.Background(), "wf/pod/main.log", 10)
	if err != nil {
		t.Fatalf("GetStep: %v", err)
	}
	if got != "telegram http=200\nincident http=401" {
		t.Errorf("GetStep = %q, want both lines intact", got)
	}
}

func TestGetStepKeepsEveryLineOnFullRead(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		// Server ignored the range entirely: plain 200, no Content-Range.
		_, _ = fmt.Fprint(w, "telegram http=200\nincident http=401\n")
	})

	got, err := c.GetStep(context.Background(), "wf/pod/main.log", 10)
	if err != nil {
		t.Fatalf("GetStep: %v", err)
	}
	if got != "telegram http=200\nincident http=401" {
		t.Errorf("GetStep = %q, want both lines intact", got)
	}
}

func TestStartsMidObject(t *testing.T) {
	tests := []struct {
		contentRange string
		want         bool
	}{
		{"bytes 4096-8191/16384", true},
		{"bytes 0-35/36", false}, // whole object in one 206
		{"bytes */16384", false}, // unsatisfiable range
		{"", false},              // plain 200
		{"garbage", false},
	}
	for _, tc := range tests {
		if got := startsMidObject(tc.contentRange); got != tc.want {
			t.Errorf("startsMidObject(%q) = %v, want %v", tc.contentRange, got, tc.want)
		}
	}
}

func TestGetStepAppliesTailLimit(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "one\ntwo\nthree\nfour\n")
	})

	got, err := c.GetStep(context.Background(), "wf/pod/main.log", 2)
	if err != nil {
		t.Fatalf("GetStep: %v", err)
	}
	if got != "three\nfour" {
		t.Errorf("GetStep = %q, want the last two lines", got)
	}
}

func TestGetStepRequiresKey(t *testing.T) {
	c := NewClient("https://example.invalid", "b", "a", "s")
	if _, err := c.GetStep(context.Background(), "", 10); err == nil {
		t.Error("expected an error for an empty key")
	}
}

func TestPodFromKey(t *testing.T) {
	tests := []struct{ key, prefix, want string }{
		{"wf-1/wf-1-run-poller-9/main.log", "wf-1/", "wf-1-run-poller-9"},
		{"other/wf-1-run-poller-9/main.log", "wf-1/", ""},
		{"wf-1/main.log", "wf-1/", ""},
		{"wf-1/", "wf-1/", ""},
		// Regression: only the exact leaf "main.log" is a step log. Anything
		// else under a pod's prefix (an output artifact, a nested marker)
		// must not be surfaced as one — a prior version accepted anything
		// with a second "/", which would have let GetStep return binary
		// artifact bytes as if they were log lines.
		{"wf-1/wf-1-run-poller-9/output.json", "wf-1/", ""},
		{"wf-1/wf-1-run-poller-9/archive/main.log", "wf-1/", ""},
	}
	for _, tc := range tests {
		if got := podFromKey(tc.key, tc.prefix); got != tc.want {
			t.Errorf("podFromKey(%q, %q) = %q, want %q", tc.key, tc.prefix, got, tc.want)
		}
	}
}

// Regression: bytesPerLineHint is only a starting guess. When actual lines
// run well past 2KiB (verbose agent output), the first window can land
// short of the requested line count; GetStep must widen the window instead
// of silently handing back fewer lines than asked for.
func TestGetStepExpandsWindowForLongLines(t *testing.T) {
	const lineSize = 4000
	const totalLines = 200
	var line strings.Builder
	for i := 0; i < lineSize-1; i++ {
		line.WriteByte('x')
	}
	oneLine := line.String() + "\n"
	full := strings.Repeat(oneLine, totalLines)

	requests := 0
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		rng := r.Header.Get("Range")
		var n int
		if _, err := fmt.Sscanf(rng, "bytes=-%d", &n); err != nil {
			t.Fatalf("unexpected Range header %q: %v", rng, err)
		}
		total := len(full)
		if n > total {
			n = total
		}
		start := total - n
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, total-1, total))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = fmt.Fprint(w, full[start:])
	})

	got, err := c.GetStep(context.Background(), "wf/pod/main.log", 100)
	if err != nil {
		t.Fatalf("GetStep: %v", err)
	}
	if n := countLines(got); n < 100 {
		t.Errorf("got %d lines, want at least 100 (window did not expand)", n)
	}
	if requests < 2 {
		t.Errorf("expected the window to widen across multiple requests, got %d request(s)", requests)
	}
}

// Regression: Argo can archive a zero-byte main.log for a step that produced
// no output. A suffix range against an empty object comes back as 416, not
// an empty 206 — that must be treated as a valid empty log, not an error.
func TestGetStepHandlesZeroByteObject(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Range", "bytes */0")
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
	})

	got, err := c.GetStep(context.Background(), "wf/pod/main.log", 10)
	if err != nil {
		t.Fatalf("GetStep on an empty archived log should not error: %v", err)
	}
	if got != "" {
		t.Errorf("GetStep = %q, want empty string for a zero-byte log", got)
	}
}

func TestLastLines(t *testing.T) {
	if got := lastLines("", 5); got != "" {
		t.Errorf("lastLines(\"\") = %q", got)
	}
	if got := lastLines("only\n", 5); got != "only" {
		t.Errorf("lastLines trailing newline = %q", got)
	}
	if got := lastLines("a\nb\nc", 2); got != "b\nc" {
		t.Errorf("lastLines = %q, want b\\nc", got)
	}
}

func TestNewClientNormalizesEndpoint(t *testing.T) {
	// R2 endpoints are normally configured without a scheme.
	if got := NewClient("acct.r2.cloudflarestorage.com", "b", "a", "s").baseURL; got != "https://acct.r2.cloudflarestorage.com" {
		t.Errorf("baseURL = %q", got)
	}
	if got := NewClient("http://localhost:9000/", "b", "a", "s").baseURL; got != "http://localhost:9000" {
		t.Errorf("baseURL = %q, want trailing slash trimmed", got)
	}
}
