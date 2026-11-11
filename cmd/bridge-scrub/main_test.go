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

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestScrubCLIRequiresExplicitConsentAndScopedDatabase(t *testing.T) {
	cases := []struct {
		name	string
		args	[]string
		want	string
	}{
		{name: "no confirmation", args: nil, want: "--confirm=scrub-legacy-results"},
		{name: "unrecognized confirmation", args: []string{"--confirm=do-something-else"}, want: "--confirm=scrub-legacy-results"},
		{name: "too large batch", args: []string{"--confirm=scrub-legacy-results", "--batch-size=1001"}, want: "batch-size"},
		{name: "unbounded loop", args: []string{"--confirm=scrub-legacy-results", "--max-batches=10001"}, want: "max-batches"},
		{name: "unexpected positional argument", args: []string{"--confirm=scrub-legacy-results", "extra"}, want: "--confirm=scrub-legacy-results"},
		{name: "no scoped DB secret", args: []string{"--confirm=scrub-legacy-results"}, want: "MCTL_BRIDGE_SCRUB_DATABASE_URL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := run(context.Background(), tc.args, func(string) string { return "" }, &out)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("run error = %v, want containing %q", err, tc.want)
			}
			if out.Len() != 0 {
				t.Fatalf("rejected invocation wrote %q", out.String())
			}
		})
	}
}

type scrubBatchResult struct {
	n   int
	rem int64
	err error
}

type fakeScrubBatch struct {
	rows   []scrubBatchResult
	calls  int
	limits []int
}

func (f *fakeScrubBatch) ScrubLegacyResultBatch(_ context.Context, limit int) (int, int64, error) {
	f.limits = append(f.limits, limit)
	if f.calls >= len(f.rows) {
		return 0, 0, errors.New("unexpected extra scrub batch")
	}
	r := f.rows[f.calls]
	f.calls++
	return r.n, r.rem, r.err
}

func TestScrubBatchesProgressAndZeroRemaining(t *testing.T) {
	f := &fakeScrubBatch{}
	f.rows = append(f.rows, scrubBatchResult{n: 2, rem: 1}, scrubBatchResult{n: 1, rem: 0})
	var out bytes.Buffer
	if err := scrubBatches(context.Background(), f, &out, 2, 10); err != nil {
		t.Fatal(err)
	}
	if f.calls != 2 || f.limits[0] != 2 || f.limits[1] != 2 {
		t.Fatalf("batches/limits = %d/%v", f.calls, f.limits)
	}
	for _, part := range []string{"total_scrubbed=2 remaining=1", "total_scrubbed=3 remaining=0", "verify no old writers"} {
		if !strings.Contains(out.String(), part) {
			t.Fatalf("output %q missing %q", out.String(), part)
		}
	}
}

func TestScrubBatchesNoProgressAndCapAreFailures(t *testing.T) {
	cases := []struct {
		name	string
		n	int
		rem	int64
		want	string
	}{
		{name: "locked", n: 0, rem: 5, want: "no progress"},
		{name: "capped", n: 1, rem: 4, want: "stopped at batch cap"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeScrubBatch{rows: []scrubBatchResult{{n: tc.n, rem: tc.rem}}}
			var out bytes.Buffer
			err := scrubBatches(context.Background(), f, &out, 1, 1)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
		})
	}
}

func TestScrubBatchesCountsCommittedRowsOnCountError(t *testing.T) {
	f := &fakeScrubBatch{rows: []scrubBatchResult{{n: 2, rem: 0, err: errors.New("count failed after commit")}}}
	var out bytes.Buffer
	err := scrubBatches(context.Background(), f, &out, 2, 1)
	if err == nil || !strings.Contains(err.Error(), "processed 2 rows") {
		t.Fatalf("post-commit error should include committed rows: %v", err)
	}
}

func TestScrubBatchesCancellationBeforeWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := &fakeScrubBatch{}
	err := scrubBatches(ctx, f, &bytes.Buffer{}, 100, 1)
	if !errors.Is(err, context.Canceled) || f.calls != 0 {
		t.Fatalf("cancelled run err=%v calls=%d", err, f.calls)
	}
}
