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
	"strconv"
	"testing"
	"time"
)

func TestParseEvidenceRetentionDays(t *testing.T) {
	cases := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"", 0, false},
		{"0", 0, false},
		{" 90 ", 90, false},
		{strconv.Itoa(maxEvidenceRetentionDays), maxEvidenceRetentionDays, false},
		{"-1", 0, true},
		{"abc", 0, true},
		{strconv.Itoa(maxEvidenceRetentionDays + 1), 0, true},
		// Large enough to wrap days*24h negative if accepted.
		{"200000", 0, true},
	}
	for _, c := range cases {
		got, err := parseEvidenceRetentionDays(c.in)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("parseEvidenceRetentionDays(%q) = %d, %v; want %d, err=%v", c.in, got, err, c.want, c.wantErr)
		}
	}
}

// The bound must keep the retention duration positive: this is what stops
// the purge cutoff from landing in the future.
func TestMaxEvidenceRetentionDaysFitsDuration(t *testing.T) {
	if d := time.Duration(maxEvidenceRetentionDays) * 24 * time.Hour; d <= 0 {
		t.Fatalf("maxEvidenceRetentionDays overflows time.Duration: %s", d)
	}
}
