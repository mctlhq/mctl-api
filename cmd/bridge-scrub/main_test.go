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
	"strings"
	"testing"
)

func TestScrubCLIRequiresExplicitConsentAndScopedDatabase(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
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
