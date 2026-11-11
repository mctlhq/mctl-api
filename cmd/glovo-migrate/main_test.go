// Copyright 2026 MCTL Authors
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
	"strings"
	"testing"
)

func TestRunRefusesWithoutEnvAndNeverEchoesTheDSN(t *testing.T) {
	const secret = "s3cr3t-pw-cli" //nolint:gosec // throwaway value the test asserts is never echoed
	var out, errb bytes.Buffer

	t.Setenv("MCTL_GLOVO_MIGRATE_DSN", "")
	if code := run([]string{"-workitems-role", "mctl_api_workitems"}, &out, &errb); code != 1 {
		t.Fatalf("empty env: exit %d", code)
	}

	// A plaintext DSN is refused before any connection, and the message does
	// not carry the DSN or the password.
	t.Setenv("MCTL_GLOVO_MIGRATE_DSN", "postgres://glovo_migrator:"+secret+"@127.0.0.1:1/db?sslmode=disable")
	out.Reset()
	errb.Reset()
	if code := run([]string{"-workitems-role", "mctl_api_workitems"}, &out, &errb); code != 1 {
		t.Fatalf("plaintext DSN: exit %d", code)
	}
	if all := out.String() + errb.String(); strings.Contains(all, secret) || strings.Contains(all, "postgres://") || !strings.Contains(all, "sslmode") {
		t.Fatalf("output: %q", all)
	}

	// No work-items role: refused.
	t.Setenv("MCTL_GLOVO_MIGRATE_DSN", "postgres://glovo_migrator:"+secret+"@127.0.0.1:1/db?sslmode=require")
	errb.Reset()
	if code := run(nil, &out, &errb); code != 1 || strings.Contains(errb.String(), secret) {
		t.Fatalf("no work-items role: exit %d, %q", code, errb.String())
	}

	// Mutually exclusive modes.
	if code := run([]string{"-dry-run", "-verify", "-workitems-role", "x"}, &out, &errb); code != 1 {
		t.Fatalf("dry-run with verify: exit %d", code)
	}

	// An unreachable database is "could not observe" (exit 3), never ok.
	errb.Reset()
	if code := run([]string{"-verify", "-workitems-role", "mctl_api_workitems"}, &out, &errb); code != 3 || strings.Contains(errb.String(), secret) {
		t.Fatalf("unreachable database: exit %d, %q", code, errb.String())
	}
}
