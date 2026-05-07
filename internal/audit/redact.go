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

package audit

import "strings"

// sensitiveValueLen is the length above which a parameter value is treated as
// likely-credential. Picked to leave normal short values (URLs, tags, names,
// flags) untouched while catching cookie blobs, JWTs, base64 token bundles.
const sensitiveValueLen = 100

// sensitiveMarkers is a small allowlist of fragments that signal a secret
// regardless of length. Anchored on what has actually leaked through the
// audit log historically (Upwork OAuth tokens, JWTs, GitHub PATs, Slack).
var sensitiveMarkers = []string{
	"oauth2v2_int_",
	"eyj",          // JWT base64 prefix (header `{"alg":...}`)
	"bearer ",      // Authorization: Bearer ...
	"ghp_",         // GitHub classic PAT
	"github_pat_",  // GitHub fine-grained PAT
	"xoxb-",        // Slack bot token
	"xoxp-",        // Slack user token
	"cf_clearance", // Cloudflare clearance cookie
}

// IsLikelySensitive returns true when a parameter value should be masked
// before being returned to a client. Heuristic: long values OR values
// containing one of the well-known credential markers.
func IsLikelySensitive(value string) bool {
	if len(value) >= sensitiveValueLen {
		return true
	}
	lower := strings.ToLower(value)
	for _, marker := range sensitiveMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// RedactEntry returns a copy of e with sensitive values in Parameters masked.
//
// Applied at read-time so historical entries persisted before this code
// landed are also protected. Two-tier strategy:
//  1. Multi-value fields (env_vars / secret_env_vars) are split on newlines
//     and each KEY=value pair is masked independently — preserves visibility
//     into which keys were set without leaking the values.
//  2. Other fields are masked whole when the value looks sensitive.
func RedactEntry(e Entry) Entry {
	if len(e.Parameters) == 0 {
		return e
	}
	out := make(map[string]string, len(e.Parameters))
	for k, v := range e.Parameters {
		switch k {
		case "env_vars", "secret_env_vars":
			out[k] = redactEnvVarsBlock(v)
		default:
			if IsLikelySensitive(v) {
				out[k] = "[REDACTED]"
			} else {
				out[k] = v
			}
		}
	}
	e.Parameters = out
	return e
}

// RedactEntries applies RedactEntry to a slice in place-equivalent fashion,
// returning a new slice so callers don't accidentally mutate the audit store.
func RedactEntries(entries []Entry) []Entry {
	if len(entries) == 0 {
		return entries
	}
	out := make([]Entry, len(entries))
	for i := range entries {
		out[i] = RedactEntry(entries[i])
	}
	return out
}

// redactEnvVarsBlock masks values inside a newline-separated KEY=value
// block. Lines without an `=` pass through untouched.
func redactEnvVarsBlock(block string) string {
	if block == "" {
		return block
	}
	lines := strings.Split(block, "\n")
	for i, line := range lines {
		idx := strings.Index(line, "=")
		if idx <= 0 {
			continue
		}
		key := line[:idx]
		val := line[idx+1:]
		if IsLikelySensitive(val) {
			lines[i] = key + "=[REDACTED]"
		}
	}
	return strings.Join(lines, "\n")
}
