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

// Package secretscan provides best-effort regex detection of common secret
// patterns in text payloads. Used by the OpenClaw skill/identity save handlers
// to reject content that appears to embed credentials.
package secretscan

import "regexp"

// patternEntry pairs a human-friendly name with its compiled regex.
// The name is returned to the caller so it can surface which family of
// secret was matched without echoing the raw value back to the user.
type patternEntry struct {
	name string
	re   *regexp.Regexp
}

// patterns is ordered from most-specific to most-generic so callers see the
// most informative label on ambiguous matches (e.g. a JWT inside a generic
// bearer assignment still reports as "jwt").
var patterns = []patternEntry{
	{name: "github-fine-grained-pat", re: regexp.MustCompile(`github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}`)},
	{name: "github-pat", re: regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`)},
	{name: "github-oauth-token", re: regexp.MustCompile(`gho_[A-Za-z0-9]{36}`)},
	{name: "github-user-token", re: regexp.MustCompile(`ghu_[A-Za-z0-9]{36}`)},
	{name: "github-server-token", re: regexp.MustCompile(`ghs_[A-Za-z0-9]{36}`)},
	{name: "github-refresh-token", re: regexp.MustCompile(`ghr_[A-Za-z0-9]{36}`)},
	{name: "aws-access-key-id", re: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{name: "slack-token", re: regexp.MustCompile(`xox[bpoa]-[A-Za-z0-9-]{10,}`)},
	{name: "jwt", re: regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)},
	{name: "private-key", re: regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`)},
	// Generic high-entropy assignment. Kept last so a more specific match
	// reports the more informative label.
	{name: "generic-credential-assignment", re: regexp.MustCompile(`(?i)(secret|token|api[_-]?key|password|bearer)\s*[:=]\s*[^\s'"]{16,}`)},
}

// Scan returns the name of the first matching pattern and true if content
// appears to contain a secret. The matched substring is never returned — we
// do not want to echo the secret back to the caller or into logs.
func Scan(content []byte) (pattern string, found bool) {
	for _, p := range patterns {
		if p.re.Match(content) {
			return p.name, true
		}
	}
	return "", false
}
