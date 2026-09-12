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

// Package ghtoken supplies GitHub credentials that may change while the
// process runs.
//
// It exists because of one property of GitHub App installation tokens: they
// live 60 minutes. The platform re-mints them every 30 (the
// rotate-github-app-tokens CronWorkflow in mctl-gitops) and re-syncs the
// Kubernetes Secret that carries them -- but a process that read its token
// from an environment variable never sees that. Environment variables are
// fixed when the container starts, so an envFrom consumer would serve an
// expired token within the hour and keep serving it.
//
// The shape that works is the one mctl-agents-worker already uses: mount the
// token as a file and re-read it before each use. A Source is that read,
// deferred to call time.
package ghtoken

import (
	"fmt"
	"os"
	"strings"
)

// Source returns the credential to use right now.
//
// It is consulted per operation rather than once at construction, which is the
// entire point: a caller holding a Source survives a rotation, a caller
// holding a string does not.
//
// A nil Source means "not configured" and callers treat it as such; that is
// why Static and File return nil for an empty input rather than a Source that
// yields an empty string, so "unset" is one condition to check instead of two.
type Source func() (string, error)

// Static returns a Source that always yields v, or nil when v is empty.
//
// For credentials that genuinely do not rotate -- a PAT in an environment
// variable, a value in a test -- and as the fallback that keeps local runs
// working without a mounted file.
func Static(v string) Source {
	if v == "" {
		return nil
	}
	return func() (string, error) { return v, nil }
}

// File returns a Source that reads path on every call, or nil when path is
// empty.
//
// Deliberately no caching. A read of a projected Secret volume is a page from
// the kernel's cache, and the operations behind it are a git fetch and a
// workflow dispatch -- neither is frequent enough for the read to matter, and
// any caching scheme would have to guess when the file changed, which is the
// bug this package exists to avoid.
//
// Trailing whitespace is trimmed. Kubernetes writes Secret values verbatim, so
// a value stored with a trailing newline would otherwise travel into an
// Authorization header and be rejected for a token that looks correct in every
// listing.
func File(path string) Source {
	if path == "" {
		return nil
	}
	return func() (string, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("reading github token from %s: %w", path, err)
		}
		v := strings.TrimSpace(string(b))
		if v == "" {
			return "", fmt.Errorf("github token file %s is empty", path)
		}
		return v, nil
	}
}

// FirstOf returns the first non-nil Source, or nil if there is none.
//
// It picks between configurations, not between results: the winner is chosen
// once, at wiring time, so a mounted file that starts failing surfaces as an
// error rather than silently falling back to a stale environment variable.
func FirstOf(sources ...Source) Source {
	for _, s := range sources {
		if s != nil {
			return s
		}
	}
	return nil
}

// Resolve reads s, treating a nil Source as the empty string.
//
// Saves every caller the same nil check before use.
func Resolve(s Source) (string, error) {
	if s == nil {
		return "", nil
	}
	return s()
}
