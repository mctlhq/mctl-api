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

package operations

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SanitizePreviewTag converts a git ref to a valid Docker image tag segment:
// lowercases, collapses runs of non [a-z0-9] characters into a single hyphen,
// trims leading/trailing hyphens, and caps the result at 30 characters. Refs
// that contain no alphanumeric characters fall back to "ref" rather than
// producing an empty segment.
func SanitizePreviewTag(ref string) string {
	var b strings.Builder
	lastHyphen := false
	for _, r := range ref {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastHyphen = false
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + 32)
			lastHyphen = false
		default:
			if b.Len() > 0 && !lastHyphen {
				b.WriteByte('-')
				lastHyphen = true
			}
		}
	}
	out := strings.TrimRight(b.String(), "-")
	if out == "" {
		return "ref"
	}
	if len(out) > 30 {
		out = strings.TrimRight(out[:30], "-")
	}
	return out
}

// GeneratePreviewTag builds an auto-generated image tag for a build-from-branch
// preview deploy. It combines the Unix timestamp with a short random suffix so
// concurrent builds for the same ref (e.g. a rerun fired within the same
// second) don't collide on the same tag.
func GeneratePreviewTag(ref string) string {
	return fmt.Sprintf("preview-%s-%d-%s", SanitizePreviewTag(ref), time.Now().Unix(), uuid.New().String()[:8])
}

// PreparePreviewDeployInput mutates input in place for the "preview-deploy"
// operation's build-from-branch mode: it requires dockerfile_repo whenever
// git_ref is set (the platform needs a source repo to build from), and
// auto-generates image_tag from git_ref when the caller didn't supply one.
// When git_ref is not set, image_tag must already be present — the caller is
// deploying an existing image, not building from source.
func PreparePreviewDeployInput(input map[string]string) error {
	if input["git_ref"] != "" {
		if input["dockerfile_repo"] == "" {
			return fmt.Errorf("dockerfile_repo is required when git_ref is set")
		}
		if input["image_tag"] == "" {
			input["image_tag"] = GeneratePreviewTag(input["git_ref"])
		}
		return nil
	}
	if input["image_tag"] == "" {
		return fmt.Errorf("image_tag is required when git_ref is not set")
	}
	return nil
}
