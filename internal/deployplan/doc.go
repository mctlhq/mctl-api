// Package deployplan computes immutable, server-side deploy plans
// (mctl-api#866).
//
// testdata/upstream holds snapshots of the mctl-gitops files that the preview
// compiler must agree with (wft-preview-deploy.yaml, tpl-git-commit.yaml and
// rewrite_preview_values.py). They are test fixtures only and never read at
// runtime. mctl-gitops stays the source of truth; provenance.json records the
// commit and SHA-256 each snapshot came from, and
// scripts/refresh-deployplan-upstream.sh is the only way to update them.
package deployplan
