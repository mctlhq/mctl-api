# Upstream snapshots (test fixtures)

These files are copies of mctl-gitops files that the deploy-plan preview
compiler must agree with. They exist only so `internal/deployplan` tests can
run inside this repository. They are never read at runtime.

- Source of truth: `mctlhq/mctl-gitops`. `provenance.json` records the commit
  and SHA-256 of every snapshot.
- Do not edit these files by hand. Refresh them with
  `scripts/refresh-deployplan-upstream.sh [ref]`, which rewrites the files and
  `provenance.json` together.
- CI (`validate.yml`, step "deploy-plan upstream drift") compares them with
  mctl-gitops `main` and fails on any difference, so a template change upstream
  cannot leave the golden tests checking stale behaviour.
