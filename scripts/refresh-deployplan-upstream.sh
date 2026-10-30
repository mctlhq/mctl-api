#!/usr/bin/env bash
# Refresh the mctl-gitops snapshots that internal/deployplan tests compile
# against (mctl-api#866). They are test fixtures, not a second source of
# truth: the source is mctl-gitops, and provenance.json records the commit
# each snapshot was taken from and its SHA-256.
#
#   scripts/refresh-deployplan-upstream.sh [gitops-ref]   # default: main
#
# Needs gh with read access to mctlhq/mctl-gitops. Fails closed: any fetch
# error aborts before provenance.json is rewritten.
set -euo pipefail

ref="${1:-main}"
repo="mctlhq/mctl-gitops"
root="$(cd "$(dirname "$0")/.." && pwd)"
dir="$root/internal/deployplan/testdata/upstream"

files=(
  "platform-gitops/argo-workflows/cluster-templates/wft-preview-deploy.yaml"
  "platform-gitops/argo-workflows/cluster-templates/tpl-git-commit.yaml"
  "platform-gitops/argo-workflows/scripts/rewrite_preview_values.py"
)

sha="$(gh api "repos/$repo/commits/$ref" --jq .sha)"
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo "could not resolve $ref in $repo" >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

entries=()
for src in "${files[@]}"; do
  name="$(basename "$src")"
  gh api -H 'Accept: application/vnd.github.raw' "repos/$repo/contents/$src?ref=$sha" > "$tmp/$name"
  test -s "$tmp/$name" || { echo "empty fetch: $src" >&2; exit 1; }
  sum="$(sha256_of "$tmp/$name")"
  entries+=("{\"source_path\":\"$src\",\"snapshot\":\"$name\",\"sha256\":\"$sum\"}")
done

joined="$(IFS=,; echo "${entries[*]}")"
python3 - "$tmp/provenance.json" "$repo" "$sha" "$joined" <<'PY'
import json, sys, datetime
path, repo, sha, joined = sys.argv[1:]
doc = {
    "source_repo": repo,
    "source_commit": sha,
    "captured_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "refresh": "scripts/refresh-deployplan-upstream.sh",
    "files": json.loads("[" + joined + "]"),
}
with open(path, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
PY
test -s "$tmp/provenance.json"

# Everything was fetched and written; only now replace the committed files,
# so a failure above leaves the tree untouched.
for src in "${files[@]}"; do
  name="$(basename "$src")"
  mv "$tmp/$name" "$dir/$name"
done
mv "$tmp/provenance.json" "$dir/provenance.json"
echo "snapshots refreshed from $repo@$sha"
