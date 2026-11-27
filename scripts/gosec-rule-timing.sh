#!/usr/bin/env bash
# Time golangci-lint's gosec on ./internal/api/ one rule at a time.
# Prints "rule seconds issues". Writes only to a temp dir; never touches
# .golangci.yml.
#
# A run that did not finish (crash, timeout, bad config) is printed as FAILED
# with its exit code, never as "0 issues", and the script then exits 1.
set -uo pipefail

# The rules of the gosec version bundled with golangci-lint v2.11.4. Update
# this list when the pinned linter moves: a rule that is missing here is not
# measured.
RULES=${RULES:-"G101 G102 G103 G104 G106 G107 G108 G109 G110 G111 G112 G113 G114 G115 G116 G117 G118 G119 G120 G121 G122 G123 G201 G202 G203 G204 G301 G302 G303 G304 G305 G306 G307 G401 G402 G403 G404 G405 G406 G407 G408 G501 G502 G503 G504 G505 G506 G507 G601 G602 G701 G702 G703 G704 G705 G706 G707"}
TARGET=${TARGET:-./internal/api/}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failed=0

printf '%-6s %8s %s\n' rule seconds issues
for rule in $RULES; do
  cat > "$tmp/cfg.yml" <<CFG
version: "2"
linters:
  default: none
  enable: [gosec]
  settings:
    gosec:
      includes: [$rule]
issues:
  max-issues-per-linter: 0
  max-same-issues: 0
CFG
  start=$(date +%s)
  # A fresh cache per rule: a cached result would time the cache, not the rule.
  out=$(GOLANGCI_LINT_CACHE="$tmp/cache-$rule" golangci-lint run --config "$tmp/cfg.yml" --timeout 25m "$TARGET" 2>&1)
  rc=$?
  end=$(date +%s)
  # 0: ran, nothing found. 1: ran, issues found. Anything else: not observed.
  if [ "$rc" -eq 0 ]; then
    issues=0
  elif [ "$rc" -eq 1 ] && printf '%s\n' "$out" | grep -q '(gosec)$'; then
    issues=$(printf '%s\n' "$out" | grep -c '(gosec)$')
  else
    issues="FAILED(exit $rc)"
    failed=1
    printf '%s\n' "$out" | tail -n 5 >&2
  fi
  printf '%-6s %8s %s\n' "$rule" "$((end - start))" "$issues"
done
exit "$failed"
