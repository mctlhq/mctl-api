#!/usr/bin/env bash
# Time golangci-lint's gosec on ./internal/api/ one rule at a time.
# Prints "rule seconds issues". Writes only to a temp dir; never touches
# .golangci.yml.
set -uo pipefail

RULES=${RULES:-"G101 G102 G103 G104 G106 G107 G108 G109 G110 G111 G112 G114 G115 G117 G201 G202 G203 G204 G301 G302 G303 G304 G305 G306 G307 G401 G402 G403 G404 G405 G406 G407 G408 G409 G501 G502 G503 G504 G505 G506 G507 G601 G602 G701 G702 G703 G704 G705 G706 G707"}
TARGET=${TARGET:-./internal/api/}
tmp=$(mktemp -d)

printf '%-6s %8s %6s\n' rule seconds issues
for rule in $RULES; do
  cat > "$tmp/cfg.yml" <<EOF
version: "2"
linters:
  default: none
  enable: [gosec]
  settings:
    gosec:
      includes: [$rule]
EOF
  start=$(date +%s)
  out=$(golangci-lint run --config "$tmp/cfg.yml" --timeout 25m "$TARGET" 2>&1)
  end=$(date +%s)
  issues=$(printf '%s\n' "$out" | grep -c "(gosec)" || true)
  printf '%-6s %8s %6s\n' "$rule" "$((end - start))" "$issues"
done
