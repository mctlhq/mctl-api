#!/usr/bin/env bash
# Seed a real v1alpha2 agent-platform definition+profile pair for
# issue-investigator and bind them in shadow — see
# docs/agent-platform-registry.md for the full contract this exercises.
#
# Binds into shadow, not production: the live dev-loop pipeline still
# resolves production through the v1 agent_releases path
# (ISSUE_INVESTIGATOR_RESOLVER_MODE=legacy), so this gives mctl-agents
# something real to resolve against with zero blast radius on a running
# pipeline.
#
#   MCTL_API_URL=https://api.mctl.ai MCTL_API_TOKEN=… scripts/seed-agent-platform.sh [--dry-run]
#
# Idempotent in the sense that matters operationally: republishing the same
# (agent, version) or (profile, version) is a 409 this script treats as
# "already seeded" rather than a failure, so re-running after a partial
# failure is safe. It always attempts the bind — CreateBinding is
# append-only, so a rerun with the same pair adds a new (harmless) revision
# rather than erroring; that is by design (see design.md's "Idempotency"
# note), not a bug in this script.
set -euo pipefail

case "${1:-}" in
  "")          dry_run=0 ;;
  --dry-run)   dry_run=1 ;;
  *) echo "usage: $0 [--dry-run]  (unknown argument: $1)" >&2; exit 2 ;;
esac
[ $# -le 1 ] || { echo "usage: $0 [--dry-run]" >&2; exit 2; }

: "${MCTL_API_URL:?set MCTL_API_URL, e.g. https://api.mctl.ai}"
: "${MCTL_API_TOKEN:?set MCTL_API_TOKEN (admin bearer token)}"
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 2; }

agent="issue-investigator"
definition_version="1.0.0"
profile="standard-investigate"
profile_version="1.0.0"
environment="shadow"
profile_range=">=1.0.0 <2.0.0"

# api_call: $1 = method, $2 = path, $3 = json body (optional).
# Sets the globals REPLY_BODY and REPLY_STATUS. Never fails on a non-2xx
# response itself (set -e would otherwise abort before the caller gets a
# chance to treat 409 as "already seeded").
REPLY_BODY=""
REPLY_STATUS=""
api_call() {
  local method="$1" path="$2" body="${3:-}"
  local args=(-sS -X "$method" -H "Authorization: Bearer $MCTL_API_TOKEN" -H "Content-Type: application/json" -w '\n%{http_code}')
  if [ -n "$body" ]; then args+=(--data "$body"); fi
  local response
  response=$(curl "${args[@]}" "$MCTL_API_URL$path")
  REPLY_STATUS="${response##*$'\n'}"
  REPLY_BODY="${response%$'\n'*}"
}

echo "== ensuring agent definition exists: $agent =="
if [ "$dry_run" = 1 ]; then
  echo "POST /api/v1/agents  {\"name\":\"$agent\",\"owner\":\"mctl-agents\"}"
else
  api_call POST "/api/v1/agents" "$(jq -nc --arg name "$agent" '{name: $name, owner: "mctl-agents"}')"
  # CreateAgentDefinition upserts in place (200/201 either way); anything
  # else here is a real failure worth stopping for.
  case "$REPLY_STATUS" in
    2??) : ;;
    *) echo "create agent definition failed (HTTP $REPLY_STATUS): $REPLY_BODY" >&2; exit 1 ;;
  esac
fi

echo "== seeding agent definition version: $agent @ $definition_version =="
definition_spec=$(jq -nc --arg agent "$agent" '{
  apiVersion: "agents.mctl.ai/v1alpha2",
  kind: "AgentDefinition",
  metadata: {name: $agent},
  spec: {description: "Turns a GitHub issue into a spec-driven proposal."}
}')
definition_body=$(jq -nc \
  --arg version "$definition_version" \
  --arg spec "$definition_spec" \
  --arg profile_range "$profile_range" \
  '{
    version: $version,
    spec: $spec,
    owner: "mctl-agents",
    source_manifest: {
      repo: "mctlhq/mctl-agents",
      path: "agents/_manifests/issue-investigator/agent.yaml",
      git_sha: "seed-script",
      content_hash: "seed-script"
    },
    profile_range: $profile_range
  }')

if [ "$dry_run" = 1 ]; then
  echo "POST /api/v1/agents/$agent/definition-versions"
  echo "$definition_body" | jq .
else
  api_call POST "/api/v1/agents/$agent/definition-versions" "$definition_body"
  case "$REPLY_STATUS" in
    201) echo "published $agent@$definition_version" ;;
    409) echo "$agent@$definition_version already published, continuing" ;;
    *) echo "publish definition version failed (HTTP $REPLY_STATUS): $REPLY_BODY" >&2; exit 1 ;;
  esac
fi

echo "== seeding execution profile version: $profile @ $profile_version =="
profile_spec=$(jq -nc '{
  apiVersion: "agents.mctl.ai/v1alpha2",
  kind: "ExecutionProfile",
  maxTokens: 200000,
  maxToolCalls: 100,
  timeoutSeconds: 1800
}')
profile_body=$(jq -nc \
  --arg version "$profile_version" \
  --arg spec "$profile_spec" \
  '{
    version: $version,
    spec: $spec,
    owner: "mctl-agents",
    source_manifest: {
      repo: "mctlhq/platform-gitops",
      path: "agent-platform/profiles/standard-investigate.yaml",
      git_sha: "seed-script",
      content_hash: "seed-script"
    }
  }')

if [ "$dry_run" = 1 ]; then
  echo "POST /api/v1/agent-profiles/$profile/versions"
  echo "$profile_body" | jq .
else
  api_call POST "/api/v1/agent-profiles/$profile/versions" "$profile_body"
  case "$REPLY_STATUS" in
    201) echo "published $profile@$profile_version" ;;
    409) echo "$profile@$profile_version already published, continuing" ;;
    *) echo "publish profile version failed (HTTP $REPLY_STATUS): $REPLY_BODY" >&2; exit 1 ;;
  esac
fi

echo "== binding $agent to $definition_version + $profile@$profile_version in $environment =="
bind_body=$(jq -nc \
  --arg environment "$environment" \
  --arg definition_version "$definition_version" \
  --arg profile "$profile" \
  --arg profile_version "$profile_version" \
  '{
    environment: $environment,
    definition_version: $definition_version,
    profile: $profile,
    profile_version: $profile_version,
    binding_source: "registry",
    reason: "seed-agent-platform.sh"
  }')

if [ "$dry_run" = 1 ]; then
  echo "POST /api/v1/agents/$agent/bindings"
  echo "$bind_body" | jq .
  exit 0
fi

api_call POST "/api/v1/agents/$agent/bindings" "$bind_body"
if [ "$REPLY_STATUS" = "201" ]; then
  revision=$(jq -r .revision <<<"$REPLY_BODY")
  echo "bound $agent in $environment at revision $revision"
else
  echo "create binding failed (HTTP $REPLY_STATUS): $REPLY_BODY" >&2
  exit 1
fi

echo "== verifying =="
curl -sS -H "Authorization: Bearer $MCTL_API_TOKEN" "$MCTL_API_URL/api/v1/agents/$agent" | jq .
