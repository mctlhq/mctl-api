#!/bin/zsh
# usage: run-worker.sh <name> <role: control|execution|implementation> [extra docker args...]
# The production worker entrypoint of mctl-gitops platform-gitops/services/admins/
# mctl-agents-worker{,-implement,-exec}/values.yaml, with the same env and the same
# container hardening (read-only rootfs, non-root, all caps dropped), on a network
# with no egress. Synthetic credentials only.
name=$1; role=$2; shift 2
M=${MIG_DIR:?}; D=$(cd "$(dirname $0)" && pwd)
IMG=${IMG:-ghcr.io/mctlhq/mctl-agents:1.117.0}
docker run -d --name $name --platform linux/amd64 --network mig2-int \
  --read-only --tmpfs /tmp --tmpfs /home/app/.local --cap-drop ALL --security-opt no-new-privileges \
  --memory 896m \
  -v $M/certs:/certs:ro -v $M/gh:/var/run/secrets/github:ro \
  -e SSL_CERT_FILE=/certs/ca.pem -e REQUESTS_CA_BUNDLE=/certs/ca.pem \
  -e TEMPORAL_ADDRESS=temporal.mig.test:7233 -e TEMPORAL_NAMESPACE=mctl-agents \
  -e MCTL_TOKEN=synthetic-service-token-not-a-secret \
  -e GITHUB_TOKEN_FILE=/var/run/secrets/github/GITHUB_TOKEN \
  -e ANTHROPIC_BASE_URL=http://llm.mig.test:9000 \
  -e LOG_LEVEL=info -e MCTL_TRACE_WORKFLOW_TYPES=DevLoopWorkflow -e MCTL_TRACE_ARGO_PARAM=true \
  -e PYTHONDONTWRITEBYTECODE=1 -e MALLOC_ARENA_MAX=2 -e LIFECYCLE_ROLLOUT_MODE=observe \
  -e EXECUTION_REQUEST_DISPATCHER=true -e EXECUTION_REQUEST_POLL_SECONDS=${POLL:-2} -e MCTL_POLICY_APPROVALS=mctl-api \
  "$@" \
  $IMG python -m orchestrator.temporal.worker --role $role
