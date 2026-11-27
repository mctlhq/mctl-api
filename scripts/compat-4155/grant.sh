#!/bin/zsh
# usage: grant.sh <create|spend> args...   (runs grant_worker.py in the production image on the no-egress network)
M=${MIG_DIR:?}; D=$(cd "$(dirname $0)" && pwd)
docker run --rm --platform linux/amd64 --network mig2-int --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  -v $M/certs:/certs:ro -v $D:/mig:ro -e SSL_CERT_FILE=/certs/ca.pem -e PYTHONPATH=/app \
  -e MCTL_TOKEN=synthetic-service-token-not-a-secret -e MCTL_POLICY_APPROVALS=mctl-api \
  --entrypoint python ${IMG:-ghcr.io/mctlhq/mctl-agents:1.117.0} /mig/grant_worker.py "$@" 2>&1 | grep -v model-policy | tail -15
