#!/bin/zsh
# usage: pod.sh <sa-token-string>   (runs the image's run_token exchange as a pod would; prints POD_RESULT)
M=${MIG_DIR:?}; D=$(cd "$(dirname $0)" && pwd)
mkdir -p $M/sa; printf '%s' "$1" > $M/sa/token; chmod 644 $M/sa/token
docker run --rm --platform linux/amd64 --network mig2-int --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  -v $M/certs:/certs:ro -v $M/sa:/var/run/secrets/mctl-api:ro -v $D:/mig:ro \
  -e SSL_CERT_FILE=/certs/ca.pem -e MCTL_RUN_TOKEN_MODE=enforce -e PYTHONPATH=/app \
  --entrypoint python ${IMG:-ghcr.io/mctlhq/mctl-agents:1.117.0} /mig/pod_exchange.py 2>&1 | tail -20
