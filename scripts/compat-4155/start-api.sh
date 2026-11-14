#!/bin/zsh
# usage: start-api.sh <binary> <port> <logfile> <pidfile> [extra VAR=value ...]
# Synthetic configuration only. The service token below is a throwaway string used
# by the local worker container and the driver; it grants nothing anywhere else.
bin=$1; port=$2; log=$3; pidf=$4; shift 4
M=${MIG_DIR:?set MIG_DIR}
env -i PATH=$PATH HOME=$HOME \
  PORT=$port LISTEN_ADDR=127.0.0.1:$port \
  AUDIT_DB_URL="postgres://postgres@127.0.0.1:${PGPORT_MIG:-55461}/${MIG_DB:-compat}?sslmode=disable" \
  MCTL_AGENT_SERVICE_TOKEN=synthetic-service-token-not-a-secret \
  AUTH_REQUIRED=false ALLOW_INSECURE_DB=1 \
  KUBECONFIG=$M/kubeconfig \
  AGENT_RUN_EXCHANGE_AUDIENCE=mctl-api-run-exchange \
  TEMPORAL_ADDRESS=127.0.0.1:17233 TEMPORAL_NAMESPACE=mctl-agents \
  "$@" \
  $bin > $log 2>&1 &
echo $! > $pidf
