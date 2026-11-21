"""Runs INSIDE the production image as the implementer pod would: the image's own
orchestrator.run_token (1.117.0) trades the projected ServiceAccount token for a run
token in MCTL_RUN_TOKEN_MODE=enforce, probes the scope, then revokes it.
Prints one JSON line with the outcome. No claims are sent by this code, only the
Kubernetes token (see run_token.py)."""
import json, os, sys
from orchestrator import run_token
out = {"mode": run_token.mode()}
try:
    tok = run_token.exchange()
    out.update(exchange="ok", scope=tok.scope, execution_id=tok.execution_id, token_id=tok.token_id, expires_at=tok.expires_at)
    try:
        out["probe_enforced"] = run_token.probe_scope(tok)
    except run_token.RunTokenError as e:
        out["probe_error"] = str(e)
    run_token.revoke(tok)
    out["revoked"] = True
except run_token.RunTokenError as e:
    out.update(exchange="refused", error=str(e))
print("POD_RESULT " + json.dumps(out), flush=True)
