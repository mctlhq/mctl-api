"""Runs INSIDE the production image (1.117.0). Drives the worker's own grant code,
the same functions the DevLoop activities call, against mctl-api over TLS:
  create <execution_id> <service> <slug>   -> request_devloop_approval's create (aa.ActionApprovalClient)
  spend  <execution_id> <approval_ref> <service> <slug> -> submit_delegated_approve's _mint_and_execute
Prints one JSON line GRANT_RESULT. The proposal content digest is a fixed synthetic
value: the GitHub read that normally produces it is stubbed out (no egress)."""
import asyncio, hashlib, json, sys
from datetime import UTC, datetime, timedelta
from orchestrator import action_approvals as aa
from orchestrator.temporal.activities import delegated_approval as da

DIGEST = "sha256:" + hashlib.sha256(b"synthetic proposal content").hexdigest()

def create(execution_id, service, slug):
    intent = da.approval_intent(execution_id, service, slug, DIGEST)
    ans = aa.ActionApprovalClient().create(
        intent, key=aa.idempotency_key(intent, 0), expires_at=datetime.now(UTC) + timedelta(hours=1))
    rec = ans.record
    return {"status": ans.status, "reason": ans.reason, "id": getattr(rec, "id", ""), "state": getattr(rec, "state", ""),
            "intent_hash_matches": bool(rec) and rec.intent_hash == aa.intent_hash(intent), "digest": DIGEST}

async def spend(execution_id, ref, service, slug):
    import httpx
    from orchestrator.temporal.mctl_client import MCTL_API_BASE_URL, auth_headers
    async with httpx.AsyncClient(base_url=MCTL_API_BASE_URL, timeout=30) as client:
        out = await da._mint_and_execute(client, auth_headers(), da.DelegatedApproveInput(execution_id, ref, service, slug))
    return {"workflow": out} if isinstance(out, str) else {"refusal": out.refusal, "code": out.code}

cmd = sys.argv[1]
res = create(*sys.argv[2:5]) if cmd == "create" else asyncio.run(spend(*sys.argv[2:6]))
print("GRANT_RESULT " + json.dumps(res), flush=True)
