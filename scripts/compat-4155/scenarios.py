#!/usr/bin/env python3
"""Scenario driver for the local 4.155.0 compat test. Synthetic data only.

Prereqs (see run-all.sh): Postgres 16, Temporal dev server, fake kube, edge proxy, mctl-api 4.155.0 (:18301)
and 4.154.0 (:18302) on ONE database, the no-egress docker network with the sidecar, and the three
production worker roles of mctl-agents:1.117.0 running.

Everything the worker and the pod do is done by code from the production image; the driver only plays the
parts that have no local equivalent (a human clicking approve, the surface creating an execution request,
Argo scheduling a pod), and says so in each scenario's `notes`.
"""
import json, os, re, subprocess, sys, time, urllib.error, urllib.request

M = os.environ["MIG_DIR"]; D = os.path.dirname(os.path.abspath(__file__))
P155, P154 = 18301, 18302
SVC = "synthetic-service-token-not-a-secret"
PSQL = "/opt/homebrew/opt/postgresql@16/bin/psql"
TEMPORAL = ["temporal", "workflow", "--address", "127.0.0.1:17233", "--namespace", "mctl-agents"]
RES = []
RUN = str(int(time.time()))[-5:]          # unique suffix per run
N = [int(RUN) + 70000]

def nxt(): N[0] += 1; return N[0]

def http(method, path, body=None, port=P155, auth=None, host=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, method=method)
    if data is not None: req.add_header("Content-Type", "application/json")
    if auth: req.add_header("Authorization", "Bearer " + auth)
    try:
        with urllib.request.urlopen(req, timeout=30) as r: raw, st = r.read(), r.status
    except urllib.error.HTTPError as e: raw, st = e.read(), e.code
    try: return st, json.loads(raw or b"{}")
    except ValueError: return st, raw.decode()[:300]

def psql(sql):
    return subprocess.run([PSQL, "-h", "127.0.0.1", "-p", "55461", "-U", "postgres", "-At", "compat", "-c", sql],
                          capture_output=True, text=True).stdout.strip()

def sh(args, **kw): return subprocess.run(args, capture_output=True, text=True, **kw)

def edge_mode(m):
    sh(["curl", "-s", "--cacert", f"{M}/certs/ca.pem", "-X", "POST", f"https://localhost:18443/_edge/mode?mode={m}"])

def edge_since(ts, pred=lambda r: True):
    out = []
    for l in open(f"{M}/edge.jsonl"):
        r = json.loads(l)
        if r["ts"] >= ts and r["host"] == "api.mctl.ai" and pred(r): out.append(r)
    return out

def brief(r): return {"method": r["method"], "path": r["path"].split("?")[0], "status": r["status"], "replica": r["upstream"],
                      "req": r["req_body"][:200], "resp": r["resp_body"][:260]}

def kube(path, body=None):
    req = urllib.request.Request("http://127.0.0.1:18080" + path, data=json.dumps(body).encode() if body is not None else None,
                                 method="POST" if body is not None else "GET")
    with urllib.request.urlopen(req, timeout=10) as r: return json.loads(r.read())

def wait(cond, timeout=90, step=1.0):
    t = time.time()
    while time.time() - t < timeout:
        v = cond()
        if v: return v
        time.sleep(step)
    return None

def record(id_, title, verdict, evidence, notes=""):
    RES.append({"id": id_, "title": title, "verdict": verdict, "evidence": evidence, "notes": notes})
    print(f"[{verdict}] {id_} {title}", flush=True)

def new_item(issue_no=None, key=None):
    key = key or f"https://github.com/mctlhq/mctl-web/issues/{issue_no}"
    st, b = http("POST", "/api/v1/work-items", {"tenant": "admins", "title": "synthetic compat item", "external_key": key,
                                                  "origin_surface": "test"}, auth=SVC)
    assert st in (200, 201), (st, b)
    return b["work_item"]["id"], b["work_item"]["state_version"]

def exec_request(wi, ver, key, port=P155):
    # the surface side: a person asks for the item to run (the service principal may not, by design)
    return http("POST", f"/api/v1/work-items/{wi}/execution-requests",
                {"kind": "start", "expected_state_version": ver, "surface": "test", "idempotency_key": key}, port=port)

def xr_state(wi):
    st, b = http("GET", f"/api/v1/work-items/{wi}/execution-requests")
    return (b.get("execution_requests") or [{}])[0]

def dispatch_log(wi): 
    out = sh(["docker", "logs", "mig2-worker-control"]).stdout.splitlines() + []
    return [l for l in out if "EXECUTION_REQUEST_DISPATCH" in l and wi in l]

def pod(token):
    r = sh([f"{D}/pod.sh", token], env={**os.environ})
    m = re.search(r"POD_RESULT (.*)", r.stdout)
    return json.loads(m.group(1)) if m else {"raw": (r.stdout + r.stderr)[-400:]}

def grant(*args):
    r = sh([f"{D}/grant.sh", *args], env={**os.environ})
    m = re.search(r"GRANT_RESULT (.*)", r.stdout)
    return json.loads(m.group(1)) if m else {"raw": (r.stdout + r.stderr)[-400:]}

def start_swept(service, slug):
    for old in list(kube("/_admin/workflows")): finish(old)   # free the single implement slot
    time.sleep(8)
    before = set(kube("/_admin/workflows"))
    wid = f"swept-{RUN}-{nxt()}"
    r = sh(TEMPORAL[:2] + ["start", *TEMPORAL[2:], "--type", "SweptImplementWorkflow", "--task-queue", "mctl-dev-loop",
                           "--workflow-id", wid, "--input", json.dumps({"service": service, "slug": slug})])
    name = wait(lambda: next(iter(set(kube("/_admin/workflows")) - before), None), 120)
    return wid, name

def run_pod_for(wf, token, sa="mctl-agents-runner", deadline=7200):
    kube("/_admin/workflow-phase", {"name": wf, "phase": "Running", "deadline_seconds": deadline})
    kube("/_admin/pod", {"name": f"{wf}-run-implementer-1", "sa": sa, "workflow": wf, "token": token})
    return pod(token)

def finish(wf, phase="Succeeded"): kube("/_admin/workflow-phase", {"name": wf, "phase": phase})

def decide(aar):
    return http("POST", f"/api/v1/action-approvals/{aar}/decision", {"decision": "approve", "reason": "synthetic compat test"})[0]

def open_exec_item(issue_no):
    wi, ver = new_item(issue_no)
    st, b = http("POST", f"/api/v1/work-items/{wi}/executions",
                 {"engine": "temporal", "engine_ref": f"dev-loop-mctlhq-mctl-web-{issue_no}", "phase": "Running"}, auth=SVC)
    assert st == 201, (st, b)
    return wi, b["execution"]["id"]

# ------------------------------------------------------------------ scenarios
def s_legacy(tag, port_create, mode, n=1):
    """L: create -> claim -> deliver -> fulfil by the real worker dispatcher."""
    edge_mode(mode); t0 = time.time(); rows = []; ok = True
    for i in range(n):
        wi, ver = new_item(nxt())
        st, b = exec_request(wi, ver, f"{tag}-{i}", port=port_create)
        st_create = st
        x = wait(lambda: (lambda x: x if x.get("state") in ("fulfilled", "rejected") else None)(xr_state(wi)), 60) or xr_state(wi)
        calls = [brief(r) for r in edge_since(t0, lambda r: wi in r["path"] or wi in r["req_body"] or "execution-requests" in r["path"]
                                               and r["status"] != 204)]
        ok = ok and st_create == 201 and x.get("state") == "fulfilled" and x.get("execution_id", "").startswith("we_")
        rows.append({"work_item": wi, "create_status": st_create, "final_state": x.get("state"), "execution_id": x.get("execution_id"),
                     "claimed_by": x.get("claimed_by")})
    claims = [brief(r) for r in edge_since(t0, lambda r: "execution-requests/" in r["path"] and r["path"].endswith(("/fulfil", "/reject")))]
    bad = [c for c in edge_since(t0) if c["status"] >= 500]
    return ok and not bad, {"items": rows, "fulfil_calls": claims, "edge_5xx": len(bad)}

def main():
    only = sys.argv[1:] 
    want = lambda k: not only or k in only
    all_calls_t0 = time.time()

    # ---- L1 legacy path, 4.155 only
    if want("L1"):
        ok, ev = s_legacy("L1", P155, "0")
        record("L1", "legacy create/claim/fulfil via 1.117.0 dispatcher, 4.155.0", "PASS" if ok else "FAIL", ev,
               "request created by the driver as a person (surface), claimed+delivered+fulfilled by the worker image")

    # ---- L2 reject path
    if want("L2"):
        edge_mode("0"); t0 = time.time()
        wi, ver = new_item(key=f"note:compat-{RUN}-{nxt()}")
        st, _ = exec_request(wi, ver, f"L2-{RUN}")
        x = wait(lambda: (lambda x: x if x.get("state") in ("fulfilled", "rejected") else None)(xr_state(wi)), 60) or xr_state(wi)
        calls = [brief(r) for r in edge_since(t0, lambda r: r["path"].endswith("/reject"))]
        ok = st == 201 and x.get("state") == "rejected" and calls and calls[0]["status"] in (200, 204)
        record("L2", "reject: item without a runnable GitHub issue target", "PASS" if ok else "FAIL",
               {"create_status": st, "request": {k: x.get(k) for k in ("state", "reject_reason", "reason", "closed_at")}, "reject_calls": calls})

    # ---- L3 409 execution_active, nothing stored
    if want("L3"):
        res = {}
        for label, port in (("4.155.0", P155), ("4.154.0", P154)):
            wi, ex = open_exec_item(nxt())
            before = (psql(f"select count(*) from work_item_execution_requests where work_item_id='{wi}'"),
                      psql(f"select count(*) from work_item_events where work_item_id='{wi}'"))
            st, b = exec_request(wi, 1, f"L3-{label}-{RUN}", port=port)
            after = (psql(f"select count(*) from work_item_execution_requests where work_item_id='{wi}'"),
                     psql(f"select count(*) from work_item_events where work_item_id='{wi}'"))
            res[label] = {"status": st, "code": b.get("code") if isinstance(b, dict) else b, "requests_before_after": [before[0], after[0]],
                          "events_before_after": [before[1], after[1]]}
        ok = all(r["status"] == 409 and r["code"] == "execution_active" and r["requests_before_after"][0] == r["requests_before_after"][1] == "0"
                 and r["events_before_after"][0] == r["events_before_after"][1] for r in res.values())
        record("L3", "409 execution_active stores nothing (queue-while-active switch unset)", "PASS" if ok else "FAIL", res,
               "driver-side request on an item with an open execution; worker never sees the request, so this is an API-only check")

    # ---- G: grant-pinned exchange
    if want("G"):
        edge_mode("0")
        issue = nxt(); slug = f"issue-{issue}-compat"
        wi, ex = open_exec_item(issue)
        t0 = time.time()
        wid, wf = start_swept("mctl-web", slug)
        sent = [brief(r) for r in edge_since(t0, lambda r: r["path"].endswith("/operations/mctl-agents-implement/execute"))]
        params = [(p["name"], p["value"]) for p in kube("/_admin/workflows").get(wf, {}).get("spec", {}).get("arguments", {}).get("parameters", [])] if wf else None
        record("G0", "1.117.0 sweep submit sends service and slug (no execution_id)", "PASS" if sent and params and ("service", "mctl-web") in params and ("slug", slug) in params and not any(n == "execution_id" for n, _ in params) else "FAIL",
               {"worker_request": sent[:1], "argo_workflow_arguments": params, "temporal_workflow": wid})
        if wf:
            r1 = run_pod_for(wf, f"sa-{RUN}-G1")
            record("G1", "exchange with no grant -> fail closed 403 agent_run_grant_not_found", "PASS" if "HTTP 403 agent_run_grant_not_found" in r1.get("error", "") else "FAIL", r1)
            g = grant("create", ex, "mctl-web", slug); aar = g.get("id")
            r2 = pod(f"sa-{RUN}-G1")
            record("G2", "exchange with a requested but undecided grant -> 403", "PASS" if "HTTP 403 agent_run_grant_not_found" in r2.get("error", "") else "FAIL",
                   {"create": g, "exchange": r2})
            dst = decide(aar)
            r3 = pod(f"sa-{RUN}-G1")
            record("G3", "exchange with a decided but unspent grant -> 403", "PASS" if "HTTP 403 agent_run_grant_not_found" in r3.get("error", "") else "FAIL",
                   {"decision_status": dst, "exchange": r3})
            sp = grant("spend", ex, aar, "mctl-web", slug)
            r4 = pod(f"sa-{RUN}-G1")
            t_ex = [brief(r) for r in edge_since(t0, lambda r: "agent-run-tokens" in r["path"])]
            ok = "workflow" in sp and r4.get("exchange") == "ok" and r4.get("scope") == "implement-grant" and r4.get("probe_enforced") is True and r4.get("revoked")
            record("G4", "exchange after a spent, human-decided grant -> 201 scope implement-grant, scope probe refused, self-revoke", "PASS" if ok else "FAIL",
                   {"spend": sp, "exchange": r4, "http_trail": t_ex[-6:]},
                   "decider is oidc:dev-user: the API ran with AUTH_REQUIRED=false, so the 'human' is the local dev admin, not a real IdP user")
            # a second pod of the same run after the grant was spent: still fine (grant is pinned, not re-spent)
            kube("/_admin/pod", {"name": f"{wf}-run-implementer-2", "sa": "mctl-agents-runner", "workflow": wf, "token": f"sa-{RUN}-G5"})
            r5 = pod(f"sa-{RUN}-G5")
            record("G5", "second pod of the same run exchanges again against the same spent grant", "PASS" if r5.get("exchange") == "ok" else "FAIL", r5)
            finish(wf)
        # negative targets, submitted straight through the API (as the worker would be able to, but with bad shapes)
        for gid, extra, why in (("G6", {"service": "mctl-web"}, "slug missing"), ("G7", {"service": "mctl-web", "slug": "a/b"}, "slug with a separator")):
            before = set(kube("/_admin/workflows"))
            st, b = http("POST", "/api/v1/operations/mctl-agents-implement/execute", extra, auth=SVC)
            if st in (200, 202):
                name = next(iter(set(kube("/_admin/workflows")) - before), None)
                r = run_pod_for(name, f"sa-{RUN}-{gid}") if name else {}
                ok = "HTTP 403 agent_run_exchange_refused" in r.get("error", "")
                record(gid, f"exchange for an implement run with {why} -> fail closed", "PASS" if ok else "FAIL", {"submit_status": st, "exchange": r})
            else:
                record(gid, f"exchange for an implement run with {why}", "PASS" if st == 400 else "FAIL",
                       {"submit_status": st, "body": b}, "refused already at submit by the API validation, so no run to exchange for")
        # execution-bound implement run (the DevLoop's own submit shape), driver-submitted
        before = set(kube("/_admin/workflows"))
        st, b = http("POST", "/api/v1/operations/mctl-agents-implement/execute", {"service": "mctl-web", "slug": slug, "execution_id": ex}, auth=SVC)
        name = wait(lambda: next(iter(set(kube("/_admin/workflows")) - before), None), 10)
        r = run_pod_for(name, f"sa-{RUN}-G8") if name else {}
        record("G8", "execution-bound implement run (DevLoop submit shape) -> scope implement, bound to its execution",
               "PASS" if r.get("scope") == "implement" and r.get("execution_id") == ex else "FAIL", {"submit_status": st, "exchange": r},
               "submitted by the driver: the DevLoop's own submit cannot progress locally (needs GitHub), so this is the API half only")
        if name: finish(name)


    # ---- M: mixed replicas on one DB (edge routes the worker's api.mctl.ai calls)
    def g_chain(mode, label):
        edge_mode(mode); issue = nxt(); slug = f"issue-{issue}-compat"
        wi, ex = open_exec_item(issue); t0 = time.time()
        wid, wf = start_swept("mctl-web", slug)
        if not wf: return {"error": "no workflow submitted"}
        out = {"submit": [brief(r) for r in edge_since(t0, lambda r: r["path"].endswith("/mctl-agents-implement/execute"))][:1]}
        out["no_grant"] = run_pod_for(wf, f"sa-{RUN}-{label}-a").get("error", "")[:120]
        g = grant("create", ex, "mctl-web", slug); out["create"] = g
        if g.get("id"):
            out["decide"] = decide(g["id"]); out["spend"] = grant("spend", ex, g["id"], "mctl-web", slug)
            out["exchange"] = pod(f"sa-{RUN}-{label}-a")
        out["replicas_seen"] = sorted({r["upstream"] for r in edge_since(t0)})
        finish(wf); return out
    if want("M"):
        # M1 legacy dispatcher with round-robin: claim/fulfil land on both replicas, request created on 4.154 and on 4.155
        edge_mode("rr"); t0 = time.time(); rows = []
        for i, port in enumerate((P154, P155, P154, P155)):
            wi, ver = new_item(nxt()); st, _ = exec_request(wi, ver, f"M1-{RUN}-{i}", port=port)
            x = wait(lambda: (lambda x: x if x.get("state") in ("fulfilled", "rejected") else None)(xr_state(wi)), 60) or xr_state(wi)
            rows.append({"created_on": "4.154.0" if port == P154 else "4.155.0", "create_status": st, "final_state": x.get("state"), "execution_id": x.get("execution_id")})
        reps = {}
        for r in edge_since(t0, lambda r: "execution-requests" in r["path"]): reps[r["upstream"]] = reps.get(r["upstream"], 0) + 1
        record("M1", "legacy path with 4.154.0 and 4.155.0 serving the worker alternately (round-robin)",
               "PASS" if all(r["create_status"] == 201 and r["final_state"] == "fulfilled" for r in rows) and len(reps) == 2 else "FAIL",
               {"items": rows, "execution_request_calls_per_replica": reps, "edge_5xx": len([r for r in edge_since(t0) if r["status"] >= 500])})
        # M2 grant-pinned chain entirely on the OLD replica
        o = g_chain("1", "M2")
        ok = o.get("exchange", {}).get("scope") == "implement-grant"
        record("M2", "grant-pinned run whose worker calls and token exchange are all served by 4.154.0", "INFO-PASS" if ok else "INFO-FAIL", o,
               "informational: shows what a worker call does if the old replica serves it during a rolling update; expected-FAIL means the old replica cannot mint implement-grant")
        # M3 chain split: create+spend on one replica, exchange on the other (rr alternation is request-wise)
        o = g_chain("rr", "M3")
        record("M3", "grant-pinned run, calls alternating between replicas (round-robin)", "INFO", o)
        edge_mode("0")

    # ---- O: old code against the schema migrated by the new code
    if want("O"):
        st155 = psql("select max(version) from schema_migrations") if psql("select to_regclass('schema_migrations')") else ""
        edge_mode("1"); t0 = time.time()
        wi, ver = new_item(nxt()); st, _ = exec_request(wi, ver, f"O1-{RUN}", port=P154)
        x = wait(lambda: (lambda x: x if x.get("state") in ("fulfilled", "rejected") else None)(xr_state(wi)), 60) or xr_state(wi)
        errs = [l for l in open(f"{M}/api-4154.log").read().splitlines() if '"level":"ERROR"' in l or "level=ERROR" in l][-5:]
        record("O1", "4.154.0 only (worker 1.117.0) against the database already migrated by 4.155.0: legacy path", "PASS" if st == 201 and x.get("state") == "fulfilled" else "FAIL",
               {"create_status": st, "final": x.get("state"), "recent_error_lines_4154": [e[:240] for e in errs], "migrations_note": st155})
        edge_mode("0")

    json.dump(RES, open(f"{M}/results-{'-'.join(only) or 'all'}.json", "w"), indent=1)

main()
