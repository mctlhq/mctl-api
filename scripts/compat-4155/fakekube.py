#!/usr/bin/env python3
"""Minimal fake Kubernetes API for the local compat test (no cluster, synthetic).

It implements only what mctl-api calls on the paths under test:
  - POST   /apis/authentication.k8s.io/v1/tokenreviews   (agent run token exchange)
  - GET    /api/v1/namespaces/{ns}/pods/{name}
  - GET    /apis/argoproj.io/v1alpha1/namespaces/{ns}/workflows/{name}
  - POST   /apis/argoproj.io/v1alpha1/namespaces/{ns}/workflows   (operations execute)
Admin (test driver only):
  - POST /_admin/pod  {"name","sa","workflow","token","phase"?}   register a pod + its projected token
  - POST /_admin/workflow-phase {"name","phase"}                  set status.phase / startedAt
  - GET  /_admin/workflows                                         dump stored workflows
Every request is logged as JSON. usage: fakekube.py <port> <log> <namespace> <audience> """
import json, sys, time, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
port, logp, NS, AUD = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
log = open(logp, "a", buffering=1)
WF, PODS, TOKENS = {}, {}, {}

def now(): return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def _fields(b):
    """Yield (field_no, wire_type, value) of one protobuf message."""
    i = 0
    while i < len(b):
        k, i = _varint(b, i); no, wt = k >> 3, k & 7
        if wt == 0: v, i = _varint(b, i)
        elif wt == 2:
            ln, i = _varint(b, i); v = b[i:i + ln]; i += ln
        elif wt == 1: v = b[i:i + 8]; i += 8
        elif wt == 5: v = b[i:i + 4]; i += 4
        else: raise ValueError("wire type %d" % wt)
        yield no, wt, v

def _varint(b, i):
    r = sh = 0
    while True:
        c = b[i]; i += 1; r |= (c & 0x7F) << sh; sh += 7
        if not c & 0x80: return r, i

def pb_token(raw):
    """k8s protobuf envelope -> runtime.Unknown.raw (field 2) -> TokenReview.spec (field 2) -> Spec.token (field 1)."""
    unk = next(v for n, _, v in _fields(raw[4:]) if n == 2)
    spec = next(v for n, _, v in _fields(unk) if n == 2)
    return next((v for n, _, v in _fields(spec) if n == 1), b"").decode()

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def send(self, code, obj):
        b = json.dumps(obj).encode()
        log.write(json.dumps({"ts": time.time(), "m": self.command, "p": self.path, "code": code}) + "\n")
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) or b"{}"
        if raw.startswith(b"k8s\x00"):  # client-go sends built-in types as protobuf
            return {"spec": {"token": pb_token(raw)}}
        return json.loads(raw)
    def notfound(self, kind, name):
        self.send(404, {"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "NotFound",
                        "code": 404, "message": f"{kind} {name} not found"})
    def do_POST(self):
        p, b = self.path.split("?")[0], self.body()
        if p == "/apis/authentication.k8s.io/v1/tokenreviews":
            tok = b.get("spec", {}).get("token", "")
            t = TOKENS.get(tok)
            if not t:
                b["status"] = {"authenticated": False, "error": "unknown token"}
            else:
                b["status"] = {"authenticated": True, "audiences": [AUD],
                    "user": {"username": f"system:serviceaccount:{NS}:{t['sa']}", "uid": "u-" + t["pod"],
                             "extra": {"authentication.kubernetes.io/pod-name": [t["pod"]],
                                       "authentication.kubernetes.io/pod-uid": [t["pod_uid"]]}}}
            return self.send(201, b)
        if p == "/_admin/pod":
            wf = WF.get(b["workflow"])
            uid = str(uuid.uuid4()); pod = b["name"]
            PODS[pod] = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": pod, "namespace": NS, "uid": uid,
                "labels": {"workflows.argoproj.io/workflow": b["workflow"]},
                "ownerReferences": [{"apiVersion": "argoproj.io/v1alpha1", "kind": "Workflow", "name": b["workflow"],
                                     "uid": (wf or {}).get("metadata", {}).get("uid", "none"), "controller": True}]},
                "spec": {"serviceAccountName": b["sa"]}, "status": {"phase": b.get("phase", "Running")}}
            TOKENS[b["token"]] = {"sa": b["sa"], "pod": pod, "pod_uid": uid}
            return self.send(200, {"ok": True})
        if p == "/_admin/workflow-phase":
            wf = WF.get(b["name"])
            if not wf: return self.notfound("workflow", b["name"])
            wf.setdefault("status", {})["phase"] = b["phase"]
            wf["status"].setdefault("startedAt", now())
            if b.get("deadline_seconds") is not None:
                wf["spec"]["activeDeadlineSeconds"] = b["deadline_seconds"]
            return self.send(200, {"ok": True})
        parts = p.strip("/").split("/")
        if parts[:3] == ["apis", "argoproj.io", "v1alpha1"] and parts[-1] == "workflows":
            b["metadata"]["uid"] = str(uuid.uuid4()); b["metadata"]["creationTimestamp"] = now()
            b["status"] = {"phase": "Pending"}
            WF[b["metadata"]["name"]] = b
            return self.send(201, b)
        self.notfound("path", p)
    def do_GET(self):
        p = self.path.split("?")[0]; parts = p.strip("/").split("/")
        if p == "/_admin/workflows": return self.send(200, WF)
        if len(parts) == 6 and parts[:2] == ["api", "v1"] and parts[2] == "namespaces" and parts[4] == "pods":
            return self.send(200, PODS[parts[5]]) if parts[5] in PODS else self.notfound("pod", parts[5])
        if len(parts) == 7 and parts[:3] == ["apis", "argoproj.io", "v1alpha1"] and parts[-2] == "workflows":
            return self.send(200, WF[parts[-1]]) if parts[-1] in WF else self.notfound("workflow", parts[-1])
        self.notfound("path", p)
ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
