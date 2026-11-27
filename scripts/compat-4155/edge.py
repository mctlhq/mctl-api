#!/usr/bin/env python3
"""TLS edge for the local compat test (synthetic data only).

The 1.117.0 worker refuses a non-https MCTL_API_BASE_URL, so mctl-api is put
behind TLS here. Requests with Host api.github.com are answered by a stub
(404 + a log line), so the worker's hard-coded GitHub URLs never leave the
machine. Everything else is proxied to the mctl-api upstreams, either pinned
to one replica or round-robin (mixed-replica mode), and recorded as JSON lines.

usage: edge.py --listen 18443 --cert edge.pem --key edge.key --log edge.jsonl
               --upstream http://127.0.0.1:18301 [--upstream http://127.0.0.1:18302]
               [--mode rr|first] 
Runtime control: POST /_edge/mode?mode=rr|first|<index>  (Host localhost only)
"""
import argparse, http.client, itertools, json, ssl, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

ap = argparse.ArgumentParser()
ap.add_argument("--listen", type=int, required=True)
ap.add_argument("--cert", required=True)
ap.add_argument("--key", required=True)
ap.add_argument("--log", required=True)
ap.add_argument("--upstream", action="append", required=True)
ap.add_argument("--mode", default="first")
args = ap.parse_args()

ups = [urlparse(u) for u in args.upstream]
state = {"mode": args.mode, "rr": itertools.count()}
lock = threading.Lock()
logf = open(args.log, "a", buffering=1)

def pick():
    m = state["mode"]
    if m == "rr":
        return next(state["rr"]) % len(ups)
    if m.isdigit():
        return int(m) % len(ups)
    return 0

def redact(h):
    out = {}
    for k, v in h.items():
        if k.lower() == "authorization":
            scheme, _, tok = v.partition(" ")
            v = f"{scheme} {tok[:8]}...(len {len(tok)})"
        out[k] = v
    return out

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def _do(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        host = (self.headers.get("Host") or "").split(":")[0]
        rec = {"ts": time.time(), "host": host, "method": self.command, "path": self.path,
               "req_headers": redact(dict(self.headers)), "req_body": body.decode("utf-8", "replace")[:4000]}
        if host == "localhost" and self.path.startswith("/_edge/mode"):
            with lock:
                state["mode"] = parse_qs(urlparse(self.path).query)["mode"][0]
            return self._reply(200, b'{"ok":true}', rec, upstream="edge")
        if host == "api.github.com":
            return self._reply(404, b'{"message":"Not Found (local compat stub)"}', rec, upstream="github-stub")
        with lock:
            i = pick()
        u = ups[i]
        try:
            c = http.client.HTTPConnection(u.hostname, u.port, timeout=60)
            hdrs = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "connection")}
            c.request(self.command, self.path, body=body or None, headers=hdrs)
            r = c.getresponse(); data = r.read()
            self._reply(r.status, data, rec, upstream=f"{u.hostname}:{u.port}", ctype=r.getheader("Content-Type"))
        except Exception as e:
            self._reply(502, json.dumps({"error": str(e)}).encode(), rec, upstream="error")
    def _reply(self, status, data, rec, upstream, ctype="application/json"):
        rec.update(status=status, upstream=upstream, resp_body=data.decode("utf-8", "replace")[:4000])
        logf.write(json.dumps(rec) + "\n")
        self.send_response(status)
        self.send_header("Content-Type", ctype or "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Edge-Upstream", upstream)
        self.end_headers(); self.wfile.write(data)
    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _do

srv = ThreadingHTTPServer(("127.0.0.1", args.listen), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(args.cert, args.key)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
print("edge listening", args.listen, flush=True)
srv.serve_forever()
