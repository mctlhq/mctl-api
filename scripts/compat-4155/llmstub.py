#!/usr/bin/env python3
"""Fake Anthropic-style endpoint. Answers every call with a fixed message and
records it, so a worker that tried to call an LLM is visible and no real key or
network is ever involved. usage: llmstub.py <port> <log>"""
import json, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
port, log = int(sys.argv[1]), open(sys.argv[2], "a", buffering=1)
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _do(self):
        n = int(self.headers.get("Content-Length") or 0); self.rfile.read(n)
        log.write(json.dumps({"ts": time.time(), "method": self.command, "path": self.path}) + "\n")
        b = json.dumps({"id": "msg_stub", "type": "message", "role": "assistant", "model": "stub",
                        "content": [{"type": "text", "text": "stub"}], "stop_reason": "end_turn",
                        "usage": {"input_tokens": 1, "output_tokens": 1}}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    do_GET = do_POST = _do
ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
