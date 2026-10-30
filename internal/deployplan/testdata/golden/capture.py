#!/usr/bin/env python3
"""Capture the golden expectations for internal/deployplan.

Run from internal/deployplan/testdata/golden:

    python3 capture.py

For every case directory (case.json, base.yaml) it produces the effective
preview values by running the SNAPSHOT of the real script
(../upstream/rewrite_preview_values.py) and applying the `--set` overrides
read from the SNAPSHOT of the real workflow template
(../upstream/wft-preview-deploy.yaml). The intent-derived changes are applied
the way the snapshot of tpl-git-commit.yaml assigns them. Nothing here reads
another repository: the inputs are the pinned snapshots in this repository.

Outputs per case: expected-before.yaml (no intent), expected-after.yaml
(with the intent) or expected-refused.txt when the script exits non-zero.
captured-from.json records the source_commit of ../upstream/provenance.json;
TestGoldenCapturedFromPinnedSnapshots fails when they differ.
"""
import copy
import json
import os
import re
import subprocess
import sys
import tempfile

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
UP = os.path.join(HERE, "..", "upstream")


def load_set_overrides():
    """The (key, value, is_string, is_port) of every --set in the template."""
    out = []
    for line in open(os.path.join(UP, "wft-preview-deploy.yaml"), encoding="utf-8"):
        s = line.strip()
        m = re.match(r'^(\$\{PORT:\+)?--set(-string)? (.+?)\}?\s*\\?$', s)
        if not m or "helm" in s:
            continue
        is_port, is_string, rest = bool(m.group(1)), bool(m.group(2)), m.group(3)
        if rest.startswith('"') and rest.endswith('"'):
            rest = rest[1:-1]
        key, _, value = rest.partition("=")
        key = key.replace("\\\\", "\\")
        value = value.strip('"')
        out.append((key, value, is_string, is_port))
    return out


def split_path(key):
    parts, cur, i = [], "", 0
    after_index = False
    while i < len(key):
        c = key[i]
        if c == "\\" and i + 1 < len(key):
            cur += key[i + 1]
            i += 2
            continue
        if c == ".":
            if not after_index:
                parts.append(cur)
            cur = ""
            after_index = False
        elif c == "[":
            if cur:
                parts.append(cur)
            j = key.index("]", i)
            parts.append(int(key[i + 1 : j]))
            cur = ""
            i = j
            after_index = True
        else:
            cur += c
        i += 1
    if cur:
        parts.append(cur)
    return parts


def helm_set(values, key, raw, is_string):
    if raw.startswith("{") and raw.endswith("}"):
        val = [x for x in raw[1:-1].split(",") if x]
    elif is_string:
        val = raw
    elif raw in ("true", "false"):
        val = raw == "true"
    elif re.fullmatch(r"-?[0-9]+", raw):
        val = int(raw)
    else:
        val = raw
    parts = split_path(key)
    cur = values
    for i, p in enumerate(parts):
        last = i == len(parts) - 1
        nxt = parts[i + 1] if not last else None
        if isinstance(p, int):
            while len(cur) <= p:
                cur.append(None)
            if last:
                cur[p] = val
            else:
                if cur[p] is None:
                    cur[p] = [] if isinstance(nxt, int) else {}
                cur = cur[p]
        else:
            if last:
                cur[p] = val
            else:
                if not isinstance(cur.get(p), (dict, list)):
                    cur[p] = [] if isinstance(nxt, int) else {}
                cur = cur[p]


def apply_intent(v, intent):
    """The intent-derived changes, as tpl-git-commit assigns them."""
    spec, md = intent["spec"], intent["metadata"]
    rt = spec["runtime"]
    v.setdefault("service", {})["port"] = rt["port"]
    v.setdefault("probes", {}).setdefault("liveness", {})["path"] = rt["healthPath"]
    v["probes"].setdefault("readiness", {})["path"] = rt["healthPath"]
    v["replicaCount"] = rt.get("replicas", 1)
    if "resources" in spec:
        r = spec["resources"]
        v["resources"] = {
            "requests": {"cpu": r["requests"]["cpu"], "memory": r["requests"]["memory"]},
            "limits": {"cpu": r["limits"]["cpu"], "memory": r["limits"]["memory"]},
        }
    for k, val in spec.get("env", {}).items():
        v.setdefault("env", {})[k] = val
    refs = spec.get("secretRefs", [])
    if refs:
        name = md["service"] + "-secrets"
        ext = v.setdefault("externalSecret", {})
        ext["targetSecret"] = name
        if not isinstance(ext.get("data"), list):
            ext["data"] = []
        for ref in refs:
            if not any(isinstance(d, dict) and d.get("secretKey") == ref["env"] for d in ext["data"]):
                ext["data"].append({
                    "secretKey": ref["env"],
                    "remoteKey": "teams/%s/%s" % (md["tenant"], md["service"]),
                    "property": ref["property"],
                })
        env_from = [e for e in (v.get("envFrom") or []) if (e.get("secretRef") or {}).get("name") != name]
        env_from.append({"secretRef": {"name": name}})
        v["envFrom"] = env_from


def effective(case, base, intent):
    v = copy.deepcopy(base)
    if intent is not None:
        apply_intent(v, intent)
    with tempfile.TemporaryDirectory() as tmp:
        src, dst = os.path.join(tmp, "in.yaml"), os.path.join(tmp, "out.yaml")
        with open(src, "w", encoding="utf-8") as f:
            yaml.safe_dump(v, f, sort_keys=False)
        p = subprocess.run(
            [sys.executable, os.path.join(UP, "rewrite_preview_values.py"),
             "--team", case["tenant"], "--service", case["service"], "--in", src, "--out", dst],
            capture_output=True, text=True,
        )
        if p.returncode != 0:
            return None
        out = yaml.safe_load(open(dst, encoding="utf-8"))
    subst = {
        "${TAG}": "rev-" + case["revision"],
        "${HOST}": case["host"],
        "${RELEASE}": "preview-%s-%s" % (case["service"], case["preview_id"]),
        "${PREVIEW_ID}": case["preview_id"],
        "${PORT}": str((intent or {}).get("spec", {}).get("runtime", {}).get("port", "")),
    }
    for key, value, is_string, is_port in load_set_overrides():
        if is_port:
            continue  # the Go compiler sets service.port with the intent
        for k, s in subst.items():
            value = value.replace(k, s)
        helm_set(out, key, value, is_string)
    return out


def main():
    prov = json.load(open(os.path.join(UP, "provenance.json"), encoding="utf-8"))
    for name in sorted(os.listdir(HERE)):
        d = os.path.join(HERE, name)
        if not os.path.isdir(d):
            continue
        case = json.load(open(os.path.join(d, "case.json"), encoding="utf-8"))
        base = yaml.safe_load(open(os.path.join(d, "base.yaml"), encoding="utf-8"))
        intent = case.get("intent")
        for fname in ("expected-before.yaml", "expected-after.yaml", "expected-refused.txt"):
            if os.path.exists(os.path.join(d, fname)):
                os.remove(os.path.join(d, fname))
        before = effective(case, base, None)
        after = effective(case, base, intent) if intent is not None else None
        if before is None or (intent is not None and after is None):
            open(os.path.join(d, "expected-refused.txt"), "w").write("refused\n")
            continue
        yaml.safe_dump(before, open(os.path.join(d, "expected-before.yaml"), "w", encoding="utf-8"), sort_keys=True)
        if after is not None:
            yaml.safe_dump(after, open(os.path.join(d, "expected-after.yaml"), "w", encoding="utf-8"), sort_keys=True)
    json.dump({"source_commit": prov["source_commit"]}, open(os.path.join(HERE, "captured-from.json"), "w"), indent=2)
    open(os.path.join(HERE, "captured-from.json"), "a").write("\n")


if __name__ == "__main__":
    main()
