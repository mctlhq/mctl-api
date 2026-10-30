#!/usr/bin/env python3
"""Rewrite a service values.yaml so a preview Helm release cannot read prod secrets.

Tenant Vault paths
    teams/<team>/<service>/<leaf>
    secret/data/teams/<team>/<service>/<leaf>
become
    teams/<team>/<service>/preview/<leaf>
    secret/data/teams/<team>/<service>/preview/<leaf>

Team-scoped ExternalSecrets are forced onto the namespaced tenant-store
(eso-tenant-<team>-preview), which can only read the preview/ prefix.
Platform paths (platform/*, ClusterSecretStore) are left unchanged — they are
shared infrastructure (GHCR, the R2 artifact store), not tenant production credentials.

Exits non-zero if a values file still points a tenant-store ES at a non-preview
teams/ path after rewrite, or if one ExternalSecret mixes platform and team keys.
"""
from __future__ import annotations

import argparse
import copy
import sys
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.stderr.write("PyYAML is required (apk add py3-yaml)\n")
    sys.exit(2)


DATA_PREFIX = "secret/data/"


def strip_data_prefix(key: str) -> tuple[str, str]:
    if key.startswith(DATA_PREFIX):
        return DATA_PREFIX, key[len(DATA_PREFIX) :]
    return "", key


def rewrite_remote_key(key: str, team: str, service: str) -> str:
    if not key:
        return key
    prefix, path = strip_data_prefix(key)
    if path.startswith("platform/"):
        return key
    teams_prefix = f"teams/{team}/"
    if not path.startswith("teams/"):
        raise SystemExit(
            f"refusing preview deploy: unrecognized Vault path {key!r} "
            f"(expected teams/<team>/... or platform/...)"
        )
    if not path.startswith(teams_prefix):
        raise SystemExit(
            f"refusing preview deploy: Vault path {key!r} is not under {teams_prefix}"
        )
    rest = path[len(teams_prefix) :]
    parts = rest.split("/", 1)
    svc = parts[0]
    remainder = parts[1] if len(parts) > 1 else ""
    if remainder.startswith("preview/") or remainder == "preview":
        return key
    new = f"teams/{team}/{svc}/preview"
    if remainder:
        new += f"/{remainder}"
    return prefix + new


def _remote_keys_in_data(data: list | None) -> list[str]:
    if not isinstance(data, list):
        return []
    keys = []
    for item in data:
        if isinstance(item, dict) and item.get("remoteKey"):
            keys.append(str(item["remoteKey"]))
    return keys


def _classify_keys(keys: list[str]) -> str:
    """Return 'platform', 'team', 'mixed', or 'empty'."""
    has_platform = False
    has_team = False
    for k in keys:
        _, path = strip_data_prefix(k)
        if path.startswith("platform/"):
            has_platform = True
        elif path.startswith("teams/"):
            has_team = True
    if has_platform and has_team:
        return "mixed"
    if has_team:
        return "team"
    if has_platform:
        return "platform"
    return "empty"


def _force_tenant_store(obj: dict) -> None:
    obj["store"] = "tenant-store"
    obj["storeKind"] = "SecretStore"


def _rewrite_data_list(data: list | None, team: str, service: str) -> None:
    if not isinstance(data, list):
        return
    for item in data:
        if isinstance(item, dict) and "remoteKey" in item:
            item["remoteKey"] = rewrite_remote_key(str(item["remoteKey"]), team, service)


def rewrite_values(values: dict, team: str, service: str) -> dict:
    out = copy.deepcopy(values)

    ext = out.get("externalSecret")
    if isinstance(ext, dict):
        _rewrite_data_list(ext.get("data"), team, service)
        kind = _classify_keys(_remote_keys_in_data(ext.get("data")))
        if kind == "mixed":
            raise SystemExit(
                "refusing preview deploy: externalSecret mixes platform/ and teams/ keys"
            )
        if kind == "team":
            _force_tenant_store(ext)

    extras = out.get("extraExternalSecrets")
    if isinstance(extras, dict):
        for name, es in extras.items():
            if not isinstance(es, dict):
                continue
            _rewrite_data_list(es.get("data"), team, service)
            kind = _classify_keys(_remote_keys_in_data(es.get("data")))
            if kind == "mixed":
                raise SystemExit(
                    f"refusing preview deploy: extraExternalSecrets.{name} mixes platform/ and teams/ keys"
                )
            if kind == "team":
                _force_tenant_store(es)

    db = out.get("dbSecret")
    if isinstance(db, dict) and db.get("vaultPath"):
        db["vaultPath"] = rewrite_remote_key(str(db["vaultPath"]), team, service)
        _, path = strip_data_prefix(str(db["vaultPath"]))
        if path.startswith("teams/"):
            _force_tenant_store(db)

    return out


def _assert_no_prod_team_paths(values: dict, team: str) -> None:
    """Belt-and-suspenders: any remaining teams/<team>/ path must include /preview/."""

    def walk(obj: Any, loc: str) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                walk(v, f"{loc}.{k}")
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                walk(v, f"{loc}[{i}]")
        elif isinstance(obj, str):
            _, path = strip_data_prefix(obj)
            needle = f"teams/{team}/"
            if path.startswith(needle) and "/preview/" not in path and not path.endswith("/preview"):
                raise SystemExit(
                    f"refusing preview deploy: {loc} still points at production Vault path {obj!r}"
                )

    walk(values.get("externalSecret"), "externalSecret")
    walk(values.get("extraExternalSecrets"), "extraExternalSecrets")
    walk(values.get("dbSecret"), "dbSecret")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--team", required=True)
    parser.add_argument("--service", required=True)
    parser.add_argument("--in", dest="src", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    with open(args.src, encoding="utf-8") as f:
        values = yaml.safe_load(f) or {}
    if not isinstance(values, dict):
        raise SystemExit(f"{args.src} is not a YAML mapping")

    rewritten = rewrite_values(values, args.team, args.service)
    _assert_no_prod_team_paths(rewritten, args.team)

    with open(args.out, "w", encoding="utf-8") as f:
        yaml.safe_dump(rewritten, f, sort_keys=False, allow_unicode=True)
    print(f"Wrote preview values to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
