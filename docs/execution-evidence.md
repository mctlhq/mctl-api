# Execution evidence: durable storage and retrieval (mctl-api#409)

This document describes Tier B of the execution-evidence contract:
persisting and retrieving sealed `evidence.mctl.ai/v1alpha1` envelopes.
Tier A — the envelope schema and its sealing algorithm — lives in
`orchestrator/execution_evidence.py` in mctl-agents, ADR 018 and its
Amendment 1 (mctlhq/mctl-agents#539, PR #540, merged as `9fe775f`). This
package, `internal/evidence`, never invents its own identity rule: it
re-derives Tier A's exactly.

## Contract boundary

mctl-api's evidence store gives a sealed envelope a durable home next to
the canonical platform state it references: `work_items` /
`work_item_executions` (`internal/workitems`), `work_item_context_snapshots`,
`work_item_execution_requests`, `action_approval_requests` and
`model_usage_records`. It stores **references and hashes only** — never a
second copy of execution or work-item state, and never prompts, tool
payloads, artifact bodies, execution phase, work-item lifecycle state or
approval state.

**Evidence is never written to GitOps or any public repository.** An
earlier direction (mctl-agents#483, `orchestrator/evidence_store.py`,
`_evidence/` trees in the public `mctl-gitops` repository) is superseded and
is not reintroduced in any form. Evidence lives exclusively in mctl-api's
own PostgreSQL storage.

## The Tier A identity algorithm

The server recomputes, on every write and every read:

1. Parse the envelope as strict JSON: reject unknown or duplicate keys.
2. Build the **content payload**: every top-level field except
   `evidence_id`, `content_hash` and `created_at`. Each optional block
   (`policy_decisions`, `snapshot_refs`, `execution_request`, `usage`,
   `approvals`, `artifacts`, `gaps`) takes part only when present and
   non-empty.
3. Rebuild the `execution` block through the Amendment 1 leaf rule:
   `execution_id`, `work_item_id` and `trace_id` are always present (as `""`
   when blank); `runtime_execution_id` is present only when non-blank. A
   received `"runtime_execution_id": ""` hashes exactly as if the key were
   absent.
4. Serialize with Tier A's canonical-JSON rule
   (`orchestrator/context_snapshot.py`'s `_canonical_json`):
   `json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)`.
   That means sorted keys, no HTML escaping of `<`/`>`/`&` (unlike Go's
   `encoding/json` default), and every non-ASCII character escaped as
   `\uXXXX` (`ensure_ascii=True`, Python's default) with a UTF-16 surrogate
   pair above the BMP.
5. `content_hash = "sha256:" + hex(sha256(canonical))`,
   `evidence_id = "ev-" + content_hash[7:23]`.
6. The envelope's own `evidence_id`/`content_hash` must equal the
   recomputed values, or the write is refused with `400
   evidence_hash_mismatch` — never corrected silently.

`internal/evidence/types.go` implements this in `CanonicalContentJSON`,
`ContentHash` and `EvidenceIDFor`; `internal/evidence/testdata/` carries
golden vectors covering a `we_`-only join (issue-investigator shape), an
`ex-`-only join (implementer shape), a both-identities join (shepherd
shape), a blank-`runtime_execution_id` variant, non-ASCII text and
`<`/`>`/`&` in a string. `internal/evidence/types_test.go`'s
`TestGoldenVectorConformance` is blocking: this store does not ship if it
does not reproduce every vector's `content_hash` and `evidence_id` byte for
byte.

## The `we_` / `ex-` join (ADR 018 Amendment 1)

mctlhq/mctl-agents#539 (merged) decided the execution join: two distinct,
typed fields, not one overloaded string.

| Field | Meaning | Shape |
|---|---|---|
| `execution_id` | canonical work execution (`internal/workitems.Execution`) | `we_…` or blank |
| `runtime_execution_id` | ADR 011 `ExecutionContext.context_id` | `ex-` + 16 lowercase hex, or blank |

This layer mirrors that join, never classifies it:

- both identities are stored verbatim in their own columns
  (`execution_id`, `runtime_execution_id` on `execution_evidence`), backed
  by `CHECK` constraints that repeat Tier A's shape rules at the storage
  layer;
- at least one of the two must be non-blank; neither may hold the other's
  shape;
- both are independently indexed and independently queryable — a
  both-identities envelope is found by its `we_` filter and by its `ex-`
  filter;
- `primary_execution_ref` (`("work", execution_id)` when set, else
  `("runtime", runtime_execution_id)`) is derived at read time and never
  stored;
- a runtime-only envelope (implementer and shepherd runs today) is stored
  with an empty derived projection, never rejected for lacking a `we_`.

## Two tables: immutable record and rebuildable projection

`execution_evidence` is the sealed, insert-only record: an ordinary
`UPDATE` is rejected at the database level by a `BEFORE UPDATE` trigger
(`execution_evidence_no_update`), the same shape as
`work_item_context_snapshots_no_update`. `DELETE` stays permitted — it is
the retention mechanism.

`execution_evidence_refs` is a **rebuildable, non-authoritative** index:
repository, issue/PR, engine and engine ref, work item and tenant, derived
best-effort from `work_item_executions` and `work_items.external_key` at
ingest time. If a column here ever disagrees with canonical state, canonical
state wins and the entry is read as a stale index, never as an answer.
`Store.RebuildRefs` recomputes it losslessly; dropping and recomputing every
row loses nothing, because nothing here is load-bearing.

There is deliberately **no foreign key** from `execution_evidence` to
`work_items` or `work_item_executions`: `docs/work-context-contract.md`
("ID scheme") mandates correlation over foreign keys, the two stores may
live in different databases (`EVIDENCE_DB_URL` can differ from
`WORK_ITEMS_DB_URL`), and a foreign key would make evidence die with a
`WORKITEM_RETENTION_DAYS` purge — which would defeat the entire point of a
tamper-evident record that outlives the work item's own housekeeping.

## Availability, gaps and retention

- **Store not configured** (`Options.Evidence == nil`, `EVIDENCE_DISABLED`
  set, or no `EVIDENCE_DB_URL`/`AUDIT_DB_URL`): every evidence route answers
  `503 evidence_store_unavailable`, never an empty list.
- **Evidence genuinely absent**: `404 evidence_not_found` on
  `GET /api/v1/evidence/{id}`; an empty `"evidence": []` on the list routes.
- **Evidence present**: `200`.

`EVIDENCE_RETENTION_DAYS` (unset or `0`, the default) retains evidence
indefinitely. A positive value runs a background sweep
(`cmd/api/main.go`'s `startEvidenceRetentionSweep`) that deletes whole rows
older than that age — never a partial redaction, because a redacted
envelope would no longer hash to its `content_hash` and would be refused on
read anyway. Deletion cascades to `execution_evidence_refs`.

## Authorization

- `POST /api/v1/evidence/records` needs `evidence:write`: the dedicated
  evidence-writer principal (`service:mctl-agents-evidence`, authenticated
  by `MCTL_EVIDENCE_WRITER_TOKEN`) or an admin. The evidence writer may call
  no other route (`evidenceWriterGate`, the same shape as `usageWriterGate`
  for the usage ledger).
- `GET /api/v1/evidence/{id}` and `GET /api/v1/evidence` are admin-only:
  cross-cutting governance evidence is more sensitive than a workflow
  status.
- `GET /api/v1/work-items/{id}/evidence` reuses `visibleWorkItem` /
  `canSeeWorkItem`: a work item the caller may not see answers `404`, never
  `403`, so neither the work item's existence nor any evidence attached to
  it leaks.
- Every accepted ingest writes an audit entry naming the evidence id, the
  primary execution identity, and the ingesting principal.
