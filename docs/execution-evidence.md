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
- `GET /api/v1/evidence/{id}`, `GET /api/v1/evidence` and
  `GET /api/v1/evidence/current` are admin-only:
  cross-cutting governance evidence is more sensitive than a workflow
  status.
- `GET /api/v1/work-items/{id}/evidence` reuses `visibleWorkItem` /
  `canSeeWorkItem`: a work item the caller may not see answers `404`, never
  `403`, so neither the work item's existence nor any evidence attached to
  it leaks. `GET /api/v1/work-items/{id}/evidence/current` goes through the
  same gate (see "Current vs historical" below).
- Every accepted ingest writes an audit entry naming the evidence id, the
  primary execution identity, and the ingesting principal.

## ADR 018 Amendment 2: versions, subject, tool calls, provenance

mctlhq/mctl-agents#199 (contract merged as mctlhq/mctl-agents#575) added
four optional envelope blocks and the `observation_failed` gap code. This
store implements the ADR's "Tier B follow-up" checklist.

**Accepted keys, re-validated on ingest.** `versions`, `subject`,
`tool_calls` and `provenance` are accepted top-level keys. Each is absent
when missing or `null` (`tool_calls` also when `[]`), and then hashes
exactly as before: every pre-amendment vector keeps its literal hash. A
present block is decoded strictly (unknown keys, non-string leaves and a
non-integer `release_revision` are refused) and rebuilt in Tier A's
`to_dict()` shape before hashing, which is what Tier A's
`recompute_content_hash()` hashes. Every rule of Tier A's `validate()` is
re-run (`internal/evidence/amendment2.go`): the `versions` slug/version/hash
shapes and the signed 64-bit `release_revision`; the closed subject kinds,
the numbered `ref` of a `pull_request`/`issue`, the `owner/name` repository
with no path fragment, and a full lowercase 40/64-hex `revision` for
`pull_request`/`branch`/`release`; `subject` requires `provenance`; the
governed tool-call kinds (`policy_checkpoint.ACTION_KINDS`), the closed
statuses and `MAX_TOOL_CALLS` = 256; the closed `authority`, the
`observed_at` shape and `supersedes` = `ev-` + 16 hex, never the envelope's
own id; `observation_failed` gaps must be required; a `redacted_out` gap on
an Amendment 2 block must be required, and only such a gap excuses a blank
`subject.ref` (non-numbered kinds only), `subject.repository` or
`versions.agent`. Violations answer `400 evidence_invalid`. `observed_at`
must also be a real instant (it is stored as `TIMESTAMPTZ`).
`shepherd-pr-evidence.json` and `shepherd-pr-superseding-evidence.json` are
byte-for-byte golden vectors with their literal hashes pinned.

**Immutable columns.** `subject_kind`, `subject_repository`, `subject_ref`,
`subject_revision`, `authority`, `supersedes` (`TEXT NOT NULL DEFAULT ''`)
and `observed_at` (`TIMESTAMPTZ NULL`) are added by DDL only (`ADD COLUMN IF
NOT EXISTS`), so the immutability trigger is untouched and no backfill is
needed. They are written once at ingest from the envelope, and every read
cross-checks them against the stored envelope (a disagreement is a corrupt
row, `500`, never a silently preferred value). CHECK constraints repeat the
contract at the storage layer (authority vocabulary, `supersedes` shape and
not-self, subject requires provenance, SHA-bound revisions, plus the subject
kind vocabulary, numbered refs and whole provenance). `versions` and
`tool_calls` stay in the verbatim envelope only. Indexes:
`(subject_kind, subject_repository, subject_ref, subject_revision,
observed_at DESC) WHERE subject_kind <> ''` and `(supersedes) WHERE
supersedes <> ''`.

**Supersession at ingest.** When `provenance.supersedes` names a stored
envelope, that envelope must have the same subject and revision and an
authority no stronger than the new one, else `422
evidence_supersedes_invalid`. A target that does not exist yet is accepted:
the read rule only honours links inside a pool, so a dangling link retires
nothing.

**Exposed fields.** Every record carries `subject`, `authority`,
`observed_at`, `supersedes` and a read-time `superseded_by` (valid links
only: same subject and revision, neither subject redacted, equal or stronger
authority). They are omitted on pre-amendment records, whose JSON is
unchanged. `GET /api/v1/evidence` and `GET /api/v1/work-items/{id}/evidence`
accept `subject_kind`, `subject_repository`, `subject_ref` and
`subject_revision` filters (an unknown `subject_kind` is `400`).

### Current vs historical

`GET /api/v1/evidence/current?subject_kind=&repository=&ref=&revision=`
implements Tier A's `resolve_current` exactly (`internal/evidence/resolve.go`
is a line-for-line port, tested against Tier A's own cases and the golden
pair) and answers `{"state": ..., "evidence": ...}`:

| `state` | Meaning |
|---|---|
| `current` | exactly one envelope wins; `evidence` is that record |
| `stale_revision` | no usable evidence at this revision, some at another |
| `no_evidence` | no usable evidence for the subject at all (not "no run happened": a redacted-subject envelope answers it too) |
| `unknown_revision` | `revision` missing for `pull_request`/`branch`/`release` |
| `ambiguous` | a top-rank tie, a fully superseded pool, or two contents under one id |

Authority outranks recency (`observed` > `derived` > `asserted`; among
equals the later `observed_at` wins, the fraction normalized), and only an
equal-or-stronger envelope in the same pool retires the one it supersedes.
A malformed parameter (abbreviated or uppercase SHA, unknown kind, non-
numeric PR ref, repeated parameter) answers `400 evidence_query_invalid`,
never `no_evidence`.

Could not observe is never observed absent: the read loads the complete
pool at (subject, revision) and, only when it holds no usable envelope, one
unredacted envelope at another revision as the `stale_revision` witness;
every row is hash-verified. A pool larger than `MaxCurrentPool` (1000)
answers `500 evidence_current_pool_too_large`, and any read or verification
error is a `5xx`, never a truncated `no_evidence`.

`GET /api/v1/work-items/{id}/evidence/current` (behind `visibleWorkItem`)
resolves over the same complete pool and answers only when every record the
answer depends on is attached to that work item; otherwise `403
evidence_current_not_visible`. Resolving over the work item's slice of the
pool could call a superseded envelope current, and answering from another
work item's evidence would leak it.
