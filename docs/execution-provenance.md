# Execution provenance (execution_attempt_v1)

mctl-api#896. The canonical `attempt_id` and `lineage_root` of a work-item
execution (`we_`), recorded by the server so that the independent-review
gate (Tier A/B, see [review-receipts.md](review-receipts.md)) never takes
them on a caller's word.

## Contract

`cj` is Python `json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=True)`.

- `engine_run` = `engine_ref` up to its first `#`.
- `attempt_id` = `"at_"` + first 32 hex of SHA-256 of
  `cj(["execution_attempt_v1","attempt",engine,engine_run])`.
- `lineage_root` = `"ln_"` + first 32 hex of SHA-256 of
  `cj(["execution_attempt_v1","lineage",root_execution_id])`.
- `root_execution_id` is the first execution reached by following
  `resumed_from_execution_id` back to one that has none.

An attempt is one engine run; a lineage is one resume chain. Every input is
a stored row field; no request field supplies them.

## Record

`insertExecution` writes one `execution_provenance` row in the execution's
own transaction (a failure rolls the execution back). A trigger refuses
UPDATE. The row also records `attached_by` and `attached_by_principal`: who
chose `engine`/`engine_ref`. Provenance proves which attempt and lineage an
execution has, not that it is an eligible reviewer. Executions created
before this change have no row (`execution_provenance_absent`); no backfill.

## Reads

`GET /api/v1/executions/{execution_id}/provenance`: platform admin, or the
agent run token bound to that execution.

| Status | Code | Meaning |
| --- | --- | --- |
| 200 | | the stored record |
| 404 | `execution_provenance_absent` | read succeeded, no record |
| 503 | `execution_provenance_unavailable` | not configured, unreadable, or a stored row fails validation |
| 403 | | any other caller |

## Vectors

`internal/executionprovenance/testdata/execution_attempt_vectors.json` is the
single canonical vector file. mctl-agents vendors the exact bytes and pins the
same SHA-256:

```
9ab9cf04a5542004f5e851a0f32b87681249d3e6f7027386945ebe76a46ad24c
```

Changing the file is a `contract_version` change.
