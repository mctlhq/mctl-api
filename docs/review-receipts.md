# Durable review receipts (Tier B, Slice B)

mctl-api#897, part of epic mctlhq/.github#281. This makes the pure Tier A
contract in `internal/reviewreceipts` (mctl-api#895) durable and reachable. The
store is `internal/reviewstore`; the routes are in
`internal/api/handlers_review_receipts.go`.

## Tables

Created idempotently at startup in the evidence database
(`EVIDENCE_DB_URL`, else `AUDIT_DB_URL`). `UPDATE` is refused on all three by
`review_rows_immutable()` triggers; `DELETE` stays allowed for retention.

- `review_requests`: the sealed request document verbatim (`document`), its
  `identity_key` and `binding_key` (canonical JSON of the Tier A tuples), the
  SHA-256 of the nonce (unique), the authoring execution id, the tenant
  (taken from the authoring evidence, never from the caller) and an
  `ingest_seq` identity column.
- `review_receipts`: the sealed receipt document, `mode`, `assurance`, the
  request's tenant and `ingest_seq`. A `CHECK` forbids `mode = 'manual'` with
  `assurance = 'independent'`.
- `review_nonce_consumptions`: written only by the worker receipt path
  (`SubmitWorker`), in the same transaction as the receipt. A `CHECK` on
  `review_receipts` forbids `mode = 'worker'` with `assurance = 'advisory'`.

## Closure

Closure is computed on every read and never stored:

- `ttl`: `ingested_at + REVIEW_REQUEST_TTL <= now`.
- `superseded`: a newer request has the same identity and a different
  binding; `closed_by` names the first such request. A same-binding repeat
  closes nothing.

## Routes

| Route | Auth | Notes |
| --- | --- | --- |
| `POST /api/v1/review-requests` | `evidence:write` | Body is the sealed `ReviewRequest`, stored verbatim. 201, or 200 with `replayed:true`. |
| `POST /api/v1/review-receipts/manual` | direct human admin | Manual advisory receipt against an open manual-mode request. |
| `POST /api/v1/review-receipts` | `review`-scoped, execution-bound agent run token | Worker receipt; see Worker path. 501 `review_worker_ingest_disabled` (no body read) unless `REVIEW_WORKER_INGEST_ENABLED=true`. |
| `GET /api/v1/review-requests/{id}` | admin | The request plus closure. |
| `GET /api/v1/review-receipts` | admin | `{receipts, count, complete:true}` or a typed 503. |
| `GET /api/v1/review-gate` | admin | Subject fields and `required_assurance` as query; returns the verdict and the full gate input. |

Writes share a 30/min per-principal bucket (`review:`), separate from evidence
(120) and decisions (150). The evidence writer may call
`POST /api/v1/review-requests` and nothing else new. Bodies are capped at
64 KiB.

The manual body is
`{"request_id","subject","outcome","criteria":[{"id","status"}],"findings_ref":{"name","kind","content_hash"}}`.
Any other key (`tenant`, `submitted_by`, `reviewer_actor`, `assurance`,
`mode`, `nonce`, `created_at`) is `review_unknown_key`.

## Codes

- 400: the Tier A codes `review_malformed`, `review_unknown_key`,
  `review_bad_subject`, `review_bad_identity`, `review_rubric_mismatch`,
  `review_pass_with_unobserved`, `review_unobserved_outcome`; and
  `review_unsealed`.
- 403: `review_not_permitted`, `review_run_token_required`,
  `review_nonce_mismatch`, `review_reviewer_ineligible`,
  `review_execution_unproven`.
- 404: `review_request_not_found`.
- 409: `review_request_closed`, `review_binding_mismatch`,
  `review_request_mode_worker`, `review_nonce_reused`,
  `review_request_conflict`, `review_request_mode_manual`,
  `review_nonce_consumed`, `review_reviewer_not_independent`.
- 422: `review_authoring_unresolved`, `review_tenant_unresolved`.
- 501: `review_worker_ingest_disabled`.
- 503: `review_store_unavailable`, `review_pool_too_large`,
  `review_evidence_unavailable`, `review_principal_unavailable`,
  `review_provenance_unavailable`.

## Manual is advisory, never independent

`SealReceipt` forces `assurance=advisory` for a manual request, the store
asserts it before insert, and the table `CHECK` enforces it. Under
`required_assurance=independent` a manual PASS yields `advisory_only`; under
`any` it yields `satisfied`. A manual receipt is refused (`review_request_mode_worker`)
for a worker-mode request and never consumes the nonce.

## Reads fail closed

The pool is read with `LIMIT REVIEW_POOL_MAX+1`; one row over is
`review_pool_too_large`, and a stored document that no longer parses is
`review_store_unavailable`. No partial pool is ever returned. The gate
response carries `request`, `request_closed` and the whole `pool`, so Tier A
can re-run `evaluate_review_gate` and get the same verdict. The request
selected for a binding is the newest by `ingest_seq`, open or closed.

### Capacity

The pool is fleet-wide and append-only, and this slice has no retention (it
is out of scope of mctl-api#897). The bound is deliberate: a pool that cannot
be read completely fails the gate closed instead of evaluating a truncated
one. Operationally this means that once `review_receipts` holds more than
`REVIEW_POOL_MAX` rows, every pool read and gate read answers 503
`review_pool_too_large` until an operator acts. Either raise
`REVIEW_POOL_MAX` or purge old rows (DELETE stays allowed on all three
tables; only UPDATE is refused). A retention or per-identity read is a
follow-up and must land before the volume gets near the bound.

## Authoring verification

Request ingest checks the authoring facts against the server-written
execution provenance ([execution-provenance.md](execution-provenance.md))
before storing anything; the sealed document is never rewritten.

- Worker mode: `authoring_execution_id` must be a `we_` id with a
  provenance record, `authoring_lineage_root` must equal its `lineage_root`,
  `authoring_attempt_ids` must contain its `attempt_id`, and every listed
  attempt must belong to a recorded execution of that lineage.
- Manual mode: the same checks apply when `authoring_attempt_ids` or
  `authoring_lineage_root` is non-empty; empty facts stay permitted.

| Code | Status | Meaning |
| --- | --- | --- |
| `review_authoring_unproven` | 422 | the authoring facts do not match the record |
| `review_execution_unproven` | 403 | `ProveReviewer`: no record for the execution |
| `review_provenance_unavailable` | 503 | provenance could not be read or is not wired |

`reviewstore.ProveReviewer(ctx, executionID)` returns only the stored
attempt and lineage, for mctl-api#917 (autonomous worker ingestion) to call
with the run token's execution.

## Worker path

`POST /api/v1/review-receipts` lets an autonomous reviewer run answer a
worker-mode request (mctl-api#917). It answers 501
`review_worker_ingest_disabled`, reading no body, unless
`REVIEW_WORKER_INGEST_ENABLED=true`.

The caller must be an agent principal holding an unrevoked, unexpired run
token with the `review` scope that is bound to an execution; anything else is
403 `review_run_token_required`. The `review` scope reaches only
`GET /api/v1/whoami` and this route and is minted only by the service
principal acting directly, always with an execution.

The body is
`{"request_id","subject","nonce","outcome","criteria":[{"id","status"}],"findings_ref":{"name","kind","content_hash"},"evidence_ref"}`.
Any other key (`reviewer_execution_id`, `attempt_id`, `lineage_root`,
`reviewer_actor`, `assurance`, `mode`, `tenant`, `created_at`) is
`review_unknown_key`. The reviewer actor is `agent:<name>` from the
authenticated principal, the reviewer execution is the token's bound
execution, and its attempt and lineage come from `execution_provenance`.

Checks, in order, all before any write: request exists, is open, is
worker-mode and the subject binding matches; the nonce equals the request's
(`review_nonce_mismatch`); the reviewer execution has provenance
(`review_execution_unproven`) and is eligible (`review_reviewer_ineligible`);
the reviewer is independent of the authoring execution, attempts, lineage and
author actors (`review_reviewer_not_independent`). The nonce consumption
(`review_nonce_consumptions`, primary key on the nonce digest) and the
receipt are inserted in one transaction, so a second submit is 409
`review_nonce_consumed` and nothing half-written remains. A retry after a
success is therefore 409, not a replay.

Eligibility: the execution's provenance row must record
`attached_direct_service = true`, written by the server when the service
principal, acting directly (not relayed, not an agent), inserted the
execution (`attach_path` is `attach`, `resume`, `fulfil_start` or
`fulfil_resume`). Executions attached by developers through
`POST /api/v1/work-items/{id}/executions`, by agents, by relayed surfaces,
and every row recorded before mctl-api#917 are ineligible: a caller-chosen
`engine`/`engine_ref` can never establish independence.

Prerequisites 1-4 are delivered: provenance with `ProveReviewer`
(mctl-api#896); `we_<uuid>` ids in Tier A (mctl-agents#980) and Tier B
(mctl-api#923); the vendored vectors and parity test (mctl-agents#979); and the
run-token binding, nonce consumption and eligibility rule above
(mctl-api#917).

The reviewer agent is `review-worker`, the canonical name decided in
mctl-agents#905; the `review` scope admits only it. The one remaining step to
enable the route is an operator setting `REVIEW_WORKER_INGEST_ENABLED=true`
through a mctl-gitops change. Setting it back (or `REVIEW_RECEIPTS_DISABLED=true`)
returns the route to 501 (or 503).

## Configuration

- `REVIEW_RECEIPTS_DISABLED`: kill switch; every review route answers 503
  `review_store_unavailable`.
- `REVIEW_WORKER_INGEST_ENABLED`: `true` opens the worker receipt route;
  default off.
- `REVIEW_REQUEST_TTL`: Go duration, default `24h`. An invalid value leaves
  the store off.
- `REVIEW_POOL_MAX`: default `10000`. An invalid value leaves the store off.

Without the evidence store, request ingest answers 503
`review_evidence_unavailable`.

## MCP

`mctl_submit_review_assertion` (write, human admin only) and
`mctl_get_review_gate` (read-only).
