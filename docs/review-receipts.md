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
- `review_nonce_consumptions`: created for the worker follow-up. Nothing in
  this slice writes to it.

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
| `POST /api/v1/review-receipts` | any authenticated caller | Always 501 `review_worker_ingest_disabled`. Reads no body. |
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
- 403: `review_not_permitted`.
- 404: `review_request_not_found`.
- 409: `review_request_closed`, `review_binding_mismatch`,
  `review_request_mode_worker`, `review_nonce_reused`,
  `review_request_conflict`.
- 422: `review_authoring_unresolved`, `review_tenant_unresolved`.
- 501: `review_worker_ingest_disabled`.
- 503: `review_store_unavailable`, `review_pool_too_large`,
  `review_evidence_unavailable`, `review_principal_unavailable`.

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

## Disabled worker path

Worker receipts stay off until both hold: an authoritative
`execution_id -> attempt_id + lineage_root` (mctl-api#896) and the run-token
binding of the reviewer. Enabling it then needs a write to
`review_nonce_consumptions`; no schema change.

## Configuration

- `REVIEW_RECEIPTS_DISABLED`: kill switch; every review route answers 503
  `review_store_unavailable`.
- `REVIEW_REQUEST_TTL`: Go duration, default `24h`. An invalid value leaves
  the store off.
- `REVIEW_POOL_MAX`: default `10000`. An invalid value leaves the store off.

Without the evidence store, request ingest answers 503
`review_evidence_unavailable`.

## MCP

`mctl_submit_review_assertion` (write, human admin only) and
`mctl_get_review_gate` (read-only).
