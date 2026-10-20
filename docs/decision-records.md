# Durable decision records

mctl-api#701, audit finding G8 of mctlhq/.github#182. A decision record lets an
auditor start from one decision id and reconstruct intent → policy →
authority/approval → exact action → every execution attempt → terminal result
from durable records, without correlating telemetry. The code lives in
`internal/decisions`.

## What it reuses

It is not a second approval framework. Every link is an existing identifier:

| Link | Field | Source of truth |
| --- | --- | --- |
| Intent | `execution_id`, `work_item_id` (`wi_`), `intent_source`, `trace_id` | work items / runtime execution |
| Policy | `policy_version`, `rule_id`, `verdict`, `code`, `policy_reasons` | mctl-agents `orchestrator/policy_checkpoint.py` `Decision` |
| Authority | `actor`, `principal_id` (`prn_`), `tenant`, `authority_basis`, `approval_id` (`aar_`) | principals, action approvals (mctl-api#366, #700) |
| Exact action | `action_kind`, `operation`, `target_digest`, `args_digest`, `action_digest`, `intent_hash` | `ActionRequest.action_digest()`; `intent_hash` copied from the `aar_` |
| Attempt | `evidence_id` (`ev-`), `runtime_execution_id` (`ex-`), `commerce_invocation_id` (`inv_`) | execution evidence (mctl-api#409), ADR 011, commerce |

`verdict` and `code` are the policy checkpoint's closed vocabularies; only
`allowed` and `approved` permit, exactly as `Decision.permitted`.

## Writing

Both routes need `evidence:write` (the evidence writer, or an admin). Both are
idempotent per key: the same key with the same content returns the stored row
(200), different content is 409 `decision_idempotency_conflict`.

`POST /api/v1/decisions` records one decision. `code: approved` requires an
`approval_id`; the server reads that `aar_` and refuses (422
`decision_approval_binding`) unless it binds the same execution, action kind,
target, args digest, rule and policy version, and has been approved; its
`intent_hash` is copied onto the decision. An approval that cannot be read
refuses that write with 503 `decision_reference_unobservable`; it is never
treated as absent.

A refusal code may name the approval it is about (`approval_pending`,
`approval_intent_mismatch`, `approval_lookup_error`, ...). That is a
reference, not a claim of authority: it is not resolved or bound at write
(the approval may bind a different intent, or be unreadable, by definition)
and is resolved when the chain is read.

`POST /api/v1/decisions/{id}/attempts` appends one event:

- `phase: started` (no `attempt_no`) opens attempt n+1. Refused with 409
  `decision_not_permitted` on a refusing decision and
  `decision_already_succeeded` once any attempt succeeded.
- `phase: succeeded | failed | partial` with `attempt_no` closes that started,
  still-open attempt. `failed` and `partial` need an `error_code` (a code,
  never a message). A second terminal event for the same attempt is 409
  `decision_attempt_closed`.

Decision writes have their own rate limit (150/min per principal),
separate from evidence ingest's 120/min, so a burst of one never throttles
the other.

A retry is a new attempt; nothing is overwritten. Both tables refuse `UPDATE`
with a trigger.

## Reading

`GET /api/v1/decisions/{id}` (admin) returns the decision, its attempts with
their events, the referenced approval and evidence as read now, and `result`:
`refused`, `pending`, `in_progress`, `succeeded`, `failed` or `partial`. An
attempt that never reported an end and was followed by another reads
`unknown`, not `failed`.

A referenced record the store reports missing is listed with status
`not_found`; one about another execution is `mismatch`. An approval is
`mismatch` when any binding field (execution, work item, action kind,
target, args digest, rule, policy version) differs from the decision's, or
its `intent_hash` differs from the one bound at write; `detail` names the
fields. So an `approval_intent_mismatch` refusal reads `mismatch`, with the
diverging fields shown. A reference that
cannot be read at all fails the whole request with 503
`decision_reference_unobservable`: a partial chain is never served as a
complete one.

`GET /api/v1/decisions?execution_id=|work_item_id=|approval_id=` (admin) finds
decision ids, newest first, with `truncated`.

## Retention and redaction

Records hold ids, codes and digests only: no arguments, no target text, no
error messages, no copies of approvals or envelopes. `DECISIONS_RETENTION_DAYS`
deletes whole decisions with their attempts; unset keeps them indefinitely.
Referenced approvals and evidence keep their own retention, which is why a
chain can show `not_found`. Telemetry (the `POLICY_DECISION` log line, spans)
is never read back as a record.

Tamper-evidence is a separate decision and out of scope here.
