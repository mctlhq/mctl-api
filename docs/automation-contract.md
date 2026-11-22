# Automation contract (`automation/v1`)

Status: **contract only, proposed**. Nothing in this document is served, stored or scheduled
today. It is the reviewed target for `automation-api-store` and later slices of the Automation
Control Plane epic (mctlhq/.github#322, decision mctlhq/.github#318, outcome `EXTEND_MCTL_API`).
It adds no second store, ledger, approval engine or authority engine.

Machine-checkable form: `internal/automation/contract` (JSON Schemas under
`internal/automation/contract/schema/v1/`, fixtures under `testdata/`). The package has no
production caller; no MCP tool, REST route, table, migration, Temporal call, flag or Helm value
exists for it.

This change is contract-only (`isolated-model` or `unknown`; none of it is live enforcement). It
adds no REST route, MCP tool, OpenAPI entry, table or migration, Temporal Schedule, worker, flag,
Helm or GitOps release, Support enablement, or downstream issue, and no production importer of
`internal/automation/contract`. It reconciles the merged #950 contract with the owner-reviewed
amendments of mctl-gitops#2452, which were not part of the #948 approval.

## 1. Claim classes

Every normative statement carries one class:

- `proved-source`: true in the cited file today.
- `isolated-model`: proved only by the harness in `internal/automation/contract`; not enforced.
- `assumed`: believed, not verified.
- `unknown`: not known. Also written `UNVERIFIED` for Temporal behaviour.

The research `v0` schemas (spike evidence) have no compatibility promise; a `v0` document sent to
the harness is `automation_invalid` (`isolated-model`).

## 2. Identity

- `AutomationDefinition` is `au_` + UUID and is standing intent only, never an execution
  record (`isolated-model`).
- `AutomationRun` is a read-only view, not a table: for one `occurrence_key`, the WorkItem with
  `external_key = automation:<au_>:<occ>`, its `xr_` chain and its `we_` executions
  (`isolated-model`). Records reused: `wi_`/`we_`/`cs_` (`proved-source`:
  `docs/work-context-contract.md`, `internal/workitems/store.go`), `xr_`
  (`internal/workitems/execution_requests.go`, ADR `docs/adr/0001-queue-execution-request-while-active.md`).
- `occurrence_key = "occ_" + hex(sha256(len-prefixed("mctl.automation.occurrence.v1", au_id,
  trigger_kind, source kind, source parts...)))[:32]`, each field as `uint32be(len) || bytes`
  (`isolated-model`: `occurrence.go`). The definition version is not an input. The source is:
  `at`/`schedule`: the scheduled instant, UTC RFC 3339 with nanoseconds; `event`/`dependency`: the
  authenticated `(producer, event_type, stable_producer_event_id)`, never a per-delivery or
  transport id; manual: the server-bound `(principal, tenant, caller_idempotency_key)`, never a
  client-supplied occurrence id. An empty component is `automation_invalid`.
- Replay key: `idempotency_key = "automation-fire:" + occurrence_key`, never client chosen.
- Overlapping occurrences get different `wi_` ids; each item keeps at most one open `we_`
  (`proved-source`: `internal/workitems`).
- Claiming an occurrence again with an identical binding returns the original `wi_` and admitted
  version with `replayed: true`; it mints no second `wi_`, reserves no budget again and causes no
  other side effect (`isolated-model`: `claim.go`). Reusing a key with a different binding
  (tenant, `au_` or request hash) is `automation_occurrence_conflict` (409). The code
  `automation_occurrence_duplicate` stays in the vocabulary with its meaning unchanged and is no
  longer emitted for an identical replay.
- The admitted definition version is snapshotted on the claim, separately from the key. The
  `automation-run` view keeps `definition_version` as that admitted version.

### 2.1 Durable occurrence claim (hard gate for `automation-api-store`)

- The claim is unique on `(tenant, au_id, occurrence_key)` and maps to `wi_id`,
  `admitted_version`, `status` (`claimed|bound|closed|tombstoned|failed`) and a request hash
  (`isolated-model`: `ClaimStore`). Two racing claims mint at most one `wi_`; the model is one
  critical section, tested under `-race`.
- An unavailable claim source fails closed with `automation_authority_unavailable` and mints
  nothing.
- When the WorkItem closes or its history is cleaned up, a tombstone stays for at least the source
  replay horizon (default `DefaultTombstoneHorizon`, 30 days; the GitHub webhook redelivery window
  is `unknown`, owner to confirm). A replay inside the horizon returns `replayed: true` and mints
  nothing. After the horizon a replay is a new occurrence.
- Reconciliation of a `claimed` row with no `wi_` (a crash between claim and mint) binds it to an
  existing WorkItem found by `external_key`, or marks it `failed`. It never mints.
- Durable dedupe is `assumed` to be impossible with `external_key` alone: it matches only open
  items (`work_items_tenant_external_key_open`) and child rows cascade on delete
  (`proved-source`: `internal/workitems/store.go`). `automation-api-store` is hard-gated on
  implementing this claim durably. This change does not approve that slice.

## 3. Operations (specified, not registered)

Closed set, future MCP names `mctl_automation_*`, future REST paths
`/api/v1/automations[/{id}[/runs|:pause|:resume|:run]]` (`unknown`: not served; absent from
`internal/openapi/openapi.yaml` on purpose).

| Operation | Request | Response | Errors |
|---|---|---|---|
| `create` | `automation-create-request` | `automation-definition` (`replayed: true` on identical idempotent retry) | invalid, unknown_field, server_owned_field, template_not_allowed, trigger_unsupported, time_ambiguous, support_constraint, idempotency_key_reused, identity_unlinked, policy_drift, budget_exhausted, authority_unavailable |
| `get` | id | definition | not_found |
| `list` | cursor, `limit` 1..100, filters `state`, `template` only | page of definitions + opaque cursor | invalid |
| `update` | `automation-patch` (JSON Merge Patch, `expected_version`) | definition | version_conflict, not_found, plus create errors |
| `pause` / `resume` | `expected_version` | definition | version_conflict, not_found |
| `delete` | `expected_version` | soft delete, state `deleted` | version_conflict, not_found |
| `run` | id, `automation-manual-run-request` (`idempotency_key` only) | `automation-run` | paused, not_found, authority errors |
| `list_runs` | id, cursor, `limit` | `automation-run` page | not_found |

- `at` definitions become `completed` after their fire; Support definitions expire within 24h.
- Runs follow work-item retention; afterwards `get` answers `automation_not_found`.
- Update, pause, resume and delete require `expected_version` (optimistic CAS):
  `automation_version_conflict` (409).
- Create idempotency is scoped by `(authenticated principal, tenant, idempotency_key)`; a repeated
  key with a different body is `automation_idempotency_key_reused` (`isolated-model`).
- `run`: the body is `automation-manual-run-request.v1` with an opaque caller `idempotency_key` and
  no other field. A client-supplied `occurrence_key`, `principal`, `tenant` or `au_id` is
  `automation_server_owned_field`. The same `(principal, tenant, au_id, key)` and body replays
  the same occurrence with `replayed: true`; a different body is
  `automation_idempotency_key_reused`; another principal, tenant or `au_` derives a different
  occurrence. Execution is refused with `automation_trigger_unsupported` while manual runs are
  not gated on (`ManualRunEnabled = false`, `isolated-model`: `manual.go`).

## 4. Field ownership

- Client-writable: `schema_version`, `idempotency_key`, `name`, `template_id`, `params`, `trigger`,
  `policies`, `ttl_seconds`, `max_fires`, `auth_ref`, `requested_capabilities`, `delegate`,
  `impersonate_owner` (the last three exist only so they can be refused for Support), and
  `expected_version` on patch.
- Server-owned (rejected as `automation_server_owned_field` before the generic unknown-field
  rule): `id`, `tenant`, `owner_principal`, `created_by`, `actor`, `surface`, `origin_client_id`,
  `version`, `state`, `lifecycle`, `provenance`, `created_at`, `updated_at`, `template_binding`,
  `capability`, `task_queue`, `workflow_type`, `namespace`, `signal`. They are set from
  `auth.User` and the resolved link, never from the body (`isolated-model`).
- Derived: `sync_state`, `sync_failure_reason`, `policy_version`, run view fields.

## 5. Templates (`templates/v1`)

Closed server-side registry (`LookupTemplate`) mapping `template_id` to capability, agent scope, queue, workflow,
allowed triggers and side effects (`isolated-model`: `templates.go`; queue and workflow names are
placeholders). A client never supplies them. Temporal's task queue is fixed server-side
(`proved-source`: `internal/temporalclient/client.go`).

- `reminder.v1`: `{text <= 2 KiB}`; one side effect `notify.surface`.
- `support.diagnostic-followup.v1`: `{question_ref}`; `support` scope; no write side effect.
- The registry is separate from the enabled allowlist (`TemplateEnabled`): registration enables
  nothing. Only `reminder.v1` with `at` is enabled (`isolated-model`: `templates.go`).
- An unknown template is `automation_template_not_allowed`.

## 6. Triggers and policies

- Kinds: `at`, `schedule`, `event`, `dependency`. MVP gate (on the template and kind pair): `reminder.v1` with `at` only; `support.diagnostic-followup.v1` is not yet enabled and yields `automation_trigger_unsupported`. The
  others are schema-valid but `automation_trigger_unsupported`, as is any `event` naming
  `check_run` or `workflow_run` (no verified producer: `docs/github-events-producer.md` subscribes
  to `pull_request` and `pull_request_review` only, `proved-source`).
- `at` is an RFC 3339 `instant`, or `local` wall time + IANA `zone` + `dst_gap`
  (`shift_forward`|`reject`) + `dst_fold` (`earlier`|`later`|`reject`). `reject` on a gap or fold
  is `automation_time_ambiguous`; an unknown, offset-only or numeric GMT-family zone (`Etc/GMT+2`, `Etc/GMT-14`, `Etc/GMT0`, `GMT0`, `GMT+0`) is `automation_invalid`; `UTC`, `Etc/UTC`, `GMT`, `Etc/GMT` and named zones stay accepted
  (`isolated-model`: `trigger.go`; `time/tzdata` embedded).
- Policies, closed enums: overlap `skip|buffer_one|allow_all`; catch-up `none|latest_only` with a
  window of at most 86400s; fanout `single`; cancellation `cancel_open_runs|let_open_runs_finish`.
- `UNVERIFIED` Temporal behaviour the design relies on: overlap-policy mapping of Schedules;
  catch-up window behaviour after a namespace outage; pause/update atomicity relative to an
  in-flight action; schedule-ID uniqueness after deletion; whether Schedules are enabled in the
  deployed namespace. No Schedule API is used in the repo today (`proved-source`).

## 7. Authority

- Principal resolution: Claude/ChatGPT callers are direct OAuth principals with `origin_client_id`
  (`assumed`, owner to confirm: `surfaceid.IsSurface` knows only `telegram` and `portal`,
  `proved-source: internal/surfaceid/store.go`). Telegram uses a live `SurfaceIdentityLink`
  (`surfaceid.Store.Resolve`) plus an opaque `install_ref` whose meaning is `unknown` (no
  `AssistantInstall` type exists here).
- Unknown, unlinked, expired or revoked identity, or surface/tenant mismatch:
  `automation_identity_unlinked` (403), before any resource lookup, for every existence, owner and
  tenant combination. No default owner, ever.
- Cross-owner, cross-tenant and owner-change attempts: `automation_not_found` (404), with a
  byte-identical body to a nonexistent definition (no existence oracle; `isolated-model`).
- `created_by` is distinct from any delegate actor; a delegate is selected only through an
  existing grant (`proved-source`: `internal/delegation/delegation.go`). Audit attribution uses
  `audit.Entry` and `work_item_events.request_id`.
- Checkpoints (`isolated-model`: `authority.go`, `Decide`): (a) create/update; (b) fire time,
  before the per-fire `wi_`; (c) immediately before each externally observable side effect. Each
  re-resolves identity, install revision, tenant membership, policy version and budget from live
  sources. Order of refusal: authority unavailable (503), identity (403), not found (404), policy
  drift, budget, approval.
- Any unreadable source is `automation_authority_unavailable`. Unknown is never allowed.
- Pinned policy version differing from live: `automation_policy_drift`. Budget (per run, per day,
  per tenant) exceeded: `automation_budget_exhausted`, status 409 (decision).
- Usage authority is `unknown`. Commerce (`internal/commerce/budget.go`: payer account,
  `monthly_limit_minor`, `per_request_max_minor`) is a payer/payment limit, distinct from
  inference/FinOps usage metering with per-run, per-day and per-tenant ceilings
  (`proved-source`). While the usage authority is unknown, or is only Commerce payment, `Decide`
  denies with `automation_authority_unavailable` whatever the headroom (`isolated-model`:
  `UsageAuthority`). Reservation, settlement and release are idempotent per occurrence key
  (`assumed`: contract text only, no implementation).
- A schedule, an automation's creation, or an `auth_ref` is never human approval. An occurrence
  that needs approval requests a fresh `aar_` for its own `we_`; an `aar_` is single-use and bound
  to one execution (`proved-source`: `internal/workitems/action_approvals.go`). Foreign or
  schedule-as-approval: `automation_approval_not_reusable`; missing: `automation_approval_required`.
  `Decide` is not wired to `governance.Revalidate`.

## 8. Support constraints

`support.diagnostic-followup.v1` requires the tenant owner's authorization, exactly one tenant,
the read-only `support` scope (`proved-source`: `internal/auth/agent_scope.go`,
`docs/support-agent-scope.md`), TTL <= 24h and at most 3 fires. A delegated actor, an impersonated
owner, a write capability or an `auth_ref` without independent live authorization is refused.
Violations: `automation_support_constraint` (`isolated-model`: `support.go`).

- The template stays registered and schema-valid but absent from the enabled allowlist, so it is
  refused with `automation_trigger_unsupported` until separately authorized.
- A definition TTL of up to 24h never extends a support run token past
  `AgentScopeSupport.MaxTTL` (1h) (`proved-source`: `internal/auth/agent_scope.go`;
  `SupportTokenMaxTTL`).
- A Support fire requires all of: live, independently verified tenant-owner consent; a token
  freshly minted for this fire through a separately approved path, unexpired, TTL at most 1h, not
  self-minted by an agent or service; and no authorization from `auth_ref` presence alone.
  Otherwise `automation_support_constraint` (`isolated-model`: `CheckSupportFire`).
- mctl-api#901 is not assumed to be approved (`unknown`).

## 9. Transport and failure

- `sync_state`: `pending` (desired not yet observed in Temporal), `applied` (observed equals
  desired), `failed` (typed reason after refusal or exhausted retries). Desired vs observed is
  reconciled by a later slice.
- Orphan rule: a Temporal schedule without a live `au_` is deleted, never adopted.
- Dedupe by `occurrence_key`; exponential backoff with a cap. Telegram delivery outcome
  (`delivered`, `undeliverable`, `unknown`) is a run-view field and never re-fires an occurrence.
- Event ingress: signed producer with server-side tenant hydration over the HMAC-verified webhook
  outbox (`docs/github-events-producer.md`), replay key `(subscriber au_, producer, event_type, stable producer event id)`; a per-delivery or transport id is never part of the key (`isolated-model`: `EventSource`).

## 10. Versioning, privacy

- `automation-error.v1` codes are only added; meanings never change. Vocabulary and statuses are in
  `internal/automation/contract/schema.go` and `automation-error.schema.json`.
- Reminder text is at most 2 KiB, checked with `internal/secretscan` (refused on match) and never
  copied into audit detail.

## 11. Crosswalk

| Record | Owner | mctl-agents | mctl-telegram | mctl-support |
|---|---|---|---|---|
| `wi_`, `xr_`, `we_`, `cs_` | mctl-api | consumes | consumes | consumes |
| `aar_` | mctl-api | consumes | consumes | consumes |
| `sil_` | mctl-api; created by the surface's redeem | | redeems | |
| budget | mctl-api commerce | | | |

No consumer writes `au_`, `wi_`, `xr_`, `we_`, `aar_` or budget rows directly, or decides an `aar_`
for its own occurrence.

## 12. Proposed follow-up slices (owner review only, not filed)

1. `automation-api-store`: `au_` table and CRUD behind a flag. Hard-gated on implementing the
   durable occurrence claim of section 2.1. This change does not approve this slice.
2. `automation-temporal-reconciler`: needs the `UNVERIFIED` list resolved first.
3. `automation-reminder-delivery` (mctl-telegram).
4. `automation-support-followup` (mctl-support).
5. `automation-event-ingress`.

Each starts only after this contract is accepted and ships behind its own rollout checkpoint.

## Open questions

- Tombstone horizon: the source replay horizon (GitHub webhook redelivery window) is `unknown`;
  the owner confirms the 30-day default (section 2.1).
- Usage-metering authority for per-run, per-day and per-tenant ceilings (`unknown`, section 7).
- Whether to tighten the `instant` schema to strict RFC 3339: Go accepts a comma decimal separator
  and more than 9 fractional digits (truncated); this is only tested, not changed.
- Representation of the Telegram AssistantInstall (`install_ref`).
- Claude and ChatGPT as direct OAuth principals without a `SurfaceIdentityLink`.
- The `v0` spike schemas in mctlhq/.github were not readable when this was written; diff against
  `docs/spikes/automation-control-plane/schemas` before writing any migration note.
