# Work-context contract (`workitem/v1`)

Status: **design accepted, not yet implemented**. This document is the
canonical answer to [issue #227](https://github.com/mctlhq/mctl-api/issues/227)
("architecture: define canonical work/context ownership model across
surfaces"). It describes the target shape of a new `WorkItem` resource in
mctl-api. No code in this repository implements it yet — see "Implementation
status" at the bottom for what exists today and what is tracked as follow-up
work.

## Why this document exists

mctl has several interaction surfaces — Telegram (`mctl-telegram`),
ChatGPT/Claude over the MCP endpoint (`POST /mcp`), the CLI/REST API, and the
web portal — but no resource that durably owns "the piece of work a human
asked for". Today that state is scattered across engine-owned records that
were never meant to answer that question:

- `agent_executions` (`internal/agentregistry/store.go`) — one row per
  DevLoopWorkflow agent step. `validPhase` only accepts terminal phases
  (`Succeeded`, `Failed`, `Error`), it has no actor/owner column, and reads
  are admin-only. It is a post-hoc step log, not resumable work state.
- `audit.Entry` (`internal/audit/logger.go`) — an append-only action log
  keyed on `WorkflowName`. It answers "who did what", not "what is in flight
  for whom".
- `alerts.Alert` (`internal/alerts/types.go`) — the only tenant-scoped
  record with a real lifecycle (`open`/`analyzing`/`fix_proposed`/
  `acknowledged`/`resolved`/`suppressed`, plus the virtual `active` filter),
  but it is incident-shaped (`Severity`, `Fingerprint`,
  `Source: alertmanager|polling|github_webhook`). Reusing it would conflate
  "something broke" with "a human asked for work".
- The live Temporal `DevLoopWorkflow`, reachable only through
  `GET /api/v1/agents/dev-loop/{workflow_id}`
  (`internal/api/handlers_dev_loop.go`). Its own doc comment states it
  "does not distinguish which step a Running execution is on" and 404s once
  Temporal retention lapses. It cannot be a source of truth for durable work
  state.

Without a canonical owner, every surface is forced to keep this state
locally — exactly the parallel conversation database the platform roadmap
wants to avoid. This document defines the rule instead: **surfaces are
adapters/views. They may hold rendering and transcript state, but durable
work state, lifecycle, identity/access policy and correlation IDs live in
mctl-api**, behind the versioned contract below.

## Ownership model

- mctl-api owns a new `WorkItem` resource (new `internal/workitems` package,
  its own PostgreSQL-backed store) representing one piece of work a human
  asked for, from creation through a terminal state.
- Execution engines (Temporal, Argo) keep owning execution detail.
  `WorkItem` never copies engine state; it stores only a correlation
  reference `(engine, engine_ref)` to it.
- Surfaces (Telegram, ChatGPT/MCP, CLI, portal) are adapters. They may cache
  rendering state, transcripts, typing indicators, scroll position and retry
  buffers locally, but none of that is part of the durable contract, and
  none of it is accepted as a substitute for a `WorkItem`.
- `mctl-agents` orchestration attaches an execution and appends immutable
  `ContextSnapshot` records to a work item so "which run produced this, and
  what context did it see" survives Argo's TTL garbage collection
  (`ttlStrategy.secondsAfterCompletion`).

## ID scheme

| Prefix | Resource                          | Example                    |
|--------|------------------------------------|-----------------------------|
| `wi_`  | `WorkItem`                         | `wi_5c8e...`                |
| `we_`  | `WorkItemExecution`                | `we_9a01...`                |
| `cs_`  | `ContextSnapshot`                  | `cs_1f2b...`                |

IDs are `<prefix><uuid>` using the already-vendored `github.com/google/uuid`,
following the same shape as other mctl-api-minted IDs.

Correlation, not foreign keys, is how a `WorkItem` relates to engine and
audit state:

- `work_item_executions.(engine, engine_ref)` is joinable — by value, not by
  a database FK — to `agent_executions.temporal_workflow_id` /
  `agent_executions.argo_workflow_name`, and to `audit.Entry.WorkflowName`.
  For example `("temporal", "dev-loop-mctlhq-mctl-api-227")` or
  `("argo", "<argo_workflow_name>")`.
- `work_item_events.request_id` is the existing chi request ID surfaced by
  `internal/api/clientmeta.go` and persisted as `audit_events.request_id`
  (`internal/audit/postgres.go`), which makes work-item history and the
  audit log joinable without inventing a second correlation mechanism.

No FK is used across stores deliberately: `agent_executions` is itself
intentionally unconstrained (see the comment above
`agent_executions` in `internal/agentregistry/store.go`) and the two stores
may live in different databases.

## Resource model

- **`WorkItem`** — `id` (`wi_...`), `tenant`, `owner_principal`,
  `visibility` (`tenant` | `private`), `origin_surface`, `title`,
  `external_key`, `state`, `waiting_reason`, `superseded_by`,
  `state_version`, `created_by`, `created_at`, `updated_at`,
  `completed_at`, `schema_version` (`workitem/v1`).
- **`WorkItemEvent`** — append-only lifecycle log entry: `kind`
  (`created` | `state_changed` | `resumed` | `intent_appended` |
  `execution_attached` | `approval_requested` | `approval_decided` |
  `surface_linked`), `from_state`, `to_state`, `actor_principal`, `surface`,
  `request_id`, `detail`, `created_at`. Unique per `(work_item_id, seq)`.
- **`WorkItemIntent`** — a bounded, normalized statement of what the user
  asked for: `actor_principal`, `surface`, `text` (max 8 KiB), `params`,
  `created_at`. Never a full chat transcript.
- **`WorkItemExecution`** — `id` (`we_...`), `engine` (`temporal` | `argo`),
  `engine_ref`, `attempt`, `resumed_from_execution_id`, `phase`
  (`Pending` | `Running` | `Succeeded` | `Failed` | `Error`), `started_at`,
  `ended_at`. At most one non-terminal execution per work item.
- **`ContextSnapshot`** — `id` (`cs_...`), `execution_id`, `seq` (unique per
  `(work_item_id, execution_id)`), `snapshot_json` (opaque JSONB carrying
  its own inner `schema_version` so `mctl-agents` can evolve the payload
  without an mctl-api release), `content_hash`, `produced_by`,
  `created_at`. Append-only: no store method or API route ever updates or
  deletes a snapshot.
- **`WorkItemApproval`** — `kind`, `state`
  (`pending` | `granted` | `denied` | `expired`), `signal_engine`,
  `signal_ref`, `signal_name`, `requested_by`, `requested_at`, `decided_by`,
  `decided_at`, `reason`, `expires_at`. At most one pending approval per
  work item.
- **`SurfaceRef`** — correlates a work item to a surface-native
  conversation: `surface`, `external_id` (chat/thread/run identifier needed
  for reply routing), `actor_external_id`, `first_seen_at`, `last_seen_at`.
  Unique per `(work_item_id, surface, external_id)`.
- **`SurfaceIdentityLink`** — the only way a surface-native ID (a Telegram
  user ID, an MCP client ID) resolves to an mctl-api principal: `surface`,
  `external_id`, `principal`, `linked_at`, `linked_by`. Created only by an
  authenticated call from that principal.

Every payload returned by the work-item API carries
`"schema_version": "workitem/v1"`.

## Lifecycle

States: `active`, `waiting` (with `waiting_reason` = `input` | `approval`),
and terminal `completed`, `superseded`, `archived`.

- A work item is created in state `active`.
- While non-terminal (`active` or `waiting`), a work item accepts intent
  appends, execution attachments, snapshot appends, approval decisions and
  resume requests.
- A runtime step that needs human input or approval moves the item to
  `waiting` and records a `waiting_reason` of `input` or `approval`.
- Resuming moves a `waiting` item back to `active` and records a `resumed`
  lifecycle event. `resumed` is **not** a persisted state — it would be
  indistinguishable from `active` to every consumer while doubling the
  transition table, so it only ever appears as a `WorkItemEvent.kind`.
- Finishing, replacing or retiring a work item moves it to exactly one
  terminal state: `completed`, `superseded` or `archived`.
- A transition not in the transition table below is rejected with HTTP 409
  and leaves the stored state unchanged.
- Listing without an explicit state filter defaults to the virtual filter
  `open` (any non-terminal state), mirroring `alerts.StatusActive`
  (`internal/alerts/types.go`).

### Transition table

| From      | Event/action        | To          | Notes                                   |
|-----------|----------------------|-------------|------------------------------------------|
| (none)    | create                | `active`    | initial state                             |
| `active`  | wait(`input`)         | `waiting`   | sets `waiting_reason = input`             |
| `active`  | wait(`approval`)      | `waiting`   | sets `waiting_reason = approval`          |
| `waiting` | resume                | `active`    | writes a `resumed` event, clears reason   |
| `active`  | complete              | `completed` | terminal                                  |
| `waiting` | complete              | `completed` | terminal                                  |
| `active`  | supersede             | `superseded`| terminal, sets `superseded_by`            |
| `waiting` | supersede             | `superseded`| terminal, sets `superseded_by`            |
| `active`  | archive               | `archived`  | terminal                                  |
| `waiting` | archive               | `archived`  | terminal                                  |

Any transition out of a terminal state, or any pair not listed above, is
rejected with HTTP 409. This table is intended to live as a single exported
map in `internal/workitems/types.go` and be the one enforcement point for
lifecycle rules — no handler or caller re-implements it.

## Durable vs. surface-local state

Durable (mctl-api owns it):

- lifecycle state, owner/tenant/visibility
- bounded, normalized intents (max 8 KiB of text plus structured params)
- execution and snapshot correlations
- approvals
- surface references
- event history

Surface-local (the adapter owns it, mctl-api never stores it):

- raw chat transcripts
- message formatting, typing indicators, scroll position
- per-message IDs beyond the `(surface, external_id)` correlation tuple
- retry buffers

Enforcement: intent text is capped at 8 KiB and is required to pass through
`secretscan.Scan` (`internal/secretscan/secretscan.go`) before insert — the
same gate `handlers_openclaw.go`, `handlers_openclaw_identity.go` and
`handlers_platform_skills.go` already apply to other free-text input — so a
request with a matching secret pattern is rejected with HTTP 400 and never
persisted. This is what keeps the contract from quietly becoming a
transcript sink.

## Identity and authorization

- The acting principal is always derived from `auth.UserFromContext`
  (`internal/auth/oidc.go`) — GitHub PAT, Dex JWT, OAuth JWT, or the static
  service principal (`auth.User.IsService()`). A caller-supplied actor field
  is never accepted as the acting principal.
- Authorization is re-evaluated on every request via `user.IsAdmin()` and
  `user.HasTenantAccess(tenant)`, plus the item's `visibility`. Nothing is
  cached from creation time: because each surface transition is a fresh
  authenticated HTTP request through the existing auth middleware,
  re-evaluation is structural rather than a rule someone has to remember.
- `visibility: private` restricts non-admin access to the owning principal.
  `visibility: tenant` allows every principal with access to the owning
  tenant (`user.HasTenantAccess`).
- A surface-native identity (a Telegram user ID, an MCP client ID) resolves
  to a principal only through an explicit `SurfaceIdentityLink` created by
  an authenticated call from that principal. A deployment allowlist such as
  `telegram_owner_ids` (`internal/api/handlers_openclaw.go`,
  `parseTelegramOwnerIDs`) remains exactly what it is today — an allowlist
  for who mctl-managed OpenClaw responds to — and is never treated as proof
  of identity for work-item attribution.
- The service principal (`auth.User.IsService()`) may attach executions,
  snapshots and approval requests, but is forbidden from recording an
  approval *decision* on a human's behalf.

## Approvals

`WorkItemApproval` is the durable request/record; the runtime approval gate
stays where it already lives, inside the owning engine (for example
Temporal's `DevLoopWorkflow`). The work-item approval row never bypasses
that gate.

The decision rule mirrors `ApproveDevLoopWorkflow`
(`internal/api/handlers_dev_loop.go`), which already had to fix exactly this
class of bug (gitops#986: an `approver` field that only *defaulted* to the
caller's identity let one admin record an approval under a colleague's
name):

- the decider is taken from the authenticated caller only;
- a request body that carries an explicit, different decider is rejected
  with HTTP 400, not silently ignored;
- an approval is marked `granted` only after the engine signal (for example
  `DevLoopClient.SignalApprove`) succeeds; a signal failure leaves the
  approval `pending` and returns HTTP 502, the same mapping
  `ApproveDevLoopWorkflow` uses;
- denials and expiries never signal the engine.

## Idempotency and concurrency

The repository has no existing HTTP-level idempotency or concurrency
convention (no `ETag`, `If-Match` or `Idempotency-Key` anywhere today), so
this contract introduces one, applied uniformly across every mutating
work-item route:

1. **`Idempotency-Key`** (request header, or an `idempotency_key` body
   field) deduplicates a mutating request: per `(tenant, idempotency_key)`
   for create, per `(work_item_id, idempotency_key)` for intents,
   executions, snapshots, approvals and resume. A replay returns the
   already-created entity with HTTP 200 instead of creating a duplicate —
   the same idempotent-create-returns-existing shape `internal/domains`'
   `Store.Create` already uses.
2. **Optimistic concurrency** via `expected_state_version` in the request
   body (deliberately a body field, not an `If-Match` header: the repo has
   no ETag plumbing, and MCP tool arguments are flat strings, which would
   make a header-only contract unusable from a future MCP surface). Every
   state-changing route requires it, increments `state_version` by exactly
   one on success, and returns HTTP 409 with the current state and version
   when the supplied value does not match the stored one.
3. **Store-level serialization.** Every mutation on one work item runs
   inside a single transaction guarded by
   `pg_advisory_xact_lock(hashtext('workitem:' || id))` — the same pattern
   `agentregistry.promote` (`internal/agentregistry/store.go`) already uses
   to close exactly this class of race. Two surfaces submitting the same
   logical action concurrently always resolve to exactly one taking effect;
   the other observes either the idempotent replay or a 409.

Cross-surface open-work dedupe uses the same shape: if a create request
carries an `external_key` (for example a GitHub issue URL) that already
identifies a non-terminal work item in the same tenant, the system returns
that existing work item instead of creating a second one. A partial unique
index on `(tenant, external_key)` scoped to non-terminal states enforces
this, the same pattern `alerts_tenant_fingerprint_open` already uses in
`internal/alerts/store.go`.

## REST surface (`workitem/v1`)

Mounted under `/api/v1/work-items` inside the authenticated group. Mutating
routes join the existing write-side rate-limit group (20/min) alongside
`/operations/{name}/execute` and the dev-loop routes; reads stay outside it.

| Method & path                                                        | Purpose                                            |
|------------------------------------------------------------------------|-----------------------------------------------------|
| `POST /api/v1/work-items`                                              | open a work item (idempotent, dedupes on `external_key`) |
| `GET /api/v1/work-items`                                               | list, filtered by tenant/state/owner, default `open` |
| `GET /api/v1/work-items/{id}`                                          | current state: item, latest execution, pending approval, latest snapshot pointers, `state_version` |
| `PATCH /api/v1/work-items/{id}`                                        | state transition (`complete`, `archive`, `supersede`, `wait`); requires `expected_state_version` |
| `POST /api/v1/work-items/{id}/intents`                                 | append a user intent |
| `GET|POST /api/v1/work-items/{id}/executions`                          | list / attach-correlate an execution |
| `GET|POST /api/v1/work-items/{id}/executions/{execution_id}/snapshots` | list / append a context snapshot |
| `POST /api/v1/work-items/{id}/resume`                                  | start a new execution continuing a prior one |
| `GET /api/v1/work-items/{id}/approvals`                                | list approvals |
| `POST /api/v1/work-items/{id}/approvals/{approval_id}/decision`        | decide a pending approval |
| `POST /api/v1/work-items/{id}/surface-refs`                            | correlate a surface reference |
| `GET /api/v1/work-items/{id}/events`                                   | lifecycle history |
| `POST /api/v1/work-items/surface-identities`                           | link the caller's principal to a surface-native ID |

If the work-items store is not configured (`WORK_ITEMS_DB_URL` and
`AUDIT_DB_URL` both unset, `WORK_ITEMS_DISABLED` set, or store init failed),
every `/api/v1/work-items*` route answers HTTP 503 and a startup warning
names those routes — the same `nil`-store convention every other optional
store in `internal/api/router.go` already follows.

## Configuration (planned)

| Env var                             | Default | Purpose                                              |
|--------------------------------------|---------|-------------------------------------------------------|
| `WORK_ITEMS_DB_URL`                  | (falls back to `AUDIT_DB_URL`) | Postgres connection string for the work-items store |
| `WORK_ITEMS_DISABLED`                | unset   | kill switch; leaves the store `nil` without disabling the shared `AUDIT_DB_URL` fallback other stores depend on |
| `WORKITEM_SURFACE_RETENTION_DAYS`    | `90`    | age after which intent text and surface refs are purged, keeping the item and its correlations |
| `WORKITEM_RETENTION_DAYS`            | `365`   | age after which terminal work items are purged entirely |

## Retention and privacy

- Surface references persist only surface kind, the external IDs needed for
  reply routing, the linked principal, and first/last-seen timestamps —
  never raw transcript content.
- Audit entries for work-item operations include `work_item_id` in
  `audit.Entry.Parameters` and never include intent text or surface
  external IDs.
- A retention sweeper deletes intent text and surface references older than
  `WORKITEM_SURFACE_RETENTION_DAYS` while retaining the work item, its
  lifecycle history and its execution/snapshot correlations, and deletes
  terminal work items older than `WORKITEM_RETENTION_DAYS`.

## Versioning

Every work-item payload carries `"schema_version": "workitem/v1"`. Breaking
changes to the contract ship as a new version label, never as a silent
change to `workitem/v1`. When the contract changes, this document and
`internal/openapi/openapi.yaml` are updated together.

## Out of scope

- The Telegram, ChatGPT, CLI or portal adapters themselves. This contract
  defines what adapters read and write; building them is separate work.
- MCP tool wrappers (`mctl_*` tools) for work items. Adding tools forces
  coordinated updates to `internal/mcp/server_test.go`
  (`TestNewMCPServer_ToolCount`) and `internal/mcp/annotations_test.go`
  (`recordedHints`); the REST + OpenAPI contract is what adapters and
  `mctl-agents` need first, so MCP tools are explicit follow-up work.
- Synchronizing messages between surfaces, push/fan-out delivery, or any
  real-time subscription mechanism.
- Changing Temporal `DevLoopWorkflow` or Argo workflow semantics, replacing
  the gitops `.status.yaml` proposal flow, or moving the runtime approval
  gate out of the engine.
- Migrating existing `agent_executions`, `alerts` or `audit` rows into work
  items. Correlation is forward-only.
- Storing model conversation context or prompt history as a first-class
  resource.

## Implementation status

This document currently describes an **accepted design, not yet built**.
None of `internal/workitems`, the REST handlers, the `WorkItemStore` wiring
in `cmd/api/main.go`, the retention sweeper, or the `internal/openapi/openapi.yaml`
schemas above exist in this repository yet. Landing them is tracked as
follow-up proposals against
`platform-gitops/agents-state/mctl-api/proposals/issue-227-architecture-work-context-define-canonic/`,
split roughly along these lines so each PR is independently reviewable and
buildable:

1. `internal/workitems/types.go` and `internal/workitems/store.go` — the
   schema, the transition map, sentinel errors, and store-level CRUD/
   lifecycle/idempotency/concurrency methods, with store-level tests
   (Postgres-backed, skipped without `TEST_DATABASE_URL`, matching the
   convention in `internal/alerts/store_test.go` and
   `internal/domains/store_test.go`). No REST surface yet.
2. `internal/api/handlers_work_items.go` plus route registration in
   `internal/api/router.go`, the authorization matrix, and audit
   integration.
3. Approval projection to `DevLoopClient.SignalApprove`, the retention
   sweeper goroutine, and the `cmd/api/main.go` wiring
   (`WORK_ITEMS_DB_URL`, `WORK_ITEMS_DISABLED`, the two retention env
   vars).
4. `internal/openapi/openapi.yaml` schemas and paths, `README.md` and
   `.env.example` updates.
5. A follow-up issue for the MCP tool wrappers and the first surface
   adapter (`mctl-telegram`), filed once step 2 lands.
