# Work-context contract (`workitem/v1`)

Status: **design accepted; steps 1, 2 and 4 implemented (mctl-api#349)**. This document is the
canonical answer to [issue #227](https://github.com/mctlhq/mctl-api/issues/227)
("architecture: define canonical work/context ownership model across
surfaces"). It describes the shape of the `WorkItem` resource in mctl-api;
see "Implementation status" at the bottom for what exists today and what is
tracked as follow-up work.

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
  `surface_linked` | `snapshot_sealed` | `execution_requested` |
  `execution_request_claimed` | `execution_request_fulfilled` |
  `execution_request_rejected`), `from_state`, `to_state`, `actor_principal`, `surface`,
  `request_id`, `detail`, `created_at`. Unique per `(work_item_id, seq)`.
- **`WorkItemIntent`** — a bounded, normalized statement of what the user
  asked for: `actor_principal`, `surface`, `text` (max 8 KiB), `params`,
  `created_at`. Never a full chat transcript.
- **`WorkItemExecution`** — `id` (`we_...`), `engine` (`temporal` | `argo`),
  `engine_ref`, `attempt`, `resumed_from_execution_id`, `phase`
  (`Pending` | `Running` | `Succeeded` | `Failed` | `Error`), `started_at`,
  `ended_at`. At most one non-terminal execution per work item.
- **`ContextSnapshot`** — one sealed snapshot per execution
  (mctl-agents#431): `id` (`cs_` + 32 hex of sha256 over the execution id
  and `content_hash`, so byte-identical snapshots of two executions stay
  two snapshots), `execution_id` (unique), `execution_sequence` (must equal
  the execution's `attempt`; validation only, never the identity), the
  canonical bytes (opaque to mctl-api, a JSON object carrying its own inner
  `schema_version`, at most 1 MiB, served as `canonical_b64`),
  `content_hash` (`sha256:<hex>` of those bytes, verified on every write
  and read), `strategy`, `strategy_version`, `prior_execution_id` /
  `prior_snapshot_id` (continuity; must exist on this item and precede this
  execution; the prior execution is stored resolved through the prior
  snapshot), `produced_by`, `created_at`. Insert-only: no store method or
  API route updates a snapshot, and a trigger refuses an `UPDATE` of the
  table. The retry identity is the execution id: the same bytes and claims
  (strategy, strategy version, prior references) again return the stored
  snapshot; different bytes or claims are `snapshot_divergence` (409). A
  producer must therefore keep a retry's claims stable — mctl-agents folds
  its strategy and version into the canonical bytes, so a retry from a
  newer build is a different snapshot only if it really built a different
  one. A new execution — created by the work-item layer, e.g. a resume —
  seals its own snapshot; a human-input signal continues the current
  execution and seals nothing new. Only a service principal seals; every
  viewer of the work item may read the bytes, deliberately, since they are
  the context of that viewer's own work. A listing carries metadata only;
  the bytes come from a single-snapshot read.
- **`ExecutionRequest`** — a durable request that the item run
  (mctl-api#368): `id` (`xr_...`), `kind` (`start` | `resume`),
  `expected_state_version`, optional `resumed_from_execution_id` and
  `intent_id`, `surface`, `requested_by` (from authentication: the linked
  human on relay), `acting_principal`, `idempotency_key`, `state`
  (`pending` → `claimed` → `fulfilled` | `rejected`), `claimed_by`,
  `claimed_at`, `claim_expires_at`, `execution_id` (set only by
  fulfilment), `reason`, `created_at`, `updated_at`, `closed_at`. The
  owner rule it encodes: **a surface requests execution; a surface does not
  declare execution identity.** The surface supplies the item, the
  expected version, the intent (by id), its provenance and idempotency;
  the execution platform (a service principal) supplies `execution_id`,
  `engine` and `engine_ref` by claiming and fulfilling the request. At
  most one open (`pending` or `claimed`) request per item.
- **`WorkItemApproval`** — `kind`, `state`
  (`pending` | `granted` | `denied` | `expired`), `signal_engine`,
  `signal_ref`, `signal_name`, `requested_by`, `requested_at`, `decided_by`,
  `decided_at`, `reason`, `expires_at`. At most one pending approval per
  work item.
- **`ActionApprovalRequest`** (`actionapproval/v1`, mctl-api#366) — a
  sibling of `WorkItemApproval`, not a variant: the durable, single-use
  human approval of ONE hashed side effect of one runtime execution
  (mctl-agents#197/#198), in the same store. An execution may hold many.
  `id` (`aar_...`) binds `execution_id`, `action_kind`, `target`,
  `args_digest`, `policy_rule_id`, `policy_version`, optional
  `artifact_hash` and `work_item_id`; `intent_hash` is `sha256:<hex>` over
  the line `mctl-action-intent/v1` followed by one line
  `<field>:<byte length>:<value>` per bound field in that order, computed by
  the server (a client-sent hash must match). State `pending` →
  `approved` | `denied`, then `approved` → `consumed`; a pending or approved
  request past `expires_at` (at most 7 days ahead) reads as `expired`, and a
  decision or consume on it is refused. Create and consume: the requesting
  service principal only, `requested_by` from authentication, idempotent per
  `(requested_by, idempotency_key)` (a different intent under the same key
  is 409 `approval_idempotency_conflict`). A replayed key returns the stored
  request whatever its state, so once it is `expired`, `denied` or
  `consumed` that key can never open a new request: a client must vary the
  key per attempt (for example the intent plus an attempt counter), never
  derive it from the intent alone. Every bound field and the decision
  `reason` pass the `secretscan.Scan` gate below (400). Decide: a human admin acting
  directly only — never a service, a surface or a relayed request, never
  the requester. Consume is one compare-and-set `UPDATE` (`state='approved'`,
  matching `intent_hash`, unexpired) that records `consumed_at`, so a
  receipt authorizes exactly one side effect. Reads: every request for a
  human admin, its own requests for a service. Create, decision and consume
  are audited (ids and hashes only), and so are refused decisions and
  consumes (`action_approval.decision_refused` /
  `action_approval.consume_refused`, with the typed code). mctl-api is the approval record;
  Temporal only waits on it and re-reads it after a best-effort wake-up.
- **`SurfaceRef`** — correlates a work item to a surface-native
  conversation: `surface`, `external_id` (chat/thread/run identifier needed
  for reply routing), `actor_external_id`, `first_seen_at`, `last_seen_at`.
  Unique per `(work_item_id, surface, external_id)`.
- **`SurfaceIdentityLink`** — the only way a surface-native ID (a Telegram
  user ID, a portal subject) resolves to an mctl-api principal: `surface`,
  `external_id`, `principal`, `created_at`, `expires_at`, `revoked_at`.
  Made by a possession proof that neither side can complete alone: the
  human requests a one-time challenge, and that surface's own principal
  redeems it naming the identity it observed (mctl-api#350, see
  "Surface relay" below).

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

- **Canonical principal id: `prn_<ulid>`** (mctl-api#373). Every
  authenticated caller also carries an opaque, mctl-api-issued principal id
  (`auth.User.PrincipalID()`), resolved from the external identity it proved:
  a numeric GitHub user id, a Dex `(issuer, sub)`, the service principal or a
  surface principal. It is never derived from a login's spelling. Phase 1
  records it next to the existing login strings and authorizes nothing on
  it; phase 2 (mctl-api#377) moves authorization and tenant membership onto
  it. A relayed request also carries the relaying surface's principal
  (`auth.User.ViaPrincipalID()`). See [principals.md](principals.md).
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
   executions, approvals and resume. A replay returns the
   already-created entity with HTTP 200 instead of creating a duplicate —
   the same idempotent-create-returns-existing shape `internal/domains`'
   `Store.Create` already uses. A snapshot needs no key: its execution id
   is its identity, and the same bytes with the same strategy and prior
   references again are the 200 replay; a key sent anyway is 400.
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
`/operations/{name}/execute` and the dev-loop routes; reads stay outside it. The
platform's claim, fulfil and reject routes have their own 120/min group, as
the lifecycle-ownership writes do: the dispatcher polls claim, and on the
shared 20/min budget it would starve the workflow triggers it feeds.

| Method & path                                                        | Purpose                                            |
|------------------------------------------------------------------------|-----------------------------------------------------|
| `POST /api/v1/work-items`                                              | open a work item (idempotent, dedupes on `external_key`) |
| `GET /api/v1/work-items`                                               | list, filtered by tenant/state/owner, default `open` |
| `GET /api/v1/work-items/{id}`                                          | current state: item, latest execution, pending approval, latest snapshot pointers, `state_version` |
| `PATCH /api/v1/work-items/{id}`                                        | state transition (`complete`, `archive`, `supersede`, `wait`); requires `expected_state_version` |
| `POST /api/v1/work-items/{id}/intents`                                 | append a user intent |
| `GET|POST /api/v1/work-items/{id}/executions`                          | list / attach-correlate an execution |
| `GET|POST /api/v1/work-items/{id}/executions/{execution_id}/snapshot`  | read / seal the execution's context snapshot |
| `GET /api/v1/work-items/{id}/snapshots[/{snapshot_id}]`                | list / read sealed snapshots |
| `POST /api/v1/work-items/{id}/resume`                                  | start a new execution continuing a prior one (names the engine run: not a relay route) |
| `GET|POST /api/v1/work-items/{id}/execution-requests`                  | list / request a `start` or `resume` (no engine identity accepted) |
| `GET /api/v1/work-items/{id}/execution-requests/{request_id}`          | read one execution request |
| `POST /api/v1/execution-requests/claim`                                | claim the oldest claimable request under a lease (service only) |
| `POST /api/v1/execution-requests/{request_id}/fulfil`                  | attach the canonical execution for a claimed request (claim holder only) |
| `POST /api/v1/execution-requests/{request_id}/reject`                  | close a claimed request without an execution (claim holder only) |
| `GET /api/v1/work-items/{id}/approvals`                                | list approvals |
| `POST /api/v1/work-items/{id}/approvals/{approval_id}/decision`        | decide a pending approval |
| `POST /api/v1/work-items/{id}/surface-refs`                            | correlate a surface reference |
| `GET|POST /api/v1/action-approvals`                                    | list (`state`, `execution_id`, `limit`) / request an action approval |
| `GET /api/v1/action-approvals/{id}`                                    | read one, with lazy expiry |
| `POST /api/v1/action-approvals/{id}/decision`                          | approve or deny (human admin only) |
| `POST /api/v1/action-approvals/{id}/consume`                           | spend an approved request exactly once |
| `GET /api/v1/work-items/{id}/events`                                   | lifecycle history |

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
  Sealed snapshot bytes embed the context an execution was given (intent
  text included) and cannot be redacted in place (the table refuses
  `UPDATE`), so the sweeper (#353) deletes `work_item_context_snapshots`
  rows on the same schedule as intent text.

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

Built (mctl-api#349):

- `internal/workitems`: schema, the `Transitions` map, sentinel errors, and the
  Postgres store with idempotency, `state_version` concurrency and
  `pg_advisory_xact_lock` serialization (step 1).
- `internal/api/handlers_work_items.go` and the routes above except the ones
  listed below, the authorization matrix and audit (step 2).
- `WORK_ITEMS_DB_URL` / `WORK_ITEMS_DISABLED` wiring in `cmd/api/main.go`,
  `internal/openapi/openapi.yaml`, `README.md` and `.env.example` (step 4, and
  the wiring part of step 3).

### Surface relay (mctl-api#350)

Each surface has its own service principal (`surface:telegram`,
`surface:portal`, tokens `MCTL_SURFACE_*_TOKEN`): non-admin, no tenant,
distinct from `mctl-agent`, and confined to an allowlist of routes. There
is no generic on-behalf-of: relay is opt-in per route.

| Route | Who | |
|---|---|---|
| `POST /api/v1/surface-identities/challenges` | the human (GitHub login) | one-time code, 10 min, bound to the human and the surface; stored hashed |
| `POST /api/v1/surface-identities/redeem` | that surface's principal | `{"code"}` + `X-MCTL-Surface-Actor: <external id>` → link |
| `GET /api/v1/surface-identities`, `POST .../{id}/revoke` | the human, or a human admin | |

On a relay route the surface principal names the end user in
`X-MCTL-Surface-Actor`; mctl-api resolves the verified link for (its own
surface, that id) and runs the handler as the linked human, with its tenant
groups and never admin. An unknown, revoked or expired link, another
surface's link, or a missing header answers 403 (`link_not_found`,
`link_revoked`, `link_expired`, `relay_required`); any other caller sending
the header gets 400. Relay routes: `GET /human-input`,
`GET /human-input/{id}`, `POST /human-input/{id}/response`,
`POST /work-items`, `GET /work-items/{id}`,
`POST /work-items/{id}/intents|surface-refs`,
`GET|POST /work-items/{id}/execution-requests` and
`GET /work-items/{id}/execution-requests/{request_id}`. No relay route
accepts an engine, engine run or execution id: `POST /work-items/{id}/resume`
left the allowlist with mctl-api#368, and a surface asks for a run with an
execution request instead. A relayed request's
`surface` / `origin_surface` is forced to the relaying surface (claiming
another is 400). Both identities are kept: work-item events and audit rows
carry the human as actor and `acting_principal: surface:<name>`.

### Execution requests (mctl-api#368)

**A surface requests execution; a surface does not declare execution
identity.** `internal/workitems/execution_requests.go` and
`internal/api/handlers_execution_requests.go`, in the work-items store and
schema (`work_item_execution_requests`):

| Route | Who | |
|---|---|---|
| `POST /work-items/{id}/execution-requests` | a person directly, or a surface relaying for its linked human; never the service principal (403 `execution_request_requester_forbidden`) | `{kind, expected_state_version, resumed_from_execution_id?, intent_id?, surface?, idempotency_key?}`; `engine`, `engine_ref` or `execution_id` → 400 `execution_identity_not_accepted` |
| `GET /work-items/{id}/execution-requests[/{request_id}]` | whoever can see the item | |
| `POST /execution-requests/claim` | the service principal, directly | `{lease_seconds}` (5–900, default 60) → the request and a fresh `claim_token`, or 204 |
| `POST /execution-requests/{request_id}/fulfil` | the claim holder | `{claim_token, engine, engine_ref}` |
| `POST /execution-requests/{request_id}/reject` | the claim holder | `{claim_token, reason}` (≤ 1 KiB, secret-scanned) |

- Create refuses a stale `expected_state_version` (409
  `state_version_conflict` with the current state), a terminal item (409
  `invalid_transition`), a kind the item cannot take (`start` needs an
  active item that never ran; `resume` needs a waiting item or one that
  ran), a Pending/Running execution (409 `execution_active`), a
  `resumed_from_execution_id` or `intent_id` of another item (404
  `execution_not_found` / `intent_not_found`), and a second open request
  (409 `execution_request_open`, the open one's id in `details`).
  Idempotency is the per-item key bound to the actor, as for every other
  work-item mutation.
- Claim is a compare-and-set under the item's advisory lock: racing
  claimants serialize and one wins. A claim whose lease lapsed is
  claimable again. Each claim mints a `claim_token` (returned by claim
  only, never in a read) that fulfil and reject must present, so a lapsed
  holder is fenced even when the new holder is the same service principal
  (409 `execution_request_not_claimed`).
- Fulfil attaches the execution in the same transaction: `start` with the
  `/executions` rule (a Running execution), `resume` with the `/resume` rule
  and the request's `expected_state_version` and
  `resumed_from_execution_id` (a waiting item becomes active,
  `state_version` rises). An item that moved since is refused with its 409
  and the request stays claimed for the platform to reject. The holder
  repeating the same engine run gets the same execution; another run is 409
  `execution_request_closed`.
- Every transition writes a work-item event (`execution_requested`,
  `execution_request_claimed`, `execution_request_fulfilled`,
  `execution_request_rejected`) and an audit row. On create the actor is
  the human and a relayed call keeps `acting_principal: surface:<name>`;
  claim, fulfil and reject are the service's, with `requested_by` kept.
  Refused claims, fulfils and rejects are audited too. The reject reason
  stays on the request, never in events or audit.
- Not built here: a request TTL (an unclaimed request waits for the
  platform), cancellation by the requester, and the dispatcher that claims
  (mctl-agents#461).

Not built yet, tracked as its own issue (#353 approvals and retention):

- `GET .../approvals`, `POST .../approvals/{approval_id}/decision` and the
  projection to `DevLoopClient.SignalApprove` (step 3).
- `actor_external_id` on a surface reference stays correlation only; the
  relayed subject comes from the link, never from a body field.
- The retention sweeper and `WORKITEM_SURFACE_RETENTION_DAYS` /
  `WORKITEM_RETENTION_DAYS` (step 3).
- MCP tool wrappers and the first surface adapter (step 5).
