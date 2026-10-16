# ADR 009 — Canonical `WorkItem` and the cross-surface state contract

> **Status:** proposed
> **Date:** 2026-09-06
> **Supersedes:** nothing — this is a design document, no code changes
> **Consumers:** `mctlhq/mctl-agents#267` (resume semantics),
> `mctlhq/mctl-telegram#443` (Telegram surface adapter, epic
> `mctlhq/mctl-telegram#517`)

## Context

### Why this ADR is numbered 009, and why it lives in `mctl-api`

`docs/adr/` is where cross-cutting dev-workflow-control-plane architecture
already lives — ADR 005 through 008 are in `mctl-agents/docs/adr/`, and ADR
007 states that placement rule explicitly
(`mctl-agents/docs/adr/007-agent-definition-execution-profile-contract.md:55-58`).
The series is cross-repo by construction: 007 already specifies mctl-api
storage (`ReleaseBinding`) from inside the `mctl-agents` repo. This ADR is
the mirror case — the resource it defines is owned and stored by mctl-api,
so it lands in `mctl-api/docs/adr/` and continues the same number series
rather than restarting at 001. Numbers stay globally unique across the set.

### What already exists

The platform is not starting from nothing. Three pieces of durable
cross-surface machinery are already in production.

**1. An execution ledger keyed by Temporal workflow ID.** `AgentExecution`
(`internal/agentregistry/types.go:98-109`) records one DevLoopWorkflow step's
outcome: agent, environment, resolved version, image ref, target repo, Argo
workflow name, phase. It is written by `mctl-agents`'
`record_execution` activity
(`mctl-agents/orchestrator/temporal/activities/state.py:47-65`) through
`POST /api/v1/agents/executions` (`internal/api/router.go:304-305`), and
stored in `agent_executions` with `UNIQUE (temporal_workflow_id, agent,
argo_workflow_name)` (`internal/agentregistry/store.go:113-130`).

**2. A durable per-issue workflow with a human approval gate.**
`DevLoopWorkflow` (`mctl-agents/orchestrator/temporal/workflows/dev_loop.py:495`)
takes an `IssueRef`, pins an investigator version, and then blocks
indefinitely on `workflow.wait_condition(lambda: self._approved)`
(`dev_loop.py:555`) until the `approve` signal arrives
(`dev_loop.py:515-527`). mctl-api starts it
(`internal/api/handlers_dev_loop.go:69`), signals it
(`handlers_dev_loop.go:149`), and reads its liveness
(`handlers_dev_loop.go:234`).

**3. An identity bridge between mctl-api and Telegram.** `mctl-telegram`
verifies JWTs issued by mctl-api with the shared HMAC secret and maps the
token subject onto a local user row
(`mctl-telegram/internal/auth/sharedhmac/verifier.go:118-148`). Notably it
maps the mctl-api `admins` group to **read-only** Telegram scopes
(`verifier.go:108-114`) — the codebase already refuses to treat authority on
one surface as authority on another.

### What does not exist

- **No `WorkItem` and no `ContextSnapshot`.** A full-tree grep of
  `mctl-agents` finds neither name in first-party code — the only hits are
  vendored (`.venv/`, `.mypy_cache/`). `ContextSnapshot` exists today only as
  an illustrative YAML in the roadmap issue `mctlhq/.github#20`. Every claim
  this ADR makes about snapshots is therefore a contract for something to be
  built, not a description of something running.
- **No durable identity that is not a GitHub issue.** The workflow ID is a
  pure function of the issue URL —
  `dev-loop-{owner}-{repo}-{issue}`
  (`mctl-agents/orchestrator/temporal/issue_ref.py:29-36`), and the URL
  regex accepts `mctlhq` issues only (`issue_ref.py:12`). Work that
  originates in a Telegram thread has nothing to be keyed by.
- **A second execution for the same issue is currently impossible.**
  `StartDevLoopWorkflow` uses `WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE`
  with `WORKFLOW_ID_CONFLICT_POLICY_USE_EXISTING`
  (`internal/temporalclient/client.go:113-118`). That is exactly the
  idempotent-open semantic `mctl-telegram#443` asks for, and simultaneously a
  hard blocker for `mctl-agents#267`: because the ID is derived from the
  issue and reuse is rejected, "execution B resumes the same work" cannot be
  a second `DevLoopWorkflow` under today's ID scheme. §6 addresses this.
- **No surface provenance in the audit trail.** `audit.Entry`
  (`internal/audit/logger.go:26-43`) carries `UserID`, `ClientIP`,
  `UserAgent` and `RequestID`. Which surface a call came from is only
  inferable from a user-agent string.
- **No non-admin path to any of it.** `requireTemporalAdmin`
  (`internal/api/handlers_dev_loop.go:42-58`) gates start, approve and read
  on `user.IsAdmin()`, and `ListAgentRuns` does the same
  (`internal/api/handlers_read.go:255-264`).

### What the surfaces own today

`mctl-telegram` owns a `conversations` table
(`mctl-telegram/internal/db/agent_schema.go:313-330` SQLite,
`:530-547` PostgreSQL) with its own three-value state machine —
`active` / `paused` / `taken_over`
(`mctl-telegram/internal/db/agent_domain.go:36-38`) — a message log with
encrypted bodies (`agent_schema.go:331-339`), and an `agent_actions`
approval table whose live approvals already dedupe on
`(job_id, action_type)` (`agent_schema.go:565-590`). The owner drives it with
`/mctl status|leads|show|continue|pause|takeover|approve|reject|conversations`
(`mctl-telegram/internal/agent/control/command.go:15-24`).

This is the state the roadmap warns about: a surface that owns a lifecycle.
It is also, usefully, a proof that the surface's *own* concerns (who is
allowed to see a peer's messages, whether the bot should stay silent in a
thread) are genuinely surface-local and must not migrate into mctl-api.

## Decision

### 1. `WorkItem` is a new mctl-api resource, and the smallest one that works

Neither `AgentExecution` nor `conversations` can carry durable cross-surface
work state.

`AgentExecution` is an immutable, terminal, append-only audit row: it is
written *after* an Argo workflow reaches a terminal phase
(`state.py:1-16`), it has no lifecycle field beyond `phase`, no actor, no
surface, and its uniqueness constraint deliberately ties it to one Argo run.
Making it mutable and pre-execution would destroy the property it exists for.

`conversations` is Telegram-local and Telegram-shaped (`peer_tg_id`,
`peer_access_hash`, `autonomous_turns`), and lives in the Telegram database.

So mctl-api gains `WorkItem`. It is deliberately thin: **identity, lifecycle,
ownership, and correlation**. It stores no conversation content, no prompts,
no evidence bodies and no retrieved context. It is an index over things that
already have their own durable homes (Temporal history, Argo, GitHub,
gitops, the executions ledger), not a second copy of them.

> This satisfies the roadmap's "avoid creating a second conversation
> database" constraint by construction: there is no field on `WorkItem` that
> can hold a message.

### 2. Identity and ID shape

A `WorkItem` has two identifiers.

| Field | Shape | Purpose |
| --- | --- | --- |
| `id` | `wi-<26-char Crockford base32 ULID>` | Canonical, opaque, immutable, lexicographically time-sortable. The only ID any surface prints or accepts from a user. |
| `origin_key` | `<scheme>:<opaque>`, globally unique, immutable | Natural key of the thing that caused the work item to exist. Serves idempotent open. |

`origin_key` schemes, exhaustive for v1alpha1:

```text
github:mctlhq/<repo>/issues/<n>     # dev-loop / investigator work
telegram:conversation/<id>          # conversations.id, mctl-telegram-local surrogate
mcp:session/<opaque>                # ChatGPT / CLI-originated work
incident:<incident-id>              # mctl-agent incident responder
```

`origin_key` is deliberately *not* the work item's public name: it is an
idempotency key, and it is `UNIQUE`. An `id` never changes; an `origin_key`
never changes and is never reused.

The Telegram scheme uses `conversations.id` — the platform-internal
surrogate that `mctl-telegram#442`/`#523` made addressable by `@username`
and `user:<id>` — and never `peer_tg_id` or a peer handle. Raw Telegram
identifiers are personal data belonging to the Telegram surface and do not
cross into mctl-api (see §11).

### 3. Lifecycle states and legal transitions

Six states. `resumed` from the issue's list is modelled as a *transition*,
not a state — a resumed work item is simply `active` again, and the resume
is visible as a new execution plus a new `work_item_events` row.

| State | Meaning |
| --- | --- |
| `open` | Exists, correlated to an origin, no execution has started. |
| `active` | At least one execution is non-terminal. |
| `waiting` | Blocked on something outside the platform's control. Carries `waiting_reason` ∈ `approval`, `input`, `external`. |
| `completed` | Work is finished. Terminal for the *current* attempt; a resume is still legal. |
| `superseded` | Replaced by another work item (`superseded_by` is set). Terminal. |
| `archived` | Retention/administrative close. Terminal, no resume. |

Legal transitions — everything not listed is a `409`:

```text
open        → active | superseded | archived
active      → waiting | completed | superseded | archived
waiting     → active | completed | superseded | archived
completed   → active      (resume; requires a new execution, §7)
completed   → superseded | archived
superseded  → (terminal)
archived    → (terminal)
```

`completed → active` is the resume edge and the only backward edge in the
graph. It is never taken by a state write alone: it is a side effect of a
successful `POST /work-items/{id}/executions`.

### 4. Who owns which fields

Ownership means *who may write*. Everything is readable by any principal that
passes the §8 access check.

| Field group | Writer | Notes |
| --- | --- | --- |
| `id`, `origin_key`, `created_at` | mctl-api | Set once at open, immutable. |
| `owner_actor`, `access_scope` | mctl-api | Resolved from the authenticated principal (`internal/auth/oidc.go:39-51`), never accepted from the request body. |
| `title`, `summary` | mctl-api, on behalf of the opening surface | Free text, ≤ 512 chars, no message bodies. |
| `state`, `waiting_reason`, `revision` | mctl-api | Only mctl-api may write; `mctl-agents` and surfaces request transitions through the API. |
| `superseded_by` | mctl-api | |
| surface refs | the surface, via API | Each surface writes only its own scheme's refs. |
| executions | `mctl-agents` (service principal) | Extends the existing `POST /api/v1/agents/executions` path. |
| context snapshot rows | `mctl-agents` (service principal) | Metadata + `content_hash` only; see open question 1. |
| approval pointers | mctl-api | Derived from the existing approval mechanism, never a second copy of it (§9). |

The rule that matters: **no surface writes `state`**. `mctl-telegram` keeps
`conversations.state` for its own `active`/`paused`/`taken_over` behaviour —
those are presentation and bot-silence concerns, not platform work state, and
this ADR does not migrate them.

### 5. Surface binding, and discovery in both directions

A binding is a row in `work_item_surface_refs`:

```text
work_item_id   wi-01JBX...
surface        telegram | github | mcp | web
ref            conversation/1234        # surface-scoped, opaque to mctl-api
actor_ref      <surface-local actor id, opaque>
bound_at       timestamptz
bound_by       <mctl-api principal that wrote the binding>
```

`(surface, ref)` is `UNIQUE` — one thread binds to at most one work item.
A work item may have many refs across many surfaces; that is the point.

**Forward discovery (surface → work item)** is a local lookup. The surface
persists the `work_item_id` next to its own thread record. For
`mctl-telegram#443` this is one narrow table keyed by
`(user_id, conversation_id)`, holding a `work_item_id` and nothing else.

**Reverse discovery (work item → surfaces)** is
`GET /api/v1/work-items/{id}`, whose response includes the full
`surface_refs` array.

**Recovery discovery (surface ref → work item)** is
`GET /api/v1/work-items?surface=telegram&ref=conversation/1234`. This is the
edge case that makes the contract survivable: a surface that lost or never
wrote its local mapping can still find the canonical work item, and it is
what stops a duplicate work item being minted for a thread that already has
one. It returns at most one work item, by the `UNIQUE (surface, ref)` above.

### 6. Executions, and why resume needs a new workflow ID

Execution identity stays where it already is — `temporal_workflow_id` plus
Temporal's `run_id` — and `agent_executions` gains one nullable column:

```sql
ALTER TABLE agent_executions ADD COLUMN work_item_id TEXT;
CREATE INDEX agent_executions_work_item ON agent_executions (work_item_id, id DESC);
```

Nullable, because every row written before this ADR ships has no work item
and backfilling one would be a guess. The existing
`UNIQUE (temporal_workflow_id, agent, argo_workflow_name)`
(`internal/agentregistry/store.go:129`) is unchanged.

The blocker named in the Context section has to be resolved here.
`workflow_id_for` derives the ID from the issue URL and nothing else
(`issue_ref.py:29-36`), and `StartDevLoopWorkflow` rejects duplicates
(`internal/temporalclient/client.go:116`). A resume therefore cannot reuse
`dev-loop-mctlhq-<repo>-<n>`: that ID is spent for the life of the retention
window regardless of whether the first run succeeded.

**Decision:** work started against a `WorkItem` derives its workflow ID from
the work item and an attempt counter, not from the issue:

```text
wi-01JBX...-a1     # first execution
wi-01JBX...-a2     # resume
```

`attempt` is allocated by mctl-api under the work item's row lock, so it is
monotonic and gap-free per work item. The reuse and conflict policies stay
exactly as they are — `REJECT_DUPLICATE` + `USE_EXISTING` — which means a
retried `POST .../executions` carrying the same `attempt` is idempotent for
free, by the same mechanism that already makes `dev-loop-start` idempotent.

Issue-originated work keeps `dev-loop-{owner}-{repo}-{issue}` for
compatibility; `POST /api/v1/agents/dev-loop/start` is unchanged and remains
the legacy entry point. A work item opened with a `github:` origin binds to
that existing workflow ID as its `a1` execution rather than starting a second
one. Nothing in flight is disturbed.

**Immutability:** a resume never mutates a prior execution row or a prior
snapshot. Prior executions remain queryable at
`GET /work-items/{id}/executions`, ordered oldest-first, each with its own
`attempt`, `context_snapshot_id`, resolved agent version and phase.

### 7. How an investigator resumes across surfaces

The pilot path `mctl-agents#267` and `mctl-telegram#443` must demonstrate:

```text
Telegram thread
   └─ POST /work-items            origin_key=telegram:conversation/1234   → wi-X (open)
   └─ POST /work-items/wi-X/executions {agent: issue-investigator}
        → workflow wi-X-a1, ContextSnapshot v1, wi-X → active
   └─ investigation completes with a follow-up      wi-X → completed
CLI / MCP surface
   └─ GET /work-items?surface=telegram&ref=conversation/1234   → wi-X
   └─ GET /work-items/wi-X            → state, executions, pending approvals
   └─ POST /work-items/wi-X/surface-refs {surface: mcp, ref: session/...}
   └─ POST /work-items/wi-X/executions {resume_of: wi-X-a1, input_ref: ...}
        → workflow wi-X-a2, ContextSnapshot v2, wi-X → active
```

The second surface reads `GET /work-items/wi-X` and the executions list. It
never reads Telegram. The only thing that crosses from Telegram is the
`work_item_id` and, optionally, an appended intent record (§11) — never a
transcript. That is the acceptance criterion "resume does not depend on
replaying the original surface chat transcript", expressed as a data-flow
property rather than a promise.

`ContextSnapshot v2` is assembled fresh by the Context Control Plane
(`mctlhq/.github#20`) from the work item's own references. `v1` is not
mutated, not copied, and not fed forward as text.

### 8. Actor identity and authorization

**Every surface transition re-resolves the actor.** A work item records
`owner_actor` (the mctl-api principal that opened it) and, per surface ref,
the surface-local `actor_ref`. Neither grants anything on its own.

Authorization for any operation on a work item is evaluated against the
**calling** principal's mctl-api identity — `auth.User{ID, Groups}`
(`internal/auth/oidc.go:39-51`) — at the moment of the call. Holding a
`work_item_id` is not a capability. Being reachable in a Telegram thread that
is bound to a work item is not a capability. The codebase already encodes
this asymmetry in the direction that matters: an mctl-api `admins` claim
buys only read scopes on the Telegram side
(`mctl-telegram/internal/auth/sharedhmac/verifier.go:108-114`).

Concretely, for the pilot:

- Opening, reading, binding a surface ref and appending intent require the
  caller to be the `owner_actor` **or** an admin.
- Starting or resuming an execution, and approving anything, keeps the
  existing gate: `user.IsAdmin()`, per `requireTemporalAdmin`
  (`internal/api/handlers_dev_loop.go:53`).

This is intentionally conservative and it means the Telegram pilot can open
and correlate work items but cannot, today, start an investigator run as a
non-admin. Loosening it is open question 2 — a decision that should be made
deliberately, not smuggled in as a side effect of this contract.

### 9. Pending approvals are referenced, never re-implemented

`WorkItem` exposes a read-only `pending_approvals` array, each entry a
pointer:

```text
kind        dev-loop-implement
ref         wi-01JBX...-a1          # the workflow whose approve signal is awaited
requested_at
approve_via POST /api/v1/agents/dev-loop/{workflow_id}/approve
```

The approval itself stays exactly where it is: a Temporal signal into a
workflow blocked on `wait_condition` (`dev_loop.py:515-527`, `:555`), sent by
the existing handler (`handlers_dev_loop.go:149`). No surface gains an
approve path of its own, and mctl-api does not mint a parallel approval
record. A work item in `waiting` with `waiting_reason=approval` is a view
over the workflow's real state, refreshed on read.

`mctl-telegram`'s own `agent_actions` approvals
(`mctl-telegram/internal/db/agent_schema.go:565-590`) are a different thing —
consent for the bot to send a Telegram message — and stay Telegram-local.

### 10. Concurrency and idempotency

| Situation | Rule |
| --- | --- |
| Two surfaces open with the same `origin_key` | The `UNIQUE` constraint wins. The loser's request returns `200` with the existing work item (not `409`, not a second row). `201` means "created", `200` means "already existed" — the caller can tell. |
| Repeated `POST /work-items` from a retrying surface | Same as above; idempotent by `origin_key`. |
| Any state-changing write | Optimistic concurrency on `revision`: `If-Match: <revision>` required, `409` with the current representation on mismatch. |
| Two concurrent resumes | At most **one** non-terminal execution per work item. The second gets `409` naming the live execution. Callers that want "give me the live one" pass `Idempotency-Key`; a replay of the same key within 24h returns the original response. |
| Duplicate `POST .../executions` for an already-allocated `attempt` | Idempotent at the Temporal layer via `USE_EXISTING` (`internal/temporalclient/client.go:117`) — returns the existing run. |
| Binding a surface ref already bound elsewhere | `409`. Rebinding requires an explicit unbind; silent rebinding would orphan history. |

### 11. Durable versus surface-local state, retention, privacy

Durable, in mctl-api:

- work item identity, lifecycle, actor, access scope, revision;
- surface refs (scheme + opaque surface-scoped ref + opaque actor ref);
- execution correlation rows;
- context snapshot **metadata**: id, execution, version, source providers,
  selection strategy, `content_hash` — per `mctlhq/.github#20`'s
  "provenance without leaking retrieved content into telemetry";
- appended **intent records**: a short, caller-authored statement of what the
  user wants next (≤ 2 KB), explicitly not a message and explicitly not
  captured automatically from a thread.

Surface-local, and staying that way:

- Telegram message bodies — they are encrypted at rest in the Telegram
  database (`conversation_messages.body_encrypted`,
  `mctl-telegram/internal/db/agent_schema.go:331-339`) and are never copied
  to mctl-api;
- `peer_tg_id`, `peer_username`, `peer_access_hash`, and every other raw
  Telegram identifier;
- `conversations.state`, `autonomous_turns`, and the `/mctl` command surface;
- ChatGPT/MCP conversation content; browser session state.

Retention: work items and their correlation rows are audit records and are
retained with the audit log. Surface refs are the privacy-relevant part —
they say "this platform actor was active in this thread" — and their
retention after `archived` is open question 5.

### 12. Versioned API surface

Under the existing `/api/v1` prefix (`internal/api/router.go`), documented in
`internal/openapi/openapi.yaml` (OpenAPI 3.0.3, `internal/openapi/openapi.yaml:1-4`).
The resource schema itself carries `apiVersion: work.mctl.ai/v1alpha1`, so
the resource can evolve without a REST path break — the same split ADR 007
uses.

| Operation | Route |
| --- | --- |
| open (idempotent on `origin_key`) | `POST /api/v1/work-items` |
| get current state | `GET /api/v1/work-items/{id}` |
| find by surface ref / actor / state | `GET /api/v1/work-items?surface=&ref=&actor=&state=` |
| correlate a surface | `POST /api/v1/work-items/{id}/surface-refs` |
| append user intent | `POST /api/v1/work-items/{id}/inputs` |
| list executions + snapshots | `GET /api/v1/work-items/{id}/executions` |
| start / resume | `POST /api/v1/work-items/{id}/executions` |
| transition state | `PATCH /api/v1/work-items/{id}` (`If-Match`) |
| inspect pending approval | included in `GET /api/v1/work-items/{id}` |

Approve keeps its existing route (`internal/api/router.go:322`). Nothing in
this table replaces `POST /api/v1/agents/dev-loop/start`
(`router.go:321`) or `POST /api/v1/agents/executions` (`router.go:304`).

### Storage sketch

Same store as `agent_executions` — the `agentregistry` PostgreSQL store
(`internal/agentregistry/store.go`), because the join
work item → execution → agent version has to be a real join, not a
cross-service fan-out. Whether it stays in the `agentregistry` package or
gets its own is an implementation detail, not a contract.

```sql
CREATE TABLE work_items (
    id            TEXT PRIMARY KEY,          -- wi-<ULID>
    origin_key    TEXT NOT NULL UNIQUE,
    owner_actor   TEXT NOT NULL,
    access_scope  TEXT NOT NULL,
    title         TEXT NOT NULL DEFAULT '',
    state         TEXT NOT NULL,
    waiting_reason TEXT NOT NULL DEFAULT '',
    superseded_by TEXT,
    next_attempt  INT  NOT NULL DEFAULT 1,
    revision      BIGINT NOT NULL DEFAULT 1,
    created_at    TIMESTAMPTZ NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL
);

CREATE TABLE work_item_surface_refs (
    work_item_id TEXT NOT NULL REFERENCES work_items(id) ON DELETE CASCADE,
    surface      TEXT NOT NULL,
    ref          TEXT NOT NULL,
    actor_ref    TEXT NOT NULL DEFAULT '',
    bound_by     TEXT NOT NULL,
    bound_at     TIMESTAMPTZ NOT NULL,
    UNIQUE (surface, ref)
);

CREATE TABLE work_item_events (        -- append-only; the resume/transition trail
    id           BIGSERIAL PRIMARY KEY,
    work_item_id TEXT NOT NULL REFERENCES work_items(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,        -- opened|bound|input|execution_started|
                                       -- state_changed|approval_requested|...
    surface      TEXT NOT NULL DEFAULT '',
    actor        TEXT NOT NULL,
    detail_json  TEXT NOT NULL DEFAULT '{}',   -- no message bodies
    created_at   TIMESTAMPTZ NOT NULL
);
```

`work_item_events` is what makes "record which surface/user action caused a
transition" auditable without adding a `surface` column to `audit.Entry`
(`internal/audit/logger.go:26-43`) — though adding one there too is worth
doing, and is cheap.

## Consequences

- `mctl-agents` gains one required input on the investigator path (a
  `work_item_id`) and one changed output (`work_item_id` on the execution
  record). `record_execution`'s payload
  (`mctl-agents/orchestrator/temporal/activities/state.py:47-65`) grows one
  optional field; old workers keep working because the column is nullable.
- The `dev-loop-*` workflow-ID scheme is **not** removed. Work items add a
  second scheme alongside it. Any plan that rewrites the existing scheme in
  place would strand every in-flight loop, since the ID is the dedupe key
  (`internal/temporalclient/client.go:114-117`).
- `mctl-telegram` gains one table and no lifecycle. Its
  `active`/`paused`/`taken_over` machine is untouched, which is what keeps
  `#443`'s "existing Telegram workflows remain backward compatible during
  rollout" achievable.
- The portal/web surface gets a work-item view for free once the read routes
  exist; that is not in scope here.
- Approval remains single-sourced in Temporal. Nothing in this ADR can cause
  a second approval path to appear, because no surface is given one.

## Open questions

These are decisions this document deliberately does not make. Each blocks a
specific implementation choice and needs an owner's answer.

1. **Who owns `context_snapshots` rows?** `mctlhq/.github#20` phase 0 has not
   landed and `ContextSnapshot` does not exist in code. This ADR assumes
   mctl-api stores snapshot *metadata* and `mctl-agents` writes it. If the
   Context Control Plane wants its own store, §11 and the executions response
   change shape.
2. **Does a non-admin surface actor get to start work?** §8 keeps the
   existing admin-only gate. The alternative is a narrower
   `work-items:execute` scope for the `owner_actor`. Until this is answered,
   the Telegram pilot can correlate but not launch.
3. **Should `attempt` allocation live in mctl-api or Temporal?** §6 puts it
   in mctl-api under a row lock. A Temporal-side counter (child workflows,
   or `continue-as-new`) is the alternative and keeps mctl-api out of the
   allocation path.
4. **Does `WorkItem` eventually absorb the gitops proposal `.status.yaml`
   as the approval source of truth?** Today reconcile projects PR state onto
   that file (ADR 005). Two overlapping notions of "state of this piece of
   work" is a known hazard; this ADR does not resolve it.
5. **Retention for surface refs after `archived`.** They are the personal-data
   surface of this model. Indefinite, 90 days, or tied to the audit log's
   retention?
6. **Are Telegram autonomous peer conversations work items at all?** This ADR
   scopes `WorkItem` to platform work (investigator, dev loop, incidents). The
   bot's own lead-handling conversations are a different product surface, and
   folding them in would make `WorkItem` a CRM — an explicit non-goal of
   `#443`. Confirm.
7. **Does `audit.Entry` gain a `surface` field?** §12 records surface
   provenance in `work_item_events`, which covers work-item operations only.
   Every other audited operation still has no surface attribution.

## Non-goals

- Implementing any surface adapter, handler, migration or endpoint. This ADR
  ships no code.
- Synchronising messages between surfaces, or storing any transcript in
  mctl-api.
- Replacing Temporal as the durable orchestration engine, or introducing a
  second workflow engine.
- Migrating `mctl-telegram`'s `conversations` lifecycle, `/mctl` command
  surface, or `agent_actions` send-approvals into the platform.
- Designing portal UX.
- Cross-surface privilege inheritance in any form.

## Implementation map

| Repo | Work |
| --- | --- |
| `mctl-api` | `work_items`, `work_item_surface_refs`, `work_item_events`; `work_item_id` on `agent_executions`; the §12 routes; OpenAPI entries. |
| `mctl-agents` | `mctlhq/mctl-agents#267`: accept `work_item_id`, derive workflow IDs per §6, emit it on `record_execution`, produce a new snapshot per execution. |
| `mctl-telegram` | `mctlhq/mctl-telegram#443`: one mapping table, open/find via §5, show the work item reference to the owner, no lifecycle of its own. |
| `mctl-docs` | Surface-adapter and working-context model, once the open questions are closed. |

### Sequencing

`mctl-api` routes and storage must exist before `mctl-agents#267`, which must
exist before `mctl-telegram#443`'s end-to-end pilot — the acceptance path in
§7 needs both halves. Open questions 1 and 2 gate the first line of that
sequence.
